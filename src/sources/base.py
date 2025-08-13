"""
src/sources/base.py
Clases base mejoradas para fuentes de datos de C4A Alerts
"""
import asyncio
import aiohttp
import hashlib
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging


@dataclass
class ThreatData:
    """Estructura estándar para datos de amenazas"""
    source: str
    title: str
    description: str
    severity: str
    indicators: List[Dict[str, str]]  # [{type: 'ip', value: '1.2.3.4'}]
    cves: List[str]
    tags: List[str]
    timestamp: datetime
    confidence: float
    raw_data: Dict[str, Any]


class BaseSource(ABC):
    """Clase base para todas las fuentes de datos"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = logging.getLogger(self.__class__.__name__)
        self.rate_limiter = RateLimiter(
            calls=config.get('rate_limit', 60),
            period=config.get('rate_period', 60)
        )
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def fetch_data(self) -> List[ThreatData]:
        """Obtiene datos de la fuente"""
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        """Retorna el nombre de la fuente"""
        pass


class RateLimiter:
    """Rate limiter simple para APIs"""
    
    def __init__(self, calls: int, period: int):
        self.calls = calls
        self.period = period
        self.call_times = []
    
    async def acquire(self):
        """Espera si es necesario para respetar rate limits"""
        now = datetime.now()
        
        # Remover llamadas antiguas
        cutoff = now - timedelta(seconds=self.period)
        self.call_times = [t for t in self.call_times if t > cutoff]
        
        # Si hemos hecho demasiadas llamadas, esperar
        if len(self.call_times) >= self.calls:
            sleep_time = self.period - (now - self.call_times[0]).total_seconds()
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        self.call_times.append(now)


class TwitterSecuritySource(BaseSource):
    """Fuente de datos de Twitter/X para threat intelligence"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.bearer_token = config['bearer_token']
        self.base_url = "https://api.twitter.com/2"
        self.security_hashtags = [
            '#cve', '#0day', '#malware', '#threatintel', 
            '#cybersecurity', '#infosec', '#vulnerability'
        ]
    
    async def fetch_data(self) -> List[ThreatData]:
        """Obtiene tweets relacionados con seguridad"""
        await self.rate_limiter.acquire()
        
        query = ' OR '.join(self.security_hashtags)
        url = f"{self.base_url}/tweets/search/recent"
        
        params = {
            'query': f"{query} -is:retweet lang:en",
            'max_results': 100,
            'tweet.fields': 'created_at,public_metrics,context_annotations',
            'user.fields': 'verified,public_metrics',
            'expansions': 'author_id'
        }
        
        headers = {
            'Authorization': f'Bearer {self.bearer_token}',
            'User-Agent': 'C4A-Alerts/2.0'
        }
        
        try:
            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return await self._parse_tweets(data)
                else:
                    self.logger.error(f"Twitter API error: {response.status}")
                    return []
        except Exception as e:
            self.logger.error(f"Error fetching Twitter data: {e}")
            return []
    
    async def _parse_tweets(self, data: Dict[str, Any]) -> List[ThreatData]:
        """Parsea tweets y extrae información de amenazas"""
        threats = []
        
        if 'data' not in data:
            return threats
        
        for tweet in data['data']:
            # Extraer CVEs del texto
            cves = self._extract_cves(tweet.get('text', ''))
            
            # Extraer indicators (IPs, dominios, hashes)
            indicators = self._extract_indicators(tweet.get('text', ''))
            
            # Calcular severidad basada en engagement y verificación del usuario
            severity = self._calculate_severity(tweet, data.get('includes', {}))
            
            threat = ThreatData(
                source='twitter',
                title=f"Security Tweet: {tweet.get('text', '')[:100]}...",
                description=tweet.get('text', ''),
                severity=severity,
                indicators=indicators,
                cves=cves,
                tags=self._extract_hashtags(tweet.get('text', '')),
                timestamp=datetime.fromisoformat(tweet.get('created_at', '').replace('Z', '+00:00')),
                confidence=0.6,  # Twitter tiene confianza media
                raw_data=tweet
            )
            
            if cves or indicators:  # Solo incluir tweets con contenido relevante
                threats.append(threat)
        
        return threats
    
    def _extract_cves(self, text: str) -> List[str]:
        """Extrae CVE IDs del texto"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        return re.findall(cve_pattern, text.upper())
    
    def _extract_indicators(self, text: str) -> List[Dict[str, str]]:
        """Extrae indicadores de compromiso del texto"""
        import re
        indicators = []
        
        # IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for ip in re.findall(ip_pattern, text):
            indicators.append({'type': 'ip', 'value': ip})
        
        # Dominios
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
        for match in re.finditer(domain_pattern, text):
            domain = match.group(0)
            if not domain.endswith(('.png', '.jpg', '.gif', '.com/status')):  # Filtrar URLs de imágenes
                indicators.append({'type': 'domain', 'value': domain})
        
        # Hashes (MD5, SHA1, SHA256)
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }
        
        for hash_type, pattern in hash_patterns.items():
            for hash_val in re.findall(pattern, text):
                indicators.append({'type': 'hash', 'value': hash_val, 'hash_type': hash_type})
        
        return indicators
    
    def _extract_hashtags(self, text: str) -> List[str]:
        """Extrae hashtags del texto"""
        import re
        return re.findall(r'#\w+', text.lower())
    
    def _calculate_severity(self, tweet: Dict[str, Any], includes: Dict[str, Any]) -> str:
        """Calcula severidad basada en métricas del tweet"""
        metrics = tweet.get('public_metrics', {})
        retweets = metrics.get('retweet_count', 0)
        likes = metrics.get('like_count', 0)
        
        # Verificar si el usuario está verificado
        author_id = tweet.get('author_id')
        is_verified = False
        if 'users' in includes:
            for user in includes['users']:
                if user.get('id') == author_id:
                    is_verified = user.get('verified', False)
                    break
        
        # Calcular score
        engagement_score = (retweets * 2 + likes) / 100
        verification_bonus = 2 if is_verified else 0
        total_score = engagement_score + verification_bonus
        
        if total_score >= 10:
            return 'high'
        elif total_score >= 5:
            return 'medium'
        else:
            return 'low'
    
    def get_source_name(self) -> str:
        return "twitter"


class MalwareBazaarSource(BaseSource):
    """Fuente de datos de MalwareBazaar"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = "https://mb-api.abuse.ch/api/v1"
        self.api_key = config.get('api_key')  # Opcional para rate limits más altos
    
    async def fetch_data(self) -> List[ThreatData]:
        """Obtiene muestras recientes de malware"""
        await self.rate_limiter.acquire()
        
        url = f"{self.base_url}/"
        
        # Obtener muestras de las últimas 24 horas
        payload = {
            'query': 'get_recent',
            'selector': 'time',
            'days': '1'
        }
        
        headers = {'User-Agent': 'C4A-Alerts/2.0'}
        if self.api_key:
            headers['API-KEY'] = self.api_key
        
        try:
            async with self.session.post(url, data=payload, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return await self._parse_malware_samples(data)
                else:
                    self.logger.error(f"MalwareBazaar API error: {response.status}")
                    return []
        except Exception as e:
            self.logger.error(f"Error fetching MalwareBazaar data: {e}")
            return []
    
    async def _parse_malware_samples(self, data: Dict[str, Any]) -> List[ThreatData]:
        """Parsea muestras de malware"""
        threats = []
        
        if data.get('query_status') != 'ok' or 'data' not in data:
            return threats
        
        for sample in data['data']:
            # Extraer indicadores
            indicators = []
            
            if sample.get('sha256_hash'):
                indicators.append({
                    'type': 'hash',
                    'value': sample['sha256_hash'],
                    'hash_type': 'sha256'
                })
            
            if sample.get('md5_hash'):
                indicators.append({
                    'type': 'hash',
                    'value': sample['md5_hash'],
                    'hash_type': 'md5'
                })
            
            # Determinar severidad basada en signature
            severity = self._determine_malware_severity(sample.get('signature', ''))
            
            threat = ThreatData(
                source='malwarebazaar',
                title=f"Malware Sample: {sample.get('file_name', 'Unknown')}",
                description
