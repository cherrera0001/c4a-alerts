"""
src/sources/twitter.py
Integración con Twitter/X API para threat intelligence
"""
import asyncio
import aiohttp
import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import logging

from .base import BaseSource, ThreatData, RateLimiter
from ..core.event_bus import EventType, event_bus


class TwitterSecuritySource(BaseSource):
    """Fuente de datos de Twitter/X para threat intelligence"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.bearer_token = config['bearer_token']
        self.base_url = "https://api.twitter.com/2"
        
        # Hashtags y términos de seguridad a monitorear
        self.security_hashtags = config.get('security_hashtags', [
            '#cve', '#0day', '#malware', '#threatintel', 
            '#cybersecurity', '#infosec', '#vulnerability',
            '#ransomware', '#apt', '#breach'
        ])
        
        # Cuentas de seguridad verificadas a monitorear
        self.security_accounts = config.get('security_accounts', [
            'CVEnew', 'threatintel', 'malwrhunterteam',
            'bad_packets', 'cyb3rops', 'NCSC'
        ])
        
        # Configuración de filtros
        self.min_followers = config.get('min_followers', 1000)
        self.hours_lookback = config.get('hours_lookback', 24)
        self.max_results = config.get('max_results', 100)
        
        # Rate limiter específico para Twitter (300 requests/15min)
        self.rate_limiter = RateLimiter(calls=300, period=900)
    
    async def fetch_data(self) -> List[ThreatData]:
        """Obtiene tweets relacionados con seguridad"""
        try:
            await event_bus.publish(
                EventType.SOURCE_STARTED,
                {'source': self.get_source_name()},
                source=self.get_source_name()
            )
            
            all_threats = []
            
            # Buscar por hashtags
            hashtag_threats = await self._search_by_hashtags()
            all_threats.extend(hashtag_threats)
            
            # Buscar por cuentas específicas
            account_threats = await self._search_by_accounts()
            all_threats.extend(account_threats)
            
            # Deduplicar por tweet ID
            unique_threats = self._deduplicate_threats(all_threats)
            
            await event_bus.publish(
                EventType.SOURCE_COMPLETED,
                {
                    'source': self.get_source_name(),
                    'threats_found': len(unique_threats)
                },
                source=self.get_source_name()
            )
            
            return unique_threats
            
        except Exception as e:
            self.logger.error(f"Error fetching Twitter data: {e}")
            await event_bus.publish(
                EventType.SOURCE_FAILED,
                {
                    'source': self.get_source_name(),
                    'error': str(e)
                },
                source=self.get_source_name()
            )
            return []
    
    async def _search_by_hashtags(self) -> List[ThreatData]:
        """Busca tweets por hashtags de seguridad"""
        await self.rate_limiter.acquire()
        
        # Construir query con hashtags
        hashtag_query = ' OR '.join(self.security_hashtags)
        query = f"({hashtag_query}) -is:retweet -is:reply lang:en"
        
        # Agregar filtro temporal
        since_time = datetime.utcnow() - timedelta(hours=self.hours_lookback)
        query += f" since:{since_time.isoformat()}Z"
        
        return await self._execute_search(query, "hashtags")
    
    async def _search_by_accounts(self) -> List[ThreatData]:
        """Busca tweets de cuentas de seguridad específicas"""
        await self.rate_limiter.acquire()
        
        # Construir query con cuentas
        accounts_query = ' OR '.join([f"from:{account}" for account in self.security_accounts])
        query = f"({accounts_query}) -is:retweet lang:en"
        
        # Agregar filtro temporal
        since_time = datetime.utcnow() - timedelta(hours=self.hours_lookback)
        query += f" since:{since_time.isoformat()}Z"
        
        return await self._execute_search(query, "accounts")
    
    async def _execute_search(self, query: str, search_type: str) -> List[ThreatData]:
        """Ejecuta una búsqueda en Twitter API"""
        url = f"{self.base_url}/tweets/search/recent"
        
        params = {
            'query': query,
            'max_results': self.max_results,
            'tweet.fields': 'created_at,public_metrics,context_annotations,entities',
            'user.fields': 'verified,public_metrics,description',
            'expansions': 'author_id'
        }
        
        headers = {
            'Authorization': f'Bearer {self.bearer_token}',
            'User-Agent': 'C4A-Alerts/2.0'
        }
        
        self.logger.info(f"Searching Twitter ({search_type}): {query[:100]}...")
        
        try:
            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    threats = await self._parse_tweets(data, search_type)
                    self.logger.info(f"Found {len(threats)} threats from Twitter ({search_type})")
                    return threats
                elif response.status == 429:
                    self.logger.warning("Twitter rate limit exceeded")
                    return []
                else:
                    error_data = await response.text()
                    self.logger.error(f"Twitter API error {response.status}: {error_data}")
                    return []
                    
        except Exception as e:
            self.logger.error(f"Error executing Twitter search ({search_type}): {e}")
            return []
    
    async def _parse_tweets(self, data: Dict[str, Any], search_type: str) -> List[ThreatData]:
        """Parsea tweets y extrae información de amenazas"""
        threats = []
        
        if 'data' not in data:
            return threats
        
        # Crear mapeo de usuarios
        users_map = {}
        if 'includes' in data and 'users' in data['includes']:
            users_map = {user['id']: user for user in data['includes']['users']}
        
        for tweet in data['data']:
            try:
                # Obtener información del usuario
                author_id = tweet.get('author_id')
                user_info = users_map.get(author_id, {})
                
                # Filtrar por número mínimo de seguidores si está disponible
                user_metrics = user_info.get('public_metrics', {})
                followers_count = user_metrics.get('followers_count', 0)
                
                if search_type == "hashtags" and followers_count < self.min_followers:
                    continue
                
                # Extraer contenido relevante
                text = tweet.get('text', '')
                cves = self._extract_cves(text)
                indicators = self._extract_indicators(text)
                urls = self._extract_urls(tweet.get('entities', {}))
                
                # Solo procesar tweets con contenido relevante
                if not (cves or indicators or self._has_security_keywords(text)):
                    continue
                
                # Calcular severidad y confianza
                severity = self._calculate_severity(tweet, user_info)
                confidence = self._calculate_confidence(tweet, user_info, search_type)
                
                # Crear objeto ThreatData
                threat = ThreatData(
                    source='twitter',
                    title=f"Security Tweet: {text[:100]}{'...' if len(text) > 100 else ''}",
                    description=text,
                    severity=severity,
                    indicators=indicators + urls,
                    cves=cves,
                    tags=self._extract_hashtags(text) + [f"search:{search_type}"],
                    timestamp=self._parse_twitter_timestamp(tweet.get('created_at')),
                    confidence=confidence,
                    raw_data={
                        'tweet': tweet,
                        'user': user_info,
                        'search_type': search_type
                    }
                )
                
                threats.append(threat)
                
            except Exception as e:
                self.logger.error(f"Error parsing tweet {tweet.get('id', 'unknown')}: {e}")
                continue
        
        return threats
    
    def _extract_cves(self, text: str) -> List[str]:
        """Extrae CVE IDs del texto"""
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cves = re.findall(cve_pattern, text.upper())
        return list(set(cves))  # Eliminar duplicados
    
    def _extract_indicators(self, text: str) -> List[Dict[str, str]]:
        """Extrae indicadores de compromiso del texto"""
        indicators = []
        
        # Patrones para diferentes tipos de IoCs
        patterns = {
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        }
        
        for ioc_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                # Filtrar falsos positivos comunes
                if self._is_valid_indicator(ioc_type, match):
                    indicators.append({
                        'type': ioc_type,
                        'value': match,
                        'context': 'twitter_mention'
                    })
        
        return indicators
    
    def _extract_urls(self, entities: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extrae URLs de las entidades del tweet"""
        indicators = []
        
        if 'urls' in entities:
            for url_entity in entities['urls']:
                expanded_url = url_entity.get('expanded_url', url_entity.get('url', ''))
                if expanded_url and self._is_suspicious_url(expanded_url):
                    indicators.append({
                        'type': 'url',
                        'value': expanded_url,
                        'context': 'twitter_link'
                    })
        
        return indicators
    
    def _extract_hashtags(self, text: str) -> List[str]:
        """Extrae hashtags del texto"""
        hashtag_pattern = r'#\w+'
        hashtags = re.findall(hashtag_pattern, text.lower())
        return hashtags
    
    def _has_security_keywords(self, text: str) -> bool:
        """Verifica si el texto contiene palabras clave de seguridad"""
        security_keywords = [
            'vulnerability', 'exploit', 'malware', 'ransomware',
            'phishing', 'backdoor', 'trojan', 'botnet',
            'data breach', 'zero-day', 'patch', 'security update'
        ]
        
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in security_keywords)
    
    def _is_valid_indicator(self, ioc_type: str, value: str) -> bool:
        """Valida si un indicador es legítimo"""
        # Filtros específicos por tipo
        if ioc_type == 'domain':
            # Filtrar dominios comunes no maliciosos
            common_domains = [
                'twitter.com', 'github.com', 'google.com',
                'microsoft.com', 'cve.mitre.org', 'nvd.nist.gov'
            ]
            return not any(domain in value.lower() for domain in common_domains)
        
        elif ioc_type == 'ip':
            # Filtrar IPs privadas y comunes
            import ipaddress
            try:
                ip = ipaddress.ip_address(value)
                return not ip.is_private and not ip.is_loopback
            except ValueError:
                return False
        
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            # Los hashes son generalmente válidos si tienen el formato correcto
            return True
        
        return True
    
    def _is_suspicious_url(self, url: str) -> bool:
        """Determina si una URL es potencialmente sospechosa"""
        suspicious_indicators = [
            'bit.ly', 'tinyurl', 'pastebin.com',
            'hastebin.com', 'gist.github.com'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in suspicious_indicators)
    
    def _calculate_severity(self, tweet: Dict[str, Any], user_info: Dict[str, Any]) -> str:
        """Calcula severidad basada en métricas del tweet y usuario"""
        metrics = tweet.get('public_metrics', {})
        user_metrics = user_info.get('public_metrics', {})
        
        # Factores de severidad
        retweets = metrics.get('retweet_count', 0)
        likes = metrics.get('like_count', 0)
        replies = metrics.get('reply_count', 0)
        followers = user_metrics.get('followers_count', 0)
        is_verified = user_info.get('verified', False)
        
        # Calcular score base
        engagement_score = (retweets * 3 + likes + replies * 2) / 10
        follower_score = min(followers / 10000, 5)  # Max 5 puntos por followers
        verification_bonus = 3 if is_verified else 0
        
        total_score = engagement_score + follower_score + verification_bonus
        
        # Determinar severidad
        if total_score >= 15:
            return 'critical'
        elif total_score >= 10:
            return 'high'
        elif total_score >= 5:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_confidence(self, 
                            tweet: Dict[str, Any], 
                            user_info: Dict[str, Any], 
                            search_type: str) -> float:
        """Calcula nivel de confianza de la amenaza"""
        base_confidence = 0.4  # Confianza base para Twitter
        
        # Bonificaciones
        if user_info.get('verified', False):
            base_confidence += 0.2
        
        if search_type == "accounts":  # Cuentas curadas tienen mayor confianza
            base_confidence += 0.2
        
        # Verificar si es una cuenta de seguridad conocida
        user_description = user_info.get('description', '').lower()
        security_terms = ['security', 'threat', 'malware', 'researcher', 'analyst']
        if any(term in user_description for term in security_terms):
            base_confidence += 0.1
        
        # Penalización por baja actividad
        user_metrics = user_info.get('public_metrics', {})
        if user_metrics.get('followers_count', 0) < 100:
            base_confidence -= 0.1
        
        return min(max(base_confidence, 0.1), 1.0)  # Mantener entre 0.1 y 1.0
    
    def _parse_twitter_timestamp(self, timestamp_str: str) -> datetime:
        """Parsea timestamp de Twitter"""
        try:
            # Twitter usa formato ISO 8601
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return datetime.utcnow()
    
    def _deduplicate_threats(self, threats: List[ThreatData]) -> List[ThreatData]:
        """Elimina amenazas duplicadas basándose en tweet ID"""
        seen_ids = set()
        unique_threats = []
        
        for threat in threats:
            tweet_id = threat.raw_data.get('tweet', {}).get('id')
            if tweet_id and tweet_id not in seen_ids:
                seen_ids.add(tweet_id)
                unique_threats.append(threat)
        
        return unique_threats
    
    def get_source_name(self) -> str:
        return "twitter"
    
    async def health_check(self) -> Dict[str, Any]:
        """Realiza un health check de la fuente Twitter"""
        try:
            await self.rate_limiter.acquire()
            
            url = f"{self.base_url}/tweets/search/recent"
            params = {
                'query': '#cybersecurity',
                'max_results': 10
            }
            headers = {
                'Authorization': f'Bearer {self.bearer_token}',
                'User-Agent': 'C4A-Alerts/2.0'
            }
            
            start_time = datetime.utcnow
