"""
Alert Processing Pipeline for C4A Alerts.

Provides a modular, extensible pipeline for processing threat intelligence alerts
including normalization, deduplication, enrichment, scoring, and filtering.
"""

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Set, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from .metrics import MetricsCollector, time_stage, MetricStatus

logger = logging.getLogger(__name__)


class ProcessingStage(Enum):
    """Processing pipeline stages."""
    NORMALIZATION = "normalization"
    DEDUPLICATION = "deduplication" 
    ENRICHMENT = "enrichment"
    SCORING = "scoring"
    FILTERING = "filtering"
    CLASSIFICATION = "classification"


class AlertStatus(Enum):
    """Status of alerts during processing."""
    PENDING = "pending"
    PROCESSED = "processed"
    FILTERED = "filtered"
    ERROR = "error"


@dataclass
class ProcessedAlert:
    """Processed alert with metadata."""
    # Core fields
    id: str
    title: str
    description: str
    url: Optional[str] = None
    source: str = "unknown"
    
    # Timestamps
    published_at: datetime = field(default_factory=datetime.now)
    processed_at: datetime = field(default_factory=datetime.now)
    
    # Processing metadata
    status: AlertStatus = AlertStatus.PENDING
    processing_stages: List[str] = field(default_factory=list)
    
    # Enrichment data
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    kev_listed: bool = False
    poc_available: bool = False
    
    # Classification
    attack_types: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Scoring
    risk_score: float = 0.0
    confidence_score: float = 0.0
    
    # Original data
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    # Hashing for deduplication
    content_hash: Optional[str] = None
    
    def __post_init__(self):
        if self.content_hash is None:
            self.content_hash = self.generate_content_hash()
    
    def generate_content_hash(self) -> str:
        """Generate content hash for deduplication."""
        content = f"{self.title}{self.url}{self.source}".lower().strip()
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
    
    def add_processing_stage(self, stage: ProcessingStage) -> None:
        """Mark that alert has been processed by a stage."""
        stage_name = stage.value
        if stage_name not in self.processing_stages:
            self.processing_stages.append(stage_name)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "source": self.source,
            "published_at": self.published_at.isoformat(),
            "processed_at": self.processed_at.isoformat(),
            "status": self.status.value,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "kev_listed": self.kev_listed,
            "poc_available": self.poc_available,
            "attack_types": self.attack_types,
            "affected_products": self.affected_products,
            "mitre_techniques": self.mitre_techniques,
            "risk_score": self.risk_score,
            "confidence_score": self.confidence_score,
            "content_hash": self.content_hash,
            "processing_stages": self.processing_stages
        }


class ProcessorBase(ABC):
    """Abstract base class for alert processors."""
    
    def __init__(self, name: str):
        self.name = name
        self.enabled = True
        self.processed_count = 0
        self.error_count = 0
    
    @abstractmethod
    def process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        """Process a list of alerts and return processed alerts."""
        pass
    
    def pre_process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        """Pre-processing hook (optional override)."""
        return alerts
    
    def post_process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        """Post-processing hook (optional override)."""
        return alerts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "processed_count": self.processed_count,
            "error_count": self.error_count,
            "success_rate": (self.processed_count / (self.processed_count + self.error_count)) * 100 
                           if (self.processed_count + self.error_count) > 0 else 0
        }


class NormalizationProcessor(ProcessorBase):
    """Normalizes raw alerts into ProcessedAlert format."""
    
    def __init__(self):
        super().__init__("Normalization")
        
    def process(self, raw_alerts: List[Dict[str, Any]]) -> List[ProcessedAlert]:
        """Convert raw alerts to ProcessedAlert objects."""
        normalized_alerts = []
        
        for raw_alert in raw_alerts:
            try:
                normalized = self._normalize_single_alert(raw_alert)
                normalized.add_processing_stage(ProcessingStage.NORMALIZATION)
                normalized_alerts.append(normalized)
                self.processed_count += 1
                
            except Exception as e:
                logger.warning(f"❌ Failed to normalize alert: {e}")
                self.error_count += 1
                continue
        
        logger.info(f"✅ Normalized {len(normalized_alerts)}/{len(raw_alerts)} alerts")
        return normalized_alerts
    
    def _normalize_single_alert(self, raw_alert: Dict[str, Any]) -> ProcessedAlert:
        """Normalize a single raw alert."""
        # Extract core fields with fallbacks
        title = self._clean_text(raw_alert.get("title", ""))
        description = self._clean_text(raw_alert.get("description", raw_alert.get("summary", "")))
        url = self._validate_url(raw_alert.get("url"))
        source = raw_alert.get("source", "unknown")
        
        # Generate stable ID
        alert_id = raw_alert.get("id") or self._generate_id(title, url, source)
        
        # Parse published date
        published_at = self._parse_published_date(raw_alert.get("published", raw_alert.get("published_at")))
        
        return ProcessedAlert(
            id=alert_id,
            title=title,
            description=description,
            url=url,
            source=source,
            published_at=published_at,
            raw_data=raw_alert
        )
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize text content."""
        if not text:
            return ""
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove common prefixes/suffixes
        text = re.sub(r'^(alert|advisory|bulletin):\s*', '', text, flags=re.IGNORECASE)
        
        return text.strip()
    
    def _validate_url(self, url: Optional[str]) -> Optional[str]:
        """Validate and clean URL."""
        if not url:
            return None
        
        url = url.strip()
        
        # Basic URL validation
        if not re.match(r'^https?://', url):
            return None
        
        # Remove tracking parameters
        url = re.sub(r'[?&](utm_|ref=|src=)[^&]*', '', url)
        
        return url
    
    def _generate_id(self, title: str, url: Optional[str], source: str) -> str:
        """Generate stable ID for alert."""
        content = f"{title}{url or ''}{source}".lower().strip()
        hash_obj = hashlib.sha256(content.encode('utf-8'))
        return f"{source.lower()}-{hash_obj.hexdigest()[:12]}"
    
    def _parse_published_date(self, date_str: Any) -> datetime:
        """Parse published date from various formats."""
        if isinstance(date_str, datetime):
            return date_str
        
        if not date_str:
            return datetime.now()
        
        # Try common date formats
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ", 
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%a, %d %b %Y %H:%M:%S %z"
        ]
        
        for fmt in formats:
            try:
                if isinstance(date_str, str):
                    # Handle Z timezone
                    if date_str.endswith('Z'):
                        date_str = date_str[:-1] + '+00:00'
                    return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        logger.warning(f"⚠️ Could not parse date: {date_str}")
        return datetime.now()


class DeduplicationProcessor(ProcessorBase):
    """Removes duplicate alerts based on content hash."""
    
    def __init__(self, existing_hashes: Optional[Set[str]] = None):
        super().__init__("Deduplication")
        self.existing_hashes = existing_hashes or set()
        self.seen_hashes = set()
    
    def process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        """Remove duplicate alerts."""
        unique_alerts = []
        duplicate_count = 0
        
        for alert in alerts:
            if self._is_duplicate(alert):
                duplicate_count += 1
                alert.status = AlertStatus.FILTERED
                continue
            
            # Mark as seen
            self.seen_hashes.add(alert.content_hash)
            alert.add_processing_stage(ProcessingStage.DEDUPLICATION)
            unique_alerts.append(alert)
            self.processed_count += 1
        
        logger.info(f"✅ Deduplicated: {len(unique_alerts)} unique, {duplicate_count} duplicates removed")
        return unique_alerts
    
    def _is_duplicate(self, alert: ProcessedAlert) -> bool:
        """Check if alert is a duplicate."""
        return (alert.content_hash in self.existing_hashes or 
                alert.content_hash in self.seen_hashes)
    
    def update_existing_hashes(self, hashes: Set[str]) -> None:
        """Update the set of existing hashes."""
        self.existing_hashes.update(hashes)


class ScoringProcessor(ProcessorBase):
    """Scores alerts based on risk and relevance."""
    
    def __init__(self, scoring_config: Optional[Dict[str, Any]] = None):
        super().__init__("Scoring")
        self.config = scoring_config or self._get_default_config()
    
    def process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        """Score alerts for risk and relevance."""
        for alert in alerts:
            try:
                alert.risk_score = self._calculate_risk_score(alert)
                alert.confidence_score = self._calculate_confidence_score(alert)
                alert.add_processing_stage(ProcessingStage.SCORING)
                self.processed_count += 1
                
            except Exception as e:
                logger.warning(f"❌ Failed to score alert {alert.id}: {e}")
                self.error_count += 1
                alert.risk_score = 0.0
                alert.confidence_score = 0.0
        
        # Sort by risk score (highest first)
        alerts.sort(key=lambda x: x.risk_score, reverse=True)
        
        logger.info(f"✅ Scored {len(alerts)} alerts (avg risk: {self._average_risk_score(alerts):.1f})")
        return alerts
    
    def _calculate_risk_score(self, alert: ProcessedAlert) -> float:
        """Calculate risk score (0-10)."""
        score = 0.0
        
        # CVSS component (0-4 points)
        if alert.cvss_score:
            score += min(4.0, alert.cvss_score * 0.4)
        
        # EPSS component (0-2 points)
        if alert.epss_score:
            score += alert.epss_score * 2.0
        
        # KEV component (2 points)
        if alert.kev_listed:
            score += 2.0
        
        # PoC availability (1 point)
        if alert.poc_available:
            score += 1.0
        
        # Critical keywords (1 point)
        critical_keywords = self.config.get("critical_keywords", [])
        text = f"{alert.title} {alert.description}".lower()
        if any(keyword in text for keyword in critical_keywords):
            score += 1.0
        
        # Attack type bonus
        high_risk_attacks = ["remote code execution", "privilege escalation", "authentication bypass"]
        if any(attack.lower() in high_risk_attacks for attack in alert.attack_types):
            score += 1.0
        
        # Age factor (newer = higher score)
        age_hours = (datetime.now() - alert.published_at).total_seconds() / 3600
        if age_hours <= 24:
            score += 0.5
        elif age_hours <= 168:  # 1 week
            score += 0.25
        
        return min(10.0, score)
    
    def _calculate_confidence_score(self, alert: ProcessedAlert) -> float:
        """Calculate confidence score (0-1)."""
        confidence = 0.5  # Base confidence
        
        # Source reliability
        source_scores = self.config.get("source_reliability", {})
        source_score = source_scores.get(alert.source.lower(), 0.5)
        confidence += (source_score - 0.5) * 0.5
        
        # Data completeness
        completeness = self._calculate_completeness(alert)
        confidence += completeness * 0.3
        
        # Validation checks
        if alert.url and self._is_valid_url(alert.url):
            confidence += 0.1
        
        if alert.cvss_score and alert.cvss_score > 0:
            confidence += 0.1
        
        return min(1.0, max(0.0, confidence))
    
    def _calculate_completeness(self, alert: ProcessedAlert) -> float:
        """Calculate data completeness score."""
        fields = [
            alert.title,
            alert.description,
            alert.url,
            alert.cvss_score,
            alert.attack_types
        ]
        
        filled_fields = sum(1 for field in fields if field)
        return filled_fields / len(fields)
    
    def _is_valid_url(self, url: str) -> bool:
        """Basic URL validation."""
        return bool(re.match(r'^https?://[^\s]+$', url))
    
    def _average_risk_score(self, alerts: List[ProcessedAlert]) -> float:
        """Calculate average risk score."""
        if not alerts:
            return 0.0
        return sum(alert.risk_score for alert in alerts) / len(alerts)
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default scoring configuration."""
        return {
            "critical_keywords": [
                "critical", "urgent", "zero-day", "0day", "rce", "remote code execution",
                "privilege escalation", "authentication bypass", "exploit"
            ],
            "source_reliability": {
                "cisa": 0.9,
                "cert": 0.8,
                "mitre": 0.9,
                "github": 0.7,
                "reddit": 0.4,
                "exploitdb": 0.8,
                "threatpost": 0.6,
                "csirt chile": 0.7
            }
        }


class ClassificationProcessor(ProcessorBase):
    """Classifies alerts by attack type and affected technologies."""
    
    def __init__(self):
        super().__init__("Classification")
        self.attack_patterns = self._get_attack_patterns()
        self.product_patterns = self._get_product_patterns()
        self.mitre_mapping = self._get_mitre_mapping()
    
    def process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        """Classify alerts by attack type and technology."""
        for alert in alerts:
            try:
                # Classify attack types
                alert.attack_types = self._classify_attack_types(alert)
                
                # Extract affected products
                alert.affected_products = self._extract_products(alert)
                
                # Map to MITRE techniques
                alert.mitre_techniques = self._map_to_mitre(alert.attack_types)
                
                alert.add_processing_stage(ProcessingStage.CLASSIFICATION)
                self.processed_count += 1
                
            except Exception as e:
                logger.warning(f"❌ Classification failed for {alert.id}: {e}")
                self.error_count += 1
        
        logger.info(f"✅ Classified {len(alerts)} alerts")
        return alerts
    
    def _classify_attack_types(self, alert: ProcessedAlert) -> List[str]:
        """Classify attack types based on content analysis."""
        text = f"{alert.title} {alert.description}".lower()
        detected_types = []
        
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detected_types.append(attack_type)
                    break
        
        return detected_types
    
    def _extract_products(self, alert: ProcessedAlert) -> List[str]:
        """Extract mentions of software products."""
        text = f"{alert.title} {alert.description}".lower()
        products = []
        
        for product, patterns in self.product_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    products.append(product)
                    break
        
        return products
    
    def _map_to_mitre(self, attack_types: List[str]) -> List[str]:
        """Map attack types to MITRE ATT&CK techniques."""
        techniques = []
        
        for attack_type in attack_types:
            mitre_ids = self.mitre_mapping.get(attack_type.lower(), [])
            techniques.extend(mitre_ids)
        
        return list(set(techniques))  # Remove duplicates
    
    def _get_attack_patterns(self) -> Dict[str, List[str]]:
        """Get regex patterns for attack type detection."""
        return {
            "Remote Code Execution": [
                r'\b(remote code execution|RCE|arbitrary code|code injection)\b',
                r'\b(command injection|shell injection|eval)\b',
                r'\b(deserialization|unsafe deserialization)\b'
            ],
            "Privilege Escalation": [
                r'\b(privilege escalation|privesc|elevation)\b',
                r'\b(root access|admin rights|sudo)\b',
                r'\b(local privilege|LPE)\b'
            ],
            "Authentication Bypass": [
                r'\b(authentication bypass|auth bypass|login bypass)\b',
                r'\b(access control|authorization bypass)\b',
                r'\b(session fixation|session hijacking)\b'
            ],
            "Code Injection": [
                r'\b(SQL injection|SQLi|NoSQL injection)\b',
                r'\b(LDAP injection|XPath injection)\b',
                r'\b(template injection|SSTI)\b'
            ],
            "Cross-Site Scripting": [
                r'\b(cross.site scripting|XSS|script injection)\b',
                r'\b(reflected XSS|stored XSS|DOM XSS)\b'
            ],
            "Directory Traversal": [
                r'\b(directory traversal|path traversal)\b',
                r'\b(local file inclusion|LFI|remote file inclusion|RFI)\b'
            ],
            "Denial of Service": [
                r'\b(denial of service|DoS|DDoS)\b',
                r'\b(resource exhaustion|memory exhaustion)\b'
            ]
        }
    
    def _get_product_patterns(self) -> Dict[str, List[str]]:
        """Get regex patterns for product detection."""
        return {
            "Apache": [r'\bapache\b', r'\bhttpd\b'],
            "Nginx": [r'\bnginx\b'],
            "MySQL": [r'\bmysql\b', r'\bmariadb\b'],
            "PostgreSQL": [r'\bpostgresql\b', r'\bpostgres\b'],
            "WordPress": [r'\bwordpress\b', r'\bwp-\b'],
            "Drupal": [r'\bdrupal\b'],
            "Linux": [r'\blinux\b', r'\bubuntu\b', r'\bcentos\b', r'\brhel\b'],
            "Windows": [r'\bwindows\b', r'\bwin32\b', r'\bwin64\b'],
            "Java": [r'\bjava\b', r'\bspring\b', r'\bstruts\b'],
            "PHP": [r'\bphp\b'],
            "Python": [r'\bpython\b', r'\bdjango\b', r'\bflask\b'],
            "Node.js": [r'\bnode\.?js\b', r'\bnpm\b'],
            "Docker": [r'\bdocker\b', r'\bcontainer\b'],
            "Kubernetes": [r'\bkubernetes\b', r'\bk8s\b']
        }
    
    def _get_mitre_mapping(self) -> Dict[str, List[str]]:
        """Map attack types to MITRE ATT&CK technique IDs."""
        return {
            "remote code execution": ["T1059", "T1190"],
            "privilege escalation": ["T1068", "T1548"],
            "authentication bypass": ["T1078", "T1212"],
            "code injection": ["T1190", "T1059"],
            "cross-site scripting": ["T1059.007"],
            "directory traversal": ["T1083", "T1005"],
            "denial of service": ["T1499", "T1498"]
        }


class FilteringProcessor(ProcessorBase):
    """Filters alerts based on relevance and quality criteria."""
    
    def __init__(self, min_score: float = 3.0, max_age_days: int = 30):
        super().__init__("Filtering")
        self.min_score = min_score
        self.max_age_days = max_age_days
        self.quality_filters = self._get_quality_filters()
    
    def process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        """Filter alerts based on quality and relevance criteria."""
        filtered_alerts = []
        filter_reasons = {}
        
        for alert in alerts:
            try:
                filter_reason = self._should_filter(alert)
                
                if filter_reason:
                    alert.status = AlertStatus.FILTERED
                    filter_reasons[filter_reason] = filter_reasons.get(filter_reason, 0) + 1
                    continue
                
                alert.add_processing_stage(ProcessingStage.FILTERING)
                filtered_alerts.append(alert)
                self.processed_count += 1
                
            except Exception as e:
                logger.warning(f"❌ Filter evaluation failed for {alert.id}: {e}")
                self.error_count += 1
                # Include alert if filtering fails
                filtered_alerts.append(alert)
        
        # Log filter statistics
        filtered_count = len(alerts) - len(filtered_alerts)
        logger.info(f"✅ Filtered: {len(filtered_alerts)} passed, {filtered_count} filtered")
        
        if filter_reasons:
            logger.debug("📊 Filter reasons:")
            for reason, count in filter_reasons.items():
                logger.debug(f"  {reason}: {count} alerts")
        
        return filtered_alerts
    
    def _should_filter(self, alert: ProcessedAlert) -> Optional[str]:
        """Check if alert should be filtered out. Returns filter reason or None."""
        
        # Score filter
        if alert.risk_score < self.min_score:
            return f"low_score_{alert.risk_score:.1f}"
        
        # Age filter
        age_days = (datetime.now() - alert.published_at).days
        if age_days > self.max_age_days:
            return f"too_old_{age_days}d"
        
        # Quality filters
        for filter_name, filter_func in self.quality_filters.items():
            if not filter_func(alert):
                return f"quality_{filter_name}"
        
        return None
    
    def _get_quality_filters(self) -> Dict[str, Callable[[ProcessedAlert], bool]]:
        """Get quality filter functions."""
        return {
            "has_title": lambda alert: bool(alert.title.strip()),
            "title_not_too_short": lambda alert: len(alert.title.strip()) >= 10,
            "has_description": lambda alert: bool(alert.description.strip()),
            "valid_source": lambda alert: alert.source != "unknown",
            "not_test_data": lambda alert: not any(
                keyword in alert.title.lower() 
                for keyword in ["test", "example", "demo", "sample"]
            )
        }


class EnrichmentProcessor(ProcessorBase):
    """Enriches alerts with external data (EPSS, KEV, etc.)."""
    
    def __init__(self, enable_external_apis: bool = True):
        super().__init__("Enrichment")
        self.enable_external_apis = enable_external_apis
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    
    def process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        """Enrich alerts with external threat intelligence."""
        # Extract CVE IDs for batch processing
        cve_alerts = {}
        for alert in alerts:
            cve_ids = self._extract_cve_ids(alert)
            if cve_ids:
                cve_alerts[alert.id] = cve_ids
        
        # Batch enrich CVE data (if external APIs enabled)
        cve_enrichment = {}
        if self.enable_external_apis and cve_alerts:
            cve_enrichment = self._fetch_cve_enrichment(cve_alerts)
        
        # Process each alert
        for alert in alerts:
            try:
                # Basic enrichment (always enabled)
                self._enrich_basic_data(alert)
                
                # CVE enrichment (if available)
                if alert.id in cve_enrichment:
                    self._apply_cve_enrichment(alert, cve_enrichment[alert.id])
                
                alert.add_processing_stage(ProcessingStage.ENRICHMENT)
                self.processed_count += 1
                
            except Exception as e:
                logger.warning(f"❌ Enrichment failed for {alert.id}: {e}")
                self.error_count += 1
        
        logger.info(f"✅ Enriched {len(alerts)} alerts")
        return alerts
    
    def _extract_cve_ids(self, alert: ProcessedAlert) -> List[str]:
        """Extract CVE IDs from alert content."""
        text = f"{alert.title} {alert.description}"
        return self.cve_pattern.findall(text)
    
    def _enrich_basic_data(self, alert: ProcessedAlert) -> None:
        """Basic enrichment without external APIs."""
        # Detect PoC availability from content
        poc_indicators = [
            "proof of concept", "poc", "exploit code", "working exploit",
            "github.com", "exploit-db", "metasploit"
        ]
        
        text = f"{alert.title} {alert.description} {alert.url or ''}".lower()
        alert.poc_available = any(indicator in text for indicator in poc_indicators)
        
        # Extract version information
        version_pattern = r'\b(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)\b'
        versions = re.findall(version_pattern, alert.description)
        if versions:
            # Store latest version found
            alert.raw_data['detected_versions'] = versions
    
    def _fetch_cve_enrichment(self, cve_alerts: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
        """Fetch enrichment data for CVEs (placeholder for EPSS/KEV APIs)."""
        # TODO: Implement actual EPSS/KEV API calls
        # For now, return mock enrichment
        enrichment = {}
        
        for alert_id, cve_ids in cve_alerts.items():
            enrichment[alert_id] = {
                "cve_count": len(cve_ids),
                "primary_cve": cve_ids[0] if cve_ids else None,
                # Mock EPSS/KEV data
                "epss_score": 0.5,  # Would come from EPSS API
                "kev_listed": False  # Would come from KEV API
            }
        
        return enrichment
    
    def _apply_cve_enrichment(self, alert: ProcessedAlert, enrichment: Dict[str, Any]) -> None:
        """Apply CVE enrichment data to alert."""
        alert.epss_score = enrichment.get("epss_score")
        alert.kev_listed = enrichment.get("kev_listed", False)
        
        # Store enrichment metadata
        alert.raw_data['cve_enrichment'] = enrichment


class AlertProcessor:
    """Main alert processing pipeline coordinator."""
    
    def __init__(self, 
                 metrics_collector: Optional[MetricsCollector] = None,
                 existing_hashes: Optional[Set[str]] = None,
                 config: Optional[Dict[str, Any]] = None):
        self.metrics_collector = metrics_collector
        self.config = config or {}
        
        # Initialize processors
        self.processors = [
            NormalizationProcessor(),
            DeduplicationProcessor(existing_hashes),
            ClassificationProcessor(),
            EnrichmentProcessor(enable_external_apis=self.config.get("enable_external_apis", True)),
            ScoringProcessor(self.config.get("scoring")),
            FilteringProcessor(
                min_score=self.config.get("min_score", 3.0),
                max_age_days=self.config.get("max_age_days", 30)
            )
        ]
        
        self.processed_alerts: List[ProcessedAlert] = []
        self.processing_stats = {}
    
    def process_pipeline(self, raw_alerts: List[Dict[str, Any]]) -> List[ProcessedAlert]:
        """Execute complete processing pipeline."""
        if not raw_alerts:
            logger.info("No alerts to process")
            return []
        
        logger.info(f"🔄 Starting processing pipeline with {len(raw_alerts)} raw alerts")
        
        # Start with raw alerts
        current_alerts = raw_alerts
        stage_results = {}
        
        for processor in self.processors:
            if not processor.enabled:
                logger.debug(f"⏭️ Skipping disabled processor: {processor.name}")
                continue
            
            stage_name = processor.name.lower()
            input_count = len(current_alerts)
            
            if self.metrics_collector:
                with time_stage(self.metrics_collector, stage_name, input_count) as record:
                    try:
                        # Process alerts
                        processed_alerts = processor.process(current_alerts)
                        current_alerts = processed_alerts
                        
                        # Record metrics
                        output_count = len(processed_alerts)
                        filtered_count = input_count - output_count
                        record(output_count, filtered_count, processor.error_count)
                        
                    except Exception as e:
                        logger.error(f"❌ Processor {processor.name} failed: {e}")
                        record(0, 0, 1)
                        raise
            else:
                # Process without metrics
                try:
                    processed_alerts = processor.process(current_alerts)
                    current_alerts = processed_alerts
                    logger.info(f"✅ {processor.name}: {len(processed_alerts)} alerts")
                except Exception as e:
                    logger.error(f"❌ Processor {processor.name} failed: {e}")
                    raise
            
            # Store stage results for analysis
            stage_results[stage_name] = {
                "input_count": input_count,
                "output_count": len(current_alerts),
                "processor_stats": processor.get_stats()
            }
        
        self.processed_alerts = current_alerts
        self.processing_stats = stage_results
        
        logger.info(f"🎯 Processing pipeline completed: {len(self.processed_alerts)} final alerts")
        return self.processed_alerts
    
    def get_critical_alerts(self, min_score: float = 7.0) -> List[ProcessedAlert]:
        """Get alerts above critical score threshold."""
        critical = [alert for alert in self.processed_alerts if alert.risk_score >= min_score]
        logger.info(f"🚨 Found {len(critical)} critical alerts (score >= {min_score})")
        return critical
    
    def get_alerts_by_source(self, source_name: str) -> List[ProcessedAlert]:
        """Get alerts from specific source."""
        source_alerts = [alert for alert in self.processed_alerts if alert.source == source_name]
        return source_alerts
    
    def get_alerts_by_attack_type(self, attack_type: str) -> List[ProcessedAlert]:
        """Get alerts containing specific attack type."""
        matching_alerts = [
            alert for alert in self.processed_alerts 
            if attack_type.lower() in [at.lower() for at in alert.attack_types]
        ]
        return matching_alerts
    
    def get_processing_summary(self) -> Dict[str, Any]:
        """Get summary of processing pipeline results."""
        if not self.processing_stats:
            return {"error": "No processing stats available"}
        
        total_input = list(self.processing_stats.values())[0]["input_count"]
        total_output = len(self.processed_alerts)
        
        summary = {
            "total_input_alerts": total_input,
            "total_output_alerts": total_output,
            "processing_efficiency": (total_output / total_input * 100) if total_input > 0 else 0,
            "stage_breakdown": {},
            "risk_distribution": self._get_risk_distribution(),
            "source_distribution": self._get_source_distribution(),
            "attack_type_distribution": self._get_attack_type_distribution()
        }
        
        # Add stage breakdown
        for stage_name, stats in self.processing_stats.items():
            summary["stage_breakdown"][stage_name] = {
                "input": stats["input_count"],
                "output": stats["output_count"],
                "filtered": stats["input_count"] - stats["output_count"],
                "filter_rate": ((stats["input_count"] - stats["output_count"]) / stats["input_count"] * 100) 
                              if stats["input_count"] > 0 else 0
            }
        
        return summary
    
    def _get_risk_distribution(self) -> Dict[str, int]:
        """Get distribution of alerts by risk level."""
        distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for alert in self.processed_alerts:
            if alert.risk_score >= 8.0:
                distribution["critical"] += 1
            elif alert.risk_score >= 6.0:
                distribution["high"] += 1
            elif alert.risk_score >= 3.0:
                distribution["medium"] += 1
            else:
                distribution["low"] += 1
        
        return distribution
    
    def _get_source_distribution(self) -> Dict[str, int]:
        """Get distribution of alerts by source."""
        distribution = {}
        for alert in self.processed_alerts:
            distribution[alert.source] = distribution.get(alert.source, 0) + 1
        return distribution
    
    def _get_attack_type_distribution(self) -> Dict[str, int]:
        """Get distribution of alerts by attack type."""
        distribution = {}
        for alert in self.processed_alerts:
            for attack_type in alert.attack_types:
                distribution[attack_type] = distribution.get(attack_type, 0) + 1
        return distribution


# Utility functions
def create_default_processor(existing_hashes: Optional[Set[str]] = None,
                           min_score: float = 3.0) -> AlertProcessor:
    """Create alert processor with default configuration."""
    return AlertProcessor(
        existing_hashes=existing_hashes,
        config={
            "min_score": min_score,
            "enable_external_apis": False,  # Disabled by default for cost savings
            "max_age_days": 30
        }
    )


# Example usage and testing
if __name__ == "__main__":
    import json
    
    # Test alert processing
    sample_alerts = [
        {
            "title": "Critical Remote Code Execution in Apache Struts CVE-2024-1234",
            "description": "A critical vulnerability allows remote attackers to execute arbitrary code via crafted HTTP requests. PoC available.",
            "url": "https://example.com/cve-2024-1234",
            "source": "CISA",
            "published": "2024-08-10T10:00:00Z"
        },
        {
            "title": "SQL Injection in WordPress Plugin",
            "description": "A SQL injection vulnerability in the XYZ WordPress plugin allows attackers to access sensitive data.",
            "url": "https://example.com/cve-2024-5678", 
            "source": "GitHub",
            "published": "2024-08-11T15:30:00Z"
        },
        {
            "title": "Low severity info disclosure",
            "description": "Minor information disclosure in old software version.",
            "source": "Reddit",
            "published": "2024-07-01T12:00:00Z"  # Old alert
        }
    ]
    
    # Test processing pipeline
    processor = create_default_processor(min_score=2.0)  # Lower threshold for testing
    processed = processor.process_pipeline(sample_alerts)
    
    print("="*60)
    print("PROCESSING RESULTS:")
    print(f"Input alerts: {len(sample_alerts)}")
    print(f"Output alerts: {len(processed)}")
    
    print("\nPROCESSED ALERTS:")
    for alert in processed:
        print(f"- {alert.title}")
        print(f"  Risk Score: {alert.risk_score:.1f}")
        print(f"  Attack Types: {alert.attack_types}")
        print(f"  Products: {alert.affected_products}")
        print(f"  Status: {alert.status.value}")
        print()
    
    print("PROCESSING SUMMARY:")
    summary = processor.get_processing_summary()
    print(json.dumps(summary, indent=2))