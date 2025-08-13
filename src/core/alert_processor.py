import hashlib
import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Set, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

# Fechas SIEMPRE aware-UTC
from src.utils import coerce_utc, now_utc

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

    # Timestamps (aware-UTC)
    published_at: datetime = field(default_factory=now_utc)
    processed_at: datetime = field(default_factory=now_utc)

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
        # Fuerza timestamps a aware-UTC
        self.published_at = coerce_utc(self.published_at)
        self.processed_at = coerce_utc(self.processed_at)
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

        # Parse published date (always aware-UTC)
        published_at = self._parse_published_date(
            raw_alert.get("published", raw_alert.get("published_at"))
        )

        return ProcessedAlert(
            id=alert_id,
            title=title,
            description=description,
            url=url,
            source=source,
            published_at=published_at,
            processed_at=now_utc(),
            raw_data=raw_alert
        )

    def _clean_text(self, text: str) -> str:
        """Clean and normalize text content."""
        if not text:
            return ""
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'^(alert|advisory|bulletin):\s*', '', text, flags=re.IGNORECASE)
        return text.strip()

    def _validate_url(self, url: Optional[str]) -> Optional[str]:
        """Validate and clean URL (básica)."""
        if not url:
            return None
        url = url.strip()
        if not re.match(r'^https?://', url):
            return None
        url = re.sub(r'[?&](utm_|ref=|src=)[^&]*', '', url)
        return url

    def _generate_id(self, title: str, url: Optional[str], source: str) -> str:
        """Generate stable ID for alert."""
        content = f"{title}{url or ''}{source}".lower().strip()
        hash_obj = hashlib.sha256(content.encode('utf-8'))
        return f"{source.lower()}-{hash_obj.hexdigest()[:12]}"

    def _parse_published_date(self, value: Any) -> datetime:
        """Parse published date → aware-UTC (sin warnings innecesarios)."""
        if not value:
            return now_utc()
        try:
            return coerce_utc(value)
        except Exception:
            logger.warning(f"⚠️ Could not parse date: {value}")
            return now_utc()


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

            self.seen_hashes.add(alert.content_hash)
            alert.add_processing_stage(ProcessingStage.DEDUPLICATION)
            unique_alerts.append(alert)
            self.processed_count += 1

        logger.info(f"✅ Deduplicated: {len(unique_alerts)} unique, {duplicate_count} duplicates removed")
        return unique_alerts

    def _is_duplicate(self, alert: ProcessedAlert) -> bool:
        return (alert.content_hash in self.existing_hashes or
                alert.content_hash in self.seen_hashes)

    def update_existing_hashes(self, hashes: Set[str]) -> None:
        self.existing_hashes.update(hashes)


class ScoringProcessor(ProcessorBase):
    """Scores alerts based on risk and relevance."""

    def __init__(self, scoring_config: Optional[Dict[str, Any]] = None):
        super().__init__("Scoring")
        self.config = scoring_config or self._get_default_config()

    def process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
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

        alerts.sort(key=lambda x: x.risk_score, reverse=True)
        logger.info(f"✅ Scored {len(alerts)} alerts (avg risk: {self._average_risk_score(alerts):.1f})")
        return alerts

    def _calculate_risk_score(self, alert: ProcessedAlert) -> float:
        score = 0.0

        # CVSS (0-4)
        if alert.cvss_score:
            score += min(4.0, alert.cvss_score * 0.4)

        # EPSS (0-2)
        if alert.epss_score:
            score += alert.epss_score * 2.0

        # KEV (2)
        if alert.kev_listed:
            score += 2.0

        # PoC (1)
        if alert.poc_available:
            score += 1.0

        # Keywords críticos (1)
        critical_keywords = self.config.get("critical_keywords", [])
        text = f"{alert.title} {alert.description}".lower()
        if any(keyword in text for keyword in critical_keywords):
            score += 1.0

        # Attack high-risk (1)
        high_risk_attacks = ["remote code execution", "privilege escalation", "authentication bypass"]
        if any(attack.lower() in high_risk_attacks for attack in alert.attack_types):
            score += 1.0

        # Antigüedad (UTC aware)
        age_h = (now_utc() - coerce_utc(alert.published_at)).total_seconds() / 3600.0
        if age_h <= 24:
            score += 0.5
        elif age_h <= 168:
            score += 0.25

        return min(10.0, score)

    def _calculate_confidence_score(self, alert: ProcessedAlert) -> float:
        confidence = 0.5
        source_scores = self.config.get("source_reliability", {})
        source_score = source_scores.get(alert.source.lower(), 0.5)
        confidence += (source_score - 0.5) * 0.5

        completeness = self._calculate_completeness(alert)
        confidence += completeness * 0.3

        if alert.url and self._is_valid_url(alert.url):
            confidence += 0.1
        if alert.cvss_score and alert.cvss_score > 0:
            confidence += 0.1

        return min(1.0, max(0.0, confidence))

    def _calculate_completeness(self, alert: ProcessedAlert) -> float:
        fields = [alert.title, alert.description, alert.url, alert.cvss_score, alert.attack_types]
        filled = sum(1 for f in fields if f)
        return filled / len(fields)

    def _is_valid_url(self, url: str) -> bool:
        return bool(re.match(r'^https?://[^\s]+$', url))

    def _average_risk_score(self, alerts: List[ProcessedAlert]) -> float:
        if not alerts:
            return 0.0
        return sum(a.risk_score for a in alerts) / len(alerts)

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "critical_keywords": [
                "critical", "urgent", "zero-day", "0day","rce","remote code execution", "privilege escalation","privesc","authentication bypass","exploit","arbitrary code execution","memory corruption","buffer overflow","integer overflow","null pointer dereference","directory traversal","path traversal","LFI","local file inclusion","sql injection", "sqli","xss","cross-site scripting","ssrf","server-side request forgery", "deserialization vulnerability","misconfiguration",
                "logic flaw","command injection","open redirect","data tampering","cve-", "cwe-", "ghsa-", "nvd","cvss","phishing","spear phishing","social engineering","man-in-the-middle","mitm","denial-of-service","dos","ddos","brute force","password cracking","hash cracking","web scraping","side channel attack","reverse engineering","reversing","dynamic analysis","static analysis","bypass","jailbreak bypass","ssl pinning bypass","exploit chain","payload","backdoor","rootkit",
                "trojan","worm","malware","ransomware","spyware","adware","firmware exploitation", "supply chain attack","cryptojacking","triage","vulnerability scanner","apt","advanced persistent threat","state-sponsored","cybercrime group","ransomware group","conti","lockbit","darkside","dark web","darknet","deep web","threat actor","vulnerability broker","zero-day broker","leak","data leak","credential leak","dox","doxing","blackhat", "azure","aws","gcp","kubernetes","k8s","docker",
                "saas","api","mobile","ios","android","ipa","linux","windows","web server","apache","nginx","database","sql","nosql","cloud storage","ci/cd","iot device","firmware","security advisory","security update", "patch","patch management","remediation","mitigation","detection","threat intelligence","incident response"
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
        for alert in alerts:
            try:
                alert.attack_types = self._classify_attack_types(alert)
                alert.affected_products = self._extract_products(alert)
                alert.mitre_techniques = self._map_to_mitre(alert.attack_types)
                alert.add_processing_stage(ProcessingStage.CLASSIFICATION)
                self.processed_count += 1
            except Exception as e:
                logger.warning(f"❌ Classification failed for {alert.id}: {e}")
                self.error_count += 1

        logger.info(f"✅ Classified {len(alerts)} alerts")
        return alerts

    def _classify_attack_types(self, alert: ProcessedAlert) -> List[str]:
        text = f"{alert.title} {alert.description}".lower()
        detected = []
        for attack_type, patterns in self.attack_patterns.items():
            if any(re.search(p, text, re.IGNORECASE) for p in patterns):
                detected.append(attack_type)
        return detected

    def _extract_products(self, alert: ProcessedAlert) -> List[str]:
        text = f"{alert.title} {alert.description}".lower()
        products = []
        for product, patterns in self.product_patterns.items():
            if any(re.search(p, text, re.IGNORECASE) for p in patterns):
                products.append(product)
        return products

    def _map_to_mitre(self, attack_types: List[str]) -> List[str]:
        techniques = []
        for t in attack_types:
            techniques.extend(self.mitre_mapping.get(t.lower(), []))
        return list(set(techniques))

    def _get_attack_patterns(self) -> Dict[str, List[str]]:
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
                r'\b(cross\.?site scripting|XSS|script injection)\b',
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
                filtered_alerts.append(alert)

        filtered_count = len(alerts) - len(filtered_alerts)
        logger.info(f"✅ Filtered: {len(filtered_alerts)} passed, {filtered_count} filtered")
        return filtered_alerts

    def _should_filter(self, alert: ProcessedAlert) -> Optional[str]:
        # Score
        if alert.risk_score < self.min_score:
            return f"low_score_{alert.risk_score:.1f}"

        # Edad en días (UTC aware)
        age_days = (now_utc() - coerce_utc(alert.published_at)).total_seconds() / 86400.0
        if age_days > self.max_age_days:
            return f"too_old_{int(age_days)}d"

        # Calidad
        for name, fn in self.quality_filters.items():
            if not fn(alert):
                return f"quality_{name}"

        return None

    def _get_quality_filters(self) -> Dict[str, Callable[[ProcessedAlert], bool]]:
        return {
            "has_title": lambda a: bool(a.title.strip()),
            "title_not_too_short": lambda a: len(a.title.strip()) >= 10,
            "has_description": lambda a: bool(a.description.strip()),
            "valid_source": lambda a: a.source != "unknown",
            "not_test_data": lambda a: not any(k in a.title.lower() for k in ["test", "example", "demo", "sample"]),
        }


class EnrichmentProcessor(ProcessorBase):
    """Enriches alerts with external data (EPSS, KEV, etc.)."""

    def __init__(self, enable_external_apis: bool = True):
        super().__init__("Enrichment")
        self.enable_external_apis = enable_external_apis
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)

    def process(self, alerts: List[ProcessedAlert]) -> List[ProcessedAlert]:
        cve_alerts = {}
        for alert in alerts:
            ids_ = self._extract_cve_ids(alert)
            if ids_:
                cve_alerts[alert.id] = ids_

        cve_enrichment = {}
        if self.enable_external_apis and cve_alerts:
            cve_enrichment = self._fetch_cve_enrichment(cve_alerts)

        for alert in alerts:
            try:
                self._enrich_basic_data(alert)
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
        text = f"{alert.title} {alert.description}"
        return self.cve_pattern.findall(text)

    def _enrich_basic_data(self, alert: ProcessedAlert) -> None:
        poc_indicators = [
            "proof of concept", "poc", "exploit code", "working exploit",
            "github.com", "exploit-db", "metasploit"
        ]
        text = f"{alert.title} {alert.description} {alert.url or ''}".lower()
        alert.poc_available = any(i in text for i in poc_indicators)

        version_pattern = r'\b(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)\b'
        versions = re.findall(version_pattern, alert.description)
        if versions:
            alert.raw_data['detected_versions'] = versions

    def _fetch_cve_enrichment(self, cve_alerts: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
        enrichment = {}
        for alert_id, cve_ids in cve_alerts.items():
            enrichment[alert_id] = {
                "cve_count": len(cve_ids),
                "primary_cve": cve_ids[0] if cve_ids else None,
                "epss_score": 0.5,
                "kev_listed": False
            }
        return enrichment

    def _apply_cve_enrichment(self, alert: ProcessedAlert, enrichment: Dict[str, Any]) -> None:
        alert.epss_score = enrichment.get("epss_score")
        alert.kev_listed = enrichment.get("kev_listed", False)
        alert.raw_data['cve_enrichment'] = enrichment


class AlertProcessor:
    """Main alert processing pipeline coordinator."""

    def __init__(self,
                 metrics_collector: Optional[MetricsCollector] = None,
                 existing_hashes: Optional[Set[str]] = None,
                 config: Optional[Dict[str, Any]] = None):
        self.metrics_collector = metrics_collector
        self.config = config or {}

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
        if not raw_alerts:
            logger.info("No alerts to process")
            return []

        logger.info(f"🔄 Starting processing pipeline with {len(raw_alerts)} raw alerts")

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
                        processed_alerts = processor.process(current_alerts)  # type: ignore[arg-type]
                        current_alerts = processed_alerts
                        output_count = len(processed_alerts)
                        filtered_count = input_count - output_count
                        record(output_count, filtered_count, processor.error_count)
                    except Exception as e:
                        logger.error(f"❌ Processor {processor.name} failed: {e}")
                        record(0, 0, 1)
                        raise
            else:
                try:
                    processed_alerts = processor.process(current_alerts)  # type: ignore[arg-type]
                    current_alerts = processed_alerts
                    logger.info(f"✅ {processor.name}: {len(processed_alerts)} alerts")
                except Exception as e:
                    logger.error(f"❌ Processor {processor.name} failed: {e}")
                    raise

            stage_results[stage_name] = {
                "input_count": input_count,
                "output_count": len(current_alerts),
                "processor_stats": processor.get_stats()
            }

        self.processed_alerts = current_alerts  # type: ignore[assignment]
        self.processing_stats = stage_results

        logger.info(f"🎯 Processing pipeline completed: {len(self.processed_alerts)} final alerts")
        return self.processed_alerts

    def get_critical_alerts(self, min_score: float = 7.0) -> List[ProcessedAlert]:
        critical = [a for a in self.processed_alerts if a.risk_score >= min_score]
        logger.info(f"🚨 Found {len(critical)} critical alerts (score >= {min_score})")
        return critical

    def get_alerts_by_source(self, source_name: str) -> List[ProcessedAlert]:
        return [a for a in self.processed_alerts if a.source == source_name]

    def get_alerts_by_attack_type(self, attack_type: str) -> List[ProcessedAlert]:
        return [a for a in self.processed_alerts if attack_type.lower() in [t.lower() for t in a.attack_types]]

    def get_processing_summary(self) -> Dict[str, Any]:
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
        d = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for a in self.processed_alerts:
            if a.risk_score >= 8.0: d["critical"] += 1
            elif a.risk_score >= 6.0: d["high"] += 1
            elif a.risk_score >= 3.0: d["medium"] += 1
            else: d["low"] += 1
        return d

    def _get_source_distribution(self) -> Dict[str, int]:
        d: Dict[str, int] = {}
        for a in self.processed_alerts:
            d[a.source] = d.get(a.source, 0) + 1
        return d

    def _get_attack_type_distribution(self) -> Dict[str, int]:
        d: Dict[str, int] = {}
        for a in self.processed_alerts:
            for t in a.attack_types:
                d[t] = d.get(t, 0) + 1
        return d


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

if __name__ == "__main__":
    # Pequeño smoke test manual si ejecutas el archivo directamente.
    sample_alerts = [
        {
            "title": "Critical RCE in Apache Struts CVE-2024-1234",
            "description": "Remote code execution via crafted HTTP requests. PoC available.",
            "url": "https://example.com/cve-2024-1234",
            "source": "CISA",
            "published": "2024-08-10T10:00:00Z"
        }
    ]
    processor = create_default_processor(min_score=2.0)
    out = processor.process_pipeline(sample_alerts)
    for a in out:
        print(a.id, a.published_at, a.risk_score)
