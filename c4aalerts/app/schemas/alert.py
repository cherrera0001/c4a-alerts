"""
Alert schemas and data models.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, validator


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IOCType(str, Enum):
    """Types of Indicators of Compromise."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"
    CVE = "cve"
    MALWARE = "malware"
    THREAT_ACTOR = "threat_actor"
    TOOL = "tool"
    TACTIC = "tactic"
    TECHNIQUE = "technique"
    # Nuevos tipos específicos para malware
    PAYLOAD_DOWNLOADER = "payload_downloader"
    DROPPER = "dropper"
    SHELL_SCRIPT = "shell_script"
    BINARY_PAYLOAD = "binary_payload"
    COMMAND_AND_CONTROL = "command_and_control"

class AttackTechnique(str, Enum):
    """MITRE ATT&CK techniques."""
    T1105 = "T1105"  # Ingress Tool Transfer
    T1059_004 = "T1059.004"  # Command and Scripting Interpreter: Unix Shell
    T1059_001 = "T1059.001"  # Command and Scripting Interpreter: PowerShell
    T1071_001 = "T1071.001"  # Application Layer Protocol: Web Protocols
    T1566_001 = "T1566.001"  # Phishing: Spearphishing Attachment
    T1204_002 = "T1204.002"  # User Execution: Malicious File
    T1036_005 = "T1036.005"  # Masquerading: Match Legitimate Name or Location
    T1027 = "T1027"  # Obfuscated Files or Information
    T1071_004 = "T1071.004"  # Application Layer Protocol: DNS
    T1090 = "T1090"  # Connection Proxy

class MalwareFamily(str, Enum):
    """Known malware families."""
    REDTAIL = "redtail"
    COBALT_STRIKE = "cobalt_strike"
    METASPLOIT = "metasploit"
    EMPIRE = "empire"
    CUSTOM = "custom"
    UNKNOWN = "unknown"

class IOC(BaseModel):
    """Indicator of Compromise model."""
    value: str = Field(..., description="The IOC value")
    type: IOCType = Field(..., description="The type of IOC")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence score")
    tags: list[str] = Field(default_factory=list, description="Additional tags")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    # Nuevos campos para análisis de malware
    malware_family: MalwareFamily | None = Field(None, description="Identified malware family")
    attack_techniques: list[AttackTechnique] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    architecture_targets: list[str] = Field(default_factory=list, description="Target architectures")
    evasion_techniques: list[str] = Field(default_factory=list, description="Evasion techniques used")

class NormalizedAlert(BaseModel):
    """Normalized alert model."""
    uid: str = Field(..., description="Unique identifier for the alert")
    source: str = Field(..., description="Source of the alert")
    title: str = Field(..., description="Alert title")
    description: str = Field(default="", description="Alert description")
    severity: AlertSeverity = Field(default=AlertSeverity.MEDIUM, description="Alert severity")
    iocs: list[IOC] = Field(default_factory=list, description="List of IOCs")
    cve_id: str | None = Field(None, description="CVE identifier if applicable")
    cvss_score: float | None = Field(None, ge=0.0, le=10.0, description="CVSS score")
    epss_score: float | None = Field(None, ge=0.0, le=1.0, description="EPSS score")
    tags: list[str] = Field(default_factory=list, description="Alert tags")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    published_at: datetime | None = Field(None, description="Publication timestamp")
    content_hash: str = Field(..., min_length=8, description="Content hash for deduplication")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Overall confidence score")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    # Nuevos campos para análisis de malware
    malware_analysis: dict[str, Any] = Field(default_factory=dict, description="Malware analysis results")
    threat_intelligence: dict[str, Any] = Field(default_factory=dict, description="Threat intelligence data")
    detection_rules: list[str] = Field(default_factory=list, description="Applied detection rules")
    recommended_actions: list[str] = Field(default_factory=list, description="Recommended response actions")

    @validator('content_hash')
    def validate_content_hash(cls, v):
        """Ensure content hash is at least 8 characters long."""
        if len(v) < 8:
            raise ValueError('Content hash must be at least 8 characters long')
        return v

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class AlertResponse(BaseModel):
    """API response model for alerts."""
    status: str = Field(..., description="Response status")
    message: str = Field(..., description="Response message")
    alert: NormalizedAlert | None = Field(None, description="Alert data if applicable")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
