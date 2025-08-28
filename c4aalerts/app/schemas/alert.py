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

class IOC(BaseModel):
    """Indicator of Compromise model."""
    value: str = Field(..., description="The IOC value")
    type: IOCType = Field(..., description="The type of IOC")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence score")
    tags: list[str] = Field(default_factory=list, description="Additional tags")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

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
