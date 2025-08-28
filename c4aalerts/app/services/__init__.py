"""
C4A Alerts Services Package

Business logic services for alert processing.
"""

from .dedup import dedup_service
from .prioritize import prioritization_service
from .router import routing_service

__all__ = [
    "dedup_service",
    "prioritization_service",
    "routing_service"
]
