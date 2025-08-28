"""
Prioritization service for alerts.
"""

from typing import Any

from c4aalerts.app.schemas.alert import AlertSeverity, NormalizedAlert


class PrioritizationService:
    """Service for calculating alert priority scores."""

    def __init__(self):
        # Priority weights for different factors
        self.weights = {
            "severity": 0.4,
            "cvss_score": 0.3,
            "epss_score": 0.2,
            "confidence": 0.1
        }

    def calculate_priority(self, alert: NormalizedAlert) -> float:
        """
        Calculate priority score for an alert.

        Args:
            alert: The alert to prioritize

        Returns:
            Priority score between 0.0 and 10.0
        """
        score = 0.0

        # Severity score (0-10)
        severity_score = self._get_severity_score(alert.severity)
        score += severity_score * self.weights["severity"]

        # CVSS score (0-10)
        if alert.cvss_score is not None:
            score += alert.cvss_score * self.weights["cvss_score"]

        # EPSS score (0-1, convert to 0-10)
        if alert.epss_score is not None:
            epss_score = alert.epss_score * 10.0
            score += epss_score * self.weights["epss_score"]

        # Confidence score (0-1, convert to 0-10)
        confidence_score = alert.confidence * 10.0
        score += confidence_score * self.weights["confidence"]

        return min(score, 10.0)  # Cap at 10.0

    def _get_severity_score(self, severity: AlertSeverity) -> float:
        """Convert severity enum to numeric score."""
        severity_scores = {
            AlertSeverity.LOW: 2.5,
            AlertSeverity.MEDIUM: 5.0,
            AlertSeverity.HIGH: 7.5,
            AlertSeverity.CRITICAL: 10.0
        }
        return severity_scores.get(severity, 5.0)

    def get_priority_breakdown(self, alert: NormalizedAlert) -> dict[str, Any]:
        """Get detailed priority calculation breakdown."""
        severity_score = self._get_severity_score(alert.severity)

        breakdown = {
            "total_score": self.calculate_priority(alert),
            "components": {
                "severity": {
                    "score": severity_score,
                    "weight": self.weights["severity"],
                    "contribution": severity_score * self.weights["severity"]
                },
                "cvss_score": {
                    "score": alert.cvss_score or 0.0,
                    "weight": self.weights["cvss_score"],
                    "contribution": (alert.cvss_score or 0.0) * self.weights["cvss_score"]
                },
                "epss_score": {
                    "score": (alert.epss_score or 0.0) * 10.0,
                    "weight": self.weights["epss_score"],
                    "contribution": (alert.epss_score or 0.0) * 10.0 * self.weights["epss_score"]
                },
                "confidence": {
                    "score": alert.confidence * 10.0,
                    "weight": self.weights["confidence"],
                    "contribution": alert.confidence * 10.0 * self.weights["confidence"]
                }
            }
        }

        return breakdown

# Global instance
prioritization_service = PrioritizationService()
