"""
Routing service for alert notifications.
"""

from typing import Any

from c4aalerts.app.schemas.alert import AlertSeverity, NormalizedAlert


class RoutingService:
    """Service for determining notification channels for alerts."""

    def __init__(self):
        # Default routing rules
        self.routing_rules = {
            AlertSeverity.LOW: ["email"],
            AlertSeverity.MEDIUM: ["email", "slack"],
            AlertSeverity.HIGH: ["email", "slack", "telegram"],
            AlertSeverity.CRITICAL: ["email", "slack", "telegram", "webhook"]
        }

        # Tag-based routing
        self.tag_routing = {
            "critical-infrastructure": ["email", "slack", "telegram", "webhook"],
            "zero-day": ["email", "slack", "telegram", "webhook"],
            "apt": ["email", "slack", "telegram"],
            "ransomware": ["email", "slack", "telegram"],
            "phishing": ["email", "slack"],
            "malware": ["email", "slack"]
        }

    def get_target_channels(self, alert: NormalizedAlert) -> list[str]:
        """
        Determine target notification channels for an alert.

        Args:
            alert: The alert to route

        Returns:
            List of channel names
        """
        channels = set()

        # Add severity-based channels
        severity_channels = self.routing_rules.get(alert.severity, ["email"])
        channels.update(severity_channels)

        # Add tag-based channels
        for tag in alert.tags:
            tag_channels = self.tag_routing.get(tag.lower(), [])
            channels.update(tag_channels)

        # Always include email for critical alerts
        if alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            channels.add("email")

        return list(channels)

    def get_routing_breakdown(self, alert: NormalizedAlert) -> dict[str, Any]:
        """Get detailed routing breakdown."""
        channels = self.get_target_channels(alert)

        breakdown = {
            "target_channels": channels,
            "reasoning": {
                "severity_based": self.routing_rules.get(alert.severity, ["email"]),
                "tag_based": []
            }
        }

        # Add tag-based reasoning
        for tag in alert.tags:
            tag_channels = self.tag_routing.get(tag.lower(), [])
            if tag_channels:
                breakdown["reasoning"]["tag_based"].append({
                    "tag": tag,
                    "channels": tag_channels
                })

        return breakdown

    def add_routing_rule(self, severity: AlertSeverity, channels: list[str]):
        """Add a custom routing rule."""
        self.routing_rules[severity] = channels

    def add_tag_rule(self, tag: str, channels: list[str]):
        """Add a custom tag-based routing rule."""
        self.tag_routing[tag.lower()] = channels

# Global instance
routing_service = RoutingService()
