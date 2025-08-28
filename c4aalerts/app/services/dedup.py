"""
Deduplication service for alerts.
"""

from datetime import datetime, timedelta
from typing import Any

from c4aalerts.app.schemas.alert import NormalizedAlert


class DedupService:
    """Service for detecting and handling duplicate alerts."""

    def __init__(self):
        self._seen_hashes: set[str] = set()
        self._hash_expiry: dict[str, datetime] = {}
        self._expiry_hours = 24  # Hash expires after 24 hours

    def is_duplicate(self, alert: NormalizedAlert) -> bool:
        """
        Check if an alert is a duplicate.

        Args:
            alert: The alert to check

        Returns:
            True if duplicate, False otherwise
        """
        # Clean expired hashes
        self._clean_expired_hashes()

        # Check if hash exists
        if alert.content_hash in self._seen_hashes:
            return True

        # Add to seen hashes
        self._seen_hashes.add(alert.content_hash)
        self._hash_expiry[alert.content_hash] = datetime.utcnow() + timedelta(hours=self._expiry_hours)

        return False

    def _clean_expired_hashes(self):
        """Remove expired hashes from memory."""
        now = datetime.utcnow()
        expired_hashes = [
            hash_val for hash_val, expiry in self._hash_expiry.items()
            if expiry < now
        ]

        for hash_val in expired_hashes:
            self._seen_hashes.discard(hash_val)
            del self._hash_expiry[hash_val]

    def get_hash_stats(self) -> dict[str, Any]:
        """Get deduplication statistics."""
        return {
            "total_hashes": len(self._seen_hashes),
            "expired_hashes": len(self._hash_expiry),
            "expiry_hours": self._expiry_hours
        }

# Global instance
dedup_service = DedupService()
