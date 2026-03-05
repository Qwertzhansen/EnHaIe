"""
NHI Discovery Tool – Custom Exception Hierarchy

Ermöglicht präzises Fehlerhandling durch Caller.
"""


class NHIDiscoveryError(Exception):
    """Basisklasse für alle NHI-Discovery-Fehler."""


class DiscoveryError(NHIDiscoveryError):
    """Fehler beim AWS-API-Zugriff während der IAM-Discovery."""


class InvalidPolicyDocumentError(NHIDiscoveryError):
    """Ungültiges oder nicht parsebares IAM-Policy-Dokument."""


class DatabaseError(NHIDiscoveryError):
    """Fehler bei Datenbankoperationen."""


class ConfigurationError(NHIDiscoveryError):
    """Fehlende oder ungültige Konfiguration."""
