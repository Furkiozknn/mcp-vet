"""mcp-vet: evidence-gathering for MCP servers.

The philosophy the project started with was "read before you install, verify
before you trust". Nothing here replaces that; the point is to put better
evidence in front of the person doing the reading.

Never present "not flagged" as "safe". No static analyzer can prove an MCP
server is harmless, and this one does not try.
"""
from .models import (  # noqa: F401
    Area,
    AuditReport,
    Capability,
    Confidence,
    CredentialRequirement,
    DataFlow,
    Evidence,
    Finding,
    NetworkEndpoint,
    Severity,
    Status,
    SCHEMA_VERSION,
)

__version__ = "0.5.0"
__all__ = [
    "Area", "AuditReport", "Capability", "Confidence", "CredentialRequirement",
    "DataFlow", "Evidence", "Finding", "NetworkEndpoint", "Severity", "Status",
    "SCHEMA_VERSION", "__version__",
]
