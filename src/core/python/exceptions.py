"""Custom exceptions used by core runtime and analysis modules."""


class SentinelException(Exception):
    """Base exception for Supply Chain Sentinel."""


class ExtractionError(SentinelException):
    """Raised when package extraction fails."""


class EntropyCalculationError(SentinelException):
    """Raised when entropy calculation fails."""


class SandboxError(SentinelException):
    """Raised when sandbox operations fail."""


class AnalysisError(SentinelException):
    """Raised when analysis pipeline fails."""


class ConfigurationError(SentinelException):
    """Raised when configuration is invalid."""


# Backward-compatible aliases used by already-wired modules.
SentinelError = SentinelException
ConfigError = ConfigurationError
