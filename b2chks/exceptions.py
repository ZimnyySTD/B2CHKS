"""Domain-specific exceptions for B2CHKS."""

class B2CHKSError(Exception):
    """Base class for all B2CHKS exceptions."""
    pass

class ManifestError(B2CHKSError):
    """Raised when manifest validation or parsing fails."""
    pass

class IntegrityError(B2CHKSError):
    """Raised when chunk SHA-256 hash or inventory check fails."""
    pass

class AuthenticationError(B2CHKSError):
    """Raised when signature verification or GCM decryption auth tag check fails."""
    pass

class DecryptionError(AuthenticationError):
    """Raised when decryption fails due to invalid passphrase or corrupted ciphertext."""
    pass

class ChunkError(B2CHKSError):
    """Raised when chunk reading, writing, or size validation fails."""
    pass

class CompressionError(B2CHKSError):
    """Raised when compression or decompression fails."""
    pass

class CancelledError(B2CHKSError):
    """Raised when an operation is cancelled via cancellation token."""
    pass

class MissingDependencyError(B2CHKSError):
    """Raised when a required native backend dependency is missing."""
    pass
