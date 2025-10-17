
import hashlib
import os
from typing import Optional
from datetime import datetime

def generate_file_hash(file_path: str) -> str:
    """Generate the SHA256 hash of a file.

    Args:
        file_path (str): The path to the file for which the hash should be generated.

    Returns:
        str: The SHA256 hexadecimal hash of the file.

    Raises:
        FileNotFoundError: If the specified file does not exist.

    Examples:
        >>> generate_file_hash("data.txt")
        '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def validate_file_size(file_path: str, max_size_mb: int = 10) -> bool:
    """Validate that the file size is within an allowed limit.

    Args:
        file_path (str): Path to the file to validate.
        max_size_mb (int): Maximum allowed file size in megabytes.
            Defaults to 10.

    Returns:
        bool: True if the file size is within the allowed limit, False otherwise.

    Raises:
        FileNotFoundError: If the file does not exist.
"""
    file_size = os.path.getsize(file_path)
    max_size_bytes = max_size_mb * 1024 * 1024
    return file_size <= max_size_bytes

def format_confidence(confidence: float) -> str:
    """Format a confidence score as a percentage string.

    Args:
        confidence (float): Confidence score between 0 and 1.

    Returns:
        str: The formatted percentage string.

    Examples:
        >>> format_confidence(0.8567)
        '85.67%'
    """
    return f"{confidence * 100:.2f}%"

def get_timestamp() -> str:
    """Get the current UTC timestamp in ISO format.

    Returns:
        str: The current UTC timestamp as an ISO-formatted string.

    Examples:
        >>> get_timestamp()
        '2025-10-15T12:45:30.123456'
    """
    return datetime.utcnow().isoformat()
