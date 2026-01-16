"""Minimal replacement for the deprecated crypt module using libcrypt via ctypes."""

import ctypes
import ctypes.util
import threading

__all__ = ["crypt"]

_libcrypt = None
_libcrypt_lock = threading.Lock()


def _load_libcrypt():
    """Load libcrypt from the system and cache the handle."""
    global _libcrypt  # pylint: disable=global-statement
    if _libcrypt is not None:
        return _libcrypt

    candidates = []
    libcrypt_name = ctypes.util.find_library("crypt")
    if libcrypt_name:
        candidates.append(libcrypt_name)
    candidates.extend(["libcrypt.so.2", "libcrypt.so.1", "libcrypt.so"])

    for candidate in candidates:
        if not candidate:
            continue
        try:
            library = ctypes.CDLL(candidate, use_errno=True)
            library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            library.crypt.restype = ctypes.c_char_p
            _libcrypt = library
            return _libcrypt
        except (AttributeError, OSError):
            continue
    raise ImportError("libcrypt not found")


def crypt(word, salt):
    """Hash *word* with *salt* using libcrypt."""
    library = _load_libcrypt()
    word_bytes = word.encode("utf-8") if isinstance(word, str) else word
    salt_bytes = salt.encode("utf-8") if isinstance(salt, str) else salt

    if isinstance(word_bytes, bytearray):
        word_bytes = bytes(word_bytes)
    if isinstance(salt_bytes, bytearray):
        salt_bytes = bytes(salt_bytes)

    if not isinstance(word_bytes, (bytes, bytearray)):
        raise TypeError("word must be str or bytes")
    if not isinstance(salt_bytes, (bytes, bytearray)):
        raise TypeError("salt must be str or bytes")

    with _libcrypt_lock:
        ctypes.set_errno(0)
        result = library.crypt(word_bytes, salt_bytes)
        errno_value = ctypes.get_errno()
    if not result:
        raise OSError(errno_value, "libcrypt failed to hash password")
    return result.decode("utf-8")
