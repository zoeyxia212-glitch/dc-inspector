"""Errors whose message is written for the API client.

Only these are echoed back in a 400 response. Any other exception (ValueError from int(),
KeyError, ...) gets a fixed message, so internal details never leak to the client.
"""


class PublicError(ValueError):
    """An error whose message was written for the user.

    Handlers return ``exc.message`` (set explicitly here), never ``str(exc)``, so only text we
    wrote ourselves reaches the client.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InputError(PublicError):
    """Invalid input; the message is safe to show to the user."""


def log_safe(value: object) -> str:
    """Neutralise CR/LF so a client cannot forge extra lines in text logs (log injection)."""
    return str(value or "").replace("\r", "\\r").replace("\n", "\\n")


def int_arg(value, name: str, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise InputError(f"{name} must be a whole number") from None
    if not low <= number <= high:
        raise InputError(f"{name} must be between {low} and {high}")
    return number
