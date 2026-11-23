"""Errors whose message is written for the API client.

Only these are echoed back in a 400 response. Any other exception (ValueError from int(),
KeyError, ...) gets a fixed message, so internal details never leak to the client.
"""


class InputError(ValueError):
    """Invalid input; the message is safe to show to the user."""


def int_arg(value, name: str, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise InputError(f"{name} must be a whole number") from None
    if not low <= number <= high:
        raise InputError(f"{name} must be between {low} and {high}")
    return number
