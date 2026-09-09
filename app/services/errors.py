"""The one error type the service layer raises.

Error text is written for a person and names the actual problem, so it is
worth carrying unchanged all the way to whichever interface is asking. The
HTTP layer turns this into an HTTPException; the desktop interface puts the
same sentence in a dialog.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Something the person did or asked for cannot be done, and why."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status

    def __str__(self) -> str:
        return self.message


class NotFound(ServiceError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status=404)
