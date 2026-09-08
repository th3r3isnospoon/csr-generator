"""Errors that can be shown safely to users."""


class ApplicationError(Exception):
    """An expected operation failure."""


class ValidationError(ApplicationError):
    def __init__(self, message: str, field: str = ""):
        super().__init__(message)
        self.field = field


class Cancelled(ApplicationError):
    """Operation cancelled before publishing outputs."""
