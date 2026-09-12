"""Exceptions for the trial runner."""


class PauseTrialException(Exception):
    """Raised when user or error handler requests a clean pause of the trial."""
    pass


class SkipTaskException(Exception):
    """Raised when user or error handler requests skipping the current task."""
    pass
