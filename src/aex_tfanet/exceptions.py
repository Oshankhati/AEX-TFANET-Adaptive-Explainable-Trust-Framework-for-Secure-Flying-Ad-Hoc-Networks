"""Project-specific errors. Serious failures must not be swallowed."""

from __future__ import annotations


class AexTfanetError(Exception):
    """Base error."""


class ConfigError(AexTfanetError):
    """Invalid or missing configuration."""


class EnvironmentError(AexTfanetError):
    """Missing runtime dependency (NS-3, compiler, dataset, model)."""


class NotImplementedPhaseError(AexTfanetError):
    """The requested command belongs to a later implementation phase."""


class DataValidationError(AexTfanetError):
    """Simulation CSV or summary failed schema/value checks."""


class SimulationError(AexTfanetError):
    """Simulation backend failed."""
