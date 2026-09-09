"""Everything the interfaces do, with no interface in it.

The HTTP layer and the desktop interface both call in here, so behaviour and
error wording stay identical whichever one is asking. Nothing in this package
may import FastAPI, Qt, or anything else that ties it to one of them.
"""

from __future__ import annotations

from . import (
    adapters_svc,
    decode,
    findings,
    lifecycle,
    maintenance,
    marks,
    naming,
    networks,
    settings_svc,
    spectrum,
    survey_svc,
)
from .errors import NotFound, ServiceError

__all__ = [
    "ServiceError",
    "NotFound",
    "adapters_svc",
    "decode",
    "findings",
    "lifecycle",
    "maintenance",
    "marks",
    "naming",
    "networks",
    "settings_svc",
    "spectrum",
    "survey_svc",
]
