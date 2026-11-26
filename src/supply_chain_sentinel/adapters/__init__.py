"""Explicit ecosystem adapters; npm is the only implemented ecosystem."""

from typing import Protocol

from ..models import Artifact


class EcosystemAdapter(Protocol):
    def acquire(self, spec: str, *, offline: bool = False, integrity: str = "") -> Artifact: ...
