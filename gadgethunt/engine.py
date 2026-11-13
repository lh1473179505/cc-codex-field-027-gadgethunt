"""Gadget-chain search. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from gadgethunt.ir import ClassDef


def hunt(classes: dict[str, ClassDef], policy: dict[str, Any]) -> dict[str, Any]:
    raise NotImplementedError("hunt is not implemented in this snapshot")
