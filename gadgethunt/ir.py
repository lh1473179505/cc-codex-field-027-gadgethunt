"""Load a class IR graph for the lab object dialect 'binobj'. Chain search is not implemented here."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class IRError(Exception):
    pass


@dataclass
class Instr:
    op: str
    args: list[Any]


@dataclass
class Method:
    name: str
    params: list[str]
    body: list[Instr]


@dataclass
class ClassDef:
    name: str
    bases: list[str]
    fields: dict[str, str]
    methods: dict[str, Method]
    magic: dict[str, str]


def load_program(path: str | Path) -> dict[str, ClassDef]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    classes: dict[str, ClassDef] = {}
    for item in raw.get("classes") or []:
        methods = {}
        for m in item.get("methods") or []:
            body = [Instr(str(i["op"]), list(i.get("args") or [])) for i in m.get("body") or []]
            methods[m["name"]] = Method(m["name"], list(m.get("params") or []), body)
        classes[item["name"]] = ClassDef(
            name=item["name"],
            bases=list(item.get("bases") or []),
            fields=dict(item.get("fields") or {}),
            methods=methods,
            magic=dict(item.get("magic") or {}),
        )
    if not classes:
        raise IRError("no classes")
    return classes


def load_policy(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
