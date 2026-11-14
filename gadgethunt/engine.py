"""Static taint-based gadget-chain search over the binobj class IR.

This is an abstract interpretation over the instruction bodies: values carry
taint, a set of sanitizer kinds that cover them, a set of possible runtime
types, and a provenance path (the chain of Class.method steps the taint has
flowed through). The IR is never executed as Python.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gadgethunt.ir import ClassDef

ALL_KINDS = frozenset({"cmd", "path"})


@dataclass(frozen=True)
class Val:
    tainted: bool = False
    sanitized: frozenset = frozenset()
    types: frozenset = frozenset()
    path: tuple = ()

    def covers(self, kind: str) -> bool:
        return kind in self.sanitized


UNTAINTED = Val()


def _join(a: Val, b: Val) -> Val:
    if a is b:
        return a
    tainted = a.tainted or b.tainted
    if a.tainted and a.path:
        path = a.path
    elif b.tainted and b.path:
        path = b.path
    else:
        path = a.path or b.path
    return Val(tainted, a.sanitized & b.sanitized, a.types | b.types, path)


def _append_step(v: Val, step: str) -> Val:
    if not v.tainted:
        return v
    if v.path and v.path[-1] == step:
        return v
    return Val(v.tainted, v.sanitized, v.types, v.path + (step,))


class Engine:
    def __init__(self, classes: dict[str, ClassDef], policy: dict[str, Any]):
        self.classes = classes
        self.policy = policy or {}
        self.sinks = list(self.policy.get("sinks") or [])
        self.static_methods = set(self.policy.get("static_methods") or [])
        self.max_depth = int(self.policy.get("max_depth", 6))
        self.max_chains = int(self.policy.get("max_chains", 16))
        self.fields: dict[tuple, Val] = {}
        self.chains: list[dict[str, Any]] = []
        self._chain_keys: set[tuple] = set()
        self.truncated = False
        self._budget = 500000
        # Pre-resolve sources through magic aliases: {(class, real_method)}.
        self.sources: set[tuple] = set()
        for s in self.policy.get("sources") or []:
            r = self.resolve(str(s.get("class", "")), str(s.get("method", "")))
            if r:
                self.sources.add((r[0], r[1]))

    def resolve(self, cls_name: str, method: str):
        """Method lookup: class first, then bases in order, recursively.

        Magic aliases rename the requested method before the per-class check.
        Returns (defining_class, real_method_name) or None.
        """
        seen = set()
        stack = [cls_name]
        # Iterative DFS preserving base order.
        def visit(name: str):
            if name in seen:
                return None
            seen.add(name)
            c = self.classes.get(name)
            if c is None:
                return None
            real = c.magic.get(method, method)
            if real in c.methods:
                return (name, real)
            for base in c.bases:
                r = visit(base)
                if r:
                    return r
            return None

        return visit(cls_name)

    def match_sink(self, def_cls: str, method: str):
        for s in self.sinks:
            if s.get("class") == def_cls and s.get("method") == method:
                return s
        return None

    def is_static(self, cls_name: str, method: str) -> bool:
        return (
            method in self.static_methods
            or f"{cls_name}.{method}" in self.static_methods
        )

    def sink_hit(self, sink: dict, step: str, obj: Val, args: list) -> None:
        kind = str(sink.get("kind", ""))
        mode = str(sink.get("tainted", "args"))
        cands = []
        if mode in ("args", "any"):
            cands.extend(args)
        if mode in ("receiver", "any"):
            cands.append(obj)
        for v in cands:
            if v.tainted and not v.covers(kind):
                steps = list(v.path) + [step]
                key = tuple(steps)
                if key in self._chain_keys:
                    return
                self._chain_keys.add(key)
                self.chains.append({
                    "source": steps[0],
                    "sink": step,
                    "kind": kind,
                    "steps": steps,
                })
                return

    def do_call(self, obj: Val, method: str, args: list, depth: int,
                static_cls: str | None = None) -> Val:
        types = {static_cls} if static_cls else set(obj.types)
        result = UNTAINTED
        for t in sorted(types):
            r = self.resolve(t, method)
            if not r:
                continue
            def_cls, real = r
            step = f"{def_cls}.{real}"
            involved = list(args) if static_cls else [obj] + list(args)
            if depth + 1 > self.max_depth:
                if any(v.tainted for v in involved):
                    self.truncated = True
                continue
            sink = self.match_sink(def_cls, real)
            if sink:
                self.sink_hit(sink, step, obj, list(args))
                continue
            static = static_cls is not None or self.is_static(def_cls, real)
            entered_args = [_append_step(a, step) for a in args]
            self_val = None if static else _append_step(obj, step)
            ret = self.exec_method(def_cls, real, entered_args, self_val, depth + 1)
            if (def_cls, real) in self.sources:
                taint_path = ret.path if ret.tainted and ret.path else (step,)
                ret = Val(True, frozenset(), ret.types, taint_path)
            result = _join(result, ret)
        return result

    def exec_method(self, cls_name: str, method: str, args: list,
                    self_val: Val | None, depth: int) -> Val:
        m = self.classes[cls_name].methods[method]
        cur_step = f"{cls_name}.{method}"
        locals_: dict[str, Val] = {}
        if self_val is not None:
            locals_["self"] = self_val
        for i, p in enumerate(m.params):
            locals_[p] = args[i] if i < len(args) else UNTAINTED
        ret = UNTAINTED
        for ins in m.body:
            self._budget -= 1
            if self._budget <= 0:
                return ret
            op, a = ins.op, ins.args
            if op == "const":
                locals_[a[0]] = UNTAINTED
            elif op == "move":
                locals_[a[0]] = locals_.get(a[1], UNTAINTED)
            elif op == "new":
                locals_[a[0]] = Val(False, frozenset(), frozenset({a[1]}), ())
            elif op == "phi":
                locals_[a[0]] = _join(locals_.get(a[1], UNTAINTED),
                                      locals_.get(a[2], UNTAINTED))
            elif op == "sanitize":
                src = locals_.get(a[1], UNTAINTED)
                kinds = ALL_KINDS if a[2] == "any" else frozenset({a[2]})
                locals_[a[0]] = Val(src.tainted, src.sanitized | kinds,
                                    src.types, src.path)
            elif op == "check_type":
                v = locals_.get(a[0], UNTAINTED)
                if not v.types or a[1] in v.types:
                    types = frozenset({a[1]})
                else:
                    types = v.types | {a[1]}
                locals_[a[0]] = Val(v.tainted, v.sanitized, types, v.path)
            elif op == "store_field":
                obj = locals_.get(a[0], UNTAINTED)
                src = locals_.get(a[2], UNTAINTED)
                for t in obj.types:
                    key = (t, a[1])
                    old = self.fields.get(key)
                    self.fields[key] = src if old is None else _join(old, src)
            elif op == "load_field":
                obj = locals_.get(a[1], UNTAINTED)
                val = UNTAINTED
                decl_types: set = set()
                for t in obj.types:
                    f = self.fields.get((t, a[2]))
                    if f is not None:
                        val = _join(val, f)
                    c = self.classes.get(t)
                    if c is not None:
                        decl = c.fields.get(a[2])
                        if decl in self.classes:
                            decl_types.add(decl)
                types = val.types | frozenset(decl_types)
                loaded = Val(val.tainted, val.sanitized, types, val.path)
                locals_[a[0]] = _append_step(loaded, cur_step)
            elif op == "call":
                obj = locals_.get(a[1], UNTAINTED)
                cargs = [locals_.get(x, UNTAINTED) for x in a[3:]]
                locals_[a[0]] = self.do_call(obj, a[2], cargs, depth)
            elif op == "call_static":
                cargs = [locals_.get(x, UNTAINTED) for x in a[3:]]
                locals_[a[0]] = self.do_call(UNTAINTED, a[2], cargs, depth,
                                             static_cls=a[1])
            elif op == "return":
                ret = _join(ret, locals_.get(a[0], UNTAINTED))
        return ret

    def run(self) -> dict[str, Any]:
        for cls_name, real in sorted(self.sources):
            step = f"{cls_name}.{real}"
            m = self.classes[cls_name].methods[real]
            tainted = Val(True, frozenset(), frozenset(), (step,))
            args = [tainted for _ in m.params]
            self_val = Val(False, frozenset(), frozenset({cls_name}), ())
            if self.is_static(cls_name, real):
                self_val = None
            self.exec_method(cls_name, real, args, self_val, 0)
        decision = "deny" if self.chains else "allow"
        reason_codes = []
        if self.chains:
            reason_codes.append("gadget_found")
        if self.truncated:
            reason_codes.append("depth_truncated")
        report = {
            "decision": decision,
            "reason_codes": reason_codes,
            "chains": self.chains[: self.max_chains],
        }
        if len(self.chains) > self.max_chains:
            report["notes"] = (
                f"chain list truncated to max_chains={self.max_chains}; "
                f"{len(self.chains)} chains found"
            )
        return report


def hunt(classes: dict[str, ClassDef], policy: dict[str, Any]) -> dict[str, Any]:
    return Engine(classes, policy).run()
