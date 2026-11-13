# Hunt rules

Reuse `load_program` and `load_policy`. This is a static search over the binobj class IR, not a concrete interpreter run. Do not exec the IR as Python and do not call `eval`.

## Instruction semantics (for taint)

Methods have a body of instructions. Locals are named. `self` is implicit in instance methods (every method except those listed in `policy.static_methods`).

- `const dst, value` — dst is untainted unless the constant is tagged in policy (public fixtures do not tag constants).
- `move dst, src`
- `load_field dst, obj, field`
- `store_field obj, field, src`
- `new dst, ClassName` — dst has type ClassName; taint from constructor args is handled by `call`.
- `call dst, obj, method, arg...` — resolve `method` on the runtime type of `obj` (see types). If the callee is a sink, this is a sink hit when any argument (including obj for some sinks, see below) is tainted and unsanitized.
- `call_static dst, ClassName, method, arg...`
- `return src`
- `sanitize dst, src, kind` — marks dst as sanitized for that kind (`cmd`, `path`, or `any`). `any` covers all kinds. Sanitization does not remove type information.
- `phi dst, a, b` — join; dst is tainted if either input is, sanitized only if *both* incoming sanitized sets cover the same kind (intersection).
- `check_type obj, ClassName` — narrows obj's type to ClassName on the remaining path (the IR is already in a single straight-line / explicitly joined form; treat this as a type filter: if a later `call` relies on that type, only ClassName's method applies after the check). If you cannot prove the type, explore both the narrowed type and the original declared type as alternatives and report a chain if either reaches a sink.

## Types and dispatch

Each class has `bases` (single or multiple). Method lookup walks the class then bases in order, recursively, first match wins. `fields` map field name → declared class name or `str` / `bytes` / `int`.

Magic aliases (the `magic` map on a class) rename methods: if `magic` contains `{"from_stream": "read_obj"}`, a call to `from_stream` uses `read_obj`'s body. Policy `source_methods` lists method names (after magic alias expansion) that introduce taint into their *return value*. Typically `from_stream` / `read_obj` on a decoder class.

## Sources, sinks, sanitizers

`policy.sources` is a list of `{class, method}`. Calling that method (including via magic alias) taints the return register.

`policy.sinks` is a list of `{class, method, kind, tainted}`. `tainted` is `args` (any argument after the receiver), `receiver` (obj itself), or `any`. Kinds are `cmd` or `path`. A sink hit requires a matching kind: a `cmd` sink is not covered by a `path` sanitizer.

`policy.max_depth` limits the number of *call* edges in a chain (default 6). `policy.max_chains` is a report cap (default 16); still set `decision` correctly even if you truncate the list.

A chain is a sequence of `Class.method` starting at a source method and ending at a sink method, where taint actually flows through arguments/fields/returns according to the bodies. Do not report a chain that only shares a class but never moves taint. Do not report a chain whose taint passed through a sanitizer of the matching kind (or `any`) on every path to the sink.

## Decision

This lab treats *finding* a feasible unsanitized chain as a policy *deny* (the program is unsafe). If no such chain exists within the depth cap, `allow`.

If you hit the depth cap on a path that still has tainted values and a remaining unresolved call that might be a sink, include `depth_truncated` in `reason_codes` (in addition to `gadget_found` if another complete chain was found). Do not invent a sink you did not reach.

## Report

- `decision`: `deny` if at least one unsanitized source-to-sink chain exists; otherwise `allow`
- `reason_codes`: empty on allow (or only `depth_truncated` if that happened and no complete chain was found — still allow, but keep the code so the truncation is visible). On deny: `gadget_found`, optionally `depth_truncated`.
- `chains`: a list of objects `{source, sink, kind, steps}` where `steps` is a list of `Class.method` strings from source to sink inclusive. Order does not need to be unique-sorted, but do not duplicate identical step lists.
- `notes`: optional

Exit 0 on allow, 1 on deny, 2 if the program or policy cannot be read.

## Public fixtures

`--program fixtures/programs/NAME.json --policy fixtures/policy.json`:

- `safe-sanitize.json` → allow (source flows into `system` but a `cmd` sanitizer sits in between)
- `direct-exec.json` → deny, chain from `Decoder.from_stream` to `Proc.system` (kind `cmd`)
- `field-flow.json` → deny, taint is stored on a field and later used by `File.write` (kind `path`)
- `poly-dispatch.json` → deny, a base-typed receiver is actually `EvilHandler` whose `handle` calls `Proc.system`
- `magic-source.json` → deny, source is declared as `from_stream` but the class aliases it to `read_obj`
- `sanitized-path-not-cmd.json` → deny, a `path` sanitizer does not protect a `cmd` sink
- `depth-cap.json` with the same policy (`max_depth` is 3) → allow, `reason_codes` may include `depth_truncated` (the only route to a sink is longer than 3 calls)
