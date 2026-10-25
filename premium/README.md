# Premium modules (AGPL-3.0-or-later OR Commercial)

Everything in this directory is **dual-licensed**: AGPL-3.0-or-later (see [`LICENSE`](LICENSE)) **or**
a commercial license from the author. The Apache-2.0 license of the repository core does **not**
apply here. See [`../LICENSING.md`](../LICENSING.md) for the full model.

These are the project's high-value capabilities. The core (`scripts/`) keeps the detection,
string/metadata recovery and triage that make the free tool useful; the deeper analysis lives here.

## Modules

- **`lift_vm.py`** — static VM devirtualizer. Finds a RustCloak-virtualized function's bytecode blob,
  recovers the (randomized, operand-encrypted) opcode map by parsing the dispatch, resolves the
  constant pool, and lifts the bytecode to C pseudocode with control-flow structuring.
- **`devirt_emulate.py`** — emulation-based VM devirtualizer. Recovers the VM's instruction set by
  *running* the interpreter under Unicorn and observing opcode semantics (register-file dataflow +
  value relations, control flow from successor offsets, memory from dereferences), rather than
  pattern-matching the dispatch's native code. Codegen-agnostic and obfuscation-resistant (it
  observes what the interpreter *computes*), with a Python-VM correctness gate that re-executes the
  recovered program and refuses anything it cannot reproduce. Depends on `lift_vm` for rendering.
- **`deobf_deflatten.py`**, **`deobf_cff.py`** — control-flow deobfuscation (de-flattening and
  compare-tree recovery) for OLLVM-style flattened functions, x86-64 and AArch64.
- **`deobf_expr.py`** — simplifies Mixed Boolean-Arithmetic (MBA) and opaque predicates with the Z3
  SMT solver.
- **`llm_triage.py`** — LLM-assisted triage layer over the recovered artifacts.

All depend only on the Apache-2.0 core, never the reverse.

## Rule that keeps the model sound

**The core must never import a premium module.** A premium module may depend on the core (AGPL can
incorporate Apache-2.0 code), never the reverse — otherwise the copyleft would propagate into the
core and break the Apache-2.0 guarantee. New premium code goes here and is imported only by other
premium code or invoked as a standalone entry point.

## SPDX header for every file here

Start each source file with:

```
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
#
# Dual-licensed: AGPL-3.0-or-later OR a commercial license.
# Commercial licensing: Ve (VAHPEM) <ve0912084386@gmail.com>
```

The per-file SPDX identifier is authoritative.

## Contributing here

Contributions to this directory require a signed [Contributor License Agreement](../CLA.md), so the
author retains the rights needed to offer the commercial license.
