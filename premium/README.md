# Premium modules (AGPL-3.0-or-later OR Commercial)

Everything in this directory is **dual-licensed**: AGPL-3.0-or-later (see [`LICENSE`](LICENSE)) **or**
a commercial license from the author. The Apache-2.0 license of the repository core does **not**
apply here. See [`../LICENSING.md`](../LICENSING.md) for the full model.

New high-value capabilities are authored here, under the dual license, from their first commit.
Code already published under the Apache-2.0 core stays there — permissive-licensed code cannot be
meaningfully relicensed after the fact.

## Modules

- **`devirt_emulate.py`** — emulation-based VM devirtualization. Recovers a RustCloak VM's opcode
  map, operand key and constant pool by *running* the interpreter under Unicorn and observing opcode
  semantics (register-file dataflow + value relations), rather than pattern-matching the dispatch's
  native code. This is codegen-agnostic (any switch lowering) and obfuscation-resistant (it observes
  what the interpreter *computes*, so an interpreter hardened with MBA/flattening does not defeat
  it), with a correctness gate that re-executes the recovered program and refuses anything it cannot
  reproduce. It depends on the core lifter (`scripts/lift_vm.py`) for decode and rendering —
  premium → core, never the reverse. Current scope: branchless functions; control flow, memory and
  calls are the next extension.

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
