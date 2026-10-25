# Licensing

rust-deobf uses an **open-core** model. There are two tiers, with different licenses.

## Core — Apache License 2.0

Everything in the repository **except** the `premium/` directory is licensed under the
Apache License 2.0 (see [`LICENSE`](LICENSE)). This is a permissive, OSI-approved license:
you may use it, including in closed-source and commercial products, with attribution and
subject to Apache 2.0's patent terms. The core is, and will stay, free.

This covers detection (including VM / anti-emulation detection), string and
metadata recovery, artifact/IOC extraction, and the SOC triage pipeline — the
capabilities that make the free tool useful on its own.

## Premium modules — AGPL-3.0-or-later OR Commercial

Modules under the `premium/` directory are **dual-licensed**:

> Licensed under the GNU Affero General Public License v3.0 **or later**
> (AGPL-3.0-or-later), **OR** under a separate commercial license.
> Contact the author for commercial licensing.

- **AGPL-3.0-or-later** — free for open-source, research, and personal use. Note the AGPL's
  network clause: if you run a modified version of a premium module as a network service,
  you must offer that service's users the corresponding source. See [`premium/LICENSE`](premium/LICENSE).
- **Commercial license** — for using a premium module in a closed-source product or a hosted
  service without the AGPL's source-disclosure obligations. Contact
  **Ve (VAHPEM) &lt;ve0912084386@gmail.com&gt;**.

Each file under `premium/` carries an `SPDX-License-Identifier` header stating its license.
The per-file SPDX header is authoritative; GitHub's repository-level license badge reflects the
Apache-2.0 core only and does **not** relicense the premium modules.

## Why two tiers

The core is a public good and a *produit d'appel* — it builds reputation and adoption. The
premium modules are the high-effort capabilities whose value the author chooses to protect and,
optionally, monetize. Keeping the copyright wholly with the author (see [`CLA.md`](CLA.md)) is
what makes the dual license possible.

## Contributing

Contributions to **core** are accepted under Apache-2.0 inbound=outbound. Contributions to
**premium/** require signing the [Contributor License Agreement](CLA.md) so the dual-license can
be maintained. See [`CLA.md`](CLA.md).
