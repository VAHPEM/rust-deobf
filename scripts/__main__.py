# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
"""`python -m rust_deobf ...` == the `rust-deobf` console command."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
