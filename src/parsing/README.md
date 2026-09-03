# URL Parsing & Public Suffix List Module

This module implements deterministic URL parsing, scheme/host normalization, IDNA UTS #46 processing, IP literal detection, and registrable-site extraction.

## Key Files
- `phase2c_url_parser.py`: Primary Phase-2C/3 parser anchored to official PSL snapshot (2026-08-17).
- `phase2b_common.py`: Core shared normalization and URL parsing helper routines.

## PSL Rules & Groupings
- **`site_key_private`**: Primary organizational grouping using ICANN + private PSL rules. Preserves multi-tenant isolation (e.g., `user.github.io` vs `other.github.io`).
- **`site_key_icann`**: Secondary sensitivity grouping using ICANN top-level domains only.
