# Changelog
All notable changes to this project are documented here.

## [0.1.1] - 2026-09-29
### Fixed
- README example vector typo (line 26 → 'z' corrected to → 'x'). Closes qa doc-finding from cycle_147.
- Version bump to 0.1.1.

## [0.1.0] - 2026-09-29
### Added
- Initial release. Zero-dependency RFC 6901 JSON Pointer parser (parse / evaluate / unescape) with full CLI. 123/123 tests passing across 8 categories (tokenisation, tilde escape, evaluate, numeric indices, fuzz, CLI, errors, edge). ASan/UBSan=N/A (pure Python stdlib).
