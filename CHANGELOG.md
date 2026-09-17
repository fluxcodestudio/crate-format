# Changelog — the `.crate` format specification

All notable changes to FORMAT.md, recovery_reference.py and the vectors are recorded here.
The format's major version is the only breaking mechanism; additive fields never require one.

## [4.0.1] — 2026-09-17

### Changed
- **Relicensed MIT (+CC0) → MPL-2.0.** Same permissive integration posture — embedding the
  decoder unchanged requires nothing from us — but the file-level copyleft now guarantees the
  format's reference tooling can never be taken closed, and the license's patent grant and
  trademark preservation are built in (PATENTS.md continues to cover anyone implementing the
  spec from scratch without our files). The earlier CC0 dedication of the decoder was
  withdrawn as part of this change: its "unforkable floor" and the promise's "unrevokable
  floor" pulled in opposite directions, and the steward chose the position MPL-2.0 protects.

## [4.0] — 2026-09-17

### Added
- Initial publication: the complete decode specification (container, per-entry reconstruction
  rules, fail-closed refusals, the versioning discipline, honest boundaries).
- The reference decoder, including symlink recreation (location confined, target literal,
  per-entry failures never abort the rest).
- Six test vectors with sources, SHA256SUMS, and the one-command `verify.sh` gate with
  per-vector anti-vacuity assertions — plain hybrid, CDC dedup, ICR + cross-stem residual,
  WavPack float/10-channel, junk-strip + symlinks + dedup, and an encrypted split package
  with PAR2 sidecars.
- PROMISE.md (longevity: free unpacking forever, backward compatibility as a release gate,
  full-source release on dissolution or abandonment — never acquisition — and the hosted-data
  retrieval window), PATENTS.md (irrevocable royalty-free patent non-assert with defensive
  termination), LICENSE (MIT + CC0 on the decoder).
