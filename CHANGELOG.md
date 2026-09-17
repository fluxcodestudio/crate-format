# Changelog — the `.crate` format specification

All notable changes to FORMAT.md, recovery_reference.py and the vectors are recorded here.
The format's major version is the only breaking mechanism; additive fields never require one.

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
