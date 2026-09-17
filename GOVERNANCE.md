# Governance

**Steward:** Fluxcode Studio LLC (Jon Rezin, founder) — benevolent dictator for as long as the
company stewards the format.

- **Spec changes** (`FORMAT.md`, the reference decoder, the vectors): proposed via GitHub
  issues; decided and merged by the steward. Every merge is validated by `verify.sh` in CI, and
  every release of the spec is tagged and recorded in [CHANGELOG.md](CHANGELOG.md).
- **Breaking changes** ship only as a new format major version, per the versioning discipline
  in FORMAT.md §3 — and a pack-side feature that is not taught to this specification does not
  ship in Crate either.
- **Succession.** The commitments in [PROMISE.md](PROMISE.md) — free unpacking forever, the
  full-source release on dissolution or abandonment (never acquisition), the hosted-data
  retrieval window — bind any successor steward. They are commitments to users, not policies of
  a particular owner.
- **This repository's provenance is preserved off-platform** (Software Heritage; a DOI deposit)
  so that neither GitHub's existence nor ours is a single point of failure for the format.
