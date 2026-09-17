# Security policy

The reference decoder treats everything in a `.crate` manifest as **untrusted input** — it came
out of a file someone sent you. Fail-closed refusals (absolute/`..`/symlink-escaping paths,
future format majors, unknown feature tokens, structural nonsense) are the specification, and
recovery_reference.py implements them.

## Reporting a vulnerability

- **Where:** GitHub → Security → "Report a vulnerability" (private disclosure), or email
  security@fluxcode.studio if you prefer mail.
- **What we want:** hostile manifests that read or write outside the output tree, bypass a
  refusal, quarantine incorrectly, or make the decoder misreport verification. Path-confinement
  and verification-integrity reports are the highest-value class.
- **Response:** acknowledged within a week; fixed and credited (opt-in) in the next release,
  with a new vector where one can be built.
- **Scope:** the reference decoder and the format's trust model. Do not test against the Crate
  application or its services from this repository — that is a separate product with its own
  disclosure channel.
