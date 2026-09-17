# The longevity promise

*Fluxcode Studio LLC — the makers of Crate — to everyone whose masters live in `.crate`
packages. Dated 2026-09-17. This document is the commitment; the format spec, reference decoder
and test vectors in this repository are its proof, today.*

## 1. Unpacking is free, forever — in every sense

- Unpacking and verifying `.crate` packages is free in the Crate app, always, on every
  platform — no payment, no account, no expiration.
- And it is free of *us*: this repository contains everything required to rebuild every file in
  every package byte-for-byte without any Crate software — the format specification, a
  dependency-free reference decoder, and test vectors a stranger can run. If you never open
  Crate again, your files are still yours.

## 2. Backward compatibility is a release gate, not a hope

- New releases of Crate decode every package ever produced by an older release.
- The format's major version is the only breaking mechanism, and a pack stamped with a feature
  an older reader does not know is refused *cleanly* — never half-restored.
- A pack-side feature that has not been taught to the public spec and the reference decoder does
  not ship. This is enforced mechanically in our release gates.

## 3. If Fluxcode Studio ever dissolves or abandons the format

If Fluxcode Studio LLC ever dissolves, ceases operations, or publicly abandons the `.crate`
format, then the **complete source code of Crate — packing, verification, everything — will be
released promptly under a permissive open-source license** (Apache-2.0 or MIT, at the
community's choice), so the tool itself can live on without us.

- **Trigger, stated precisely:** dissolution or liquidation of Fluxcode Studio LLC; a public
  announcement of abandonment of the format; or twelve consecutive months of total inactivity
  (no release, no commit, no operating site) — whichever comes first.
- **Trigger, stated equally precisely:** this clause does **not** trigger on acquisition,
  merger, or change of control. A successor company that keeps honoring these commitments
  inherits them as-is. We write this exclusion down because a pre-committed release obligation
  that fires on acquisition would harm the very users it exists to protect.
- The reference decoder in this repository is dedicated to the public domain (in addition to
  the MIT license below), to the extent such dedication is valid where you are — so the floor
  of this promise cannot be revoked by any future act.

## 4. The lineage we stand in

Every format users already trust was built by a team this size or smaller — ZIP, tar, gzip,
7-Zip, FLAC, WavPack were all one-person or handful projects at launch, and became universal
because the *ecosystem* adopted them, not because their makers were big. Longevity comes from
openness, and openness is what this repository is.
