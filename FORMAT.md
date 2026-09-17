# The `.crate` format — decode specification

**Version of this document:** format major 4 · written 2026-09-17.
**Normative decoder:** [`recovery_reference.py`](recovery_reference.py) —
dependency-free Python plus the `flac`, `wvunpack` and standard `7z`/`age`/`par2` CLIs.
**Proof:** `sh verify.sh` rebuilds every shipped test vector byte-exactly using only those tools.

A `.crate` package is designed so that **every file it contains can be rebuilt byte-for-byte
without any Crate software** — no app, no server, no license, forever. This document is the
complete specification of *how*. Everything in it is exercised, before each Crate release, by a
gate that rebuilds real packages with these rules and compares every byte; the vectors in
`vectors/` are the public form of that gate.

## 0. The container

A `.crate` file is one of:

- a **7-Zip archive** (`7z` format ≥ v0.4), possibly **passphrase-encrypted** — then the whole
  file is an [age](https://age-encryption.org) (scrypt) payload around the archive;
- **split volumes** named `NAME.partNNNofMMM.crate` — one 7-Zip stream cut at byte boundaries:
  concatenate the parts in index order first;
- optionally accompanied by **PAR2 sidecars** (`NAME.crate.par2`, `NAME.crate.vol*.par2`) usable
  by any PAR2 tool to repair damage without re-downloading.

Open it with any 7-Zip-compatible tool. `-spd` (store-dashes-disable / literal names) matters:
without it, 7-Zip *globs* a `*` in a stored path and wanders the disk — always extract with
literal-name handling.

Inside the archive:

| path | contents |
|---|---|
| *(your files)* | non-audio files stored verbatim; audio as `*.flac` / `*.wv` streams |
| `.crate/manifest.json` | the manifest: what was packed, how each file rebuilds, each file's `sha256_original` |
| `.crate/wrappers/` | container bytes excised from around audio regions (content-addressed by SHA-256) |
| `.crate/chunks/` | CDC chunk-blob streams (sub-file dedup) |
| `.crate/xattrs/` | extended attributes and resource forks (app-side restore) |

`manifest.json` is plain JSON. It may additionally carry an Ed25519 signature
(`.crate/manifest.sig`, pubkey embedded in the manifest); signature checking is *optional* for
recovery — `sha256_original` alone proves byte-exactness of the rebuild relative to what was
packed.

## 1. Reconstruction rules

Walk `manifest.files[]`. Every entry carries `sha256_original` — **the rebuild is not done until
every file's SHA-256 matches it.** That field is the only trusted gate.

| manifest fields | how to rebuild the original file |
|---|---|
| `codec_used: "none"` | the file is stored verbatim at `encoded_path` — done |
| `dedup_of: <sha>` | byte-identical duplicate: copy the already-rebuilt file whose `sha256_original` matches |
| `codec_used: "flac"` / `"wavpack"` | whole-file stream (legacy manifests; today's packs container-split everything): `flac -d --keep-foreign-metadata-if-present` / `wvunpack`. **The FLAC flag is not optional** — without it every foreign WAVE/AIFF chunk the original carried (`bext`, `iXML`, `cue`, `LIST`/`INFO`…) is silently dropped and the hash fails. A few legacy WAVs make `flac` refuse the flag outright — retry without it and let `sha256_original` judge. **Decode to a short-extension temp name and rename** — see the wvunpack trap below |
| `codec_used: "flac-raw"` / `"wavpack-raw"` | container-split (most audio): the stream decodes to the file's raw PCM *audio region*; original bytes = `wrappers/<wrapper_sha256>` ‖ decoded PCM ‖ `wrappers/<trailer_sha256>` (either wrapper may be absent). FLAC honours real endianness — decode with `flac -d --force-raw-format --endian=<per raw_endian> --sign=<per raw_signed>`. **WavPack does not**: the raw region is always encoded little-endian whatever the source's byte order, so a `.wv` stream is byte-transparent — `wvunpack --raw` returns the same bytes that went in, big-endian sources included; do **not** apply `raw_endian` to it |
| `chunk_refs: [{blob, offset, len}…]` | sub-file dedup: decode `chunk_blobs[blob].encoded_path` once to raw PCM; the file's audio region = concatenation of `pcm[offset : offset+len]` slices in order; then wrap as flac-raw |
| `residual_refs: {anchors: […]}` | cross-stem residual: decode this file's stream to PCM `r`; rebuild each anchor first; audio = per-sample `r + Σ(anchor samples)`, **wrapping modulo 2^bits** (two's-complement add, `bit_depth` from the entry); then wrap as flac-raw |
| `inter_channel_ref: {anchor, shift, block_frames, ks}` | panned-mono residual: decode the stream to interleaved PCM `[A, r]` (A = channel `anchor`); for frame `i` in block `b = i / block_frames`: `pred = (ks[b] * A[i] + (1 << (shift-1))) >> shift` (arithmetic shift); other channel `B[i] = r[i] + pred`, wrapping modulo 2^bits; re-interleave, wrap as flac-raw |
| `codec_used: "essence-streams"` | multi-range container split (AAF/OMF). The entry carries `skeleton_sha256` and `essence_streams: [{encoded_path, codec_used, channels, bit_depth, sample_rate, raw_endian, raw_signed, runs}]` with `runs` = `[file_offset, len, pcm_offset]` triples. The *skeleton* at `wrappers/<skeleton_sha256>` is the original file with every run's bytes excised. Rebuild: decode each stream to one PCM buffer; write each run's `pcm[pcm_offset : pcm_offset+len]` back at `file_offset`; skeleton bytes fill every gap and the tail. Invariants (each violation is a hard FAIL — no truncation, no padding): runs strictly ascending by `file_offset`, non-overlapping across ALL streams of the entry, every `len > 0`; per stream, decoded PCM length equals the sum of its runs' `len` and the `pcm_offset`s tile `[0, that sum)` exactly; `len(skeleton) + Σ len == original size`. The final `sha256_original` check remains mandatory. An essence entry never also carries `wrapper_sha256`, `trailer_sha256`, `chunk_refs`, `residual_refs`, or `inter_channel_ref`. This rule takes precedence over the plain flac-raw/wavpack-raw rule; older decoders must fail closed on it |

Sample decoding for the integer math: samples are little/big-endian per `raw_endian`, signed per
`raw_signed`, `ceil(bit_depth/8)` bytes each, channels interleaved. "Wrapping modulo 2^bits" =
ordinary fixed-width overflow (mask to `bit_depth` bits, sign-extend). The residual transforms
are integer-only — the pack side never applies them to float audio, so this math never meets a
float sample.

> **The wvunpack `-o` trap — the one thing that will silently break a reimplementation.**
> `wvunpack` treats the trailing `.xxx` of an `-o` name as an extension only when it is **1–4
> characters**. Anything longer (or no dot at all) counts as "no extension" and wvunpack
> **appends its own**: `-o out.rawpcm --raw` writes `out.rawpcm.raw`. Nothing fails — it exits 0.
> Always decode to a ≤4-character extension you control (`.pcm`, `.tmp`) and rename, accepting
> `<name>.raw`/`<name>.wav` as the same result.

**Symlinks.** `manifest.symlinks[]` records each filesystem symlink the session contained:
`path` (relative to the session root) and `target` (**stored as a literal string, never
resolved**). Recreate each link verbatim — recreating a link writes nothing through it, so any
target string is safe to recreate. The `path` is untrusted input: validate it (relative, no
`..`, confined to the output tree) before creating anything. A link that cannot be created on
the recovering filesystem is reported and counted; it never aborts the rest.

**Expanded archives (`archive_groups`).** With archive expansion enabled, a multi-file archive
in the session was opened and its members packed as ordinary `files[]` entries under
`<archive-path>/<inner-path>` — the rules above rebuild them byte-exactly with no new logic, as
loose files. `archive_groups[]` only records that Crate's app re-containers them into a nested
`<name>.crate` on restore for presentation — a convenience the format does not require. The
outer archive's exact zip/rar byte layout is the one thing not reproduced.

**OS-generated junk (`manifest.excluded`).** A default pack strips cross-platform OS clutter
(macOS `.DS_Store`, `._*`, `Icon\r`, `.Spotlight-V100/`, `.Trashes/`, `.fseventsd/`,
`.TemporaryItems/`, `.DocumentRevisions-V100/`; Windows `Thumbs.db`, `ehthumbs.db`,
`Desktop.ini`, `$RECYCLE.BIN/`, `System Volume Information/`; Linux `.Trash-*/`, `.directory`,
`.fuse_hidden*`, `.nfs*`). These are regenerated by the OS and are not user content; each
stripped path is **disclosed** in `manifest.excluded` and nothing is lost. The exact predicate
lives in the reference script as `is_os_junk()` and is **era-versioned**: the set a pack was
written under comes from its `junk_lexicon` field when stamped, else from `app_version`
(≥ 1.7 → lexicon 2, older/unparseable → lexicon 1). Old packs can carry `files[]` rows that were
listed but never archived (junk under their own era); the rebuild loop skips those rows only on a
non-exact-clone pack, only when the path is junk under the pack's own lexicon, and only when the
row genuinely has no encoded artifact. Exact-clone packs (manifest `keep_os_junk` + the
`"exact-clone"` feature token) keep the junk as ordinary `files[]` entries, which rebuild
verbatim like any other file.

## 2. What the decoder must refuse

**Everything the manifest says is untrusted input** — it came out of a file someone sent you.
Fail closed, whole-package (write nothing) on:

- an unreadable/absent/non-Crate `manifest.json`;
- a `crate_manifest_version` major NEWER than the decoder implements;
- a `required_features` token the decoder does not implement;
- a duplicate `chunk_blobs[].id` (the slice map would be ambiguous);
- any path that is absolute, contains `..`, or resolves outside its directory via a symlink —
  for READING as much as WRITING (`original_path`, `encoded_path`, wrapper/skeleton blob names,
  per-stream paths, symlink locations). Without this, a hostile manifest could read arbitrary
  files off the recovering machine and splice them into "restored" audio.

Fail per-entry (report, count, keep rebuilding the rest) on:

- mutually-exclusive mechanisms on one entry; empty/negative/overrunning `chunk_refs`; an
  unresolvable or self-referential residual anchor; an unusable `bit_depth`; any violated
  essence geometry invariant; a rebuilt file whose SHA-256 mismatches `sha256_original`
  (**quarantine** it as `<name>.UNVERIFIED` — wrong bytes at the right path are worse than a
  missing file — and never let it serve as a `dedup_of` canonical or a residual anchor).

## 3. Versioning discipline (the compatibility promise)

- **Major-version bumps are the only breaking mechanism.** Anything a decoder of major *N*
  cannot read ships with major *N+1* and a `required_features` token. Old decoders must refuse
  cleanly (write nothing) rather than guess.
- Additive fields are always safe: a decoder ignores what it does not know.
- The junk lexicon is era-versioned and never edited in place; readers infer old eras
  forever.
- When a new pack-side transform lands, the reference decoder and this document are updated in
  the same change — a transform that is not specified here must not ship. This rule is enforced
  mechanically in Crate's release gates.

## 3a. Writing a conformant minimal pack (the essentials)

Any app may produce valid `.crate` packages without Crate's compression engine — the full
tier stack (CDC dedup, residual transforms) is optional; a minimal writer is fully conformant:

- non-audio files stored verbatim (`codec_used: "none"`); PCM audio as `flac-raw` container-split
  streams (wrappers excised, `sha256_original` over the whole original file);
- `manifest.json` with `crate_manifest_version`, one `files[]` entry per file carrying
  `original_path`, `codec_used`, `encoded_path`, `original_bytes` and `sha256_original`; junk the
  writer stripped is disclosed in `excluded[]`; `symlinks[]` recorded as literal targets;
- the container is one 7-Zip archive (volumes/split/encryption/PAR2 all optional); audio may also
  be stored as whole-file `.flac` only when foreign metadata is preserved (`--keep-foreign-metadata-if-present`).

The reference decoder is the conformance oracle: your pack must rebuild byte-exactly through it,
every file, `exit 0`. Valid and *small* are different goals — minimal packs trade the size the
engine's dedup and residual tiers buy for write-side simplicity.

## 4. Scope and honest boundaries

The reference decoder rebuilds **file contents** byte-for-byte, and recreates recorded symlinks.
It does not replay: filesystem permissions/timestamps (`fs_meta`), extended attributes and
resource forks (`.crate/xattrs/`), or empty directories — the Crate app's own restore replays
those, and they are not part of what `sha256_original` covers. The outer envelope of an expanded
archive is not reproduced (its members are). This is the complete list.
