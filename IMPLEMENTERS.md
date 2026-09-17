# Implementing `.crate` — the writer's guide

**Audience:** an engineer adding `.crate` export or import to their own application — no Crate
source, no permission slip, no conversation with us required. This is Lane 1 from the
[README](README.md); the license is [MPL-2.0](LICENSE) and that is the whole legal brief.

**The one sentence version:** write a 7-Zip archive containing your non-audio files verbatim, your
PCM audio as FLAC streams with the container bytes excised, and a JSON manifest that records how
every file rebuilds — then prove it with our reference decoder.

**The arbiter of conformance:** [`recovery_reference.py`](recovery_reference.py). A package your
writer produces is conformant if and only if the reference decoder rebuilds every file
byte-exactly from it and exits 0. Not "looks right" — rebuilds byte-exactly.

---

## 1. The container

One **7-Zip archive** (format ≥ v0.4 — any modern 7-Zip produces this). Inside:

| path | what you put there |
|---|---|
| *(your files)* | non-audio files stored verbatim; audio as `*.flac` streams |
| `.crate/manifest.json` | the manifest (§3) — plain JSON, UTF-8 |
| `.crate/wrappers/` | the container bytes you excised from around each audio region, named by their SHA-256 |

Everything else the format supports is **optional**: WavPack streams, sub-file dedup
(`.crate/chunks/`), residual transforms, AAF/OMF essence splitting, age encryption, split
volumes, PAR2 sidecars, extended attributes. A conformant writer needs none of them. Skip all of
it on v1 of your integration — the packages are valid and larger, and you can add tiers later.

**Extraction rule your readers must know** (and your writer should never violate): stored paths
are LITERAL. 7-Zip without `-spd` globs a `*` in a stored path — so your writer must not emit
glob-hostile paths, and readers extract with `-spd`.

**No top-level folder requirement:** the manifest's `original_path` values are relative to the
session root and are the ONLY layout authority. Extracted archives reconstruct that root from the
manifest, not from archive folders.

## 2. Classify each input file

Walk the user's session folder. For each file:

1. **Non-audio** (session files, plugin data, images, PDFs, anything you don't parse): store
   verbatim. Manifest entry: `codec_used: "none"`, and `encoded_path` points at the stored copy.
2. **PCM audio you recognize** (WAV/AIFF/CAF/Wave64 — parse the container): split the container
   bytes into `wrapper` (everything before the PCM audio region) + the raw PCM + `trailer`
   (everything after). Store the wrapper/trailer in `.crate/wrappers/` keyed by their SHA-256,
   FLAC-encode the raw PCM, and record the split in the manifest (§3's `flac-raw` entry).
   - **The FLAC flag is not optional on decode:** the decoder must run
     `flac -d --keep-foreign-metadata-if-present` — your writer's job is to make that possible by
     keeping the wrapper bytes separate, so foreign chunks (bext, iXML, cue, LIST/INFO) survive.
   - Byte order: FLAC honours the source's real endianness; record `raw_endian` (`"le"`/`"be"`)
     and `raw_signed` per file.
3. **Anything else you don't recognize** (already-compressed audio, MP3, unknown binaries): store
   verbatim (`codec_used: "none"`), exactly like non-audio. **Never transcode.** Storing is always
   conformant; guessing wrong is not.

**Do not skip bytes silently.** `wrapper + audio + trailer` must equal the original file exactly —
the manifest's `sha256_original` (the SHA-256 of the ENTIRE original file) is checked on rebuild,
so a dropped bext chunk or a re-written header fails the hash and the package is non-conformant.

**Symlinks:** record them in `manifest.symlinks[]` as `{path, target}` — the path relative to the
session root, the target as the literal string (never resolved). Recreating a link writes nothing
through it. Do not follow links when walking the tree.

**OS junk** (`.DS_Store`, `Thumbs.db`, `._*`, …): skip storing it, but DISCLOSE — each stripped
path goes in `manifest.excluded[]`. Undisclosed stripping is how a rebuild looks byte-exact while
the user's folder silently lost files.

## 3. The manifest — the required fields

```json
{
  "crate_manifest_version": "4.0",
  "files": [
    {
      "id": "1",
      "original_path": "Session/Song.wav",
      "kind": "audio",
      "codec_used": "flac-raw",
      "encoded_path": "audio/Song.wav.flac",
      "wrapper_sha256": "<sha256 of the pre-audio bytes>",
      "trailer_sha256": "<sha256 of the post-audio bytes, or omit if none>",
      "bit_depth": 24,
      "channels": 2,
      "sample_rate": 48000,
      "sample_format": "int",
      "raw_endian": "le",
      "raw_signed": true,
      "original_bytes": 483028,
      "sha256_original": "<sha256 of the ENTIRE original file>"
    }
  ],
  "symlinks": [],
  "excluded": ["Session/.DS_Store"]
}
```

Field-by-field, what a decoder does with each:

- `crate_manifest_version` — the format major. **"4.0" today.** A decoder refuses a major newer
  than it implements; additive fields never require a bump.
- `files[].id` — unique within the manifest.
- `original_path` — relative, no `..`, no absolute paths. This is untrusted input to every
  decoder; hostile paths are refused wholesale.
- `codec_used` — `"none"` (verbatim) or `"flac-raw"` (container-split). A decoder must also
  handle `"flac"`/`"wavpack"` (whole-file, legacy) and the advanced tiers — read FORMAT.md §1
  before emitting anything beyond the two basic codecs.
- `encoded_path` — the stored artifact's path inside the archive, relative.
- `wrapper_sha256`/`trailer_sha256` — content-addressed names in `.crate/wrappers/`. Either may
  be omitted when that side is empty.
- `bit_depth`/`channels`/`sample_rate`/`sample_format`/`raw_endian`/`raw_signed` — the PCM
  geometry; the decoder uses them to reconstruct the exact original bytes.
- `original_bytes` — the original file's size. A rebuild that disagrees is a hard failure.
- `sha256_original` — **the only trusted gate.** The decoder hashes every rebuilt file and
  compares. Anything that mismatches is quarantined, never delivered.
- `excluded[]` — every path you stripped as OS junk.
- `symlinks[]` — as §2.

## 4. The conformance procedure (run this on YOUR pack)

```sh
# 1. extract your own package
7z x -spd -o /tmp/check your-first.crate
# 2. run the normative decoder — the reference implementation, no Crate software
python3 recovery_reference.py /tmp/check /tmp/rebuilt
#    exit 0 = every file rebuilt; a nonzero exit names the failures
# 3. compare — every rebuilt file byte-identical to your original session
diff -r /tmp/rebuilt /path/to/your/original-session
```

Pass criterion: the decoder's summary line says every file rebuilt byte-exactly (its exit status
is 0), and the tree diff is empty. The shipped `vectors/` + `verify.sh` show the same procedure
against known-good packages — use them as your sanity baseline before testing your own writer.

**The negative test matters too:** corrupt one byte inside your package's FLAC stream and confirm
the decoder quarantines that file (`<name>.UNVERIFIED`), reports the failure, and still rebuilds
the rest. A decoder that silently delivers wrong bytes is the failure mode the whole format
exists to prevent.

## 5. The three pitfalls that will bite you

1. **The wvunpack `-o` trap** — if you ever use WavPack: `wvunpack` treats an `-o` name's trailing
   `.xxx` as an extension only when it is 1–4 characters; longer names get the tool's own
   extension appended silently (exit 0, wrong file). Decode to a ≤4-character extension you
   control and rename.
2. **Foreign metadata** — FLAC drops WAVE/AIFF chunks (bext, iXML, cue, LIST/INFO) unless
   `--keep-foreign-metadata-if-present` is passed on decode. Your wrapper/trailer split exists
   precisely so those chunks live outside the FLAC stream; if you store whole-file FLAC instead,
   the flag is mandatory.
3. **The hash is over the WHOLE original file** — not the PCM, not the audio region. Every byte
   you touch (headers, chunks, trailing padding) must come back, or `sha256_original` fails.

## 6. What deliberately requires Lane 2

Everything in §1–§5 is the open floor. What is **not** in this repository: the compression engine
that reaches Crate's measured sizes — content-defined chunking and its boundary discovery, the
cross-stem and inter-channel residual transforms and their anchor selection, the estimate model.
Those are the product. If you want them embedded, write to
[licensing@fluxcode.studio](mailto:licensing@fluxcode.studio?subject=%5BCrate%5D%20Integration%20inquiry)
— a real person, within a week.

Your minimal writer is conformant the moment the reference decoder blesses it. Publish it, tell
us (see the README's credit note), and we'll list you on [ADOPTERS.md](ADOPTERS.md).
