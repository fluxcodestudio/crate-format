#!/usr/bin/env python3
"""Reference .crate recovery — rebuilds every file byte-exactly WITHOUT Crate software.

Public domain. Requires only Python 3 and the standard `flac` and `wvunpack` command-line tools.
`wvunpack` is not optional: WavPack carries 32-bit float audio, any integer audio past FLAC's
8-channel cap, and everything in a `--codec wavpack-only` pack. See docs/RECOVERY.md for the
format specification this implements.

Usage:  7z x -spd SESSION.crate -o extracted/   # any 7-Zip tool; `age -d` first if encrypted
                                                # -spd: stored names are literal, never globs
        python3 recovery_reference.py extracted/ restored/

Exit status: 0 = every file rebuilt byte-exactly; 1 = some file(s) failed (each one quarantined,
see below); 2 = the package was REFUSED as a whole (bad usage, unreadable/absent manifest, or a
manifest newer than this escrow understands — fail closed, never guess).

Three behaviours are load-bearing parity with the Crate app's own restore, not conveniences:

* **A file whose rebuilt bytes do not match `sha256_original` is QUARANTINED** — renamed
  `<name>.UNVERIFIED` (`.UNVERIFIED (2)`, `(3)`… if that name is taken) and never left sitting at
  its real path where a DAW would happily open it. Wrong bytes at the right path are worse than a
  missing file, because nothing downstream can tell.
* **A quarantined file never seeds anything else.** It cannot be a dedup canonical and it cannot be
  a residual anchor, so one bad decode cannot silently poison a second file.
* **One bad file never aborts the rest.** Every per-entry failure is caught, reported and counted;
  the remaining files are still rebuilt. Only whole-package problems (§ exit 2) refuse outright.

Everything the manifest says is treated as UNTRUSTED input — it came out of a file someone sent
you. Every path built from it, for READING as well as writing, is confined under the directory it
belongs to; an absolute path, a `..` component or a symlink pointing out of the tree is refused.
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

# Manifest majors this escrow implements: 1.x wrapper-split, 2.x dedup/CDC, 3.x ICR, 4.x essence.
# A NEWER major means a transform we have never seen, so refuse the package instead of rebuilding
# files that would silently be wrong.
MAX_MANIFEST_MAJOR = 4
# `required_features` tokens this escrow implements. Same rule: an unknown token is a refusal.
KNOWN_FEATURES = frozenset({"icr", "essence-streams", "exact-clone"})


class Refused(Exception):
    """Whole-package refusal — nothing is rebuilt (exit 2)."""


class EntryError(Exception):
    """One manifest entry is unrebuildable; every other file still gets rebuilt (exit 1)."""


# Mirrors crate-core `inventory::JUNK_LEXICON_CURRENT`. `is_os_junk` is ERA-VERSIONED there:
#   1 — macOS-only set, shipped through v1.6.1.
#   2 — the v1.7.0 cross-platform widening, EXACTLY as shipped (bare `.Trash-` / `.fuse_hidden` /
#       `.nfs` prefix matches included).
#   3 — lexicon 2 with those prefixes tightened to their machine-generated shapes
#       (`.Trash-<digits>`, `.fuse_hidden<hex>`, `.nfs<hex>`).
JUNK_LEXICON_CURRENT = 3


def is_os_junk(rel_path: str, lexicon: int = JUNK_LEXICON_CURRENT) -> bool:
    """Whether Crate's pack step strips this path as OS-generated junk, under `lexicon`.

    Mirrors crate-core `inventory::is_os_junk_lexicon` EXACTLY. The set is era-versioned because a
    reader that applies TODAY's set to YESTERDAY's package drops real content: a v1.6.1 writer
    legitimately archived `Thumbs.db` / `.Trash-1000/…`, and only lexicon 2+ calls those junk.
    Default is the CURRENT writer's set (what `recovery_test.sh` uses when verifying rebuilds of
    packs made by today's CLI); anything judging entries of an EXISTING manifest must pass the
    PACK's own era — see `effective_junk_lexicon` / `is_os_junk_for_pack`.

    The escrow never *rebuilds* stripped junk: it is OS-regenerated and, on a default (stripped)
    pack, absent from the manifest entirely (disclosed in `manifest.excluded`, not `files[]`).
    This predicate is here so a source-vs-rebuild verification can skip them honestly — a stripped
    junk file legitimately has no counterpart in the rebuild, and `recovery_test.sh` uses this to
    keep "byte-identical" from either false-failing or hiding a real miss. (Exact-clone packs keep
    the junk as ordinary `files[]` entries; those rebuild verbatim like any other file, and the
    comparison side must then filter NOTHING — see `is_os_junk_for_pack`.)
    """
    lexicon = max(1, min(int(lexicon), JUNK_LEXICON_CURRENT))
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
    # Whole-subtree junk directories. macOS names are exact — lexicon 1.
    junk_dirs = {".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems",
                 ".DocumentRevisions-V100"}
    junk_dirs_ci = {"$recycle.bin", "system volume information"}  # Windows, CI — lexicon 2+
    for p in parts:
        if p in junk_dirs:
            return True
        if lexicon >= 2:
            if p.lower() in junk_dirs_ci:
                return True
            # freedesktop trash: lexicon 2 shipped a bare `.Trash-` prefix match; lexicon 3
            # requires the real shape (`.Trash-<digits>`).
            if p.startswith(".Trash-") and (lexicon == 2 or p[len(".Trash-"):].isdigit()):
                return True
    name = parts[-1] if parts else ""
    # macOS Finder state / icon sidecar / AppleDouble — lexicon 1.
    if name in (".DS_Store", "Icon\r") or name.startswith("._"):
        return True
    if lexicon < 2:
        return False
    if name == ".directory":  # Linux (KDE) — lexicon 2+
        return True
    # Transient Linux temp sidecars: lexicon 2 shipped bare prefix matches; lexicon 3 requires the
    # machine-generated hex tail (`.nfs-session-notes.txt` is user content again).
    _hex = set("0123456789abcdefABCDEF")
    for pref in (".fuse_hidden", ".nfs"):
        if name.startswith(pref):
            tail = name[len(pref):]
            if lexicon == 2 or (tail and all(c in _hex for c in tail)):
                return True
    return name.lower() in ("thumbs.db", "ehthumbs.db", "thumbs.db:encryptable", "desktop.ini")


def _version_major_minor(v):
    """Leading-digits parse of the first two dotted components (mirrors crate-core
    `manifest::version_major_minor`): tolerates suffixes ("1.7.0-beta.2"), returns None when the
    major has no leading digits at all."""
    parts = str(v).strip().split(".", 2)
    def lead(s):
        digits = ""
        for c in s:
            if c.isdigit():
                digits += c
            else:
                break
        return int(digits) if digits else None
    major = lead(parts[0]) if parts else None
    if major is None:
        return None
    minor = lead(parts[1]) if len(parts) > 1 else None
    return major, (minor if minor is not None else 0)


def effective_junk_lexicon(manifest: dict) -> int:
    """The junk lexicon this package was WRITTEN under (mirrors crate-core
    `Manifest::effective_junk_lexicon`). A stamped `junk_lexicon` is believed (clamped to the range
    this escrow knows); an unstamped package is dated by `app_version` — the cross-platform
    widening shipped in 1.7.0, so ≥ 1.7 means lexicon 2 and anything older (or unparseable) means
    lexicon 1. Unparseable falls to the NARROW set deliberately: guessing too old restores a
    handful of housekeeping files; guessing too new silently drops a user's real bytes."""
    stamped = manifest.get("junk_lexicon")
    if isinstance(stamped, int) and not isinstance(stamped, bool) and stamped != 0:
        return max(1, min(stamped, JUNK_LEXICON_CURRENT))
    mm = _version_major_minor(manifest.get("app_version", ""))
    return 2 if (mm is not None and mm >= (1, 7)) else 1


def is_os_junk_for_pack(rel_path: str, manifest) -> bool:
    """Comparison-side junk predicate that HONOURS THE PACK, for source-vs-rebuild verification.

    An exact-clone pack (`keep_os_junk` true) stores the junk as real `files[]` content, so on
    such a pack NOTHING may be junk-filtered out of a byte-identical comparison — filtering with
    the writer's lexicon there would constitutionally exclude the very payload the mode exists to
    preserve (a rebuild that silently dropped `Thumbs.db` would still compare clean). On a normal
    (stripped) pack, filter under the PACK's own era, never the current writer's."""
    if isinstance(manifest, dict) and manifest.get("keep_os_junk"):
        return False
    lex = effective_junk_lexicon(manifest) if isinstance(manifest, dict) else JUNK_LEXICON_CURRENT
    return is_os_junk(rel_path, lex)


def junk_row_never_archived(f: dict, src: pathlib.Path, manifest: dict) -> bool:
    """Whether a `files[]` row is a legacy listed-but-never-archived junk entry, to be SKIPPED.

    Junk-under-their-own-era writers could LIST a junk path in `files[]` without ever archiving
    bytes for it; the engine's reader skips exactly those rows (junk under the PACK's lexicon, on
    a non-exact-clone package), and attempting to rebuild one here would fail the recovery on
    content the package never contained. CONSERVATIVE by design — a row is skipped only when ALL
    of these hold:
      * the pack is not exact-clone (`keep_os_junk` false/absent);
      * the path is junk under the PACK's OWN era (`effective_junk_lexicon`), never the current
        writer's wider set;
      * the entry genuinely has NO encoded artifact: no dedup/chunk/essence/residual/ICR
        mechanism, no stored wrapper/trailer blob, and no `encoded_path` that exists in the
        extracted tree.
    A junk-named row whose bytes DO exist is rebuilt like any other file — never skipped: the
    failure mode of skipping too much is silently dropping bytes someone archived on purpose.
    """
    if manifest.get("keep_os_junk"):
        return False
    rel = f.get("original_path") or ""
    if not is_os_junk(rel, effective_junk_lexicon(manifest)):
        return False
    if any(f.get(k) for k in ("dedup_of", "chunk_refs", "essence_streams",
                              "residual_refs", "inter_channel_ref",
                              "wrapper_sha256", "trailer_sha256")):
        return False
    ep = f.get("encoded_path")
    if ep:
        try:
            if safe_join(src, ep, "encoded_path").is_file():
                return False
        except EntryError:
            return False  # a hostile identifier is an entry problem to report, not a junk skip
    return True


_SCRATCH: list = []
_DECODES = [0]


def scratch_dir() -> pathlib.Path:
    """Private temp dir for decoder output — honours TMPDIR, and the EXTRACTED TREE MAY BE
    READ-ONLY (recovering straight off a mounted backup or a read-only archive volume is a
    realistic scenario, and writing scratch beside the encoded artifact would both fail there and
    risk clobbering a sibling file that happens to share the name)."""
    if not _SCRATCH:
        _SCRATCH.append(pathlib.Path(tempfile.mkdtemp(prefix="crate-recovery-")))
    return _SCRATCH[0]


def cleanup_scratch() -> None:
    """Remove the scratch dir on EVERY exit path (success, failure, refusal, Ctrl-C)."""
    while _SCRATCH:
        shutil.rmtree(_SCRATCH.pop(), ignore_errors=True)


def safe_join(root: pathlib.Path, rel, what: str = "path") -> pathlib.Path:
    """Join a manifest-supplied relative path under `root`, refusing any escape.

    Applies to READS as much as writes. `original_path`, `encoded_path`, the wrapper/skeleton
    SHA filenames and the per-stream paths all come out of a file someone sent you, and the two
    escape shapes are equally cheap to write into a hostile manifest:

        Path('/restore') / '../escape'        -> /restore/../escape      (climbs out)
        Path('/restore') / '/absolute/escape' -> /absolute/escape        (leaves entirely)

    Absolute paths, `..` components and empty identifiers are rejected outright; the result is
    then resolved and re-checked, so a symlink planted inside the extracted tree cannot be used
    as a second way out.
    """
    p = pathlib.PurePosixPath(str(rel).replace("\\", "/"))
    if not p.parts or p.is_absolute() or any(part == ".." for part in p.parts):
        raise EntryError(f"unsafe {what} in manifest: {rel!r}")
    out = root.joinpath(*p.parts)
    real_root = os.path.realpath(root)
    real_out = os.path.realpath(out)
    if real_out != real_root and not real_out.startswith(real_root + os.sep):
        raise EntryError(f"unsafe {what} in manifest (escapes via link): {rel!r}")
    return out


def quarantine(path: pathlib.Path) -> str:
    """Move wrong bytes aside, exactly as the Crate app's restore does.

    `<name>.UNVERIFIED`, probing ` (2)`, ` (3)`… when that name is already taken (a leftover from
    a previous run is the likeliest blocker). If even the rename fails the file is DELETED rather
    than left at its real path — never claim "quarantined" when it isn't.
    """
    base = pathlib.Path(str(path) + ".UNVERIFIED")
    cand, n = base, 2
    while cand.exists() and n <= 99:
        cand = pathlib.Path(f"{base} ({n})")
        n += 1
    try:
        os.rename(path, cand)
        return cand.name
    except OSError:
        try:
            path.unlink()
            return "deleted (quarantine rename failed)"
        except OSError:
            return "STILL AT ITS REAL PATH — DO NOT USE"


def decode_stream(path: pathlib.Path, codec: str, endian: str, signed: bool) -> bytes:
    """Decode a flac-raw/wavpack-raw stream to raw PCM bytes with the standard CLI tools.

    Two non-obvious rules, both load-bearing:

    * The scratch file's `.pcm` extension is chosen ON PURPOSE. `wvunpack --raw` keeps the
      `-o` name only when its extension is short (≤4 chars); anything longer makes it APPEND
      `.raw`, so an output named `x.rawpcm` is silently written as `x.rawpcm.raw`. Reading the
      requested path then raises FileNotFoundError and EVERY WavPack entry — i.e. every 32-bit
      float file, ~15% of real session audio — becomes unrecoverable. Both spellings are
      resolved below so this never depends on the tool's naming behaviour again.
    * `endian`/`signed` are deliberately NOT passed to wvunpack. Crate encodes the raw region
      with `--raw-pcm=<rate>,<bits><t><ch>,le` regardless of the file's true endianness
      (crate-core `codec::raw_pcm_spec`), so a WavPack-raw stream is a byte-transparent
      container: the bytes that went in come back out in the same order, big-endian sources
      included. `flac-raw` is the opposite — FLAC honours real endianness, so the flags matter
      there and must match what the manifest records.
    """
    _DECODES[0] += 1
    out = scratch_dir() / f"stream{_DECODES[0]}.pcm"
    try:
        if codec.startswith("flac"):
            subprocess.run(
                ["flac", "-d", "--force-raw-format",
                 "--endian=" + ("little" if endian != "be" else "big"),
                 "--sign=" + ("signed" if signed else "unsigned"),
                 "-f", "-o", str(out), str(path)],
                check=True, capture_output=True)
        else:  # wavpack-raw
            subprocess.run(["wvunpack", "-r", "-y", "-q", "-o", str(out), str(path)],
                           check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        err = (e.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        raise EntryError(f"{codec} decode of {path.name} failed: {err[-1] if err else e}")
    for cand in (out, out.with_name(out.name + ".raw")):
        if cand.exists():
            data = cand.read_bytes()
            cand.unlink()
            return data
    raise EntryError(f"{path}: {codec} decoder produced no raw PCM output")


def sample_width(bits) -> int:
    """Bytes per sample, refusing a bit depth the integer transforms cannot be done at.

    `bit_depth` is manifest-supplied, so 0, null, negative and absurd values all arrive here.
    A 0 would make `1 << (bits - 1)` a negative shift (ValueError deep inside the arithmetic);
    silently defaulting it to 16 would be worse still — it would produce plausible wrong bytes.
    """
    if not isinstance(bits, int) or isinstance(bits, bool) or not 1 <= bits <= 64:
        raise EntryError(f"unusable bit_depth {bits!r} for an integer transform")
    return max(1, (bits + 7) // 8)


def parse_samples(pcm: bytes, bits: int, endian: str, signed: bool):
    """Interleaved PCM bytes -> list of ints (sign-extended). See `split_tail` for the remainder."""
    bps = sample_width(bits)
    little = endian != "be"
    n = len(pcm) // bps
    out = []
    for i in range(n):
        chunk = pcm[i * bps:(i + 1) * bps]
        v = int.from_bytes(chunk, "little" if little else "big", signed=False)
        if signed:
            if v >= 1 << (bits - 1):
                v -= 1 << bits
        else:
            v -= 1 << (bits - 1)
        out.append(v)
    return out


def split_tail(pcm: bytes, bits: int):
    """Whole samples, and the incomplete trailing bytes that are NOT part of any sample.

    A stream whose length is not a multiple of the sample width would otherwise lose its last
    1-3 bytes on the parse/encode round trip: `parse_samples` drops them and `encode_samples`
    cannot invent them back. Carrying the remainder through verbatim keeps the transform an
    exact inverse for every input length.
    """
    bps = sample_width(bits)
    cut = len(pcm) - len(pcm) % bps
    return pcm[:cut], pcm[cut:]


def encode_samples(samples, bits: int, endian: str, signed: bool) -> bytes:
    """Ints -> interleaved PCM bytes, wrapping modulo 2^bits (exact inverse of parse_samples)."""
    bps = sample_width(bits)
    little = endian != "be"
    mask = (1 << bits) - 1
    out = bytearray()
    for s in samples:
        u = (s if signed else s + (1 << (bits - 1))) & mask
        out += u.to_bytes(bps, "little" if little else "big", signed=False)
    return bytes(out)


def load_manifest(src: pathlib.Path) -> dict:
    """Read + sanity-check the manifest. Every problem here is a WHOLE-PACKAGE refusal."""
    mp = src / ".crate" / "manifest.json"
    if not mp.is_file():
        raise Refused(f"no manifest at {mp} — is this an extracted .crate?")
    try:
        m = json.loads(mp.read_bytes().decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise Refused(f"manifest.json is not valid JSON ({e}) — refusing to guess at the format")
    if not isinstance(m, dict) or not isinstance(m.get("files"), list):
        raise Refused("manifest.json has no files[] array — not a Crate manifest")
    ver = str(m.get("crate_manifest_version", "1.0"))
    head = ver.split(".")[0]
    if not head.isdigit():
        raise Refused(f"unparseable crate_manifest_version {ver!r}")
    if int(head) > MAX_MANIFEST_MAJOR:
        raise Refused(
            f"manifest version {ver} is newer than this escrow implements (max major "
            f"{MAX_MANIFEST_MAJOR}) — refusing rather than rebuilding files that would be wrong")
    feats = m.get("required_features") or []
    if not isinstance(feats, list):
        raise Refused(f"required_features is not a list: {feats!r}")
    unknown = sorted({str(x) for x in feats} - KNOWN_FEATURES)
    if unknown:
        raise Refused(f"package requires features this escrow does not implement: {unknown}")
    return m


def check_exclusive(f: dict) -> None:
    """Sub-file mechanisms are mutually exclusive (RECOVERY.md §2.2 invariant 5).

    An entry carrying two of them is a manifest that cannot mean one thing, and the old
    if/elif ladder would have silently honoured whichever branch came first — rebuilding a
    residual file as a dedup copy, say, and only the final SHA would (maybe) notice.
    """
    mech = [k for k in ("dedup_of", "chunk_refs", "residual_refs", "inter_channel_ref")
            if f.get(k)]
    if f.get("codec_used") == "essence-streams":
        clash = mech + [k for k in ("wrapper_sha256", "trailer_sha256") if f.get(k)]
        if clash:
            raise EntryError(f"essence entry also carries {clash} — mutually exclusive")
    if "dedup_of" in mech and len(mech) > 1:
        raise EntryError(f"dedup entry also carries {[k for k in mech if k != 'dedup_of']}")
    if "chunk_refs" in mech and len(mech) > 1:
        raise EntryError(f"chunked entry also carries {[k for k in mech if k != 'chunk_refs']}")


def chunk_audio(f: dict, blob_pcm: dict, blob_err: dict) -> bytes:
    """Sub-file CDC dedup: concatenate this file's slices of the shared blobs, checked."""
    refs = f["chunk_refs"]
    if not isinstance(refs, list) or not refs:
        raise EntryError("chunk_refs is empty — nothing to concatenate")
    parts = []
    for r in refs:
        bid = r.get("blob")
        if bid in blob_err:
            raise EntryError(f"chunk blob {bid!r} did not decode: {blob_err[bid]}")
        if bid not in blob_pcm:
            raise EntryError(f"chunk_refs names blob {bid!r}, which the manifest does not define")
        off, ln = r.get("offset"), r.get("len")
        if not isinstance(off, int) or not isinstance(ln, int) or off < 0 or ln <= 0:
            raise EntryError(f"bad chunk ref offset/len: {off!r}/{ln!r}")
        pcm = blob_pcm[bid]
        if off + ln > len(pcm):
            raise EntryError(
                f"chunk ref {off}+{ln} overruns blob {bid!r} ({len(pcm)} bytes) — truncated blob?")
        parts.append(pcm[off:off + ln])
    return b"".join(parts)


def essence_bytes(f: dict, src: pathlib.Path, wrapper) -> bytes:
    """Multi-range container split (AAF/OMF): skeleton + per-stream PCM runs, spliced back.

    Every geometric invariant in RECOVERY.md is a hard failure here — a violated one means the
    splice would silently pad, truncate or transpose bytes, and only the final SHA would catch
    it (and only sometimes, since a wrong-but-plausible file still hashes to *something*).
    """
    skel = wrapper(f.get("skeleton_sha256"), "skeleton_sha256")
    streams = f.get("essence_streams")
    if not isinstance(streams, list) or not streams:
        raise EntryError("essence entry has no essence_streams")
    allruns = []
    for s in streams:
        runs = s.get("runs")
        if not isinstance(runs, list) or not runs:
            raise EntryError("essence stream has no runs")
        for r in runs:
            if not (isinstance(r, (list, tuple)) and len(r) == 3
                    and all(isinstance(x, int) and not isinstance(x, bool) for x in r)):
                raise EntryError(f"malformed essence run {r!r} (want [file_offset, len, pcm_offset])")
            if r[0] < 0 or r[1] <= 0 or r[2] < 0:
                raise EntryError(f"bad essence run geometry {list(r)}")
            allruns.append(tuple(r))
    allruns.sort(key=lambda r: r[0])
    for a, b in zip(allruns, allruns[1:]):
        if a[0] + a[1] > b[0]:
            raise EntryError(f"essence runs overlap: {list(a)} vs {list(b)}")
    total = sum(r[1] for r in allruns)
    size = f.get("original_bytes")
    if isinstance(size, int) and len(skel) + total != size:
        raise EntryError(
            f"skeleton {len(skel)} + essence {total} != original_bytes {size} — geometry is wrong")
    slices = {}
    for s in streams:
        pcm = decode_stream(safe_join(src, s["encoded_path"], "stream encoded_path"),
                            s.get("codec_used", "flac-raw"),
                            s.get("raw_endian", "le"), s.get("raw_signed", True))
        want = sum(r[1] for r in s["runs"])
        if len(pcm) != want:
            raise EntryError(f"decoded stream is {len(pcm)} bytes, runs need {want}")
        # The pcm_offsets must TILE [0, want) exactly: no gap (bytes that decoded but are never
        # written) and no reuse (one PCM region claimed by two file offsets).
        covered = sorted((r[2], r[1]) for r in s["runs"])
        at = 0
        for poff, ln in covered:
            if poff != at:
                raise EntryError(f"essence pcm_offsets do not tile: expected {at}, got {poff}")
            at += ln
        if at != want:
            raise EntryError(f"essence pcm_offsets cover {at} of {want} bytes")
        for off, ln, poff in s["runs"]:
            slices[off] = pcm[poff:poff + ln]
    out, sp, prev = bytearray(), 0, 0
    for off, ln, _ in allruns:
        gap = off - prev
        if sp + gap > len(skel):
            raise EntryError(f"skeleton is too short for the run map at file offset {off}")
        out += skel[sp:sp + gap]
        sp += gap
        out += slices[off]
        prev = off + ln
    out += skel[sp:]
    return bytes(out)


def main(src: pathlib.Path, dst: pathlib.Path) -> int:
    m = load_manifest(src)
    wrappers = src / ".crate" / "wrappers"
    dst.mkdir(parents=True, exist_ok=True)

    def wrapper(sha, what="wrapper_sha256"):
        if not sha:
            return b""
        p = safe_join(wrappers, sha, what)
        if not p.is_file():
            raise EntryError(f"{what} {sha!r} is not in .crate/wrappers/")
        return p.read_bytes()

    # Decode shared chunk blobs once. A blob that will not decode does NOT abort the run: it is
    # recorded, and only the entries that actually reference it fail.
    blob_pcm, blob_err = {}, {}
    for b in m.get("chunk_blobs", []):
        bid = b.get("id")
        if bid in blob_pcm or bid in blob_err:
            raise Refused(f"duplicate chunk blob id {bid!r} — the slice map is ambiguous")
        try:
            blob_pcm[bid] = decode_stream(
                safe_join(src, b["encoded_path"], "blob encoded_path"),
                b.get("codec", "flac-raw"), b.get("endian", "le"), b.get("signed", True))
        except Exception as e:
            blob_err[bid] = str(e)

    # Rebuild in dependency order: plain first, then residuals (need anchors), then dedup copies.
    # A file only counts as a usable source for a dedup copy or a residual anchor once it has
    # PASSED its own SHA check — the app's restore marks a quarantined file non-canonical for
    # exactly this reason, so one bad decode can never seed a second wrong file.
    verified_sha = {}
    failed = []
    entries = []
    for i, f in enumerate(m["files"]):
        if isinstance(f, dict) and isinstance(f.get("original_path"), str) and f["original_path"]:
            entries.append(f)
        else:
            failed.append((f"files[{i}]", "entry has no usable original_path"))
            print(f"  FAIL files[{i}]: entry has no usable original_path")
    by_path = {f["original_path"]: f for f in entries}
    order = ([f for f in entries if not f.get("residual_refs") and not f.get("dedup_of")]
             + [f for f in entries if f.get("residual_refs")]
             + [f for f in entries if f.get("dedup_of")])
    skipped = []
    for f in order:
        rel = f.get("original_path")
        codec = f.get("codec_used", "none")
        # Legacy junk-under-its-own-era rows that were listed but never archived are skipped the
        # same way the engine's reader skips them — see `junk_row_never_archived` for the
        # deliberately conservative conditions (never skips a row whose bytes exist).
        if junk_row_never_archived(f, src, m):
            skipped.append(rel)
            print(f"  SKIP {rel}: OS junk the packer excluded (listed, never archived) — "
                  "the OS regenerates it")
            continue
        try:
            check_exclusive(f)
            out_path = safe_join(dst, rel, "original_path")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            # NOT defaulted. `bit_depth` only matters to the residual/ICR arithmetic, and a
            # missing or zero one there used to fall back to 16 — which silently produces
            # plausible WRONG audio for any other depth. `sample_width` refuses it instead.
            bits = f.get("bit_depth")
            endian = f.get("raw_endian") or "le"
            signed = f.get("raw_signed", True)

            if f.get("dedup_of"):
                # Byte-identical duplicate of the canonical with the same content sha.
                canon = [p for p, sha in verified_sha.items() if sha == f["dedup_of"]]
                if not canon:
                    raise EntryError(
                        f"dedup_of {f['dedup_of'][:12]}… has no verified canonical to copy")
                shutil.copyfile(safe_join(dst, canon[0], "dedup canonical"), out_path)
            elif codec == "none":
                shutil.copyfile(safe_join(src, f["encoded_path"], "encoded_path"), out_path)
            elif f.get("chunk_refs") is not None:
                # Presence, not truthiness: a chunked entry whose `chunk_refs` is an EMPTY list
                # used to fall through to the plain codec branch and try to decode an
                # `encoded_path` that a chunked entry does not have — failing for a reason that
                # says nothing about the actual defect.
                audio = chunk_audio(f, blob_pcm, blob_err)
                out_path.write_bytes(wrapper(f.get("wrapper_sha256")) + audio
                                     + wrapper(f.get("trailer_sha256"), "trailer_sha256"))
            elif codec == "essence-streams":
                out_path.write_bytes(essence_bytes(f, src, wrapper))
            elif codec in ("flac-raw", "wavpack-raw"):
                audio = decode_stream(safe_join(src, f["encoded_path"], "encoded_path"),
                                      codec, endian, signed)
                if f.get("residual_refs"):
                    body, tail = split_tail(audio, bits)
                    acc = parse_samples(body, bits, endian, signed)
                    anchors = (f["residual_refs"] or {}).get("anchors") or []
                    if not anchors:
                        raise EntryError("residual_refs carries no anchors")
                    for anchor_rel in anchors:
                        a = by_path.get(anchor_rel)
                        if a is None:
                            raise EntryError(f"residual anchor {anchor_rel!r} is not in the manifest")
                        if anchor_rel == rel or a.get("residual_refs"):
                            raise EntryError(
                                f"residual anchor {anchor_rel!r} is itself a residual — unorderable")
                        if anchor_rel not in verified_sha:
                            raise EntryError(
                                f"residual anchor {anchor_rel!r} was not rebuilt+verified")
                        araw = safe_join(dst, anchor_rel, "anchor path").read_bytes()
                        # anchor's audio region = anchor bytes minus its own wrappers
                        pre = len(wrapper(a.get("wrapper_sha256")))
                        post = len(wrapper(a.get("trailer_sha256"), "trailer_sha256"))
                        aud = araw[pre:len(araw) - post if post else len(araw)]
                        asamples = parse_samples(split_tail(aud, bits)[0], bits, endian, signed)
                        if len(asamples) != len(acc):
                            raise EntryError(
                                f"residual anchor {anchor_rel!r} has {len(asamples)} samples, "
                                f"the residual has {len(acc)} — the sum cannot be reconstructed")
                        for i, x in enumerate(asamples):
                            acc[i] += x
                    audio = encode_samples(acc, bits, endian, signed) + tail
                ic = f.get("inter_channel_ref")
                if ic:
                    ks = ic.get("ks")
                    bf, shift = ic.get("block_frames"), ic.get("shift")
                    anchor = ic.get("anchor")
                    if not isinstance(ks, list) or not ks:
                        raise EntryError(f"inter_channel_ref has no coefficients: {ic!r}")
                    if not isinstance(bf, int) or bf <= 0 or not isinstance(shift, int) \
                            or not 1 <= shift <= 62 or anchor not in (0, 1):
                        raise EntryError(f"bad inter_channel_ref parameters: {ic!r}")
                    body, tail = split_tail(audio, bits)
                    s = parse_samples(body, bits, endian, signed)
                    a_off, b_off = anchor, 1 - anchor
                    bias = 1 << (shift - 1)
                    for i in range(len(s) // 2):
                        # Blocks past the last coefficient CLAMP to it — the pack side emits one
                        # k per block but a final short block shares the previous one.
                        k = ks[min(i // bf, len(ks) - 1)]
                        pred = (k * s[2 * i + a_off] + bias) >> shift
                        s[2 * i + b_off] += pred
                    audio = encode_samples(s, bits, endian, signed) + tail
                out_path.write_bytes(wrapper(f.get("wrapper_sha256")) + audio
                                     + wrapper(f.get("trailer_sha256"), "trailer_sha256"))
            elif codec in ("flac", "wavpack"):
                enc = safe_join(src, f["encoded_path"], "encoded_path")
                _DECODES[0] += 1
                tmp = scratch_dir() / f"whole{_DECODES[0]}.tmp"
                if codec == "flac":
                    # `--keep-foreign-metadata-if-present` is NOT optional: Crate's own whole-file
                    # decoder passes it (crate-core `codec::flac_decode`), and without it every
                    # foreign WAVE/AIFF chunk the original carried (bext, iXML, cue, LIST/INFO…)
                    # is dropped — measured 19336 -> 19244 bytes on a one-chunk test file, a
                    # different SHA, i.e. NOT byte-exact. A handful of legacy WAVs make flac
                    # refuse that flag outright ("legacy WAVE file has format type 1 but
                    # bits-per-sample=24"); those retry without it and the SHA check below is
                    # still the only thing trusted to bless the result.
                    base = ["flac", "-d", "-f", "-o", str(tmp), str(enc)]
                    r = subprocess.run(base[:2] + ["--keep-foreign-metadata-if-present"] + base[2:],
                                       capture_output=True)
                    if r.returncode != 0:
                        r = subprocess.run(base, capture_output=True)
                    if r.returncode != 0:
                        err = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
                        raise EntryError(f"flac -d failed: {err[-1] if err else r.returncode}")
                    cands = (tmp,)
                else:
                    # Same trap as decode_stream: wvunpack rewrites any `-o` name whose extension
                    # is longer than four characters (`Master_mix` -> `Master_mix.wav`,
                    # `Take.stereo` -> `Take.stereo.wav`), and the original filename is whatever
                    # the sender chose. So decode to a short-extension scratch name we control,
                    # then move it into place.
                    r = subprocess.run(["wvunpack", "-y", "-q", "-o", str(tmp), str(enc)],
                                       capture_output=True)
                    if r.returncode != 0:
                        err = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
                        raise EntryError(f"wvunpack failed: {err[-1] if err else r.returncode}")
                    cands = (tmp, tmp.with_name(tmp.name + ".wav"))
                got_tmp = next((c for c in cands if c.exists()), None)
                if got_tmp is None:
                    raise EntryError(f"{codec} produced no output")
                shutil.move(str(got_tmp), str(out_path))
            else:
                raise EntryError(f"unknown codec {codec!r} — this escrow cannot rebuild it")
        except Refused:
            raise
        except Exception as e:
            # Deliberately broad: ONE unrebuildable entry must never destroy the rest of a
            # recovery (the same rule the app's restore follows). Whole-package problems raise
            # `Refused` above and are re-raised untouched.
            msg = f"missing manifest field {e}" if isinstance(e, KeyError) else e
            print(f"  FAIL {rel}: {msg}")
            failed.append((rel, str(msg)))
            continue

        got = hashlib.sha256(out_path.read_bytes()).hexdigest()
        if got == f.get("sha256_original"):
            verified_sha[rel] = got
            print(f"  OK   {rel}")
        else:
            where = quarantine(out_path)
            print(f"  FAIL {rel}: SHA-256 mismatch — quarantined as {where}")
            failed.append((rel, f"content did not match sha256_original — {where}"))

    # Symlinks (manifest `symlinks[]`, same list the app's restore walks): the packer records
    # each link's location relative to the session root and its LITERAL target — stored as-is,
    # never resolved. Recreating a link writes nothing through it, so a target naming a path
    # outside the tree is harmless: it recreates the same string the sender's filesystem had.
    # The location, by contrast, is untrusted input and goes through the same confinement as
    # every write path (bad -> Refused, the whole package refused, matching the file rules).
    links_made = 0
    for s in m.get("symlinks", []):
        rel = s.get("path") if isinstance(s, dict) else None
        if not rel:
            print("  FAIL symlink entry with no path")
            failed.append(("symlinks[]", "entry has no path"))
            continue
        try:
            link_path = safe_join(dst, rel, "symlink path")
            # The link's parent may hold no real file (an otherwise-empty folder, which the
            # escrow otherwise never creates) — os.symlink refuses to a missing parent, so
            # make it, exactly as the file loop makes its own parents.
            link_path.parent.mkdir(parents=True, exist_ok=True)
            if link_path.is_symlink() or link_path.exists():
                raise EntryError("a rebuilt file already occupies the link's path")
            target = s.get("target", "")
            if not isinstance(target, str):
                raise EntryError(f"symlink target is not a string: {target!r}")
            link_path.symlink_to(target)
            links_made += 1
            print(f"  LINK {rel} -> {target}")
        except Refused:
            raise
        except Exception as e:
            # Deliberately broad, same rule as files: one uncreatable link never aborts the
            # rest (e.g. a platform or mount that forbids symlinks). It is reported and counted.
            print(f"  FAIL symlink {rel}: {e}")
            failed.append((rel, f"symlink could not be recreated: {e}"))

    total = len(m["files"])
    if skipped:
        print(f"{len(skipped)} OS-junk entr{'y' if len(skipped) == 1 else 'ies'} the packer "
              "excluded (listed, never archived) skipped — the OS regenerates them.")
    if links_made:
        print(f"{links_made} symlink{'s' if links_made != 1 else ''} recreated verbatim.")
    print(f"{len(verified_sha)} of {total} files rebuilt byte-exactly"
          + ("." if not failed else f"; {len(failed)} FAILED — DO NOT USE:"))
    for rel, why in failed:
        print(f"    {rel}: {why}")
    if failed:
        print("Failed content is never left at its real path: a hash mismatch is renamed "
              "'<name>.UNVERIFIED', and an entry that could not be rebuilt at all wrote nothing.")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    try:
        sys.exit(main(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])))
    except Refused as e:
        print(f"REFUSED: {e}")
        sys.exit(2)
    finally:
        cleanup_scratch()
