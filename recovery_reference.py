#!/usr/bin/env python3
"""Reference .crate recovery — rebuilds every file byte-exactly WITHOUT Crate software.

Public domain. Requires only Python 3 and the standard `flac` and `wvunpack` command-line tools.
`wvunpack` is not optional: WavPack carries 32-bit float audio, any integer audio past FLAC's
8-channel cap, and everything in a `--codec wavpack-only` pack. See FORMAT.md (this repository) for the
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

On volumes without hard links or atomic exclusive file rename (including macOS ExFAT),
choose a NEW restored directory. Recovery builds a private tree on that volume and publishes
it only after every entry has a verdict. A partial salvage still exits 1 and keeps bad hashes
under .UNVERIFIED names; interruption exposes no half-built restored tree. Existing output
names are preserved. Native volumes retain per-file publication and existing-directory salvage.

Everything the manifest says is treated as UNTRUSTED input — it came out of a file someone sent
you. Every path built from it, for READING as well as writing, is confined under the directory it
belongs to; an absolute path, a `..` component or a symlink pointing out of the tree is refused.
"""
import ctypes
import errno
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata

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


# Mirrors the engine's current junk lexicon constant. `is_os_junk` is era-versioned there:
#   1 — macOS-only set, shipped through v1.6.1.
#   2 — the v1.7.0 cross-platform widening, EXACTLY as shipped (bare `.Trash-` / `.fuse_hidden` /
#       `.nfs` prefix matches included).
#   3 — lexicon 2 with those prefixes tightened to their machine-generated shapes
#       (`.Trash-<digits>`, `.fuse_hidden<hex>`, `.nfs<hex>`).
JUNK_LEXICON_CURRENT = 3


def is_os_junk(rel_path: str, lexicon: int = JUNK_LEXICON_CURRENT) -> bool:
    """Whether Crate's pack step strips this path as OS-generated junk, under `lexicon`.

    Mirrors the engine's junk predicate EXACTLY. The set is era-versioned because a
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
    # Manifest paths use '/' on every writer platform. A literal POSIX backslash
    # must not become a junk-directory boundary when recovering on Windows.
    parts = [p for p in rel_path.split("/") if p]
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
    """Leading-digits parse of the first two dotted components (mirrors the engine
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
    """The junk lexicon this package was WRITTEN under (mirrors the engine
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


def manifest_path_parts(rel, what: str = "path", *, windows=None):
    """Parse a manifest name without changing its meaning on the target platform.

    Manifest separators are always '/'. A backslash in a POSIX filename is a
    literal character; Windows cannot recreate that name, so refuse the entry
    instead of restoring it under a different name and claiming success.
    """
    if windows is None:
        windows = os.name == "nt"
    name = str(rel)
    if windows and "\\" in name:
        raise EntryError(f"unsafe {what} in manifest: {rel!r}")
    path_type = pathlib.PureWindowsPath if windows else pathlib.PurePosixPath
    path = path_type(name)
    if (not path.parts or path.anchor or any(part == ".." for part in path.parts)
            or any(path_type(part).anchor for part in path.parts)):
        raise EntryError(f"unsafe {what} in manifest: {rel!r}")
    return path.parts


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
    out = root.joinpath(*manifest_path_parts(rel, what))
    real_root = os.path.realpath(root)
    real_out = os.path.realpath(out)
    if real_out != real_root and not real_out.startswith(real_root + os.sep):
        raise EntryError(f"unsafe {what} in manifest (escapes via link): {rel!r}")
    return out


def preflight_destination_namespace(dst: pathlib.Path, entries: list, links: list,
                                    src: pathlib.Path, manifest: dict) -> None:
    """Prove output names remain distinct on this volume before publishing bytes.

    Case and Unicode alias rules vary by filesystem. Build empty placeholders in
    a private directory on the destination volume, then check the actual output
    parents by inode as well. A collision must never produce a successful but
    differently shaped recovery tree.
    """
    outputs = []
    for entry in entries:
        rel = entry["original_path"]
        try:
            parts = manifest_path_parts(rel, "original_path")
        except EntryError:
            continue  # The existing per-file path reports this as a failed entry.
        if not junk_row_never_archived(entry, src, manifest):
            outputs.append((rel, parts))
    for link in links:
        rel = link.get("path") if isinstance(link, dict) else None
        if not isinstance(rel, str) or not rel:
            continue  # The existing per-link path reports this as a failed entry.
        try:
            outputs.append((rel, manifest_path_parts(rel, "symlink path")))
        except EntryError:
            continue

    # Detect likely aliases lexically, while letting the destination filesystem
    # decide whether two spellings can actually coexist (as on case-sensitive APFS).
    def key_for_parts(parts):
        return tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)

    folded, possible_aliases = {}, set()
    for rel, parts in outputs:
        for depth in range(1, len(parts) + 1):
            prefix = parts[:depth]
            key = key_for_parts(prefix)
            previous = folded.setdefault(key, prefix)
            if previous != prefix:
                possible_aliases.add(key)

    with tempfile.TemporaryDirectory(prefix=".crate-name-check-", dir=dst) as probe_name:
        probe = pathlib.Path(probe_name)
        directories = set()
        for rel, parts in outputs:
            for depth in range(1, len(parts)):
                prefix = parts[:depth]
                if prefix in directories:
                    continue
                try:
                    probe.joinpath(*prefix).mkdir()
                except FileExistsError as error:
                    kind = "case/Unicode" if key_for_parts(prefix) in possible_aliases else "filesystem"
                    raise Refused(f"destination {kind} aliases a manifest directory: {rel!r}") from error
                except OSError as error:
                    raise Refused(f"cannot preflight destination directory {rel!r}: {error}") from error
                directories.add(prefix)
            try:
                with probe.joinpath(*parts).open("xb"):
                    pass
            except FileExistsError as error:
                kind = "case/Unicode" if key_for_parts(parts) in possible_aliases else "filesystem"
                raise Refused(f"destination {kind} aliases manifest output names: {rel!r}") from error
            except OSError as error:
                raise Refused(f"cannot preflight destination name {rel!r}: {error}") from error

    # A pre-existing in-tree symlink may make two differently spelled parents
    # point to one directory even if the volume itself supports both names.
    identities = {}
    for rel, parts in outputs:
        safe_join(dst, rel, "output path")
        for depth in range(1, len(parts)):
            prefix = parts[:depth]
            directory = dst.joinpath(*prefix)
            try:
                directory.mkdir(exist_ok=True)
                stat = directory.stat()
            except OSError as error:
                raise Refused(f"cannot preflight output directory {rel!r}: {error}") from error
            identity = (stat.st_dev, stat.st_ino)
            other = identities.setdefault(identity, prefix)
            if other != prefix:
                raise Refused(f"destination directories alias: {'/'.join(other)!r} and {'/'.join(prefix)!r}")


# These bounds apply to file data; the manifest and its reference lists remain metadata.
COPY_BYTES = 1024 * 1024
PCM_WINDOW = 64 * 1024
DISK_RESERVE = 16 * 1024 * 1024


def checked_size(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= sys.maxsize:
        raise EntryError(f"invalid {what}: {value!r}")
    return value


def require_space(directory, count=0):
    if shutil.disk_usage(directory).free < count + DISK_RESERVE:
        raise EntryError("insufficient free space for private recovery scratch")


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(COPY_BYTES), b""):
            digest.update(block)
    return digest.hexdigest()


def copy_region(path, output, offset=0, length=None):
    """Copy exactly one bounded file range, refusing truncation and disk exhaustion."""
    size = path.stat().st_size
    if length is None:
        length = size - offset
    if offset < 0 or length < 0 or offset + length > size:
        raise EntryError(f"file range exceeds {path.name}")
    with path.open("rb") as source:
        source.seek(offset)
        remaining = length
        while remaining:
            block = source.read(min(COPY_BYTES, remaining))
            if not block:
                raise EntryError(f"{path.name} shortened during recovery")
            require_space(pathlib.Path(output.name).parent, len(block))
            output.write(block)
            remaining -= len(block)
    if path.stat().st_size != size:
        raise EntryError(f"{path.name} changed size during recovery")


def rename_exclusive(temporary, destination):
    """Native atomic no-replace rename for filesystems that cannot create hard links."""
    if sys.platform == "win32":
        # Windows rename is documented to raise FileExistsError instead of replacing.
        os.rename(temporary, destination)
        return
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(library, "renamex_np"):
        rename = library.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(temporary), os.fsencode(destination), 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        rename = library.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(temporary), -100, os.fsencode(destination), 1)  # AT_FDCWD, RENAME_NOREPLACE
    else:
        raise EntryError("this filesystem/platform has no atomic no-replace publication")
    if result:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def publish_verified(temporary, destination):
    """Atomically expose complete bytes without replacing any existing destination."""
    try:
        os.link(temporary, destination)
    except FileExistsError:
        raise
    except OSError:
        rename_exclusive(temporary, destination)
    else:
        temporary.unlink()



def publication_needs_private_tree(parent):
    """Probe actual same-volume publication support without exposing recovered files."""
    unsupported = {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EINVAL}
    with tempfile.TemporaryDirectory(prefix=".crate-publish-probe-", dir=parent) as name:
        probe = pathlib.Path(name)
        source, destination = probe / "source", probe / "destination"
        source.write_bytes(b"publication probe")
        try:
            os.link(source, destination)
            return False
        except OSError as error:
            if error.errno not in unsupported:
                raise Refused(f"cannot probe destination hard links: {error}") from error
        try:
            rename_exclusive(source, destination)
            return False
        except OSError as error:
            if error.errno not in unsupported:
                raise Refused(f"cannot probe destination rename: {error}") from error
        return True


def publish_private_file(temporary, destination):
    """Place verified bytes in an unpublished tree without relying on hard links.

    Exclusive creation preserves any occupied name. Bounded copying can leave a
    partial file only inside the private tree; any failure removes that file.
    The complete tree is published only after recovery has returned a verdict.
    """
    created = False
    try:
        with destination.open("xb") as output:
            created = True
            copy_region(temporary, output)
            output.flush()
            os.fsync(output.fileno())
        if file_sha256(destination) != file_sha256(temporary):
            raise EntryError("private publication copy failed SHA-256 verification")
        temporary.unlink()
    except BaseException:
        if created:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass  # An already-removed partial output is safe to leave absent.
            except OSError as error:
                # The private tree may now contain truncated bytes at the intended
                # name. Never publish that tree, even as a partial recovery.
                raise Refused(f"cannot remove incomplete private output {destination}: {error}") from error
        raise


def publish_private_tree(tree, destination):
    """Atomically move a finished same-volume tree over our own empty reservation.

    POSIX directory rename cannot replace a nonempty directory, file, or symlink.
    The exclusive mkdir claims an absent name; identity and emptiness are checked
    immediately before rename. As with private scratch, the parent must not be
    concurrently modified by an untrusted process with the same filesystem access.
    """
    try:
        destination.mkdir()
    except FileExistsError as error:
        raise Refused("destination already exists — preserving its contents") from error
    identity = destination.lstat()
    try:
        current = destination.lstat()
        if (not stat.S_ISDIR(current.st_mode)
                or (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino)
                or any(destination.iterdir())):
            raise Refused("destination reservation changed before publication")
        os.rename(tree, destination)
    except BaseException:
        # Never recursively remove a reservation that another process populated.
        try:
            current = destination.lstat()
            if ((identity.st_dev, identity.st_ino) == (current.st_dev, current.st_ino)
                    and stat.S_ISDIR(current.st_mode)):
                destination.rmdir()
        except OSError:
            pass
        raise

def quarantine(path, destination=None, *, private=False):
    """Keep failed bytes at an explicitly unverified name, never at the requested path."""
    base = pathlib.Path(str(destination or path) + ".UNVERIFIED")
    for number in range(1, 100):
        candidate = base if number == 1 else pathlib.Path(f"{base} ({number})")
        try:
            (publish_private_file if private else publish_verified)(path, candidate)
            return candidate.name
        except FileExistsError:
            continue
        except OSError:
            break
    path.unlink()
    return "discarded (unable to create quarantine name)"


def run_file_decoder(command, candidates, maximum):
    """Supervise legacy container/Windows decoders that require a seekable output file."""
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while child.poll() is None:
            for path in candidates:
                if path.exists() and path.stat().st_size > maximum:
                    raise EntryError("decoder output exceeds declared geometry")
            require_space(candidates[0].parent)
            time.sleep(0.02)
        if child.returncode:
            raise EntryError(f"decoder failed (exit {child.returncode})")
        outputs = [p for p in candidates if p.is_file() and not p.is_symlink()]
        if len(outputs) != 1 or outputs[0].stat().st_size > maximum:
            raise EntryError("decoder output is absent, ambiguous or exceeds declared geometry")
        return outputs[0]
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()


def wavpack_file_decode(path, directory, maximum):
    """Windows WavPack uses its file interface; bound it by public stream geometry first."""
    def field(number):
        with tempfile.TemporaryFile() as reply:
            subprocess.run(["wvunpack", "-q", f"-f{number}", str(path)],
                           stdin=subprocess.DEVNULL, stdout=reply,
                           stderr=subprocess.DEVNULL, timeout=30, check=True)
            reply.seek(0)
            value = reply.read(32).strip()
        if not value.isdigit() or len(value) > 16:
            raise EntryError("WavPack has no finite sample geometry")
        return int(value)

    with path.open("rb") as stream:
        header = stream.read(32)
    if len(header) != 32 or header[:4] != b"wvpk":
        raise EntryError("invalid WavPack block header")
    width = (int.from_bytes(header[24:28], "little") & 3) + 1
    channels, samples = field(4), field(6)
    if not 1 <= channels <= 4096 or not 1 <= samples < 1 << 53:
        raise EntryError("invalid WavPack sample geometry")
    expected = width * channels * samples
    if expected > maximum:
        raise EntryError("WavPack output exceeds declared geometry")
    require_space(directory, expected)
    # Verify the complete stream before limiting output; a corrupt extra tail cannot hide.
    subprocess.run(["wvunpack", "-q", "-v", str(path)], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    output = directory / "windows.pcm"
    names = (output, output.with_name(output.name + ".raw"))
    args = [str(path), str(output)] if sys.platform == "win32" else [str(path), "-o", str(output)]
    result = run_file_decoder(["wvunpack", "-r", "-q", "-y", f"--until={samples}"] + args,
                              names, expected)
    if result.stat().st_size != expected:
        raise EntryError("WavPack decoded length differs from stream geometry")
    return result


def decode_stream(path, codec, endian, signed, directory, maximum):
    """Decode raw audio onto private disk, enforcing the ceiling before each write.

    WavPack stores the incoming raw bytes transparently; only FLAC applies endian/sign flags.
    Piped WavPack output also avoids its platform-specific filename extension rewriting.
    """
    checked_size(maximum, "decode ceiling")
    require_space(directory)
    if codec == "wavpack-raw" and sys.platform == "win32":
        return wavpack_file_decode(path, directory, maximum)
    if codec == "flac-raw":
        command = ["flac", "-d", "-s", "-c", "--force-raw-format",
                   "--endian=" + ("big" if endian == "be" else "little"),
                   "--sign=" + ("signed" if signed else "unsigned"), str(path)]
    elif codec == "wavpack-raw":
        command = ["wvunpack", "-r", "-q", "-o", "-", str(path)]
    else:
        raise EntryError(f"unknown raw codec {codec!r}")
    _DECODES[0] += 1
    output = directory / f"decoded-{_DECODES[0]}.pcm"
    child = None
    try:
        with output.open("xb") as destination:
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            total = 0
            while True:
                block = child.stdout.read(min(COPY_BYTES, maximum - total + 1))
                if not block:
                    break
                if total + len(block) > maximum:
                    raise EntryError("decoded audio exceeds declared geometry")
                require_space(directory, len(block))
                destination.write(block)
                total += len(block)
            if child.wait():
                raise EntryError(f"{codec} decode of {path.name} failed")
            destination.flush()
            os.fsync(destination.fileno())
        return output
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()


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
    """Sub-file mechanisms are mutually exclusive (a format-spec refusal invariant).

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


def checked_wrapper(wrappers, sha, what="wrapper_sha256"):
    if not sha:
        return None, 0
    path = safe_join(wrappers, sha, what)
    if not path.is_file() or file_sha256(path) != sha:
        raise EntryError(f"{what} is missing or its SHA-256 does not match")
    return path, path.stat().st_size


def assemble_wrapped(output, prefix, audio, suffix):
    with output.open("xb") as stream:
        for path in (prefix, audio, suffix):
            if path is not None:
                copy_region(path, stream)
        stream.flush()
        os.fsync(stream.fileno())


def write_chunked(f, blobs, errors, wrappers, output):
    refs = f["chunk_refs"]
    if not isinstance(refs, list) or not refs:
        raise EntryError("chunk_refs is empty — nothing to concatenate")
    prefix, pre = checked_wrapper(wrappers, f.get("wrapper_sha256"))
    suffix, post = checked_wrapper(wrappers, f.get("trailer_sha256"), "trailer_sha256")
    size = checked_size(f.get("original_bytes"), "original_bytes")
    total, regions = pre + post, []
    for ref in refs:
        if not isinstance(ref, dict):
            raise EntryError("malformed chunk ref")
        bid = ref.get("blob")
        if bid in errors:
            raise EntryError(f"chunk blob {bid!r} did not decode: {errors[bid]}")
        if bid not in blobs:
            raise EntryError(f"chunk blob {bid!r} is not defined")
        offset = checked_size(ref.get("offset"), "chunk offset")
        length = checked_size(ref.get("len"), "chunk length")
        blob = blobs[bid]
        if not length or offset + length > blob.stat().st_size:
            raise EntryError(f"chunk ref {offset}+{length} overruns blob {bid!r}")
        total += length
        if total > size:
            raise EntryError("chunk slices and wrappers exceed original_bytes")
        regions.append((blob, offset, length))
    if total != size:
        raise EntryError("chunk slices and wrappers do not match original_bytes")
    with output.open("xb") as stream:
        if prefix:
            copy_region(prefix, stream)
        for path, offset, length in regions:
            copy_region(path, stream, offset, length)
        if suffix:
            copy_region(suffix, stream)
        stream.flush()
        os.fsync(stream.fileno())


def write_essence(f, src, wrappers, output, directory):
    """Splice checked PCM ranges and skeleton ranges without buffering whole streams."""
    skeleton, skel_size = checked_wrapper(wrappers, f.get("skeleton_sha256"), "skeleton_sha256")
    if skeleton is None:
        raise EntryError("essence entry has no skeleton")
    streams = f.get("essence_streams")
    if not isinstance(streams, list) or not streams:
        raise EntryError("essence entry has no essence_streams")
    allruns, decoded = [], []
    for index, stream in enumerate(streams):
        runs = stream.get("runs")
        if not isinstance(runs, list) or not runs:
            raise EntryError("essence stream has no runs")
        for run in runs:
            if not (isinstance(run, (list, tuple)) and len(run) == 3
                    and all(isinstance(n, int) and not isinstance(n, bool) for n in run)
                    and run[0] >= 0 and run[1] > 0 and run[2] >= 0):
                raise EntryError("invalid essence run geometry")
            allruns.append((run[0], run[1], run[2], index))
        at = 0
        for offset, length in sorted((r[2], r[1]) for r in runs):
            if offset != at:
                raise EntryError("essence pcm_offsets do not tile")
            at += length
        decoded.append(at)
    allruns.sort()
    previous, total = 0, 0
    for offset, length, _, _ in allruns:
        if offset < previous:
            raise EntryError("essence runs overlap")
        previous = offset + length
        total += length
    size = checked_size(f.get("original_bytes"), "original_bytes")
    if skel_size + total != size or previous > size:
        raise EntryError("essence and skeleton geometry differs from original_bytes")
    for index, stream in enumerate(streams):
        wanted = decoded[index]
        decoded[index] = decode_stream(safe_join(src, stream["encoded_path"], "stream path"),
                                       stream.get("codec_used", "flac-raw"),
                                       stream.get("raw_endian", "le"),
                                       stream.get("raw_signed", True), directory, wanted)
        if decoded[index].stat().st_size != wanted:
            raise EntryError("decoded essence length differs from run map")
    with output.open("xb") as destination:
        previous, skel_offset = 0, 0
        for offset, length, pcm_offset, index in allruns:
            gap = offset - previous
            copy_region(skeleton, destination, skel_offset, gap)
            skel_offset += gap
            copy_region(decoded[index], destination, pcm_offset, length)
            previous = offset + length
        copy_region(skeleton, destination, skel_offset, skel_size - skel_offset)
        destination.flush()
        os.fsync(destination.fileno())


def transform_audio(source, output, length, bits, endian, signed, anchors, ic):
    """Apply residual sums then ICR in frame-aligned windows, preserving incomplete tails."""
    width = sample_width(bits)
    unit = width * (2 if ic else 1)
    window = max(unit, PCM_WINDOW // unit * unit)
    body = length - length % width
    if ic:
        ks, block_frames, shift, channel = (ic.get(k) for k in
                                           ("ks", "block_frames", "shift", "anchor"))
        if not isinstance(ks, list) or not ks \
                or any(not isinstance(k, int) or isinstance(k, bool)
                       or not -(1 << 31) <= k < (1 << 31) for k in ks) \
                or not isinstance(block_frames, int) or isinstance(block_frames, bool) or block_frames <= 0 \
                or not isinstance(shift, int) or isinstance(shift, bool) or not 1 <= shift <= 62 \
                or not isinstance(channel, int) or isinstance(channel, bool) or channel not in (0, 1):
            raise EntryError("bad inter_channel_ref parameters")
    with source.open("rb") as reader, output.open("xb") as writer:
        offset = 0
        while offset < body:
            count = min(window, body - offset)
            raw = reader.read(count)
            if len(raw) != count:
                raise EntryError("truncated raw transform input")
            samples = parse_samples(raw, bits, endian, signed)
            for path, prefix in anchors:
                with path.open("rb") as anchor:
                    anchor.seek(prefix + offset)
                    raw = anchor.read(count)
                if len(raw) != count:
                    raise EntryError("truncated residual anchor")
                values = parse_samples(raw, bits, endian, signed)
                for index, value in enumerate(values):
                    samples[index] += value
            if anchors:
                # The historical inverse wraps the complete residual sum BEFORE ICR prediction.
                samples = parse_samples(encode_samples(samples, bits, endian, signed),
                                        bits, endian, signed)
            if ic:
                for index in range(len(samples) // 2):
                    frame = offset // (2 * width) + index
                    coefficient = ks[min(frame // block_frames, len(ks) - 1)]
                    prediction = (coefficient * samples[2 * index + channel]
                                  + (1 << (shift - 1))) >> shift
                    samples[2 * index + 1 - channel] += prediction
            block = encode_samples(samples, bits, endian, signed)
            require_space(output.parent, len(block))
            writer.write(block)
            offset += count
        tail = reader.read(length - body)
        if len(tail) != length - body or reader.read(1):
            raise EntryError("raw transform input length changed")
        writer.write(tail)
        writer.flush()
        os.fsync(writer.fileno())


def write_raw(f, src, dst, wrappers, by_path, verified, output, directory):
    prefix, pre = checked_wrapper(wrappers, f.get("wrapper_sha256"))
    suffix, post = checked_wrapper(wrappers, f.get("trailer_sha256"), "trailer_sha256")
    length = checked_size(f.get("original_bytes"), "original_bytes") - pre - post
    if length < 0:
        raise EntryError("wrappers exceed original_bytes")
    bits, endian, signed = f.get("bit_depth"), f.get("raw_endian") or "le", f.get("raw_signed", True)
    audio = decode_stream(safe_join(src, f["encoded_path"], "encoded_path"),
                          f["codec_used"], endian, signed, directory, length)
    if audio.stat().st_size != length:
        raise EntryError("raw decoded length differs from original_bytes and wrappers")
    anchors = []
    residual = f.get("residual_refs")
    if residual:
        refs = residual.get("anchors")
        if not isinstance(refs, list) or not refs:
            raise EntryError("residual_refs carries no anchors")
        width = sample_width(bits)
        for rel in refs:
            if rel == f["original_path"] or rel not in by_path or rel not in verified:
                raise EntryError(f"residual anchor {rel!r} was not rebuilt+verified")
            anchor = by_path[rel]
            _, before = checked_wrapper(wrappers, anchor.get("wrapper_sha256"))
            _, after = checked_wrapper(wrappers, anchor.get("trailer_sha256"), "trailer_sha256")
            path = safe_join(dst, rel, "anchor path")
            anchor_length = path.stat().st_size - before - after
            if anchor_length < 0 or anchor_length // width != length // width:
                raise EntryError(f"residual anchor {rel!r} sample count differs")
            anchors.append((path, before))
    ic = f.get("inter_channel_ref")
    if anchors or ic:
        transformed = directory / "transformed.pcm"
        transform_audio(audio, transformed, length, bits, endian, signed, anchors, ic)
        audio.unlink()
        audio = transformed
    assemble_wrapped(output, prefix, audio, suffix)


def write_whole(f, src, output, directory):
    codec = f["codec_used"]
    encoded = safe_join(src, f["encoded_path"], "encoded_path")
    temporary = directory / "whole.tmp"
    size = checked_size(f.get("original_bytes"), "original_bytes")
    require_space(directory, size)
    if codec == "flac":
        base = ["flac", "-d", "-s", "-f", "-o", str(temporary), str(encoded)]
        try:
            decoded = run_file_decoder(base[:2] + ["--keep-foreign-metadata-if-present"] + base[2:],
                                       (temporary,), size)
        except EntryError:
            temporary.unlink(missing_ok=True)
            decoded = run_file_decoder(base, (temporary,), size)
    else:
        args = ([str(encoded), str(temporary)] if sys.platform == "win32"
                else ["-o", str(temporary), str(encoded)])
        decoded = run_file_decoder(["wvunpack", "-y", "-q"] + args,
                                  (temporary, temporary.with_name(temporary.name + ".wav")), size)
    os.replace(decoded, output)


def residuals_in_dependency_order(residuals):
    """Rebuild residual anchors before residuals that depend on them.

    Unorderable entries stay in manifest order so the normal per-file checks
    report their failures without preventing independent files from rebuilding.
    """
    names = {f["original_path"] for f in residuals}
    placed, pending, ordered = set(), list(residuals), []
    while pending:
        ready = []
        for f in pending:
            refs = f.get("residual_refs")
            anchors = refs.get("anchors") if isinstance(refs, dict) else None
            if not isinstance(anchors, list):
                anchors = []  # malformed entries fail in the per-file decoder below
            if all(not isinstance(a, str) or a not in names or a in placed
                   for a in anchors):
                ready.append(f)
        if not ready:
            return ordered + pending
        ordered.extend(ready)
        placed.update(f["original_path"] for f in ready)
        ready_ids = {id(f) for f in ready}
        pending = [f for f in pending if id(f) not in ready_ids]
    return ordered


def main(src: pathlib.Path, dst: pathlib.Path) -> int:
    try:
        src = src.resolve()
        # Resolve parents, but retain a final symlink so it cannot redirect a claim.
        dst = dst.parent.resolve() / dst.name
        if src == dst or src in dst.parents or dst in src.parents:
            raise Refused("extracted and restored trees must be separate")
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not publication_needs_private_tree(dst.parent):
            return recover(src, dst)
        if os.path.lexists(dst):
            raise Refused("destination already exists — use a new recovery directory")
        with tempfile.TemporaryDirectory(prefix=".crate-recovery-tree-", dir=dst.parent) as name:
            tree = pathlib.Path(name) / "complete"
            result = recover(src, tree, private=True)
            publish_private_tree(tree, dst)
            return result
    finally:
        cleanup_scratch()


def recover(src, dst, *, private=False):
    m = load_manifest(src)
    if src == dst or src in dst.parents or dst in src.parents:
        raise Refused("extracted and restored trees must be separate")
    wrappers = src / ".crate" / "wrappers"
    entries, failed = [], []
    for index, entry in enumerate(m["files"]):
        if isinstance(entry, dict) and isinstance(entry.get("original_path"), str) and entry["original_path"]:
            entries.append(entry)
        else:
            failed.append((f"files[{index}]", "entry has no usable original_path"))
            print(f"  FAIL files[{index}]: entry has no usable original_path")
    by_path = {f["original_path"]: f for f in entries}
    if len(by_path) != len(entries):
        raise Refused("duplicate original_path — residual identity is ambiguous")
    dst.mkdir(parents=True, exist_ok=True)
    preflight_destination_namespace(dst, entries, m.get("symlinks", []), src, m)

    # Source geometry bounds legacy blobs even when their final unreferenced tail is retained.
    ceiling = sum(f["original_bytes"] for f in entries
                  if isinstance(f.get("original_bytes"), int)
                  and not isinstance(f["original_bytes"], bool) and f["original_bytes"] > 0)
    for entry in entries:
        refs = entry.get("chunk_refs")
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, dict):
                    offset, length = ref.get("offset"), ref.get("len")
                    if all(isinstance(v, int) and not isinstance(v, bool) for v in (offset, length)) \
                            and offset >= 0 and length > 0:
                        ceiling = max(ceiling, offset + length)
    blobs = m.get("chunk_blobs", [])
    if not isinstance(blobs, list):
        raise Refused("chunk_blobs is not a list")
    blob_pcm, blob_err = {}, {}
    for index, blob in enumerate(blobs):
        if not isinstance(blob, dict) or not isinstance(blob.get("id"), (str, int)) \
                or isinstance(blob.get("id"), bool):
            raise Refused("chunk blob has no usable id")
        bid = blob["id"]
        if bid in blob_pcm or bid in blob_err:
            raise Refused(f"duplicate chunk blob id {bid!r} — the slice map is ambiguous")
        try:
            directory = scratch_dir() / f"blob-{index}"
            directory.mkdir()
            blob_pcm[bid] = decode_stream(safe_join(src, blob["encoded_path"], "blob encoded_path"),
                                          blob.get("codec", "flac-raw"), blob.get("endian", "le"),
                                          blob.get("signed", True), directory, ceiling)
        except Exception as error:
            blob_err[bid] = str(error)

    verified_sha, skipped = {}, []
    order = ([f for f in entries if not f.get("residual_refs") and not f.get("dedup_of")]
             + residuals_in_dependency_order([f for f in entries if f.get("residual_refs") and not f.get("dedup_of")])
             + [f for f in entries if f.get("dedup_of")])
    for f in order:
        rel = f["original_path"]
        codec = f.get("codec_used", "none")
        try:
            out_path = safe_join(dst, rel, "original_path")
            if junk_row_never_archived(f, src, m):
                skipped.append(rel)
                print(f"  SKIP {rel}: OS junk the packer excluded (listed, never archived)")
                continue
            check_exclusive(f)
            size = checked_size(f.get("original_bytes"), "original_bytes")
            if os.path.lexists(out_path):
                raise EntryError("destination already exists — preserving its bytes")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            require_space(out_path.parent, size)
            with tempfile.TemporaryDirectory(prefix=".crate-recovery-", dir=out_path.parent) as temporary:
                directory = pathlib.Path(temporary)
                rebuilt = directory / "rebuilt"
                if f.get("dedup_of"):
                    canon = next((p for p, sha in verified_sha.items() if sha == f["dedup_of"]), None)
                    if canon is None:
                        raise EntryError("dedup_of has no verified canonical to copy")
                    with rebuilt.open("xb") as stream:
                        copy_region(safe_join(dst, canon, "dedup canonical"), stream)
                elif f.get("chunk_refs") is not None:
                    write_chunked(f, blob_pcm, blob_err, wrappers, rebuilt)
                elif codec == "none":
                    encoded = safe_join(src, f["encoded_path"], "encoded_path")
                    if encoded.stat().st_size != size:
                        raise EntryError("stored file length differs from original_bytes")
                    with rebuilt.open("xb") as stream:
                        copy_region(encoded, stream)
                elif codec == "essence-streams":
                    write_essence(f, src, wrappers, rebuilt, directory)
                elif codec in ("flac-raw", "wavpack-raw"):
                    write_raw(f, src, dst, wrappers, by_path, verified_sha, rebuilt, directory)
                elif codec in ("flac", "wavpack"):
                    write_whole(f, src, rebuilt, directory)
                else:
                    raise EntryError(f"unknown codec {codec!r} — this decoder cannot rebuild it")
                if rebuilt.stat().st_size != size:
                    raise EntryError("rebuilt length differs from original_bytes")
                got = file_sha256(rebuilt)
                if got != f.get("sha256_original"):
                    where = quarantine(rebuilt, out_path, private=private)
                    raise EntryError(f"SHA-256 mismatch — quarantined as {where}")
                # Flush every route, including stored/dedup and legacy container decoders.
                with rebuilt.open("rb") as stream:
                    os.fsync(stream.fileno())
                (publish_private_file if private else publish_verified)(rebuilt, out_path)
                verified_sha[rel] = got
                print(f"  OK   {rel}")
        except Refused:
            raise
        except Exception as error:
            msg = f"missing manifest field {error}" if isinstance(error, KeyError) else str(error)
            print(f"  FAIL {rel}: {msg}")
            failed.append((rel, msg))

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
