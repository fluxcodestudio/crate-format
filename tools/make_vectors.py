#!/usr/bin/env python3
"""
Regenerate the test vectors in vectors/ deterministically.

Every source tree is written from a fixed random seed, so running this script
reproduces the exact same session folders. The .crate packages themselves are
then packed with the Crate CLI — the same packer the app ships — so the vectors
prove the FORMAT, not a hand-built fixture.

Usage:
    CRATE_CLI=/path/to/crate-cli python3 tools/make_vectors.py

Requires: the crate-cli binary (env CRATE_CLI, or ../CRATE/target/release/crate-cli),
python3 only for source material (no third-party packages).

The shipped vectors/ tree was produced by this script; you never need to run it
to VERIFY anything — verify.sh works entirely offline against the shipped files.
"""
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VEC = REPO / "vectors"
TEST_PASSPHRASE = "crate-format-test-vector"

# ── raw WAV writers (no third-party deps; wave.py can't do 24-bit or float) ──

def wav_bytes(samples_le_int, channels, bits, sr):
    """PCM WAV from interleaved signed little-endian samples.

    Packing is per bit depth — 16-bit "<h", 24-bit three-byte two's complement,
    32-bit "<i" — and the byte width MUST match the fmt header, or the file is
    internally inconsistent (header says 16-bit, data is 4 bytes/sample): every
    parser then reads half of it as garbage audio that still round-trips to the
    same SHA, a vector that verifies without proving anything.
    """
    if bits == 16:
        data = b"".join(struct.pack("<h", s) for s in samples_le_int)
    elif bits == 24:
        data = b"".join(s.to_bytes(3, "little", signed=True) for s in samples_le_int)
    elif bits == 32:
        data = b"".join(struct.pack("<i", s) for s in samples_le_int)
    else:
        raise ValueError(f"unsupported bit depth {bits}")
    bytes_per = bits // 8
    fmt = struct.pack("<HHIIHH", 1, channels, sr, sr * channels * bytes_per,
                      channels * bytes_per, bits)
    return (b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVEfmt "
            + struct.pack("<I", 16) + fmt + b"data" + struct.pack("<I", len(data)) + data)


def wav_float32_bytes(frames_interleaved_floats, channels, sr):
    """IEEE-float WAV (format tag 3) from interleaved float samples."""
    data = b"".join(struct.pack("<f", x) for x in frames_interleaved_floats)
    fmt = struct.pack("<HHIIHH", 3, channels, sr, sr * channels * 4, channels * 4, 32)
    return (b"RIFF" + struct.pack("<I", 36 + len(data)) + b"WAVEfmt "
            + struct.pack("<I", 16) + fmt + b"data" + struct.pack("<I", len(data)) + data)


def tone(seed, n, ch, lo=-18000, hi=18000):
    """Deterministic pseudo-melodic material: seeded random walk, plausible as audio."""
    r = random.Random(seed)
    out, v = [], 0
    for _ in range(n * ch):
        v = max(lo, min(hi, v + r.randint(-1200, 1200)))
        out.append(v)
    return out


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


SR = 48000

# ── the six sessions ──

def build_01_standard(root):
    """Plain hybrid preset: an integer-stereo and a 24-bit mono file, nothing repeated.
    Guarantee proven: recoverable with literally 7z + flac + cat."""
    write(root / "Session/Audio/Bounce.wav", wav_bytes(tone(101, SR // 2, 2), 2, 16, SR))
    r = random.Random(102)
    m24 = [r.randint(-(1 << 22), (1 << 22)) for _ in range(SR // 3)]
    write(root / "Session/Audio/Vox_24.wav", wav_bytes(m24, 1, 24, SR))


def build_02_dedup(root):
    """Default preset: a repeated loop inside longer takes (sub-file CDC chunking fires)
    plus one byte-identical duplicate take (whole-file dedup fires)."""
    loop = tone(201, SR, 2)
    tail = tone(202, SR // 6, 2)
    take1 = loop + loop + tail
    write(root / "Session/Takes/Loop.wav", wav_bytes(loop, 2, 16, SR))
    write(root / "Session/Takes/Take1.wav", wav_bytes(take1, 2, 16, SR))
    write(root / "Session/Takes/Take1_copy.wav", wav_bytes(take1, 2, 16, SR))
    flo = [x / 32768.0 for x in tone(203, SR // 2, 2)]
    ftake = flo + flo + [x / 32768.0 for x in tone(204, SR // 6, 2)]
    write(root / "Session/Takes/Float_Take.wav", wav_float32_bytes(ftake, 2, SR))


def build_03_smallest(root):
    """--smallest preset: a panned pair (inter-channel/ICR coding fires) and a
    two-stem master (cross-stem residual fires) — the arithmetic transforms."""
    r = random.Random(301)
    a = [r.randint(-24000, 24000) for _ in range(SR // 2)]
    b = [max(-32768, min(32767, x // 2 + r.randint(-40, 40))) for x in a]
    master = [max(-32768, min(32767, a[i] + b[i] + r.randint(-3, 3))) for i in range(len(a))]
    write(root / "Session/Stems/Gtr_L.wav", wav_bytes(a, 1, 16, SR))
    write(root / "Session/Stems/Gtr_R.wav", wav_bytes(b, 1, 16, SR))
    write(root / "Session/Stems/Master.wav", wav_bytes(master, 1, 16, SR))
    # A stereo file whose channels are related by 3/5 — the scale FLAC's own
    # mid/side cannot express, so inter-channel (ICR) coding is a genuine win and
    # the packer keeps it. An L/2 relationship is natively expressible and gets
    # (correctly) declined — the vector only proves the rule when it actually fires.
    r2 = random.Random(303)
    pan = []
    for _ in range(90_000):
        l = r2.randint(-10_000, 10_000)
        pan.extend((l, l * 3 // 5))
    write(root / "Session/Stems/Panned.wav", wav_bytes(pan, 2, 16, 44_100))


def build_04_wavpack(root):
    """--codec wavpack-only: 32-bit float (past FLAC's integer comfort) and a
    10-channel integer file (past FLAC's 8-channel cap) — the WavPack decode
    rules, including the wvunpack output-name trap, are what this proves."""
    fl = [x / 32768.0 for x in tone(401, SR // 3, 2)]
    write(root / "Session/Audio/Float_Mix.wav", wav_float32_bytes(fl, 2, SR))
    write(root / "Session/Audio/Atmos_10ch.wav", wav_bytes(tone(402, SR // 8, 10), 10, 16, SR))


def build_05_housekeeping(root):
    """Default preset: OS junk the pack strips and discloses, filesystem symlinks
    it records verbatim, and an exact duplicate pair it dedups."""
    keep = tone(501, SR // 4, 2)
    write(root / "Session/Keep.wav", wav_bytes(keep, 2, 16, SR))
    write(root / "Session/Copy.wav", wav_bytes(keep, 2, 16, SR))  # exact duplicate
    (root / "Session/.DS_Store").write_bytes(b"\x00\x01Bud1\x00" * 8)
    (root / "Session/._Keep.wav").write_bytes(b"AppleDouble stub" * 4)
    (root / "Session/Thumbs.db").write_bytes(b"\xd0\xcf\x11\xe0stub" * 4)
    os.symlink("Keep.wav", root / "Session/Rel.wav")
    (root / "Session/Nested").mkdir(exist_ok=True)
    os.symlink("../Keep.wav", root / "Session/Nested/Up.wav")
    os.symlink("Ghost.wav", root / "Session/Dangling.wav")


def build_06_gauntlet(root):
    """--smallest + passphrase encryption + 64K split volumes + PAR2 recovery,
    on enough material that the recovery records genuinely ship (>1 MiB pack
    floor). Proves the escrow's whole toolchain: cat, age -d, 7z, then rebuild."""
    write(root / "Session/Pad.wav", wav_bytes(tone(601, SR * 12, 2), 2, 16, SR))
    r = random.Random(602)
    a = [r.randint(-24000, 24000) for _ in range(SR * 2)]
    b = [max(-32768, min(32767, x // 2 + r.randint(-30, 30))) for x in a]
    write(root / "Session/StemA.wav", wav_bytes(a, 1, 16, SR))
    write(root / "Session/StemB.wav", wav_bytes(b, 1, 16, SR))


# ── pack invocations (name → CLI flags) ──

PACKS = [
    ("01-standard", []),
    ("02-dedup", []),
    ("03-smallest", ["--smallest"]),  # env added in main(): CRATE_CDC=0 CRATE_ICR=1 CRATE_RESIDUAL=1
    ("04-wavpack", ["--codec", "wavpack-only"]),
    ("05-housekeeping", []),
    ("06-gauntlet", ["--smallest", "--passphrase", TEST_PASSPHRASE,
                     "--split", "512K", "--recovery-pct", "20"]),
]

BUILDERS = {
    "01-standard": build_01_standard,
    "02-dedup": build_02_dedup,
    "03-smallest": build_03_smallest,
    "04-wavpack": build_04_wavpack,
    "05-housekeeping": build_05_housekeeping,
    "06-gauntlet": build_06_gauntlet,
}


def main():
    cli = Path(os.environ.get("CRATE_CLI")
               or REPO.parent / "CRATE" / "target" / "release" / "crate-cli")
    if not cli.is_file():
        sys.exit(f"crate-cli not found (set CRATE_CLI): {cli}")
    # The CLI fail-closes on a missing par2 — point it at the desktop bundle's
    # sidecars (the same binaries the app ships), overridable with CRATE_SIDECARS.
    sidecars = Path(os.environ.get("CRATE_SIDECARS")
                    or REPO.parent / "CRATE" / "apps/desktop/src-tauri/binaries")
    if not (sidecars / "par2").is_file():
        sys.exit(f"bundled par2 sidecar not found (set CRATE_SIDECARS): {sidecars}")
    if VEC.exists():
        shutil.rmtree(VEC)
    VEC.mkdir()

    ENV = {"03-smallest": {"CRATE_CDC": "0", "CRATE_ICR": "1", "CRATE_RESIDUAL": "1"}}
    for name, flags in PACKS:
        src = VEC / name / "source" / "Session"
        BUILDERS[name](src)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / f"{name}.crate"
            cmd = [str(cli), "pack", str(src), "--staging", str(Path(td) / "stg"),
                   "--out", str(out), "--verify", "full", "--quiet",
                   "--sidecar-dir", str(sidecars)] + flags
            env = dict(os.environ, **ENV.get(name, {}))
            r = subprocess.run(cmd, capture_output=True, text=True, env=env)
            if r.returncode != 0:
                sys.exit(f"pack failed for {name}:\n{r.stdout}\n{r.stderr}")
            # ship every volume + sidecar the pack produced (split parts, par2, …)
            for f in Path(td).iterdir():
                if f.name.startswith(name):
                    shutil.copy2(f, VEC / f.name)
        print(f"  packed {name}")

    # SHA256SUMS over everything shipped, so a download can be checked wholesale.
    lines = []
    for p in sorted(VEC.rglob("*")):
        if p.is_file() and p.name != "SHA256SUMS":
            import hashlib
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  "
                         f"{p.relative_to(VEC)}")
    (VEC / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    print(f"  wrote SHA256SUMS ({len(lines)} files)")


if __name__ == "__main__":
    main()
