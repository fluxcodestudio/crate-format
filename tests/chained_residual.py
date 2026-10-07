#!/usr/bin/env python3
"""Recovery regression for an older manifest with two dependent residuals.

The fixture is a synthetic decode case, not output from Crate's packer. This
test only extracts and restores its committed payload; it contains no writer.
"""

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "chained-residual"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run_decoder(decoder, extracted, output):
    return subprocess.run(
        [sys.executable, str(decoder), str(extracted), str(output)],
        capture_output=True,
        text=True,
    )


def check_source_matches(output, manifest):
    source = FIXTURE / "source"
    expected = {entry["original_path"] for entry in manifest["files"]}
    actual = {str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()}
    require(actual == expected, f"delivered paths differ: actual={actual}, expected={expected}")
    for entry in manifest["files"]:
        rel = entry["original_path"]
        original = (source / rel).read_bytes()
        rebuilt = (output / rel).read_bytes()
        require(rebuilt == original, f"{rel} differs from the committed source")
        require(hashlib.sha256(rebuilt).hexdigest() == entry["sha256_original"],
                f"{rel} differs from its manifest SHA-256")


def check_failed_dependency(decoder, extracted, output, label):
    result = run_decoder(decoder, extracted, output)
    require(result.returncode == 1, f"{label}: expected per-file failure, got {result.returncode}:\n{result.stdout}\n{result.stderr}")
    require((output / "Stem.wav").read_bytes() == (FIXTURE / "source" / "Stem.wav").read_bytes(),
            f"{label}: independent Stem.wav was not recovered")
    require(not (output / "Master.wav").exists(), f"{label}: failed Master.wav was delivered")
    require(not (output / "Current.wav").exists(), f"{label}: dependent Current.wav was delivered")


def main(decoder, seven_zip):
    with tempfile.TemporaryDirectory(prefix="crate-chain-vector-") as temporary:
        work = pathlib.Path(temporary)
        extracted = work / "extracted"
        extract = subprocess.run(
            [seven_zip, "x", "-spd", "-o" + str(extracted),
             str(FIXTURE / "historical-layout.crate")],
            capture_output=True,
            text=True,
        )
        require(extract.returncode == 0,
                f"could not extract chained-residual fixture:\n{extract.stdout}\n{extract.stderr}")
        manifest_path = extracted / ".crate" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        entries = manifest["files"]
        require([entry["original_path"] for entry in entries]
                == ["Current.wav", "Master.wav", "Stem.wav"],
                "fixture no longer puts the dependent residual before its anchor")
        require(entries[0]["residual_refs"]["anchors"] == ["Master.wav"]
                and entries[1]["residual_refs"]["anchors"] == ["Stem.wav"],
                "fixture no longer contains a two-link residual chain")
        require(all(entry["codec_used"] == "flac-raw" for entry in entries),
                "fixture no longer exercises FLAC raw reconstruction")

        output = work / "restored"
        result = run_decoder(decoder, extracted, output)
        require(result.returncode == 0,
                f"valid chained residual failed:\n{result.stdout}\n{result.stderr}")
        check_source_matches(output, manifest)

        cycle = work / "cycle"
        shutil.copytree(extracted, cycle)
        cycle_manifest = json.loads((cycle / ".crate" / "manifest.json").read_text())
        cycle_manifest["files"][1]["residual_refs"]["anchors"] = ["Current.wav"]
        (cycle / ".crate" / "manifest.json").write_text(json.dumps(cycle_manifest))
        check_failed_dependency(decoder, cycle, work / "cycle-out", "cycle")

        damaged = work / "damaged"
        shutil.copytree(extracted, damaged)
        master_artifact = damaged / entries[1]["encoded_path"]
        master_artifact.write_bytes(b"not a FLAC stream")
        check_failed_dependency(decoder, damaged, work / "damaged-out", "failed anchor")

        print("chained residual: 3/3 byte-exact; cycle and failed-anchor controls refused safely")


if __name__ == "__main__":
    decoder_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "recovery_reference.py"
    seven_zip_path = sys.argv[2] if len(sys.argv) > 2 else next(
        (tool for name in ("7zz", "7za", "7z") if (tool := shutil.which(name))), None)
    if seven_zip_path is None:
        sys.exit("7-Zip is required for the chained-residual vector")
    try:
        main(decoder_path, seven_zip_path)
    except (AssertionError, OSError, KeyError, ValueError) as error:
        sys.exit(f"chained-residual vector FAILED: {error}")
