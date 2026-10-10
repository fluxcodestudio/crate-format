#!/usr/bin/env python3
"""Decoder-only recovery regressions; synthetic PCM is not a Crate writer fixture.

Real writer provenance is covered by verify.sh's six shipped packages. This suite tests
bounded file operations and failure injection without any private encoder implementation.
"""
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("bounded_reader", ROOT / "recovery_reference.py")
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def oracle_samples(data, bits, endian, signed):
    width = (bits + 7) // 8
    result = []
    for at in range(0, len(data) - len(data) % width, width):
        value = int.from_bytes(data[at:at + width], endian)
        if signed:
            value = value - (1 << bits) if value & (1 << (bits - 1)) else value
        else:
            value -= 1 << (bits - 1)
        result.append(value)
    return result


def oracle_bytes(values, bits, endian, signed):
    return b"".join(((value + (0 if signed else 1 << (bits - 1))) % (1 << bits))
                    .to_bytes((bits + 7) // 8, endian) for value in values)


class BoundedRecovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="crate-public-bounded-")
        self.work = pathlib.Path(self.temp.name)
        self.src, self.dst = self.work / "source", self.work / "restored"
        (self.src / ".crate" / "wrappers").mkdir(parents=True)
        self.manifest = {"crate_manifest_version": "4.0", "files": []}

    def tearDown(self):
        reader.cleanup_scratch()
        self.temp.cleanup()

    def entry(self, name, payload, **extra):
        (self.src / name).write_bytes(payload)
        entry = {"original_path": name, "encoded_path": name, "codec_used": "none",
                 "original_bytes": len(payload), "sha256_original": digest(payload)}
        entry.update(extra)
        self.manifest["files"].append(entry)
        return entry

    def save(self):
        (self.src / ".crate" / "manifest.json").write_text(json.dumps(self.manifest))

    def recover(self):
        self.save()
        with contextlib.redirect_stdout(io.StringIO()):
            return reader.main(self.src, self.dst)

    def wrapper(self, data):
        sha = digest(data)
        (self.src / ".crate" / "wrappers" / sha).write_bytes(data)
        return sha

    def assert_private_removed(self):
        self.assertEqual(list(self.dst.rglob(".crate-recovery-*")), [])
        self.assertEqual(reader._SCRATCH, [])

    def test_existing_destination_and_dedup_are_preserved(self):
        self.entry("anchor", b"safe anchor")
        self.entry("duplicate", b"unused", dedup_of=digest(b"safe anchor"),
                   original_bytes=11, sha256_original=digest(b"safe anchor"))
        self.assertEqual(self.recover(), 0)
        self.assertEqual((self.dst / "duplicate").read_bytes(), b"safe anchor")
        (self.dst / "anchor").write_bytes(b"user's newer file")
        self.assertEqual(self.recover(), 1)
        self.assertEqual((self.dst / "anchor").read_bytes(), b"user's newer file")
        self.assert_private_removed()

    def test_quarantine_does_not_seed_dedup_or_clobber(self):
        wrong = self.entry("bad", b"wrong", sha256_original=digest(b"right"))
        self.entry("dependent", b"wrong", dedup_of=wrong["sha256_original"],
                   sha256_original=wrong["sha256_original"])
        self.entry("good", b"good")
        self.dst.mkdir()
        (self.dst / "bad.UNVERIFIED").write_bytes(b"previous evidence")
        self.assertEqual(self.recover(), 1)
        self.assertFalse((self.dst / "bad").exists())
        self.assertFalse((self.dst / "dependent").exists())
        self.assertEqual((self.dst / "bad.UNVERIFIED").read_bytes(), b"previous evidence")
        self.assertEqual((self.dst / "bad.UNVERIFIED (2)").read_bytes(), b"wrong")
        self.assertEqual((self.dst / "good").read_bytes(), b"good")
        self.assert_private_removed()

    def test_injected_enospc_cleans_partial_and_continues(self):
        self.entry("bad", b"unfinished bytes")
        self.entry("good", b"independent")
        original = reader.copy_region

        def fail(path, output, *args, **kwargs):
            if path.name == "bad":
                output.write(b"partial")
                raise OSError(errno.ENOSPC, "injected disk full")
            return original(path, output, *args, **kwargs)

        with mock.patch.object(reader, "copy_region", fail):
            self.assertEqual(self.recover(), 1)
        self.assertFalse((self.dst / "bad").exists())
        self.assertEqual((self.dst / "good").read_bytes(), b"independent")
        self.assert_private_removed()

    def test_cancel_cleans_partial_and_preserves_prior_output(self):
        self.entry("good", b"complete")
        self.entry("cancelled", b"unfinished")
        original = reader.copy_region

        def cancel(path, output, *args, **kwargs):
            if path.name == "cancelled":
                output.write(b"partial")
                raise KeyboardInterrupt
            return original(path, output, *args, **kwargs)

        with mock.patch.object(reader, "copy_region", cancel), self.assertRaises(KeyboardInterrupt):
            self.recover()
        self.assertEqual((self.dst / "good").read_bytes(), b"complete")
        self.assertFalse((self.dst / "cancelled").exists())
        self.assert_private_removed()

    def test_hash_io_failure_remains_private(self):
        self.entry("file", b"complete")
        with mock.patch.object(reader, "file_sha256", side_effect=OSError("injected read error")):
            self.assertEqual(self.recover(), 1)
        self.assertFalse((self.dst / "file").exists())
        self.assert_private_removed()

    def test_bad_size_and_wrapper_refuse(self):
        self.entry("size", b"123", original_bytes=2)
        self.entry("boolean-size", b"1", original_bytes=True)
        corrupt = self.wrapper(b"wrapper")
        (self.src / ".crate" / "wrappers" / corrupt).write_bytes(b"changed")
        self.entry("wrapper", b"raw", codec_used="flac-raw", wrapper_sha256=corrupt)
        self.assertEqual(self.recover(), 1)
        self.assertEqual([p for p in self.dst.rglob("*") if p.is_file()], [])
        self.assert_private_removed()

    def test_sparse_chunk_offset_above_two_gib_and_geometry(self):
        blob = self.work / "blob"
        offset = (1 << 31) + 17
        with blob.open("wb") as stream:
            stream.seek(offset)
            stream.write(b"exact slice")
        entry = {"chunk_refs": [{"blob": 1, "offset": offset, "len": 11}], "original_bytes": 11}
        output = self.work / "chunked"
        reader.write_chunked(entry, {1: blob}, {}, self.src / ".crate" / "wrappers", output)
        self.assertEqual(output.read_bytes(), b"exact slice")
        entry["chunk_refs"][0]["len"] = 12
        with self.assertRaises(reader.EntryError):
            reader.write_chunked(entry, {1: blob}, {}, self.src / ".crate" / "wrappers", self.work / "bad")
        self.assertFalse((self.work / "bad").exists())
        entry["chunk_refs"][0]["len"] = True
        with self.assertRaises(reader.EntryError):
            reader.write_chunked(entry, {1: blob}, {}, self.src / ".crate" / "wrappers", self.work / "bad")

    def test_residual_icr_windows_match_scalar_oracle(self):
        cases = 0
        for bits in (8, 16, 24, 32, 64):
            for endian in ("little", "big"):
                for signed in (False, True):
                    for icr in (None, 0, 1):
                        width = (bits + 7) // 8
                        # Odd sample count plus incomplete final sample exercises both tails.
                        values = [((index * 719) % (1 << bits)) - (1 << (bits - 1)) for index in range(79)]
                        body = oracle_bytes(values, bits, endian, signed)
                        tail = bytes(range(width - 1))
                        source = self.work / "pcm"
                        source.write_bytes(body + tail)
                        anchor_paths, scalar = [], oracle_samples(body, bits, endian, signed)
                        for number in range(2):
                            anchor_values = [value * (number + 2) + 7 for value in values]
                            anchor_bytes = oracle_bytes(anchor_values, bits, endian, signed)
                            anchor = self.work / f"anchor-{number}"
                            anchor.write_bytes(b"head" + anchor_bytes + b"t")
                            anchor_paths.append((anchor, 4))
                            scalar = [a + b for a, b in zip(scalar, oracle_samples(anchor_bytes, bits, endian, signed))]
                        scalar = oracle_samples(oracle_bytes(scalar, bits, endian, signed), bits, endian, signed)
                        ic = {"ks": [32769, -(1 << 31), (1 << 31) - 1],
                              "block_frames": 7, "shift": 8, "anchor": icr} if icr is not None else None
                        if ic:
                            for frame in range(len(scalar) // 2):
                                channel = ic["anchor"]
                                k = ic["ks"][min(frame // 7, 2)]
                                scalar[2 * frame + 1 - channel] += (k * scalar[2 * frame + channel] + 128) >> 8
                        output = self.work / "transformed"
                        with mock.patch.object(reader, "PCM_WINDOW", 38):
                            reader.transform_audio(source, output, len(body + tail), bits,
                                                   "be" if endian == "big" else "le", signed, anchor_paths, ic)
                        self.assertEqual(output.read_bytes(), oracle_bytes(scalar, bits, endian, signed) + tail)
                        output.unlink()
                        cases += 1
        self.assertEqual(cases, 60)

    def test_transform_refuses_truncation_and_bad_icr(self):
        source = self.work / "short"
        source.write_bytes(b"12")
        with self.assertRaises(reader.EntryError):
            reader.transform_audio(source, self.work / "truncated", 8, 16, "le", True, [], None)
        for invalid in (True, 1 << 31, -(1 << 31) - 1):
            output = self.work / "icr"
            with self.assertRaises(reader.EntryError):
                reader.transform_audio(source, output, 2, 16, "le", True, [],
                                       {"ks": [invalid], "block_frames": 4,
                                        "shift": 8, "anchor": 0})
            self.assertFalse(output.exists())

    def test_essence_splice_and_geometry(self):
        skeleton = self.wrapper(b"AABBCC")
        (self.src / "s1").write_bytes(b"1234")
        (self.src / "s2").write_bytes(b"xyz")
        entry = {"skeleton_sha256": skeleton, "original_bytes": 13, "essence_streams": [
            {"encoded_path": "s1", "runs": [[2, 2, 2], [9, 2, 0]]},
            {"encoded_path": "s2", "runs": [[6, 3, 0]]}]}
        with mock.patch.object(reader, "decode_stream", side_effect=lambda path, *args: path) as decode:
            reader.write_essence(entry, self.src, self.src / ".crate" / "wrappers", self.work / "essence", self.work)
            self.assertEqual(decode.call_count, 2)
        self.assertEqual((self.work / "essence").read_bytes(), b"AA34BBxyz12CC")
        entry["essence_streams"][0]["runs"][1][2] = 2
        with self.assertRaises(reader.EntryError):
            reader.write_essence(entry, self.src, self.src / ".crate" / "wrappers", self.work / "bad", self.work)
        self.assertFalse((self.work / "bad").exists())

    def test_atomic_publication_both_local_paths_and_negative_control(self):
        for fallback in (False, True):
            for occupied in (False, True):
                source, destination = self.work / "private", self.work / "public"
                source.write_bytes(b"verified")
                if occupied:
                    destination.write_bytes(b"user content")
                patch = mock.patch.object(reader.os, "link", side_effect=OSError(errno.ENOTSUP, "no links")) if fallback else contextlib.nullcontext()
                with patch:
                    if occupied:
                        with self.assertRaises(FileExistsError):
                            reader.publish_verified(source, destination)
                        self.assertEqual(destination.read_bytes(), b"user content")
                        self.assertEqual(source.read_bytes(), b"verified")
                    else:
                        reader.publish_verified(source, destination)
                        self.assertEqual(destination.read_bytes(), b"verified")
                        self.assertFalse(source.exists())
                source.unlink(missing_ok=True)
                destination.unlink()
        # Explicit unsafe replacement control proves the preservation assertion is meaningful.
        source.write_bytes(b"wrong replacement")
        destination.write_bytes(b"user content")
        os.replace(source, destination)
        with self.assertRaises(AssertionError):
            self.assertEqual(destination.read_bytes(), b"user content")

    def test_memory_bounds_with_old_buffering_negative_control(self):
        source = self.work / "large"
        with source.open("wb") as stream:
            for _ in range(24):
                stream.write(b"\x9a" * (1 << 20))
        threshold = 8 << 20
        tracemalloc.start()
        reader.file_sha256(source)
        with (self.work / "copy").open("wb") as destination:
            reader.copy_region(source, destination)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLess(peak, threshold)
        tracemalloc.start()
        hashlib.sha256(source.read_bytes()).hexdigest()
        _, negative_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertGreater(negative_peak, threshold)
        self.assertEqual(reader.file_sha256(source), reader.file_sha256(self.work / "copy"))

    def test_large_stored_recovery_is_bounded_and_hash_mismatch_is_quarantined(self):
        source = self.src / "large-session.bin"
        with source.open("wb") as stream:
            for _ in range(16):
                stream.write(b"\x9a" * (1 << 20))
        expected = reader.file_sha256(source)
        self.manifest["files"].append({
            "original_path": source.name,
            "encoded_path": source.name,
            "codec_used": "none",
            "original_bytes": source.stat().st_size,
            "sha256_original": expected,
        })
        tracemalloc.start()
        try:
            self.assertEqual(self.recover(), 0)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 8 << 20)
        self.assertEqual(reader.file_sha256(self.dst / source.name), expected)

        self.manifest["files"][0]["sha256_original"] = digest(b"wrong content")
        self.dst = self.work / "corrupt-restored"
        self.assertEqual(self.recover(), 1)
        self.assertFalse((self.dst / source.name).exists())
        self.assertEqual(reader.file_sha256(self.dst / (source.name + ".UNVERIFIED")), expected)
        self.assert_private_removed()

    def test_real_raw_flac_ceiling_memory_and_enospc(self):
        self.assertIsNotNone(shutil.which("flac"), "flac required; never skip decode coverage")
        raw, encoded = self.work / "large.raw", self.work / "large.flac"
        size = 24 << 20
        with raw.open("wb") as stream:
            for _ in range(24):
                stream.write(b"\x00\x80\xff\x7f" * (1 << 18))
        subprocess.run(["flac", "-s", "--force-raw-format", "--endian=little", "--sign=signed",
                        "--channels=2", "--bps=16", "--sample-rate=48000", "-o", str(encoded), str(raw)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        source_sha = reader.file_sha256(encoded)
        tracemalloc.start()
        decoded = reader.decode_stream(encoded, "flac-raw", "le", True, self.work, size)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertLess(peak, 8 << 20)
        self.assertEqual(reader.file_sha256(raw), reader.file_sha256(decoded))
        before = set(self.work.iterdir())
        with self.assertRaises(reader.EntryError):
            reader.decode_stream(encoded, "flac-raw", "le", True, self.work, size - 1)
        self.assertEqual(before, set(self.work.iterdir()))
        probes = [0]
        original = reader.require_space

        def disk_full(*args):
            probes[0] += 1
            if probes[0] >= 3:
                raise OSError(errno.ENOSPC, "injected decoder disk full")
            return original(*args)

        children = []
        popen = reader.subprocess.Popen

        def track_child(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child

        with mock.patch.object(reader.subprocess, "Popen", track_child):
            with mock.patch.object(reader, "require_space", disk_full), self.assertRaises(OSError):
                reader.decode_stream(encoded, "flac-raw", "le", True, self.work, size)
            self.assertEqual(probes[0], 3)
            self.assertEqual(before, set(self.work.iterdir()))
            probes[0] = 0

            def cancelled(*args):
                probes[0] += 1
                if probes[0] >= 3:
                    raise KeyboardInterrupt
                return original(*args)

            with mock.patch.object(reader, "require_space", cancelled), self.assertRaises(KeyboardInterrupt):
                reader.decode_stream(encoded, "flac-raw", "le", True, self.work, size)
            self.assertEqual(probes[0], 3)
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.poll() is not None for child in children))
        self.assertEqual(before, set(self.work.iterdir()))
        self.assertEqual(reader.file_sha256(encoded), source_sha)

    def test_wavpack_file_interface_and_corruption(self):
        seven = next((shutil.which(name) for name in ("7zz", "7za", "7z") if shutil.which(name)), None)
        self.assertIsNotNone(seven, "7-Zip required; never skip WavPack coverage")
        extracted = self.work / "wavpack-vector"
        subprocess.run([seven, "x", "-spd", "-o" + str(extracted), str(ROOT / "vectors" / "04-wavpack.crate")],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        manifest = json.loads((extracted / ".crate" / "manifest.json").read_text())
        entry = next(f for f in manifest["files"] if f.get("codec_used") == "wavpack-raw")
        encoded = extracted / entry["encoded_path"]
        source_sha = reader.file_sha256(encoded)
        normal = reader.decode_stream(encoded, "wavpack-raw", "le", True, self.work, entry["original_bytes"])
        # Exercise the Windows file-mode algorithm with Unix's equivalent -o syntax.
        windows = reader.wavpack_file_decode(encoded, self.work, entry["original_bytes"])
        self.assertEqual(reader.file_sha256(normal), reader.file_sha256(windows))
        corrupt = self.work / "damaged.wv"
        corrupt.write_bytes(b"wvpk" + b"\x00" * 80)
        with self.assertRaises((reader.EntryError, subprocess.CalledProcessError)):
            reader.wavpack_file_decode(corrupt, self.work, 512)
        self.assertEqual(reader.file_sha256(encoded), source_sha)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(BoundedRecovery)
    expected = 15
    if suite.countTestCases() != expected:
        sys.exit(f"bounded recovery test count changed: {suite.countTestCases()} != {expected}")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
