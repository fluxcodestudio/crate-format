#!/usr/bin/env python3
"""Public decoder regressions for volumes without links or exclusive file rename."""
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("exfat_reader", ROOT / "recovery_reference.py")
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class PrivateTreePublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="crate-public-exfat-")
        self.work = pathlib.Path(self.temp.name)
        self.src, self.dst = self.work / "source", self.work / "restored"
        (self.src / ".crate").mkdir(parents=True)
        self.manifest = {"crate_manifest_version": "4.0", "files": []}

    def tearDown(self):
        reader.cleanup_scratch()
        self.temp.cleanup()

    def entry(self, name, payload, **extra):
        path = self.src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        self.manifest["files"].append({
            "original_path": name, "encoded_path": name, "codec_used": "none",
            "original_bytes": len(payload), "sha256_original": hashlib.sha256(payload).hexdigest(),
            **extra,
        })

    def recover(self):
        (self.src / ".crate" / "manifest.json").write_text(json.dumps(self.manifest))
        with mock.patch.object(reader.os, "link", side_effect=OSError(errno.EPERM, "no links")), \
                mock.patch.object(reader, "rename_exclusive", side_effect=OSError(errno.ENOTSUP, "no exclusive rename")), \
                contextlib.redirect_stdout(io.StringIO()):
            return reader.main(self.src, self.dst)

    def assert_no_scratch(self):
        self.assertFalse(any(p.name.startswith(".crate-") for p in self.work.iterdir()))
        self.assertEqual(reader._SCRATCH, [])

    def test_complete_tree_appears_only_after_every_file_verifies(self):
        self.entry("Album/one.wav", b"first")
        self.entry("Album/two.wav", b"second")
        self.entry("duplicate.wav", b"first", dedup_of=hashlib.sha256(b"first").hexdigest())
        self.entry("._literal", b"user file")
        original = reader.file_sha256
        inspected = []

        def observe(path):
            self.assertFalse(os.path.lexists(self.dst))
            inspected.append(path)
            return original(path)

        with mock.patch.object(reader, "file_sha256", observe):
            self.assertEqual(self.recover(), 0)
        self.assertGreater(len(inspected), 4)
        for entry in self.manifest["files"]:
            self.assertEqual((self.dst / entry["original_path"]).read_bytes(),
                             (self.src / entry["encoded_path"]).read_bytes())
        self.assert_no_scratch()

    def test_corruption_preserves_good_files_and_unverified_verdict(self):
        self.entry("bad", b"wrong", sha256_original=hashlib.sha256(b"right").hexdigest())
        self.entry("good", b"independent")
        self.assertEqual(self.recover(), 1)
        self.assertFalse((self.dst / "bad").exists())
        self.assertEqual((self.dst / "bad.UNVERIFIED").read_bytes(), b"wrong")
        self.assertEqual((self.dst / "good").read_bytes(), b"independent")
        self.assert_no_scratch()

    def test_occupied_directory_is_preserved_before_decoding(self):
        self.entry("file", b"new")
        self.dst.mkdir()
        (self.dst / "file").write_bytes(b"existing")
        with mock.patch.object(reader, "recover") as decode, self.assertRaises(reader.Refused):
            self.recover()
        decode.assert_not_called()
        self.assertEqual((self.dst / "file").read_bytes(), b"existing")
        self.assert_no_scratch()

    def test_preexisting_empty_directory_is_not_owned(self):
        self.entry("file", b"new")
        self.dst.mkdir()
        identity = self.dst.stat()
        with self.assertRaises(reader.Refused):
            self.recover()
        self.assertEqual(self.dst.stat().st_ino, identity.st_ino)
        self.assertEqual(list(self.dst.iterdir()), [])
        self.assert_no_scratch()

    def test_destination_created_during_decode_is_preserved(self):
        self.entry("file", b"new")
        original = reader.publish_private_tree

        def occupy(tree, destination):
            destination.mkdir()
            (destination / "sentinel").write_bytes(b"someone else's data")
            original(tree, destination)

        with mock.patch.object(reader, "publish_private_tree", occupy), self.assertRaises(reader.Refused):
            self.recover()
        self.assertEqual((self.dst / "sentinel").read_bytes(), b"someone else's data")
        self.assertFalse((self.dst / "file").exists())
        self.assert_no_scratch()

    def test_reservation_populated_at_rename_is_not_overwritten_or_cleaned(self):
        self.entry("file", b"new")
        rename = os.rename

        def occupy(source, destination):
            (destination / "sentinel").write_bytes(b"late arrival")
            rename(source, destination)

        with mock.patch.object(reader.os, "rename", occupy), self.assertRaises(OSError):
            self.recover()
        self.assertEqual((self.dst / "sentinel").read_bytes(), b"late arrival")
        self.assertFalse((self.dst / "file").exists())
        self.assert_no_scratch()

    def test_cancellation_never_exposes_partly_built_tree(self):
        self.entry("good", b"complete")
        self.entry("cancel", b"unfinished")
        copy = reader.copy_region

        def cancel(path, output, *args, **kwargs):
            if path.name == "cancel":
                output.write(b"partial")
                raise KeyboardInterrupt
            return copy(path, output, *args, **kwargs)

        with mock.patch.object(reader, "copy_region", cancel), self.assertRaises(KeyboardInterrupt):
            self.recover()
        self.assertFalse(self.dst.exists())
        self.assert_no_scratch()

    def test_enospc_private_copy_cannot_leave_truncated_final_file(self):
        self.entry("file", b"whole bytes")
        copy = reader.copy_region

        def fill(path, output, *args, **kwargs):
            if path.name == "rebuilt":
                output.write(b"partial")
                raise OSError(errno.ENOSPC, "disk full during private copy")
            return copy(path, output, *args, **kwargs)

        with mock.patch.object(reader, "copy_region", fill):
            self.assertEqual(self.recover(), 1)
        self.assertFalse((self.dst / "file").exists())
        self.assertEqual(list(self.dst.iterdir()), [])
        self.assert_no_scratch()

    def test_failed_private_copy_with_failed_cleanup_refuses_whole_tree(self):
        self.entry("good", b"verified first")
        self.entry("file", b"whole bytes")
        copy = reader.copy_region
        unlink = pathlib.Path.unlink
        engaged = {"copy": False, "cleanup": False}

        def fail_copy(path, output, *args, **kwargs):
            if path.name == "rebuilt" and pathlib.Path(output.name).name == "file":
                engaged["copy"] = True
                output.write(b"partial")
                raise OSError(errno.ENOSPC, "disk full during private copy")
            return copy(path, output, *args, **kwargs)

        def fail_cleanup(path, *args, **kwargs):
            if path.name == "file" and ".crate-recovery-tree-" in str(path):
                engaged["cleanup"] = True
                raise PermissionError(errno.EACCES, "cannot remove partial private file")
            return unlink(path, *args, **kwargs)

        with mock.patch.object(reader, "copy_region", fail_copy), \
                mock.patch.object(pathlib.Path, "unlink", fail_cleanup), \
                self.assertRaises(reader.Refused):
            self.recover()
        self.assertEqual(engaged, {"copy": True, "cleanup": True})
        self.assertFalse(os.path.lexists(self.dst))
        self.assert_no_scratch()

    def test_occupied_private_file_is_not_replaced(self):
        source, destination = self.work / "verified", self.work / "occupied"
        source.write_bytes(b"verified")
        destination.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            reader.publish_private_file(source, destination)
        self.assertEqual(source.read_bytes(), b"verified")
        self.assertEqual(destination.read_bytes(), b"existing")

    @unittest.skipIf(os.name == "nt", "POSIX symlink control")
    def test_final_symlink_cannot_redirect_recovery(self):
        self.entry("file", b"new")
        outside = self.work / "outside"
        outside.mkdir()
        self.dst.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(reader.Refused):
            self.recover()
        self.assertTrue(self.dst.is_symlink())
        self.assertEqual(list(outside.iterdir()), [])
        self.assert_no_scratch()


if __name__ == "__main__":
    unittest.main(verbosity=2)
