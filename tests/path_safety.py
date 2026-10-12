#!/usr/bin/env python3
"""Decoder-only path regressions. Optionally supply another reference reader path.

Usage: python3 tests/path_safety.py [path/to/recovery_reference.py]
The synthetic uncompressed entries exercise recovery, not private encoding logic.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock


READER_PATH = pathlib.Path(sys.argv.pop(1)) if len(sys.argv) > 1 else (
    pathlib.Path(__file__).resolve().parent.parent / "recovery_reference.py")
SPEC = importlib.util.spec_from_file_location("path_reader", READER_PATH)
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


class PathSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="crate-path-safety-")
        self.work = pathlib.Path(self.temp.name)
        self.src = self.work / "source"
        self.dst = self.work / "restored"
        (self.src / ".crate" / "wrappers").mkdir(parents=True)
        self.manifest = {"crate_manifest_version": "4.0", "app_version": "1.7.6",
                         "junk_lexicon": 3, "files": []}

    def tearDown(self):
        reader.cleanup_scratch()
        self.temp.cleanup()

    def entry(self, name, payload, present=True):
        if present:
            path = self.src / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.manifest["files"].append({
            "original_path": name, "encoded_path": name, "codec_used": "none",
            "original_bytes": len(payload),
            "sha256_original": hashlib.sha256(payload).hexdigest(),
        })

    def recover(self):
        (self.src / ".crate" / "manifest.json").write_text(json.dumps(self.manifest))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = reader.main(self.src, self.dst)
        return status, output.getvalue()

    @unittest.skipIf(os.name == "nt", "POSIX literal backslash names")
    def test_literal_and_nested_names_recover_separately(self):
        payloads = {r"A\B": b"literal", "A/B": b"nested",
                    r"A\.DS_Store": b"real user content",
                    r"A\..\B": b"literal dots"}
        for name, payload in payloads.items():
            self.entry(name, payload)
            self.assertEqual(reader.safe_join(self.src, name), self.src / name)
        status, output = self.recover()
        self.assertEqual(status, 0, output)
        actual = {p.relative_to(self.dst).as_posix(): p.read_bytes()
                  for p in self.dst.rglob("*") if p.is_file()}
        self.assertEqual(actual, payloads)

    @unittest.skipIf(os.name == "nt", "POSIX literal backslash names")
    def test_missing_literal_junk_looking_file_is_failure_not_skip(self):
        self.entry(r"A\.DS_Store", b"missing", present=False)
        status, output = self.recover()
        self.assertEqual(status, 1, output)
        self.assertNotIn("SKIP", output)
        self.assertFalse((self.dst / r"A\.DS_Store").exists())

    @unittest.skipIf(os.name == "nt", "POSIX literal backslash names")
    def test_junk_predicate_preserves_literal_names_in_every_era(self):
        for era in (1, 2, 3):
            for name in (r"A\.DS_Store", r"A\._song", r"A\.Spotlight-V100/file"):
                with self.subTest(era=era, name=name):
                    self.assertFalse(reader.is_os_junk(name, era))
            self.assertTrue(reader.is_os_junk("A/.DS_Store", era))
            self.assertTrue(reader.is_os_junk("A/.Spotlight-V100/file", era))

    def test_absolute_and_traversal_paths_refused(self):
        for name in ("", ".", "..", "../escape", "a/../escape", "/absolute",
                     "/../escape", "//server/share"):
            with self.subTest(name=name), self.assertRaises(reader.EntryError):
                reader.safe_join(self.src, name)
        self.assertEqual(reader.safe_join(self.src, "folder/file"), self.src / "folder/file")

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture; Windows needs symlink privilege")
    def test_symlink_escape_and_prefix_sibling_refused(self):
        outside = self.work / "source-sibling"
        outside.mkdir()
        (outside / "secret").write_bytes(b"untouched")
        (self.src / "escape").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(reader.EntryError):
            reader.safe_join(self.src, "escape/secret")
        inside = self.src / "inside"
        inside.mkdir()
        (self.src / "alias").symlink_to(inside, target_is_directory=True)
        self.assertEqual(reader.safe_join(self.src, "alias/file"), self.src / "alias/file")
        self.assertEqual((outside / "secret").read_bytes(), b"untouched")

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture; Windows needs symlink privilege")
    def test_recovery_refuses_encoded_symlink_escape(self):
        secret = self.work / "secret"
        secret.write_bytes(b"outside source")
        self.entry("escape", b"outside source", present=False)
        (self.src / "escape").symlink_to(secret)
        status, output = self.recover()
        self.assertEqual(status, 1, output)
        self.assertFalse((self.dst / "escape").exists())
        self.assertEqual(secret.read_bytes(), b"outside source")

    def test_windows_lexical_paths_refuse_drives_roots_unc_and_traversal(self):
        # Exercise the Windows parser on every host, without changing pathlib's
        # host filesystem implementation. Real Windows confinement still needs CI.
        windows_os = types.SimpleNamespace(**{**vars(os), "name": "nt"})
        with mock.patch.object(reader, "os", windows_os):
            for name in (r"C:\escape", "C:escape", r"\escape", r"\\server\share\file",
                         r"\\?\C:\escape", r"A\..\escape", "A/../escape",
                         "A/C:escape", "A/C:/escape", "A/D:"):
                with self.subTest(name=name), self.assertRaises(reader.EntryError):
                    reader.safe_join(self.src, name)
            with self.assertRaises(reader.EntryError):
                reader.safe_join(self.src, r"A\B")
            self.assertEqual(reader.safe_join(self.src, "A/B"), self.src / "A" / "B")
            self.assertFalse(reader.is_os_junk(r"A\.DS_Store"))
            self.assertTrue(reader.is_os_junk("A/.DS_Store"))
            missing = {"original_path": r"A\.DS_Store", "encoded_path": r"A\.DS_Store"}
            self.assertFalse(reader.junk_row_never_archived(missing, self.src, self.manifest))

    def test_windows_rejects_literal_backslash_for_every_manifest_path_role(self):
        # Explicit target semantics run on macOS/Linux too; the Windows CI job
        # separately exercises the native filesystem implementation.
        for role in ("original_path", "encoded_path", "stream path", "blob encoded_path",
                     "anchor path", "symlink path", "folder path"):
            with self.subTest(role=role), self.assertRaises(reader.EntryError):
                reader.manifest_path_parts(r"A\B.wav", role, windows=True)
            self.assertEqual(reader.manifest_path_parts("A/B.wav", role, windows=True),
                             ("A", "B.wav"))
            self.assertEqual(reader.manifest_path_parts(r"A\B.wav", role, windows=False),
                             (r"A\B.wav",))

    def test_windows_junk_row_cannot_skip_unrecreatable_literal_name(self):
        # A legacy listed-but-unarchived junk row must still fail name
        # validation before the early SKIP path can hide the mismatch.
        self.entry(r"A\.DS_Store", b"missing", present=False)
        windows_os = types.SimpleNamespace(**{**vars(os), "name": "nt"})
        with mock.patch.object(reader, "os", windows_os):
            status, output = self.recover()
        self.assertEqual(status, 1, output)
        self.assertIn("FAIL", output)
        self.assertNotIn("SKIP", output)

    def test_windows_encoded_literal_name_cannot_read_nested_alias(self):
        self.entry("output.wav", b"original", present=False)
        self.manifest["files"][0]["encoded_path"] = r"A\B.wav"
        (self.src / "A").mkdir()
        (self.src / "A" / "B.wav").write_bytes(b"original")
        windows_os = types.SimpleNamespace(**{**vars(os), "name": "nt"})
        with mock.patch.object(reader, "os", windows_os):
            status, output = self.recover()
        self.assertEqual(status, 1, output)
        self.assertIn("FAIL output.wav", output)
        self.assertFalse((self.dst / "output.wav").exists())

    def test_case_aliased_folders_refused_before_any_file_is_published(self):
        probe = self.work / "case-volume-probe"
        (probe / "Album").mkdir(parents=True)
        if not (probe / "album").exists():
            self.skipTest("destination volume is case-sensitive")
        self.entry("Album/one.wav", b"one")
        self.entry("album/two.wav", b"two")
        with self.assertRaisesRegex(reader.Refused, "aliases a manifest directory"):
            self.recover()
        self.assertFalse((self.dst / "Album" / "one.wav").exists())
        self.assertFalse((self.dst / "album" / "two.wav").exists())

    def test_case_aliased_file_names_refused_before_publication(self):
        probe = self.work / "file-volume-probe"
        probe.mkdir()
        (probe / "Mix.wav").write_bytes(b"")
        if not (probe / "mix.wav").exists():
            self.skipTest("destination volume is case-sensitive")
        self.entry("Mix.wav", b"one")
        self.entry("mix.wav", b"two", present=False)
        with self.assertRaisesRegex(reader.Refused, "aliases manifest output names"):
            self.recover()
        self.assertFalse((self.dst / "Mix.wav").exists())

    def test_unicode_aliased_folders_refused_before_publication(self):
        composed, decomposed = "caf\u00e9", "cafe\u0301"
        probe = self.work / "unicode-volume-probe"
        (probe / composed).mkdir(parents=True)
        if not (probe / decomposed).exists():
            self.skipTest("destination volume keeps these Unicode names distinct")
        self.entry(f"{composed}/one.wav", b"one")
        self.entry(f"{decomposed}/two.wav", b"two")
        with self.assertRaisesRegex(reader.Refused, "aliases a manifest directory"):
            self.recover()
        self.assertFalse((self.dst / composed / "one.wav").exists())
        self.assertFalse((self.dst / decomposed / "two.wav").exists())

    def test_injected_case_folder_alias_refused_before_publication(self):
        self.entry("Album/one.wav", b"one")
        self.entry("album/two.wav", b"two")
        real_mkdir = pathlib.Path.mkdir

        def aliased_mkdir(path, *args, **kwargs):
            if path.name == "album" and any(parent.name.startswith(".crate-name-check-")
                                            for parent in path.parents):
                raise FileExistsError("injected case alias")
            return real_mkdir(path, *args, **kwargs)

        with mock.patch.object(pathlib.Path, "mkdir", aliased_mkdir):
            with self.assertRaisesRegex(reader.Refused, "aliases a manifest directory"):
                self.recover()
        self.assertFalse((self.dst / "Album" / "one.wav").exists())
        self.assertFalse((self.dst / "album" / "two.wav").exists())

    def test_injected_case_file_alias_refused_before_publication(self):
        self.entry("Mix.wav", b"one")
        self.entry("mix.wav", b"two", present=False)
        real_open = pathlib.Path.open

        def aliased_open(path, mode="r", *args, **kwargs):
            if path.name == "mix.wav" and mode == "xb" and any(
                    parent.name.startswith(".crate-name-check-") for parent in path.parents):
                raise FileExistsError("injected case alias")
            return real_open(path, mode, *args, **kwargs)

        with mock.patch.object(pathlib.Path, "open", aliased_open):
            with self.assertRaisesRegex(reader.Refused, "aliases manifest output names"):
                self.recover()
        self.assertFalse((self.dst / "Mix.wav").exists())
        self.assertFalse((self.dst / "mix.wav").exists())

    def test_injected_unicode_folder_alias_refused_before_publication(self):
        composed, decomposed = "caf\u00e9", "cafe\u0301"
        self.entry(f"{composed}/one.wav", b"one")
        self.entry(f"{decomposed}/two.wav", b"two", present=False)
        real_mkdir = pathlib.Path.mkdir

        def aliased_mkdir(path, *args, **kwargs):
            if path.name == decomposed and any(parent.name.startswith(".crate-name-check-")
                                               for parent in path.parents):
                raise FileExistsError("injected Unicode alias")
            return real_mkdir(path, *args, **kwargs)

        with mock.patch.object(pathlib.Path, "mkdir", aliased_mkdir):
            with self.assertRaisesRegex(reader.Refused, "aliases a manifest directory"):
                self.recover()
        self.assertFalse((self.dst / composed / "one.wav").exists())
        self.assertFalse((self.dst / decomposed / "two.wav").exists())

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture; Windows needs symlink privilege")
    def test_existing_directory_alias_refused_by_inode_before_publication(self):
        self.entry("Album/one.wav", b"one")
        self.entry("alias/two.wav", b"two", present=False)
        self.dst.mkdir()
        (self.dst / "Album").mkdir()
        (self.dst / "alias").symlink_to("Album", target_is_directory=True)
        with self.assertRaisesRegex(reader.Refused, "destination directories alias"):
            self.recover()
        self.assertFalse((self.dst / "Album" / "one.wav").exists())
        self.assertFalse((self.dst / "alias" / "two.wav").exists())

    def test_distinct_folders_restore_with_original_names(self):
        self.entry("Album/one.wav", b"one")
        self.entry("Other/two.wav", b"two")
        status, output = self.recover()
        self.assertEqual(status, 0, output)
        self.assertEqual((self.dst / "Album" / "one.wav").read_bytes(), b"one")
        self.assertEqual((self.dst / "Other" / "two.wav").read_bytes(), b"two")


if __name__ == "__main__":
    unittest.main(verbosity=2)
