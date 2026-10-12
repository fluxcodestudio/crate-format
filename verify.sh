#!/bin/sh
# verify.sh — prove every shipped test vector rebuilds byte-exactly, without Crate.
#
#   sh verify.sh
#
# What it does, per vector in vectors/:
#   1. if the package shipped split into volumes, cat them back into one stream
#   2. if the package is passphrase-encrypted, decrypt it with age (the vector's
#      passphrase is printed before the attempt — it is part of the vector)
#   3. extract the 7-Zip container
#   4. run recovery_reference.py — the format's normative decoder — to rebuild
#      every file and check every one against the manifest's sha256_original
#   5. compare the rebuilt tree against the SHIPPED SOURCE TREE it was packed
#      from, filtering only the OS-junk files the pack disclosed in
#      manifest.excluded (the pack's own disclosure, via the decoder's predicate)
#   6. assert the interesting transform actually fired for that vector — a
#      "dedup vector" whose manifest carries no chunk blobs proves nothing
#      (anti-vacuity: an empty check is not a check)
#
# Exit 0 only if EVERY vector rebuilds byte-exactly and every anti-vacuity
# assertion holds. Any failure prints which vector, which step, and why.

set -u

REPO="$(cd "$(dirname "$0")" && pwd)"
VEC="$REPO/vectors"
REF="$REPO/recovery_reference.py"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
checks=0; fails=0
ok(){ checks=$((checks+1)); printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad(){ checks=$((checks+1)); fails=$((fails+1)); printf '  \033[31m✗ FAIL\033[0m %s\n' "$*"; }

# ── tool presence: refuse loudly, never skip silently ─────────────────────────
need(){ command -v "$1" >/dev/null 2>&1 && return 0
  printf 'missing tool: %s — %s\n' "$1" "$2"; exit 2; }
need python3 "https://www.python.org/ (any 3.8+)"
SEVEN=""
for c in 7zz 7za 7z; do command -v "$c" >/dev/null 2>&1 && SEVEN="$c" && break; done
[ -n "$SEVEN" ] || { printf 'missing tool: 7-Zip (7zz/7za/7z) — https://www.7-zip.org/\n'; exit 2; }
need flac      "https://xiph.org/flac/download/ — FLAC's command-line tools"
need wvunpack  "https://www.wavpack.com/ — WavPack's command-line tools"
need age       "https://github.com/FiloSottile/age — only needed for the encrypted vector"
need par2      "PAR2 is required to verify the recovery sidecars"

# decrypt the passphrase-encrypted vector: age reads its passphrase from the
# TERMINAL, never stdin, so feed it under expect (present on macOS and most
# Linux installs; a missing expect is a loud refusal, never a silent skip)
age_decrypt(){ # in out
  command -v expect >/dev/null 2>&1 \
    || { printf 'missing tool: expect — needed to feed the passphrase to age\n'; exit 2; }
  expect -c "
    set timeout 600
    set st {spawn age -d -o {$2} {$1}}
    eval \$st
    expect {
      -re {[Pp]assphrase} { send \"crate-format-test-vector\r\"; exp_continue }
      eof
    }
    if {[catch wait result] || [llength \$result] != 4 || [lindex \$result 2] != 0} {
      exit 1
    }
    exit [lindex \$result 3]
"
  status=$?
  [ "$status" -eq 0 ] && [ -s "$2" ]
}

# A killed, failed, or falsely successful decryptor must never publish a vector.
mkdir -p "$SCRATCH/age-control/bin"
cat >"$SCRATCH/age-control/bin/age" <<'SH'
#!/bin/sh
printf '%s' "$AGE_CONTROL_MODE" > "$AGE_CONTROL_MARKER"
case "$AGE_CONTROL_MODE" in
  killed) kill -KILL "$$" ;;
  failed) exit 7 ;;
  silent) exit 0 ;;
esac
SH
chmod +x "$SCRATCH/age-control/bin/age"
age_control_failure=""
for mode in killed failed silent; do
  rm -f "$SCRATCH/age-control/marker" "$SCRATCH/age-control/plain.7z"
  if ( AGE_CONTROL_MODE="$mode"
       AGE_CONTROL_MARKER="$SCRATCH/age-control/marker"
       PATH="$SCRATCH/age-control/bin:$PATH"
       export AGE_CONTROL_MODE AGE_CONTROL_MARKER PATH
       age_decrypt "$SCRATCH/age-control/input" "$SCRATCH/age-control/plain.7z"
     ) >"$SCRATCH/age-control/$mode.log" 2>&1; then
    age_control_failure="$age_control_failure accepted $mode child;"
  elif [ ! -f "$SCRATCH/age-control/marker" ] \
       || [ "$(cat "$SCRATCH/age-control/marker")" != "$mode" ] \
       || [ -e "$SCRATCH/age-control/plain.7z" ]; then
    age_control_failure="$age_control_failure $mode control did not engage cleanly;"
  fi
done
if [ -z "$age_control_failure" ]; then
  ok "age helper refuses killed, failed and missing-output children"
else
  bad "age helper controls failed:$age_control_failure"
fi

# Compare every published path, including junk-looking names listed as actual
# files/links/directories. Filter only stripped paths disclosed in excluded[]
# under the package's own historical junk lexicon.
# forward the caller's args verbatim: the call site passes (ref srcd outd mpath)
cmptree(){ python3 - "$@" <<'PY'
import filecmp, json, os, sys, importlib.util as u
ref, srcd, outd, mpath = sys.argv[1:5]
s = u.spec_from_file_location("r", ref); m = u.module_from_spec(s); s.loader.exec_module(m)
man = json.load(open(mpath))
listed = {row.get("original_path") for row in man.get("files", []) if isinstance(row, dict)}
listed.update(row.get("path") for row in man.get("symlinks", []) if isinstance(row, dict))
listed.update(row.get("path") for row in man.get("dirs", []) if isinstance(row, dict))
listed.update(path for path in man.get("empty_dirs", []) if isinstance(path, str))
listed = {path for path in listed if isinstance(path, str)}
excluded = {path for path in man.get("excluded", []) if isinstance(path, str)}

def disclosed_junk(rel):
    if not m.is_os_junk_for_pack(rel, man):
        return False
    # A listed descendant prevents pruning its parent even if a conflicting
    # excluded[] row names the parent. The listed path must remain comparable.
    if rel in listed or any(path.startswith(rel + "/") for path in listed):
        return False
    return any(rel == path or rel.startswith(path + "/") for path in excluded)

def walk(d):
    out = {}
    for root, dirs, files in os.walk(d, followlinks=False):
        for name in dirs[:]:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, d).replace(os.sep, "/")
            if disclosed_junk(rel):
                dirs.remove(name)
                continue
            kind = "link" if os.path.islink(path) else "dir"
            out[rel] = kind
            if kind == "link":
                dirs.remove(name)
        for fn in files:
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, d).replace(os.sep, "/")
            if not disclosed_junk(rel):
                out[rel] = "link" if os.path.islink(path) else "file"
    return out

want, got = walk(srcd), walk(outd)
missing = sorted(want.keys() - got.keys()); extra = sorted(got.keys() - want.keys())
differs = []
for r in sorted(want.keys() & got.keys()):
    a, b = os.path.join(srcd, r), os.path.join(outd, r)
    try:
        if want[r] != got[r]:
            differs.append(f"{r} (type {want[r]} != {got[r]})")
        elif want[r] == "link":  # compare LITERAL targets, never stat through
            if os.readlink(a) != os.readlink(b):
                differs.append(r + " (link target differs)")
        elif want[r] == "file" and not filecmp.cmp(a, b, shallow=False):
            differs.append(r)
    except OSError as e:
        differs.append(f"{r} ({e})")  # a broken comparison is a VERDICT, never silence
if not any(kind != "dir" for kind in want.values()):
    print("compared 0 files — the source tree never got built"); sys.exit(1)
if missing or differs or extra:
    print(f"missing={missing[:5]} differs={differs[:5]} extra={extra[:5]} (of {len(want)})")
    sys.exit(1)
PY
}

# An empty diff is proof only when the comparator itself completed successfully.
# Keep this verdict shared by real vectors and the silent-failure control below.
tree_matches(){
  out=$(cmptree "$@") || return 1
  [ -z "$out" ]
}

# Prove the comparator itself fails when a source-only empty directory is lost.
comparator_failure=""
mkdir -p "$SCRATCH/comparator/src/empty" "$SCRATCH/comparator/out/empty"
printf 'source bytes' > "$SCRATCH/comparator/src/file"
cp "$SCRATCH/comparator/src/file" "$SCRATCH/comparator/out/file"
printf '{"files": [], "excluded": []}\n' > "$SCRATCH/comparator/manifest.json"
if positive_output=$(cmptree "$REF" "$SCRATCH/comparator/src" "$SCRATCH/comparator/out" "$SCRATCH/comparator/manifest.json") \
   && [ -z "$positive_output" ]; then
  rmdir "$SCRATCH/comparator/out/empty"
  if missing_dir_output=$(cmptree "$REF" "$SCRATCH/comparator/src" "$SCRATCH/comparator/out" "$SCRATCH/comparator/manifest.json"); then
    comparator_failure="accepted a missing empty directory"
  elif printf '%s\n' "$missing_dir_output" | grep -Fq "missing=['empty']"; then
    :
  else
    comparator_failure="did not identify missing empty directory: $missing_dir_output"
  fi
else
  comparator_failure="empty-directory positive control failed"
fi

# A broken comparator can exit nonzero without printing a diff. That must never
# be counted as a byte-identical vector, even though the captured output is empty.
if tree_matches "$SCRATCH/comparator/missing-reference.py" \
     "$SCRATCH/comparator/src" "$SCRATCH/comparator/out" \
     "$SCRATCH/comparator/manifest.json" 2>"$SCRATCH/comparator/silent-error.log"; then
  comparator_failure="$comparator_failure; accepted a silent comparator failure"
elif [ -n "$out" ] || [ ! -s "$SCRATCH/comparator/silent-error.log" ]; then
  comparator_failure="$comparator_failure; silent comparator failure control did not engage"
fi

# A junk-looking name that is listed as real payload must be checked. The same
# name may be ignored only when the pack explicitly disclosed stripping it.
mkdir -p "$SCRATCH/junk-comparator/src" "$SCRATCH/junk-comparator/out"
printf 'real payload' > "$SCRATCH/junk-comparator/src/Thumbs.db"
cp "$SCRATCH/junk-comparator/src/Thumbs.db" "$SCRATCH/junk-comparator/out/Thumbs.db"
printf 'anchor payload' > "$SCRATCH/junk-comparator/src/anchor"
cp "$SCRATCH/junk-comparator/src/anchor" "$SCRATCH/junk-comparator/out/anchor"
printf '{"app_version":"1.7.6", "files":[{"original_path":"Thumbs.db"},{"original_path":"anchor"}], "excluded":[]}\n' \
  > "$SCRATCH/junk-comparator/manifest.json"
if listed_positive=$(cmptree "$REF" "$SCRATCH/junk-comparator/src" "$SCRATCH/junk-comparator/out" "$SCRATCH/junk-comparator/manifest.json") \
   && [ -z "$listed_positive" ]; then
  rm "$SCRATCH/junk-comparator/out/Thumbs.db"
  if listed_missing=$(cmptree "$REF" "$SCRATCH/junk-comparator/src" "$SCRATCH/junk-comparator/out" "$SCRATCH/junk-comparator/manifest.json"); then
    comparator_failure="$comparator_failure; accepted a missing listed Thumbs.db"
  elif printf '%s\n' "$listed_missing" | grep -Fq "missing=['Thumbs.db']"; then
    printf '{"app_version":"1.7.6", "files":[{"original_path":"Thumbs.db"},{"original_path":"anchor"}], "excluded":["Thumbs.db"]}\n' \
      > "$SCRATCH/junk-comparator/manifest.json"
    if overlap_missing=$(cmptree "$REF" "$SCRATCH/junk-comparator/src" "$SCRATCH/junk-comparator/out" "$SCRATCH/junk-comparator/manifest.json"); then
      comparator_failure="$comparator_failure; excluded row hid a listed Thumbs.db"
    elif ! printf '%s\n' "$overlap_missing" | grep -Fq "missing=['Thumbs.db']"; then
      comparator_failure="$comparator_failure; listed/excluded overlap failed for wrong reason: $overlap_missing"
    fi
    printf '{"app_version":"1.7.6", "files":[{"original_path":"anchor"}], "excluded":["Thumbs.db"]}\n' \
      > "$SCRATCH/junk-comparator/manifest.json"
    if disclosed_missing=$(cmptree "$REF" "$SCRATCH/junk-comparator/src" "$SCRATCH/junk-comparator/out" "$SCRATCH/junk-comparator/manifest.json") \
       && [ -z "$disclosed_missing" ]; then
      :
    else
      comparator_failure="$comparator_failure; did not honor disclosed stripped Thumbs.db"
    fi
    printf '{"app_version":"1.6.1", "files":[{"original_path":"anchor"}], "excluded":["Thumbs.db"]}\n' \
      > "$SCRATCH/junk-comparator/manifest.json"
    if old_era_missing=$(cmptree "$REF" "$SCRATCH/junk-comparator/src" "$SCRATCH/junk-comparator/out" "$SCRATCH/junk-comparator/manifest.json"); then
      comparator_failure="$comparator_failure; newer junk rule hid an older-era Thumbs.db"
    elif ! printf '%s\n' "$old_era_missing" | grep -Fq "missing=['Thumbs.db']"; then
      comparator_failure="$comparator_failure; older-era refusal had wrong cause: $old_era_missing"
    fi
  else
    comparator_failure="$comparator_failure; listed Thumbs.db mismatch had wrong cause: $listed_missing"
  fi
else
  comparator_failure="$comparator_failure; listed-junk positive control failed"
fi
if [ -z "$comparator_failure" ]; then
  ok "tree comparator: empty dirs and listed junk required; disclosed junk excluded; silent failure refused"
else
  bad "tree comparator controls failed: $comparator_failure"
fi

printf 'verifying the .crate test vectors — no Crate software involved\n\n'

verify_one(){ # $1 = vector name, $2.. = shell snippet anti-vacuity assertions
  name="$1"; want="$2"; shift 2
  v="$VEC/$name"
  [ -d "$v/source" ] || { bad "$name: no shipped source tree"; return; }
  w="$SCRATCH/$name"; mkdir -p "$w"

  # one stream: cat split volumes back together
  if ls "$VEC/$name".part[0-9]*of*.crate >/dev/null 2>&1; then
    # glob directly — never `cat $(ls ...)`, which word-splits on spaces in the path
    ls "$VEC/$name".part001of* >/dev/null 2>&1 || { bad "$name: volume part001 missing"; return; }
    cat "$VEC/$name".part*of*.crate > "$w/stream.crate"
  else
    cp "$VEC/$name.crate" "$w/stream.crate" 2>/dev/null \
      || { bad "$name: no package found"; return; }
  fi

  # encryption: age (scrypt). The passphrase is a documented part of the vector.
  if head -c 64 "$w/stream.crate" | grep -q "age-encryption"; then
    printf '  (encrypted vector — passphrase: crate-format-test-vector)\n'
    age_decrypt "$w/stream.crate" "$w/plain.7z" >/dev/null 2>&1 \
      || { bad "$name: age decryption failed"; return; }
    mv "$w/plain.7z" "$w/stream.7z"
  else
    cp "$w/stream.crate" "$w/stream.7z"
  fi

  "$SEVEN" x -spd -o"$w/pkg" "$w/stream.7z" >/dev/null 2>&1 \
    || { bad "$name: 7-Zip extraction failed"; return; }
  [ -f "$w/pkg/.crate/manifest.json" ] \
    || { bad "$name: no .crate/manifest.json in the container"; return; }

  if python3 "$REF" "$w/pkg" "$w/out" > "$w/escrow.log" 2>&1; then
    :
  else
    bad "$name: reference decoder failed (exit $?)"
    sed 's/^/    /' "$w/escrow.log" | tail -6
    return
  fi

  if tree_matches "$REF" "$v/source/Session" "$w/out" "$w/pkg/.crate/manifest.json"; then
    ok "$name: rebuilt byte-identical to the shipped source"
  else
    bad "$name: rebuild differs — ${out:-comparator failed without diff output}"; return
  fi

  # anti-vacuity: the vector's reason to exist must be visible in the manifest
  if eval "$want"; then
    ok "$name: $want_note"
  else
    bad "$name: anti-vacuity failed — $want_note (the transform never fired; the vector proves nothing)"
  fi
}

want_note=""
want01='true'
want02='python3 -c "import json,sys; m=json.load(open(sys.argv[1])); assert m.get(\"chunk_blobs\") and any(f.get(\"chunk_refs\") for f in m[\"files\"]), \"no chunk store\"" "$w/pkg/.crate/manifest.json"'
want03='python3 -c "import json,sys; m=json.load(open(sys.argv[1])); assert any(f.get(\"inter_channel_ref\") for f in m[\"files\"]) and any(f.get(\"residual_refs\") for f in m[\"files\"]), \"transforms absent\"" "$w/pkg/.crate/manifest.json"'
want04='python3 -c "import json,sys; m=json.load(open(sys.argv[1])); assert any(f.get(\"codec_used\")==\"wavpack-raw\" for f in m[\"files\"]), \"no wavpack stream\"" "$w/pkg/.crate/manifest.json"'
want05='python3 -c "import json,sys; m=json.load(open(sys.argv[1])); assert len(m.get(\"excluded\",[]))==3 and len(m.get(\"symlinks\",[]))==3 and any(f.get(\"dedup_of\") for f in m[\"files\"]), \"housekeeping absent\"" "$w/pkg/.crate/manifest.json"'
want06='test -f "$w/pkg/.crate/manifest.json"'

want_note="the sub-file chunk store (chunk_blobs + chunk_refs) is present"
verify_one "02-dedup" "$want02"
want_note="inter-channel (ICR) AND cross-stem residual are present"
verify_one "03-smallest" "$want03"
want_note="a WavPack-raw stream is present (float audio)"
verify_one "04-wavpack" "$want04"
want_note="junk disclosure + symlink records + whole-file dedup are present"
verify_one "05-housekeeping" "$want05"
want_note="the encrypted, split package rebuilt"
verify_one "06-gauntlet" "$want06"
want_note="plain hybrid packs rebuild with 7z + flac + the decoder"
verify_one "01-standard" "$want01"

# A separate synthetic historical-layout vector covers a dependency that the
# current writer does not produce. It is kept outside vectors/ so the six
# real-writer packages above retain their stated provenance.
if python3 "$REPO/tests/chained_residual.py" "$REF" "$SEVEN" >"$SCRATCH/chained-residual.log" 2>&1; then
  ok "chained residual: 3 files byte-exact; cycle and failed-anchor controls refused safely"
else
  bad "chained residual: historical dependency recovery failed"
  cat "$SCRATCH/chained-residual.log"
fi

# the split-volume guarantee, exercised explicitly: the 06 vector ships as
# volumes; its rebuild above already ran through the cat path.
if par2 verify -q "$VEC"/06-gauntlet.crate.par2 >/dev/null 2>&1 \
   || par2 v -q "$VEC"/06-gauntlet.crate.par2 >/dev/null 2>&1; then
  ok "PAR2 sidecars verify clean (06-gauntlet)"
else
  bad "PAR2 sidecars do not verify (06-gauntlet)"
fi

# the shipped tree must hash to its own manifest — catch a corrupted download
if ( cd "$VEC" && shasum -a 256 -c SHA256SUMS >"$SCRATCH/checksums.log" 2>&1 ); then
  ok "SHA256SUMS: every shipped file hashes clean"
else
  bad "SHA256SUMS: a shipped file does not match its recorded hash"
  grep -v ': OK$' "$SCRATCH/checksums.log" || cat "$SCRATCH/checksums.log"
fi

# Native case/Unicode alias checks can only engage on volumes with those alias
# rules. Their injected counterparts run on every host. Refuse any other skip.
portable_unittest_passed(){ python3 - "$1" "$2" "$3" <<'PY'
import re
import sys

log, suite, expected = sys.argv[1], sys.argv[2], int(sys.argv[3])
allowed_skips = {
    "empty-directories": {
        "test_existing_case_alias_refuses_without_writing_below_it":
            "skipped 'destination filesystem is case-sensitive'",
        "test_existing_unicode_alias_refuses_without_writing_below_it":
            "skipped 'destination filesystem does not alias these Unicode names'",
    },
    "path-safety": {
        "test_case_aliased_file_names_refused_before_publication":
            "skipped 'destination volume is case-sensitive'",
        "test_case_aliased_folders_refused_before_any_file_is_published":
            "skipped 'destination volume is case-sensitive'",
        "test_unicode_aliased_folders_refused_before_publication":
            "skipped 'destination volume keeps these Unicode names distinct'",
    },
}[suite]
with open(log, encoding="utf-8") as stream:
    output = stream.read()
statuses = re.findall(r"^(test_\w+) \([^\n]+\) \.\.\. (ok|skipped '[^\n]*')$",
                      output, re.MULTILINE)
skipped = {name: status for name, status in statuses if status.startswith("skipped ")}
summary = re.search(r"^Ran (\d+) tests in [^\n]+$", output, re.MULTILINE)
verdict = re.search(r"^OK(?: \(skipped=(\d+)\))?$", output, re.MULTILINE)
valid = (summary is not None and int(summary.group(1)) == expected
         and len(statuses) == expected
         and len({name for name, _ in statuses}) == expected
         and all(allowed_skips.get(name) == reason for name, reason in skipped.items())
         and verdict is not None and int(verdict.group(1) or 0) == len(skipped))
if not valid:
    print(f"{suite}: expected {expected} named tests, got {len(statuses)}; "
          f"skipped={skipped}; allowed={allowed_skips}")
sys.exit(0 if valid else 1)
PY
}

cat >"$SCRATCH/unexpected-skip.log" <<'EOF'
test_unexpected_control (__main__.Controls.test_unexpected_control) ... skipped 'unexpected'
----------------------------------------------------------------------
Ran 1 tests in 0.001s

OK (skipped=1)
EOF
if portable_unittest_passed "$SCRATCH/unexpected-skip.log" empty-directories 1 >/dev/null; then
  bad "unittest gate accepted an unexpected skipped control"
else
  ok "unittest gate refuses an unexpected skipped control"
fi

if python3 "$REPO/tests/recut176_bounded.py" >"$SCRATCH/bounded.log" 2>&1 \
   && grep -Eq '^Ran 15 tests ' "$SCRATCH/bounded.log" \
   && grep -qx 'OK' "$SCRATCH/bounded.log"; then
  ok "bounded decoder: 15 recovery, integrity and failure controls executed"
else
  bad "bounded decoder controls failed or did not all execute"
  tail -40 "$SCRATCH/bounded.log"
fi

if python3 "$REPO/tests/empty_directories.py" >"$SCRATCH/empty-directories.log" 2>&1 \
   && portable_unittest_passed "$SCRATCH/empty-directories.log" empty-directories 21; then
  ok "empty directories: 21 controls passed or had named filesystem exclusions"
else
  bad "empty-directory controls failed or did not all execute"
  tail -40 "$SCRATCH/empty-directories.log"
fi

if python3 "$REPO/tests/path_safety.py" "$REF" >"$SCRATCH/path-safety.log" 2>&1 \
   && portable_unittest_passed "$SCRATCH/path-safety.log" path-safety 18; then
  ok "path safety: 18 controls passed or had named filesystem exclusions"
else
  bad "path safety controls failed or did not all execute"
  tail -40 "$SCRATCH/path-safety.log"
fi

if python3 "$REPO/tests/exfat_publication.py" >"$SCRATCH/exfat-publication.log" 2>&1 \
   && grep -Eq '^Ran 12 tests ' "$SCRATCH/exfat-publication.log" \
   && grep -qx 'OK' "$SCRATCH/exfat-publication.log"; then
  ok "ExFAT publication: 12 private-tree, corruption, occupied-name and failure controls executed"
else
  bad "ExFAT publication controls failed or did not all execute"
  tail -40 "$SCRATCH/exfat-publication.log"
fi

[ "$checks" -eq 22 ] || { printf 'expected 22 checks, got %s\n' "$checks" >&2; exit 1; }

printf '\n%s\n' \
  "$([ $fails -eq 0 ] && printf 'RESULT: PASS — %s checks; every vector rebuilt byte-exactly with standard tools' "$checks" \
                           || printf 'RESULT: %s FAILURE(S) — %s checks executed; do not trust the escrow claim' "$fails" "$checks")"
[ $fails -eq 0 ]
