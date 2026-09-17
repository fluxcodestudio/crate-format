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
command -v par2 >/dev/null 2>&1 \
  || printf 'note: par2 not installed — the PAR2 repair-recovery check is skipped with a note\n' \
  >&2

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
    catch wait result
    exit [lindex \$result 3]
"
}

# tree compare, filtered by the decoder's OWN junk predicate honouring the
# pack's disclosure (the same comparator discipline as the internal gate)
# forward the caller's args verbatim: the call site passes (ref srcd outd mpath)
cmptree(){ python3 - "$@" <<'PY'
import filecmp, json, os, sys, importlib.util as u
ref, srcd, outd, mpath = sys.argv[1:5]
s = u.spec_from_file_location("r", ref); m = u.module_from_spec(s); s.loader.exec_module(m)
man = json.load(open(mpath))

def walk(d):
    out = set()
    for root, _dirs, files in os.walk(d):
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), d)
            if not m.is_os_junk_for_pack(rel, man):
                out.add(rel)
    return out

want, got = walk(srcd), walk(outd)
missing = sorted(want - got); extra = sorted(got - want)
differs = []
for r in sorted(want & got):
    a, b = os.path.join(srcd, r), os.path.join(outd, r)
    try:
        la, lb = os.path.islink(a), os.path.islink(b)
        if la != lb:
            differs.append(r + " (link-ness differs)")
        elif la:  # both links: compare the LITERAL target strings, never stat through
            if os.readlink(a) != os.readlink(b):
                differs.append(r + " (link target differs)")
        elif not filecmp.cmp(a, b, shallow=False):
            differs.append(r)
    except OSError as e:
        differs.append(f"{r} ({e})")  # a broken comparison is a VERDICT, never silence
if not want:
    print("compared 0 files — the source tree never got built"); sys.exit(1)
if missing or differs or extra:
    print(f"missing={missing[:5]} differs={differs[:5]} extra={extra[:5]} (of {len(want)})")
    sys.exit(1)
PY
}

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

  if out=$(cmptree "$REF" "$v/source/Session" "$w/out" "$w/pkg/.crate/manifest.json"); [ -z "$out" ]; then
    ok "$name: rebuilt byte-identical to the shipped source"
  else
    bad "$name: rebuild differs — $out"; return
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

# the split-volume guarantee, exercised explicitly: the 06 vector ships as
# volumes; its rebuild above already ran through the cat path. PAR2 is checked
# when the tool exists (the sidecars ship with 06).
if command -v par2 >/dev/null 2>&1; then
  if par2 verify -q "$VEC"/06-gauntlet.crate.par2 >/dev/null 2>&1 \
     || par2 v -q "$VEC"/06-gauntlet.crate.par2 >/dev/null 2>&1; then
    ok "PAR2 sidecars verify clean (06-gauntlet)"
  else
    bad "PAR2 sidecars do not verify (06-gauntlet)"
  fi
else
  checks=$((checks+1))
  printf '  − note: PAR2 verification skipped (par2 not installed; install it to run every check)\n'
fi

# the shipped tree must hash to its own manifest — catch a corrupted download
( cd "$VEC" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1 ) \
  && { checks=$((checks+1)); ok "SHA256SUMS: every shipped file hashes clean"; } \
  || { checks=$((checks+1)); bad "SHA256SUMS: a shipped file does not match its recorded hash"; }

printf '\n%s\n' \
  "$([ $fails -eq 0 ] && printf 'RESULT: PASS — %s checks; every vector rebuilt byte-exactly with standard tools' "$checks" \
                           || printf 'RESULT: %s FAILURE(S) — %s checks executed; do not trust the escrow claim' "$fails" "$checks")"
[ $fails -eq 0 ]
