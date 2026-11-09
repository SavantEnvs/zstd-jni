#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer checks of the zstd-jni JNI glue, run through mayhem/kat (built by
# build.sh with normal flags). Every check compares produced bytes with upstream's committed fixtures
# (src/test/resources) via cmp, so a no-op / exit(0) replacement of the library or the probe fails.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

KAT=/mayhem/kat
R=src/test/resources
[ -x "$KAT" ] || { echo "missing $KAT — mayhem/build.sh did not produce it" >&2; emit_ctrf zstd-jni-kat 0 1; exit 1; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

passed=0; failed=0
ok()   { echo "PASS $1"; passed=$((passed+1)); }
fail() { echo "FAIL $1" >&2; failed=$((failed+1)); }

# check <name> <expected-file> <output-file> <expected stdout|""> -- <kat args...>
check() {
  local name="$1" want="$2" got="$3" line="$4"; shift 5
  rm -f "$got"
  local out
  out=$("$KAT" "$@" 2>"$W/err") || { fail "$name (kat exit $?: $(head -c 200 "$W/err"))"; return; }
  [ -s "$got" ] || { fail "$name (no output written)"; return; }
  if [ -n "$line" ] && [ "$out" != "$line" ]; then fail "$name (stdout '$out' != '$line')"; return; fi
  cmp -s "$want" "$got" && ok "$name" || fail "$name (output differs from $want)"
}

# decompression of upstream's fixtures reproduces the original bytes
check "decompress sized frame"      $R/xmlsmall "$W/o" "size=102 id=0" -- decomp $R/xmlsmall-sized.zst "$W/o"
for f in xml-1 xml-3 xml-6 xml-9 xml-advanced xml-1-sized; do
  check "stream-decompress $f.zst"  $R/xml "$W/o" "" -- sdecomp $R/$f.zst "$W/o"
done

# compression output is a zstd frame (magic 28 b5 2f fd) that decompresses back to the input
for l in 1 3 9 19; do
  rm -f "$W/c"
  "$KAT" comp $l $R/xmlsmall "$W/c" >/dev/null 2>&1
  magic=$(head -c 4 "$W/c" 2>/dev/null | od -An -tx1 | tr -d ' \n')
  if [ "$magic" = "28b52ffd" ]; then ok "compress level $l magic"; else fail "compress level $l magic ('$magic')"; fi
  check "compress level $l round trip" $R/xmlsmall "$W/o" "size=102 id=0" -- decomp "$W/c" "$W/o"
done

rm -f "$W/c"
"$KAT" comp 3 $R/xml "$W/c" >/dev/null 2>&1
csz=$(stat -c %s "$W/c" 2>/dev/null || echo 0)
if [ "$csz" -gt 100000 ] && [ "$csz" -lt 1000000 ]; then ok "compress xml size plausible ($csz)"; else fail "compress xml size ($csz)"; fi
check "compress xml round trip" $R/xml "$W/o" "size=5345280 id=0" -- decomp "$W/c" "$W/o"

# streaming natives: compress with the output-stream natives, decompress with the input-stream natives
head -c 700000 $R/xml > "$W/part"
check "output/input stream round trip" "$W/part" "$W/o" "" -- stream "$W/part" "$W/o"

# a truncated frame must be rejected, not silently accepted
head -c 5000 $R/xml-3.zst > "$W/trunc.zst"
rm -f "$W/o"
if "$KAT" sdecomp "$W/trunc.zst" "$W/o" >/dev/null 2>&1; then
  # accepted only if the probe reports a complete frame, which a truncated one never is
  fail "truncated frame accepted"
else
  ok "truncated frame rejected"
fi

emit_ctrf zstd-jni-kat "$passed" "$failed"
