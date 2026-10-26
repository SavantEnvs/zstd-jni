#!/usr/bin/env bash
#
# mayhem/build.sh — build the zstd-jni fuzz harnesses and the known-answer test probe.
#
# The JNI glue (src/main/native/jni_*.c) is compiled UNMODIFIED together with the vendored zstd
# sources and driven through a mock JNIEnv (mayhem/mock_jni.h), so no JDK is needed. The library is
# built twice: instrumented ($SANITIZER_FLAGS + DWARF 3 + libFuzzer coverage) for the fuzz and
# -standalone binaries, and with plain -O2 for the test probe (mayhem/kat) that test.sh runs.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
N=src/main/native
OUT=build/mayhem
rm -rf "$OUT"
mkdir -p "$OUT/fuzz" "$OUT/plain"

LIB_SRCS=$(ls $N/common/*.c $N/compress/*.c $N/decompress/*.c $N/dictBuilder/*.c $N/jni_*.c)
INC="-Ijni -I$N -I$N/common -I$N/compress -I$N/decompress -I$N/dictBuilder"
DEFS="-DZSTD_MULTITHREAD=1 -D_GNU_SOURCE"

# 1) instrumented library. ZSTD_DISABLE_ASM keeps the Huffman decoder in C so ASan/UBSan see it.
compile_fuzz() {
  local f="$1"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 $DEFS -DZSTD_DISABLE_ASM=1 $INC \
      -c "$f" -o "$OUT/fuzz/$(echo "$f" | tr '/' '_').o"
}
export -f compile_fuzz
export OUT INC DEFS
printf '%s\n' $LIB_SRCS | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'compile_fuzz {}'
ar rcs "$OUT/fuzz/libzstdjni.a" "$OUT"/fuzz/*.o

# 2) harnesses: fuzzer binary + standalone run-once reproducer, both with leak detection switched off
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
for t in fuzz_decompress fuzz_compress fuzz_dict; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 $INC -Wall -Wno-unused-function \
      -c "mayhem/$t.c" -o "$OUT/$t.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$t.o" "$OUT/fuzz/libzstdjni.a" "$OUT/lsan_off.o" \
      -lpthread -o "/mayhem/$t"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$t.o" "$OUT/fuzz/libzstdjni.a" "$OUT/lsan_off.o" \
      -lpthread -o "/mayhem/$t-standalone"
done

# 3) test probe with the project's normal flags (ASM Huffman decoder on, no sanitizers)
printf '%s\n' $LIB_SRCS | xargs -P "$MAYHEM_JOBS" -I{} bash -c \
  "$CC -O2 $COVERAGE_FLAGS $DEFS $INC -c {} -o $OUT/plain/\$(echo {} | tr '/' '_').o"
$CC -O2 $COVERAGE_FLAGS -c $N/decompress/huf_decompress_amd64.S -o "$OUT/plain/huf_amd64.o" 2>/dev/null || true
$CC -O2 $COVERAGE_FLAGS $INC -Wall -Wno-unused-function -c mayhem/kat.c -o "$OUT/plain/kat_main.o"
$CC -O2 $COVERAGE_FLAGS "$OUT"/plain/*.o -lpthread -o /mayhem/kat
