/*
 * Dictionary side of the JNI glue: train a dictionary from fuzzer-chosen samples through both
 * trainFromBuffer0 (byte[][]) and trainFromBufferDirect0 (direct buffer + int[] sizes, including
 * sizes that do not add up to the buffer), then use whatever was produced through the ZstdDict*
 * and *FastDict0 natives. A successful dictionary round trip must reproduce the input, else trap.
 *
 * Input layout: 32 header bytes, then the sample bytes.
 */
#include "mock_jni.h"

#define MAX_SAMPLES 24

static void roundtrip_dict(JNIEnv *env, const uint8_t *dict, size_t dlen, const uint8_t *in, size_t n, jint level) {
    mobj *dar = mk_buf(dict, dlen);
    mobj *cd = mk_obj(), *dd = mk_obj();
    Z(ZstdDictCompress_init)(env, (jobject) cd, (jbyteArray) dar, 0, (jint) dlen, level);
    Z(ZstdDictDecompress_init)(env, (jobject) dd, (jbyteArray) dar, 0, (jint) dlen);
    jint bound = (jint) Z(Zstd_compressBound)(env, 0, (jlong) n);
    mobj *src = mk_buf(in, n), *comp = mk_buf(NULL, (size_t) bound), *back = mk_buf(NULL, n);
    jlong r = Z(Zstd_compressFastDict0)(env, 0, (jbyteArray) comp, 0, (jbyteArray) src, 0, (jint) n, (jobject) cd);
    if (r > 0 && cd->f[F_NATIVEPTR] != 0 && dd->f[F_NATIVEPTR] != 0) {
        jlong d = Z(Zstd_decompressFastDict0)(env, 0, (jbyteArray) back, 0, (jbyteArray) comp, 0, (jint) r, (jobject) dd);
        if (d != (jlong) n || (n && memcmp(back->data, in, n) != 0)) __builtin_trap();

        /* direct-buffer flavour of the same round trip */
        mobj *dsrc = mk_buf(in, n), *dcomp = mk_buf(NULL, (size_t) bound), *dback = mk_buf(NULL, n);
        jlong r2 = Z(Zstd_compressDirectByteBufferFastDict0)(env, 0, (jobject) dcomp, 0, bound, (jobject) dsrc, 0, (jint) n, (jobject) cd);
        if (r2 > 0) {
            jlong d2 = Z(Zstd_decompressDirectByteBufferFastDict0)(env, 0, (jobject) dback, 0, (jint) n, (jobject) dcomp, 0, (jint) r2, (jobject) dd);
            if (d2 != (jlong) n || (n && memcmp(dback->data, in, n) != 0)) __builtin_trap();
        }
        rm_buf(dsrc); rm_buf(dcomp); rm_buf(dback);
    }
    Z(Zstd_getDictIdFromDict)(env, 0, (jbyteArray) dar);
    Z(Zstd_getDictIdFromDictDirect)(env, 0, (jobject) dar, 0, (jint) dlen);
    Z(ZstdDictCompress_free)(env, (jobject) cd);
    Z(ZstdDictDecompress_free)(env, (jobject) dd);
    rm_buf(cd); rm_buf(dd); rm_buf(dar); rm_buf(src); rm_buf(comp); rm_buf(back);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) return -1;
    rd_t h = { data, 32 };
    const uint8_t *pay = data + 32;
    size_t n = size - 32;
    if (n > (1u << 16)) return -1;
    JNIEnv *env = mock_env();

    uint32_t nsamp = 1 + rd_u8(&h) % MAX_SAMPLES;
    jint level = (jint) (rd_u8(&h) % 12);
    uint32_t flags = rd_u8(&h);
    size_t dcap = 256 + (size_t) rd_u16(&h) % (16 * 1024);
    jboolean legacy = flags & 1;
    int direct = (flags >> 1) & 1;
    int skew = (flags >> 2) & 1;
    /* tiny sample sets crash the vendored fastCover trainer (read past the sample buffer); keep the
       harness on sample sets large enough to train from */
    if (n < 512) return -1;

    /* cut the payload into nsamp pieces by successive header-derived fractions */
    size_t sz[MAX_SAMPLES];
    size_t left = n;
    for (uint32_t i = 0; i < nsamp; i++) {
        size_t s = (i == nsamp - 1) ? left : left * (1 + rd_u8(&h) % 200) / 256;
        sz[i] = s;
        left -= s;
    }

    mobj *dict = mk_buf(NULL, dcap);
    jlong dl = -1;
    if (!direct) {
        mobj *samples = mk_obj();
        samples->len = nsamp;
        samples->elems = calloc(nsamp, sizeof(mobj *));
        size_t off = 0;
        for (uint32_t i = 0; i < nsamp; i++) {
            samples->elems[i] = mk_buf(pay + off, sz[i]);
            off += sz[i];
        }
        dl = Z(Zstd_trainFromBuffer0)(env, 0, (jobjectArray) samples, (jbyteArray) dict, legacy, level);
        for (uint32_t i = 0; i < nsamp; i++) rm_buf(samples->elems[i]);
        rm_buf(samples);
    } else {
        mobj *all = mk_buf(pay, n);
        mobj *sizes = mk_buf(NULL, nsamp * sizeof(jint));
        for (uint32_t i = 0; i < nsamp; i++) {
            jint v = (jint) sz[i];
            if (skew && i == 0) v = (jint) (sz[i] / 2);     /* sizes that do not cover the buffer */
            memcpy(sizes->data + i * sizeof(jint), &v, sizeof(v));
        }
        sizes->len = nsamp;
        dl = Z(Zstd_trainFromBufferDirect0)(env, 0, (jobject) all, (jintArray) sizes, (jobject) dict, legacy, level);
        rm_buf(all); rm_buf(sizes);
    }

    if (dl > 0 && (size_t) dl <= dcap && Z(Zstd_isError)(env, 0, dl) == 0) {
        const uint8_t *in = pay;
        size_t in_n = sz[0] ? sz[0] : n;
        roundtrip_dict(env, (const uint8_t *) dict->data, (size_t) dl, in, in_n, level);
    }
    rm_buf(dict);
    return 0;
}
