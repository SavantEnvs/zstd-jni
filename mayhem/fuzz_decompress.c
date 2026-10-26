/*
 * Decompression side of the JNI glue, fed untrusted bytes: frame inspection (sizes, dict ids), one-shot
 * decompress into byte[] / direct buffers / raw pointers, ZstdDecompressCtx streaming, and the
 * InputStream / BufferDecompressingStream natives. Optionally the first part of the payload is used as a
 * dictionary (ZstdDictDecompress / loadDDict0 / loadDictDecompress).
 *
 * Input layout: 16 header bytes, then payload (a zstd frame, optionally preceded by a dictionary).
 */
#include "mock_jni.h"

#define MAX_DST (1 << 20)

static void inspect(JNIEnv *env, const uint8_t *p, size_t n, rd_t *h) {
    mobj *arr = mk_buf(p, n);
    mobj *dir = mk_buf(p, n);
    jint off = n ? (jint) (rd_u8(h) % (n + 1)) : 0;
    jint lim = (jint) (n - off);
    jboolean ml = rd_u8(h) & 1;

    Z(Zstd_decompressedSize0)(env, 0, (jbyteArray) arr, off, lim, ml);
    Z(Zstd_getFrameContentSize0)(env, 0, (jbyteArray) arr, off, lim, ml);
    Z(Zstd_findFrameCompressedSize0)(env, 0, (jbyteArray) arr, off, lim);
    Z(Zstd_getDictIdFromFrame)(env, 0, (jbyteArray) arr);
    Z(Zstd_getDictIdFromDict)(env, 0, (jbyteArray) arr);
    Z(Zstd_findDirectByteBufferFrameCompressedSize)(env, 0, (jobject) dir, off, lim);
    Z(Zstd_decompressedDirectByteBufferSize)(env, 0, (jobject) dir, off, lim, ml);
    Z(Zstd_getDirectByteBufferFrameContentSize)(env, 0, (jobject) dir, off, lim, ml);
    Z(Zstd_getDictIdFromFrameBuffer)(env, 0, (jobject) dir);
    Z(Zstd_getDictIdFromDictDirect)(env, 0, (jobject) dir, off, lim);
    Z(Zstd_getErrorName)(env, 0, -(jlong) (rd_u8(h) % 100));
    rm_buf(arr);
    rm_buf(dir);
}

static void oneshot(JNIEnv *env, jlong dctx, const uint8_t *p, size_t n, jlong content, rd_t *h) {
    jint cap = (content > 0 && content <= MAX_DST) ? (jint) content : (jint) (1u << (rd_u8(h) % 20));
    jint doff = (jint) (rd_u8(h) % 4);
    mobj *src = mk_buf(p, n);
    mobj *dsta = mk_buf(NULL, (size_t) cap + doff);
    mobj *srcd = mk_buf(p, n);
    mobj *dstd = mk_buf(NULL, (size_t) cap + doff);

    Z(ZstdDecompressCtx_decompressByteArray0)(env, 0, dctx, (jbyteArray) dsta, doff, cap, (jbyteArray) src, 0, (jint) n);
    Z(ZstdDecompressCtx_decompressDirectByteBuffer0)(env, 0, dctx, (jobject) dstd, doff, cap, (jobject) srcd, 0, (jint) n);
    Z(ZstdDecompressCtx_decompressByteArrayToDirectByteBuffer0)(env, 0, dctx, (jobject) dstd, doff, cap, (jbyteArray) src, 0, (jint) n);
    Z(ZstdDecompressCtx_decompressDirectByteBufferToByteArray0)(env, 0, dctx, (jbyteArray) dsta, doff, cap, (jobject) srcd, 0, (jint) n);
    Z(Zstd_decompressUnsafe)(env, 0, (jlong) (intptr_t) dsta->data, cap, (jlong) (intptr_t) src->data, (jlong) n);

    rm_buf(src); rm_buf(dsta); rm_buf(srcd); rm_buf(dstd);
}

static void ctx_stream(JNIEnv *env, jlong dctx, const uint8_t *p, size_t n, int variant, rd_t *h) {
    jint chunk = (jint) (1 + rd_u16(h) % 4096);
    jint dcap = (jint) (1 + rd_u16(h) % 8192);
    mobj *src = mk_buf(p, n);
    mobj *dst = mk_buf(NULL, (size_t) dcap);
    mobj *srcd = mk_buf(p, n);
    mobj *dstd = mk_buf(NULL, (size_t) dcap);
    jint soff = 0;
    for (int it = 0; it < 2000; it++) {
        jint ssz = (jint) n - soff < chunk ? (jint) n : soff + chunk;
        jlong r = 0;
        switch (variant) {
        case 0: r = Z(ZstdDecompressCtx_decompressByteArrayStream0)(env, 0, dctx, (jbyteArray) dst, 0, 0, dcap, (jbyteArray) src, 0, soff, ssz); break;
        case 1: r = Z(ZstdDecompressCtx_decompressDirectByteBufferStream0)(env, 0, dctx, (jobject) dstd, 0, dcap, (jobject) srcd, soff, ssz); break;
        case 2: r = Z(ZstdDecompressCtx_decompressByteArrayToDirectByteBufferStream0)(env, 0, dctx, (jobject) dstd, 0, dcap, (jbyteArray) src, 0, soff, ssz); break;
        default: r = Z(ZstdDecompressCtx_decompressDirectByteBufferToByteArrayStream0)(env, 0, dctx, (jbyteArray) dst, 0, 0, dcap, (jobject) srcd, soff, ssz); break;
        }
        if (r & (1ULL << 63)) break;                    /* frame complete */
        if (((uint64_t) r >> 32) == 0 && (r & (1ULL << 31))) break; /* error */
        jint nsoff = (jint) (r & 0x7fffffff);
        jint ndoff = (jint) ((r >> 32) & 0x7fffffff);
        if (nsoff == soff && ndoff == 0) break;
        soff = nsoff;
    }
    rm_buf(src); rm_buf(dst); rm_buf(srcd); rm_buf(dstd);
}

static void input_stream(JNIEnv *env, const uint8_t *p, size_t n, rd_t *h) {
    mobj *self = mk_obj();
    jint csz = (jint) (1 + rd_u16(h) % 4096);
    jlong ds = Z(ZstdInputStreamNoFinalizer_createDStream)(env, (jclass) self);
    Z(ZstdInputStreamNoFinalizer_initDStream)(env, (jclass) self, ds);
    mobj *src = mk_buf(p, n);
    jint dcap = (jint) Z(ZstdInputStreamNoFinalizer_recommendedDOutSize)(env, (jclass) self);
    mobj *dst = mk_buf(NULL, (size_t) dcap);
    jint limit = 0;
    for (int it = 0; it < 2000; it++) {
        limit = (jint) n - (jint) self->f[F_SRCPOS] < csz ? (jint) n : (jint) self->f[F_SRCPOS] + csz;
        self->f[F_DSTPOS] = 0;
        jlong r = Z(ZstdInputStreamNoFinalizer_decompressStream)(env, (jclass) self, ds, (jbyteArray) dst, dcap, (jbyteArray) src, limit);
        if (r < 0) break;
        if (self->f[F_SRCPOS] >= (jlong) n && self->f[F_DSTPOS] == 0) break;
    }
    Z(ZstdInputStreamNoFinalizer_resetDStream)(env, (jclass) self, ds);
    Z(ZstdInputStreamNoFinalizer_freeDStream)(env, (jclass) self, ds);
    rm_buf(src); rm_buf(dst); rm_buf(self);
}

static void buffer_streams(JNIEnv *env, const uint8_t *p, size_t n, rd_t *h) {
    jint dcap = (jint) (1 + rd_u16(h) % 8192);
    {
        mobj *self = mk_obj();
        jlong ds = Z(ZstdBufferDecompressingStreamNoFinalizer_createDStreamNative)(env, (jclass) self);
        Z(ZstdBufferDecompressingStreamNoFinalizer_initDStreamNative)(env, (jclass) self, ds);
        mobj *src = mk_buf(p, n), *dst = mk_buf(NULL, (size_t) dcap);
        jint soff = 0;
        for (int it = 0; it < 2000; it++) {
            jlong r = Z(ZstdBufferDecompressingStreamNoFinalizer_decompressStreamNative)(env, (jclass) self, ds, (jbyteArray) dst, 0, dcap, (jbyteArray) src, soff, (jint) n - soff);
            soff += (jint) self->f[F_CONSUMED];
            if (r <= 0 && (r < 0 || soff >= (jint) n)) break;
            if (soff >= (jint) n && self->f[F_PRODUCED] == 0) break;
        }
        Z(ZstdBufferDecompressingStreamNoFinalizer_freeDStreamNative)(env, (jclass) self, ds);
        rm_buf(src); rm_buf(dst); rm_buf(self);
    }
    {
        mobj *self = mk_obj();
        jlong ds = Z(ZstdDirectBufferDecompressingStreamNoFinalizer_createDStreamNative)(env, (jclass) self);
        Z(ZstdDirectBufferDecompressingStreamNoFinalizer_initDStreamNative)(env, (jclass) self, ds);
        mobj *src = mk_buf(p, n), *dst = mk_buf(NULL, (size_t) dcap);
        jint soff = 0;
        for (int it = 0; it < 2000; it++) {
            jlong r = Z(ZstdDirectBufferDecompressingStreamNoFinalizer_decompressStreamNative)(env, (jclass) self, ds, (jobject) dst, 0, dcap, (jobject) src, soff, (jint) n - soff);
            soff += (jint) self->f[F_CONSUMED];
            if (r <= 0 && (r < 0 || soff >= (jint) n)) break;
            if (soff >= (jint) n && self->f[F_PRODUCED] == 0) break;
        }
        Z(ZstdDirectBufferDecompressingStreamNoFinalizer_freeDStreamNative)(env, (jclass) self, ds);
        rm_buf(src); rm_buf(dst); rm_buf(self);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return -1;
    rd_t h = { data, 16 };
    const uint8_t *pay = data + 16;
    size_t n = size - 16;
    JNIEnv *env = mock_env();

    uint32_t mode = rd_u8(&h);
    uint32_t dictlen = rd_u8(&h);
    mobj *dict = NULL;
    if (mode & 1) {                       /* dictionary = leading bytes of the payload */
        if (dictlen > n) dictlen = (uint32_t) n;
        dict = mk_buf(pay, dictlen);
        pay += dictlen;
        n -= dictlen;
    }

    jlong dctx = Z(ZstdDecompressCtx_init)(env, 0);
    if (mode & 2) Z(Zstd_setDecompressionMagicless)(env, 0, dctx, 1);
    if (mode & 4) Z(Zstd_setDecompressionLongMax)(env, 0, dctx, 10 + (jint) (rd_u8(&h) % 18));
    if (mode & 8) Z(Zstd_setRefMultipleDDicts)(env, 0, dctx, 1);

    mobj *ddict = NULL;
    if (dict) {
        switch ((mode >> 4) & 3) {
        case 0: Z(ZstdDecompressCtx_loadDDict0)(env, 0, dctx, (jbyteArray) dict); break;
        case 1: Z(Zstd_loadDictDecompress)(env, 0, dctx, (jbyteArray) dict, (jint) dict->len); break;
        default:
            ddict = mk_obj();
            if ((mode >> 4) & 1) Z(ZstdDictDecompress_init)(env, (jobject) ddict, (jbyteArray) dict, 0, (jint) dict->len);
            else Z(ZstdDictDecompress_initDirect)(env, (jobject) ddict, (jobject) dict, 0, (jint) dict->len, 0);
            Z(ZstdDecompressCtx_loadDDictFast0)(env, 0, dctx, (jobject) ddict);
            break;
        }
    }

    inspect(env, pay, n, &h);

    mobj *fr = mk_buf(pay, n);
    jlong content = Z(Zstd_getFrameContentSize0)(env, 0, (jbyteArray) fr, 0, (jint) n, (mode >> 1) & 1);
    rm_buf(fr);
    oneshot(env, dctx, pay, n, content, &h);

    if (ddict) {
        mobj *src = mk_buf(pay, n);
        mobj *dst = mk_buf(NULL, 1 << 12);
        Z(Zstd_decompressFastDict0)(env, 0, (jbyteArray) dst, 0, (jbyteArray) src, 0, (jint) n, (jobject) ddict);
        rm_buf(src); rm_buf(dst);
    }

    ctx_stream(env, dctx, pay, n, (mode >> 6) & 3, &h);
    Z(ZstdDecompressCtx_reset0)(env, 0, dctx);
    Z(ZstdDecompressCtx_free)(env, 0, dctx);

    if (!(mode & 1)) {
        input_stream(env, pay, n, &h);
        buffer_streams(env, pay, n, &h);
    }

    if (ddict) { Z(ZstdDictDecompress_free)(env, (jobject) ddict); rm_buf(ddict); }
    rm_buf(dict);
    return 0;
}
