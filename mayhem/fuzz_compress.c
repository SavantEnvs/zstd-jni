/*
 * Compression side of the JNI glue with a round-trip oracle: the payload is compressed through the
 * byte[] / direct-buffer / stream / OutputStream natives with fuzzer-chosen parameters (level, checksum,
 * long-distance matching, workers, window/hash/chain logs, an optional content dictionary), then
 * decompressed through the JNI decompress natives and compared to the input. Any mismatch traps.
 *
 * Input layout: 32 header bytes, then the payload to compress.
 */
#include "mock_jni.h"

typedef struct {
    jint level, checksum, content, dictid, magicless;
    jint extra, wlog, hlog, clog, slog, mml, tlen, strat, ldm, workers, job, overlap;
} prm_t;

static void parse_params(prm_t *p, rd_t *h) {
    uint32_t b0 = rd_u8(h), f = rd_u8(h), g = rd_u8(h);
    p->level = (jint) ((int8_t) b0 % 17);
    p->checksum = f & 1;
    p->content = (f >> 1) & 1;
    p->dictid = (f >> 2) & 1;
    p->magicless = (f >> 3) & 1;
    p->extra = (f >> 4) & 1;
    p->ldm = (f >> 5) & 3;
    p->workers = (g & 1) ? 1 + (jint) ((g >> 1) & 1) : 0;
    p->wlog = 10 + (jint) (rd_u8(h) % 12);
    p->hlog = 6 + (jint) (rd_u8(h) % 13);
    p->clog = 6 + (jint) (rd_u8(h) % 13);
    p->slog = 1 + (jint) (rd_u8(h) % 10);
    p->mml = 3 + (jint) (rd_u8(h) % 5);
    p->tlen = (jint) (rd_u8(h) % 64);
    p->strat = 1 + (jint) (rd_u8(h) % 9);
    uint32_t jb = rd_u16(h);
    p->job = (g & 4) ? (jint) (jb * 16) : 0;
    p->overlap = (jint) (rd_u8(h) % 10);
}

static jlong mk_cctx(JNIEnv *env, const prm_t *p) {
    jlong c = Z(ZstdCompressCtx_init)(env, 0);
    Z(ZstdCompressCtx_setLevel0)(env, 0, c, p->level);
    Z(ZstdCompressCtx_setChecksum0)(env, 0, c, (jboolean) p->checksum);
    Z(ZstdCompressCtx_setContentSize0)(env, 0, c, (jboolean) p->content);
    Z(ZstdCompressCtx_setDictID0)(env, 0, c, (jboolean) p->dictid);
    if (p->magicless) Z(Zstd_setCompressionMagicless)(env, 0, c, 1);
    if (p->ldm) Z(Zstd_setEnableLongDistanceMatching)(env, 0, c, p->ldm);
    if (p->workers) {
        Z(Zstd_setCompressionWorkers)(env, 0, c, p->workers);
        if (p->job) Z(Zstd_setCompressionJobSize)(env, 0, c, p->job);
        Z(Zstd_setCompressionOverlapLog)(env, 0, c, p->overlap);
    }
    if (p->extra) {
        Z(Zstd_setCompressionWindowLog)(env, 0, c, p->wlog);
        Z(Zstd_setCompressionHashLog)(env, 0, c, p->hlog);
        Z(Zstd_setCompressionChainLog)(env, 0, c, p->clog);
        Z(Zstd_setCompressionSearchLog)(env, 0, c, p->slog);
        Z(Zstd_setCompressionMinMatch)(env, 0, c, p->mml);
        Z(Zstd_setCompressionTargetLength)(env, 0, c, p->tlen);
        Z(Zstd_setCompressionStrategy)(env, 0, c, p->strat);
    }
    return c;
}

static jlong mk_dctx(JNIEnv *env, const prm_t *p) {
    jlong d = Z(ZstdDecompressCtx_init)(env, 0);
    if (p->magicless) Z(Zstd_setDecompressionMagicless)(env, 0, d, 1);
    Z(Zstd_setDecompressionLongMax)(env, 0, d, 31);
    return d;
}

typedef struct { uint8_t *p; size_t n, cap; } vec_t;
static void vec_add(vec_t *v, const void *src, size_t n) {
    if (v->n + n > v->cap) { v->cap = (v->n + n) * 2 + 64; v->p = realloc(v->p, v->cap); }
    if (n) memcpy(v->p + v->n, src, n);
    v->n += n;
}

static void roundtrip(JNIEnv *env, jlong dctx, const uint8_t *comp, size_t clen, const uint8_t *orig, size_t n) {
    mobj *src = mk_buf(comp, clen);
    mobj *dst = mk_buf(NULL, n);
    jlong r = Z(ZstdDecompressCtx_decompressByteArray0)(env, 0, dctx, (jbyteArray) dst, 0, (jint) n, (jbyteArray) src, 0, (jint) clen);
    if (r != (jlong) n || (n && memcmp(dst->data, orig, n) != 0)) __builtin_trap();
    rm_buf(src);
    rm_buf(dst);
}

static void compress_oneshot(JNIEnv *env, const prm_t *p, const uint8_t *in, size_t n, jlong dctx, int variant) {
    jlong c = mk_cctx(env, p);
    jint bound = (jint) Z(Zstd_compressBound)(env, 0, (jlong) n);
    mobj *src = mk_buf(in, n), *dst = mk_buf(NULL, (size_t) bound + 3);
    jlong r;
    if (variant == 0)
        r = Z(ZstdCompressCtx_compressByteArray0)(env, 0, c, (jbyteArray) dst, 3, bound, (jbyteArray) src, 0, (jint) n);
    else if (variant == 1)
        r = Z(ZstdCompressCtx_compressDirectByteBuffer0)(env, 0, c, (jobject) dst, 3, bound, (jobject) src, 0, (jint) n);
    else
        r = Z(Zstd_compressUnsafe)(env, 0, (jlong) (intptr_t) dst->data + 3, bound, (jlong) (intptr_t) src->data, (jlong) n, p->level, (jboolean) p->checksum);
    if (r > 0 && variant != 2) roundtrip(env, dctx, (uint8_t *) dst->data + 3, (size_t) r, in, n);
    if (r > 0 && variant == 2) {
        prm_t q = *p; q.magicless = 0;
        jlong d2 = mk_dctx(env, &q);
        roundtrip(env, d2, (uint8_t *) dst->data + 3, (size_t) r, in, n);
        Z(ZstdDecompressCtx_free)(env, 0, d2);
    }
    rm_buf(src); rm_buf(dst);
    Z(ZstdCompressCtx_free)(env, 0, c);
}

static void compress_stream(JNIEnv *env, const prm_t *p, const uint8_t *in, size_t n, jlong dctx, int variant, rd_t *h) {
    jlong c = mk_cctx(env, p);
    jint chunk = (jint) (1 + rd_u16(h) % 8192);
    jint ocap = (jint) (1 + rd_u16(h) % 4096);
    mobj *src = mk_buf(in, n), *dst = mk_buf(NULL, (size_t) ocap);
    vec_t out = { 0 };
    jint soff = 0;
    int done = 0;
    for (int it = 0; it < 20000 && !done; it++) {
        jint end_op = (soff >= (jint) n) ? 2 : (rd_u8(h) % 7 == 0 ? 1 : 0);
        jint ssz = ((jint) n - soff < chunk) ? (jint) n : soff + chunk;
        jlong r;
        switch (variant) {
        case 0: r = Z(ZstdCompressCtx_compressByteArrayStream0)(env, 0, c, (jbyteArray) dst, 0, 0, ocap, (jbyteArray) src, 0, soff, ssz, end_op); break;
        case 1: r = Z(ZstdCompressCtx_compressDirectByteBufferStream0)(env, 0, c, (jobject) dst, 0, ocap, (jobject) src, soff, ssz, end_op); break;
        case 2: r = Z(ZstdCompressCtx_compressByteArrayToDirectByteBufferStream0)(env, 0, c, (jobject) dst, 0, ocap, (jbyteArray) src, 0, soff, ssz, end_op); break;
        default: r = Z(ZstdCompressCtx_compressDirectByteBufferToByteArrayStream0)(env, 0, c, (jbyteArray) dst, 0, 0, ocap, (jobject) src, soff, ssz, end_op); break;
        }
        if (((uint64_t) r >> 32) == 0 && (r & (1ULL << 31))) goto out;   /* encoded error */
        jint nd = (jint) (((uint64_t) r >> 32) & 0x7fffffff);
        jint ns = (jint) (r & 0x7fffffff);
        vec_add(&out, dst->data, (size_t) nd);
        soff = ns;
        if ((r & (1ULL << 63)) && end_op == 2) done = 1;
    }
    if (done) roundtrip(env, dctx, out.p, out.n, in, n);
out:
    free(out.p);
    rm_buf(src); rm_buf(dst);
    Z(ZstdCompressCtx_free)(env, 0, c);
}

static void output_stream(JNIEnv *env, const prm_t *p, const uint8_t *in, size_t n, jlong dctx, rd_t *h) {
    mobj *self = mk_obj();
    jlong cs = Z(ZstdOutputStreamNoFinalizer_createCStream)(env, (jclass) self);
    Z(ZstdOutputStreamNoFinalizer_resetCStream)(env, (jclass) self, cs);
    Z(Zstd_setCompressionLevel)(env, 0, cs, p->level);
    Z(Zstd_setCompressionChecksums)(env, 0, cs, (jboolean) p->checksum);
    if (p->magicless) Z(Zstd_setCompressionMagicless)(env, 0, cs, 1);
    if (p->workers) Z(Zstd_setCompressionWorkers)(env, 0, cs, p->workers);
    jint ocap = (jint) Z(ZstdOutputStreamNoFinalizer_recommendedCOutSize)(env, (jclass) self);
    mobj *src = mk_buf(in, n), *dst = mk_buf(NULL, (size_t) ocap);
    vec_t out = { 0 };
    int ok = 1;
    self->f[F_SRCPOS] = 0;
    for (int it = 0; it < 20000 && self->f[F_SRCPOS] < (jlong) n; it++) {
        self->f[F_DSTPOS] = 0;
        jlong r = Z(ZstdOutputStreamNoFinalizer_compressStream)(env, (jclass) self, cs, (jbyteArray) dst, ocap, (jbyteArray) src, (jint) n);
        if (r < 0) { ok = 0; break; }
        vec_add(&out, dst->data, (size_t) self->f[F_DSTPOS]);
        if (rd_u8(h) % 5 == 0) {
            self->f[F_DSTPOS] = 0;
            r = Z(ZstdOutputStreamNoFinalizer_flushStream)(env, (jclass) self, cs, (jbyteArray) dst, ocap);
            if (r < 0) { ok = 0; break; }
            vec_add(&out, dst->data, (size_t) self->f[F_DSTPOS]);
        }
    }
    for (int it = 0; ok && it < 20000; it++) {
        self->f[F_DSTPOS] = 0;
        jlong r = Z(ZstdOutputStreamNoFinalizer_endStream)(env, (jclass) self, cs, (jbyteArray) dst, ocap);
        if (r < 0) { ok = 0; break; }
        vec_add(&out, dst->data, (size_t) self->f[F_DSTPOS]);
        if (r == 0) break;
    }
    if (ok) roundtrip(env, dctx, out.p, out.n, in, n);
    free(out.p);
    Z(ZstdOutputStreamNoFinalizer_freeCStream)(env, (jclass) self, cs);
    rm_buf(src); rm_buf(dst); rm_buf(self);
}

static void direct_stream(JNIEnv *env, const prm_t *p, const uint8_t *in, size_t n, jlong dctx, rd_t *h) {
    mobj *self = mk_obj();
    jlong cs = Z(ZstdDirectBufferCompressingStreamNoFinalizer_createCStream)(env, (jclass) self);
    Z(ZstdDirectBufferCompressingStreamNoFinalizer_initCStream)(env, (jclass) self, cs, p->level);
    jint ocap = 1 + (jint) (rd_u16(h) % 4096);
    mobj *src = mk_buf(in, n), *dst = mk_buf(NULL, (size_t) ocap);
    vec_t out = { 0 };
    jint soff = 0;
    int ok = 1;
    for (int it = 0; it < 20000 && soff < (jint) n; it++) {
        jlong r = Z(ZstdDirectBufferCompressingStreamNoFinalizer_compressDirectByteBuffer)(env, (jclass) self, cs, (jobject) dst, 0, ocap, (jobject) src, soff, (jint) n - soff);
        if (r < 0) { ok = 0; break; }
        vec_add(&out, dst->data, (size_t) self->f[F_PRODUCED]);
        soff += (jint) self->f[F_CONSUMED];
        if (self->f[F_CONSUMED] == 0 && self->f[F_PRODUCED] == 0) { ok = 0; break; }
    }
    for (int it = 0; ok && it < 20000; it++) {
        jlong r = Z(ZstdDirectBufferCompressingStreamNoFinalizer_endStream)(env, (jclass) self, cs, (jobject) dst, 0, ocap);
        if (r < 0) { ok = 0; break; }
        vec_add(&out, dst->data, (size_t) self->f[F_PRODUCED]);
        if (r == 0) break;
    }
    if (ok) {
        prm_t q = *p; q.magicless = 0;
        jlong d2 = mk_dctx(env, &q);
        roundtrip(env, d2, out.p, out.n, in, n);
        Z(ZstdDecompressCtx_free)(env, 0, d2);
    }
    (void) dctx;
    free(out.p);
    Z(ZstdDirectBufferCompressingStreamNoFinalizer_freeCStream)(env, (jclass) self, cs);
    rm_buf(src); rm_buf(dst); rm_buf(self);
}

static void with_dict(JNIEnv *env, const prm_t *p, const uint8_t *dict, size_t dlen, const uint8_t *in, size_t n, int variant) {
    mobj *dar = mk_buf(dict, dlen);
    /* the FastDict one-shot compress takes none of the ctx params, so its frames always carry the magic */
    prm_t dp = *p;
    if (variant == 3) dp.magicless = 0;
    jlong c = mk_cctx(env, p), d = mk_dctx(env, &dp);
    mobj *cd = mk_obj(), *dd = mk_obj();
    jint bound = (jint) Z(Zstd_compressBound)(env, 0, (jlong) n);
    mobj *src = mk_buf(in, n), *dst = mk_buf(NULL, (size_t) bound);
    jlong r = -1;
    switch (variant) {
    case 0:
        Z(ZstdCompressCtx_loadCDict0)(env, 0, c, (jbyteArray) dar);
        Z(ZstdDecompressCtx_loadDDict0)(env, 0, d, (jbyteArray) dar);
        r = Z(ZstdCompressCtx_compressByteArray0)(env, 0, c, (jbyteArray) dst, 0, bound, (jbyteArray) src, 0, (jint) n);
        break;
    case 1:
        Z(Zstd_loadDictCompress)(env, 0, c, (jbyteArray) dar, (jint) dlen);
        Z(Zstd_loadDictDecompress)(env, 0, d, (jbyteArray) dar, (jint) dlen);
        r = Z(ZstdCompressCtx_compressByteArray0)(env, 0, c, (jbyteArray) dst, 0, bound, (jbyteArray) src, 0, (jint) n);
        break;
    default:
        Z(ZstdDictCompress_init)(env, (jobject) cd, (jbyteArray) dar, 0, (jint) dlen, p->level);
        Z(ZstdDictDecompress_init)(env, (jobject) dd, (jbyteArray) dar, 0, (jint) dlen);
        if (variant == 2) {
            Z(ZstdCompressCtx_loadCDictFast0)(env, 0, c, (jobject) cd);
            Z(ZstdDecompressCtx_loadDDictFast0)(env, 0, d, (jobject) dd);
            r = Z(ZstdCompressCtx_compressByteArray0)(env, 0, c, (jbyteArray) dst, 0, bound, (jbyteArray) src, 0, (jint) n);
        } else {
            r = Z(Zstd_compressFastDict0)(env, 0, (jbyteArray) dst, 0, (jbyteArray) src, 0, (jint) n, (jobject) cd);
            Z(ZstdDecompressCtx_loadDDictFast0)(env, 0, d, (jobject) dd);
        }
        break;
    }
    if (r > 0) roundtrip(env, d, (uint8_t *) dst->data, (size_t) r, in, n);
    if (variant >= 2) {
        Z(ZstdCompressCtx_loadCDictFast0)(env, 0, c, NULL);
        Z(ZstdDecompressCtx_loadDDictFast0)(env, 0, d, NULL);
        Z(ZstdDictCompress_free)(env, (jobject) cd);
        Z(ZstdDictDecompress_free)(env, (jobject) dd);
    }
    Z(ZstdCompressCtx_free)(env, 0, c);
    Z(ZstdDecompressCtx_free)(env, 0, d);
    rm_buf(cd); rm_buf(dd); rm_buf(src); rm_buf(dst); rm_buf(dar);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) return -1;
    rd_t h = { data, 32 };
    const uint8_t *pay = data + 32;
    size_t n = size - 32;
    if (n > (1u << 20)) return -1;
    JNIEnv *env = mock_env();

    prm_t p;
    parse_params(&p, &h);
    uint32_t sel = rd_u8(&h);
    uint32_t dsel = rd_u8(&h);

    jlong dctx = mk_dctx(env, &p);

    if (sel & 0x80) {                         /* content dictionary = leading bytes of the payload */
        size_t dlen = dsel % 200 * 8;
        if (dlen > n) dlen = n;
        with_dict(env, &p, pay, dlen, pay + dlen, n - dlen, (int) (sel & 3));
    } else {
        compress_oneshot(env, &p, pay, n, dctx, (int) (sel & 3) % 3);
        compress_stream(env, &p, pay, n, dctx, (int) ((sel >> 2) & 3), &h);
        if (sel & 0x10) output_stream(env, &p, pay, n, dctx, &h);
        if (sel & 0x20) direct_stream(env, &p, pay, n, dctx, &h);
    }
    Z(ZstdDecompressCtx_free)(env, 0, dctx);
    return 0;
}
