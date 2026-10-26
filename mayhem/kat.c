/*
 * Known-answer probe for mayhem/test.sh: drives the real JNI glue (through the mock JNIEnv) on files.
 *   kat decomp <in.zst> <out>          decompress; prints "size=<content size> id=<dict id>"
 *   kat comp <level> <in> <out>        compress with content size + checksum
 *   kat stream <in> <out>              compress via the streaming natives, decompress via the stream natives
 *   kat sdecomp <in.zst> <out>         decompress a (possibly size-less) frame with the input-stream natives
 * Built with the project's normal flags (no sanitizers, no fuzzer).
 */
#include "mock_jni.h"
#include <stdio.h>

static uint8_t *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long l = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(l ? (size_t) l : 1);
    if (fread(b, 1, (size_t) l, f) != (size_t) l) { perror("read"); exit(2); }
    fclose(f);
    *n = (size_t) l;
    return b;
}

static void spit(const char *path, const void *p, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(2); }
    if (fwrite(p, 1, n, f) != n) { perror("write"); exit(2); }
    fclose(f);
}


/* decompress a whole frame with the input-stream natives; NULL on error or if output would exceed max */
static uint8_t *stream_decomp(JNIEnv *env, const uint8_t *in, size_t on, size_t max, size_t *bn_out) {
    mobj *isrc = mk_buf(in, on), *idst = mk_buf(NULL, 4096);
    mobj *iself = mk_obj();
    jlong ds = Z(ZstdInputStreamNoFinalizer_createDStream)(env, (jclass) iself);
    Z(ZstdInputStreamNoFinalizer_initDStream)(env, (jclass) iself, ds);
    uint8_t *back = malloc(max + 1);
    size_t bn = 0;
    iself->f[F_SRCPOS] = 0;
    for (int it = 0; it < 10000000; it++) {
        iself->f[F_DSTPOS] = 0;
        jlong r = Z(ZstdInputStreamNoFinalizer_decompressStream)(env, (jclass) iself, ds, (jbyteArray) idst, 4096, (jbyteArray) isrc, (jint) on);
        if (Z(Zstd_isError)(env, 0, r)) return NULL;
        if (bn + (size_t) iself->f[F_DSTPOS] > max) return NULL;
        memcpy(back + bn, idst->data, (size_t) iself->f[F_DSTPOS]);
        bn += (size_t) iself->f[F_DSTPOS];
        if (r == 0) break;
    }
    Z(ZstdInputStreamNoFinalizer_freeDStream)(env, (jclass) iself, ds);
    *bn_out = bn;
    return back;
}

int main(int argc, char **argv) {
    JNIEnv *env = mock_env();
    if (argc == 4 && !strcmp(argv[1], "decomp")) {
        size_t n;
        uint8_t *in = slurp(argv[2], &n);
        mobj *src = mk_buf(in, n);
        jlong sz = Z(Zstd_decompressedSize0)(env, 0, (jbyteArray) src, 0, (jint) n, 0);
        jlong id = Z(Zstd_getDictIdFromFrame)(env, 0, (jbyteArray) src);
        if (sz <= 0) { fprintf(stderr, "no content size\n"); return 1; }
        mobj *dst = mk_buf(NULL, (size_t) sz);
        jlong d = Z(Zstd_decompressUnsafe)(env, 0, (jlong) (intptr_t) dst->data, sz, (jlong) (intptr_t) src->data, (jlong) n);
        if (d != sz) { fprintf(stderr, "decompressUnsafe=%lld\n", (long long) d); return 1; }
        jlong ctx = Z(ZstdDecompressCtx_init)(env, 0);
        mobj *dst2 = mk_buf(NULL, (size_t) sz);
        jlong d2 = Z(ZstdDecompressCtx_decompressByteArray0)(env, 0, ctx, (jbyteArray) dst2, 0, (jint) sz, (jbyteArray) src, 0, (jint) n);
        Z(ZstdDecompressCtx_free)(env, 0, ctx);
        if (d2 != sz || memcmp(dst->data, dst2->data, (size_t) sz)) { fprintf(stderr, "ctx path differs\n"); return 1; }
        spit(argv[3], dst->data, (size_t) sz);
        printf("size=%lld id=%lld\n", (long long) sz, (long long) id);
        return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "comp")) {
        size_t n;
        uint8_t *in = slurp(argv[3], &n);
        mobj *src = mk_buf(in, n);
        jint bound = (jint) Z(Zstd_compressBound)(env, 0, (jlong) n);
        mobj *dst = mk_buf(NULL, (size_t) bound);
        jlong c = Z(ZstdCompressCtx_init)(env, 0);
        Z(ZstdCompressCtx_setLevel0)(env, 0, c, atoi(argv[2]));
        Z(ZstdCompressCtx_setChecksum0)(env, 0, c, 1);
        Z(ZstdCompressCtx_setContentSize0)(env, 0, c, 1);
        jlong r = Z(ZstdCompressCtx_compressByteArray0)(env, 0, c, (jbyteArray) dst, 0, bound, (jbyteArray) src, 0, (jint) n);
        Z(ZstdCompressCtx_free)(env, 0, c);
        if (r <= 0) { fprintf(stderr, "compress=%lld\n", (long long) r); return 1; }
        spit(argv[4], dst->data, (size_t) r);
        printf("compressed=%lld\n", (long long) r);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "stream")) {
        size_t n;
        uint8_t *in = slurp(argv[2], &n);
        mobj *self = mk_obj();
        jlong cs = Z(ZstdOutputStreamNoFinalizer_createCStream)(env, (jclass) self);
        Z(ZstdOutputStreamNoFinalizer_resetCStream)(env, (jclass) self, cs);
        Z(Zstd_setCompressionLevel)(env, 0, cs, 3);
        jint ocap = (jint) Z(ZstdOutputStreamNoFinalizer_recommendedCOutSize)(env, (jclass) self);
        mobj *src = mk_buf(in, n), *dst = mk_buf(NULL, (size_t) ocap);
        uint8_t *out = malloc(n + n / 2 + 1024);
        size_t on = 0;
        self->f[F_SRCPOS] = 0;
        while (self->f[F_SRCPOS] < (jlong) n) {
            self->f[F_DSTPOS] = 0;
            if (Z(ZstdOutputStreamNoFinalizer_compressStream)(env, (jclass) self, cs, (jbyteArray) dst, ocap, (jbyteArray) src, (jint) n) < 0) return 1;
            memcpy(out + on, dst->data, (size_t) self->f[F_DSTPOS]);
            on += (size_t) self->f[F_DSTPOS];
        }
        for (;;) {
            self->f[F_DSTPOS] = 0;
            jlong r = Z(ZstdOutputStreamNoFinalizer_endStream)(env, (jclass) self, cs, (jbyteArray) dst, ocap);
            if (r < 0) return 1;
            memcpy(out + on, dst->data, (size_t) self->f[F_DSTPOS]);
            on += (size_t) self->f[F_DSTPOS];
            if (r == 0) break;
        }
        Z(ZstdOutputStreamNoFinalizer_freeCStream)(env, (jclass) self, cs);

        size_t bn;
        uint8_t *back = stream_decomp(env, out, on, n, &bn);
        if (!back) return 1;
        spit(argv[3], back, bn);
        printf("streamed=%zu\n", on);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "sdecomp")) {
        size_t n, bn;
        uint8_t *in = slurp(argv[2], &n);
        uint8_t *back = stream_decomp(env, in, n, 64u << 20, &bn);
        if (!back) return 1;
        spit(argv[3], back, bn);
        printf("size=%zu\n", bn);
        return 0;
    }
    fprintf(stderr, "usage: kat decomp <in> <out> | comp <level> <in> <out> | stream <in> <out>\n");
    return 2;
}
