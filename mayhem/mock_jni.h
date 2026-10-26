/*
 * Minimal in-process JNIEnv so the unmodified JNI glue in src/main/native/jni_*.c can be driven
 * from a libFuzzer harness without a JVM. Arrays and direct buffers are exact-size heap blocks, so
 * ASan sees any read/write past what the Java caller handed in.
 */
#ifndef MAYHEM_MOCK_JNI_H
#define MAYHEM_MOCK_JNI_H

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { F_SRCPOS, F_DSTPOS, F_CONSUMED, F_PRODUCED, F_NATIVEPTR, F_COUNT };

typedef struct mobj {
    char *data;
    jlong len;
    struct mobj **elems;
    jlong f[F_COUNT];
} mobj;

static const char *mock_last_string = "";

static mobj *mk_buf(const void *src, size_t n) {
    mobj *o = calloc(1, sizeof(*o));
    o->data = malloc(n ? n : 1);
    if (src && n) memcpy(o->data, src, n);
    else memset(o->data, 0, n ? n : 1);
    o->len = (jlong) n;
    return o;
}
static void rm_buf(mobj *o) { if (o) { free(o->data); free(o->elems); free(o); } }
static mobj *mk_obj(void) { return calloc(1, sizeof(mobj)); }
static mobj mock_dummy;

static jsize m_GetArrayLength(JNIEnv *e, jarray a) { (void) e; return (jsize) ((mobj *) a)->len; }
static jlong m_GetDirectBufferCapacity(JNIEnv *e, jobject b) { (void) e; return b ? ((mobj *) b)->len : -1; }
static void *m_GetDirectBufferAddress(JNIEnv *e, jobject b) { (void) e; return b ? ((mobj *) b)->data : NULL; }
static void *m_GetPrimitiveArrayCritical(JNIEnv *e, jarray a, jboolean *c) { (void) e; (void) c; return ((mobj *) a)->data; }
static void m_ReleasePrimitiveArrayCritical(JNIEnv *e, jarray a, void *p, jint m) { (void) e; (void) a; (void) p; (void) m; }
static jclass m_GetObjectClass(JNIEnv *e, jobject o) { (void) e; return (jclass) o; }
static jclass m_FindClass(JNIEnv *e, const char *n) { (void) e; (void) n; return (jclass) &mock_dummy; }
static jint m_ThrowNew(JNIEnv *e, jclass c, const char *m) { (void) e; (void) c; (void) m; return 0; }
static jstring m_NewStringUTF(JNIEnv *e, const char *s) { (void) e; mock_last_string = s; return (jstring) &mock_dummy; }
static void m_DeleteLocalRef(JNIEnv *e, jobject o) { (void) e; (void) o; }
static jobject m_GetObjectArrayElement(JNIEnv *e, jobjectArray a, jsize i) { (void) e; return (jobject) ((mobj *) a)->elems[i]; }
static void m_GetByteArrayRegion(JNIEnv *e, jbyteArray a, jsize s, jsize l, jbyte *b) {
    (void) e;
    memcpy(b, ((mobj *) a)->data + s, (size_t) l);
}
static jfieldID m_GetFieldID(JNIEnv *e, jclass c, const char *n, const char *s) {
    (void) e; (void) c; (void) s;
    if (!strcmp(n, "srcPos")) return (jfieldID) (uintptr_t) (F_SRCPOS + 1);
    if (!strcmp(n, "dstPos")) return (jfieldID) (uintptr_t) (F_DSTPOS + 1);
    if (!strcmp(n, "consumed")) return (jfieldID) (uintptr_t) (F_CONSUMED + 1);
    if (!strcmp(n, "produced")) return (jfieldID) (uintptr_t) (F_PRODUCED + 1);
    return (jfieldID) (uintptr_t) (F_NATIVEPTR + 1);
}
static jlong m_GetLongField(JNIEnv *e, jobject o, jfieldID id) { (void) e; return ((mobj *) o)->f[(uintptr_t) id - 1]; }
static void m_SetLongField(JNIEnv *e, jobject o, jfieldID id, jlong v) { (void) e; ((mobj *) o)->f[(uintptr_t) id - 1] = v; }
static void m_SetIntField(JNIEnv *e, jobject o, jfieldID id, jint v) { (void) e; ((mobj *) o)->f[(uintptr_t) id - 1] = v; }

static struct JNINativeInterface_ mock_table;
static JNIEnv mock_env_storage;

static JNIEnv *mock_env(void) {
    mock_table.GetArrayLength = m_GetArrayLength;
    mock_table.GetDirectBufferCapacity = m_GetDirectBufferCapacity;
    mock_table.GetDirectBufferAddress = m_GetDirectBufferAddress;
    mock_table.GetPrimitiveArrayCritical = m_GetPrimitiveArrayCritical;
    mock_table.ReleasePrimitiveArrayCritical = m_ReleasePrimitiveArrayCritical;
    mock_table.GetObjectClass = m_GetObjectClass;
    mock_table.FindClass = m_FindClass;
    mock_table.ThrowNew = m_ThrowNew;
    mock_table.NewStringUTF = m_NewStringUTF;
    mock_table.DeleteLocalRef = m_DeleteLocalRef;
    mock_table.GetObjectArrayElement = m_GetObjectArrayElement;
    mock_table.GetByteArrayRegion = m_GetByteArrayRegion;
    mock_table.GetFieldID = m_GetFieldID;
    mock_table.GetLongField = m_GetLongField;
    mock_table.SetLongField = m_SetLongField;
    mock_table.SetIntField = m_SetIntField;
    mock_env_storage = &mock_table;
    return &mock_env_storage;
}

/* ---- the JNI entry points under test (defined in src/main/native/jni_*.c) ---- */
#define N(ret, name, ...) extern ret name(JNIEnv *, jclass, ##__VA_ARGS__)
#define Z(n) Java_com_github_luben_zstd_##n

N(jlong, Z(Zstd_compressUnsafe), jlong, jlong, jlong, jlong, jint, jboolean);
N(jlong, Z(Zstd_decompressUnsafe), jlong, jlong, jlong, jlong);
N(jlong, Z(Zstd_decompressedSize0), jbyteArray, jint, jint, jboolean);
N(jlong, Z(Zstd_getFrameContentSize0), jbyteArray, jint, jint, jboolean);
N(jlong, Z(Zstd_findFrameCompressedSize0), jbyteArray, jint, jint);
N(jlong, Z(Zstd_findDirectByteBufferFrameCompressedSize), jobject, jint, jint);
N(jlong, Z(Zstd_getDictIdFromFrame), jbyteArray);
N(jlong, Z(Zstd_getDictIdFromFrameBuffer), jobject);
N(jlong, Z(Zstd_getDictIdFromDict), jbyteArray);
N(jlong, Z(Zstd_getDictIdFromDictDirect), jobject, jint, jint);
N(jlong, Z(Zstd_decompressedDirectByteBufferSize), jobject, jint, jint, jboolean);
N(jlong, Z(Zstd_getDirectByteBufferFrameContentSize), jobject, jint, jint, jboolean);
N(jlong, Z(Zstd_compressBound), jlong);
N(jlong, Z(Zstd_isError), jlong);
N(jstring, Z(Zstd_getErrorName), jlong);
N(jlong, Z(Zstd_getErrorCode), jlong);
N(jint, Z(Zstd_loadDictDecompress), jlong, jbyteArray, jint);
N(jint, Z(Zstd_loadDictCompress), jlong, jbyteArray, jint);
N(jint, Z(Zstd_setCompressionChecksums), jlong, jboolean);
N(jint, Z(Zstd_setCompressionMagicless), jlong, jboolean);
N(jint, Z(Zstd_setCompressionLevel), jlong, jint);
N(jint, Z(Zstd_setCompressionLong), jlong, jint);
N(jint, Z(Zstd_setDecompressionLongMax), jlong, jint);
N(jint, Z(Zstd_setDecompressionMagicless), jlong, jboolean);
N(jint, Z(Zstd_setCompressionWorkers), jlong, jint);
N(jint, Z(Zstd_setCompressionJobSize), jlong, jint);
N(jint, Z(Zstd_setCompressionOverlapLog), jlong, jint);
N(jint, Z(Zstd_setCompressionWindowLog), jlong, jint);
N(jint, Z(Zstd_setCompressionHashLog), jlong, jint);
N(jint, Z(Zstd_setCompressionChainLog), jlong, jint);
N(jint, Z(Zstd_setCompressionSearchLog), jlong, jint);
N(jint, Z(Zstd_setCompressionMinMatch), jlong, jint);
N(jint, Z(Zstd_setCompressionTargetLength), jlong, jint);
N(jint, Z(Zstd_setCompressionStrategy), jlong, jint);
N(jint, Z(Zstd_setEnableLongDistanceMatching), jlong, jint);
N(jint, Z(Zstd_setRefMultipleDDicts), jlong, jboolean);
N(jlong, Z(Zstd_trainFromBuffer0), jobjectArray, jbyteArray, jboolean, jint);
N(jlong, Z(Zstd_trainFromBufferDirect0), jobject, jintArray, jobject, jboolean, jint);
N(jlong, Z(Zstd_decompressFastDict0), jbyteArray, jint, jbyteArray, jint, jint, jobject);
N(jlong, Z(Zstd_compressFastDict0), jbyteArray, jint, jbyteArray, jint, jint, jobject);
N(jlong, Z(Zstd_compressDirectByteBufferFastDict0), jobject, jint, jint, jobject, jint, jint, jobject);
N(jlong, Z(Zstd_decompressDirectByteBufferFastDict0), jobject, jint, jint, jobject, jint, jint, jobject);

/* ZstdDictCompress / ZstdDictDecompress take the instance (jobject), not the class */
extern void Z(ZstdDictCompress_init)(JNIEnv *, jobject, jbyteArray, jint, jint, jint);
extern void Z(ZstdDictCompress_initDirect)(JNIEnv *, jobject, jobject, jint, jint, jint, jint);
extern void Z(ZstdDictCompress_free)(JNIEnv *, jobject);
extern void Z(ZstdDictDecompress_init)(JNIEnv *, jobject, jbyteArray, jint, jint);
extern void Z(ZstdDictDecompress_initDirect)(JNIEnv *, jobject, jobject, jint, jint, jint);
extern void Z(ZstdDictDecompress_free)(JNIEnv *, jobject);

N(jlong, Z(ZstdCompressCtx_init));
N(void, Z(ZstdCompressCtx_free), jlong);
N(void, Z(ZstdCompressCtx_setLevel0), jlong, jint);
N(void, Z(ZstdCompressCtx_setChecksum0), jlong, jboolean);
N(void, Z(ZstdCompressCtx_setContentSize0), jlong, jboolean);
N(void, Z(ZstdCompressCtx_setDictID0), jlong, jboolean);
N(jlong, Z(ZstdCompressCtx_loadCDictFast0), jlong, jobject);
N(jlong, Z(ZstdCompressCtx_loadCDict0), jlong, jbyteArray);
N(jlong, Z(ZstdCompressCtx_reset0), jlong);
N(jlong, Z(ZstdCompressCtx_setPledgedSrcSize0), jlong, jlong);
N(jlong, Z(ZstdCompressCtx_compressDirectByteBufferStream0), jlong, jobject, jint, jint, jobject, jint, jint, jint);
N(jlong, Z(ZstdCompressCtx_compressByteArrayToDirectByteBufferStream0), jlong, jobject, jint, jint, jbyteArray, jint, jint, jint, jint);
N(jlong, Z(ZstdCompressCtx_compressDirectByteBufferToByteArrayStream0), jlong, jbyteArray, jint, jint, jint, jobject, jint, jint, jint);
N(jlong, Z(ZstdCompressCtx_compressByteArrayStream0), jlong, jbyteArray, jint, jint, jint, jbyteArray, jint, jint, jint, jint);
N(jlong, Z(ZstdCompressCtx_compressDirectByteBuffer0), jlong, jobject, jint, jint, jobject, jint, jint);
N(jlong, Z(ZstdCompressCtx_compressByteArray0), jlong, jbyteArray, jint, jint, jbyteArray, jint, jint);

N(jlong, Z(ZstdDecompressCtx_init));
N(void, Z(ZstdDecompressCtx_free), jlong);
N(jlong, Z(ZstdDecompressCtx_loadDDictFast0), jlong, jobject);
N(jlong, Z(ZstdDecompressCtx_loadDDict0), jlong, jbyteArray);
N(jlong, Z(ZstdDecompressCtx_reset0), jlong);
N(jlong, Z(ZstdDecompressCtx_decompressDirectByteBufferStream0), jlong, jobject, jint, jint, jobject, jint, jint);
N(jlong, Z(ZstdDecompressCtx_decompressByteArrayToDirectByteBufferStream0), jlong, jobject, jint, jint, jbyteArray, jint, jint, jint);
N(jlong, Z(ZstdDecompressCtx_decompressDirectByteBufferToByteArrayStream0), jlong, jbyteArray, jint, jint, jint, jobject, jint, jint);
N(jlong, Z(ZstdDecompressCtx_decompressByteArrayStream0), jlong, jbyteArray, jint, jint, jint, jbyteArray, jint, jint, jint);
N(jlong, Z(ZstdDecompressCtx_decompressDirectByteBuffer0), jlong, jobject, jint, jint, jobject, jint, jint);
N(jlong, Z(ZstdDecompressCtx_decompressByteArray0), jlong, jbyteArray, jint, jint, jbyteArray, jint, jint);
N(jlong, Z(ZstdDecompressCtx_decompressByteArrayToDirectByteBuffer0), jlong, jobject, jint, jint, jbyteArray, jint, jint);
N(jlong, Z(ZstdDecompressCtx_decompressDirectByteBufferToByteArray0), jlong, jbyteArray, jint, jint, jobject, jint, jint);

N(jlong, Z(ZstdInputStreamNoFinalizer_recommendedDOutSize));
N(jlong, Z(ZstdInputStreamNoFinalizer_createDStream));
N(jlong, Z(ZstdInputStreamNoFinalizer_freeDStream), jlong);
N(jint, Z(ZstdInputStreamNoFinalizer_initDStream), jlong);
N(jlong, Z(ZstdInputStreamNoFinalizer_resetDStream), jlong);
N(jlong, Z(ZstdInputStreamNoFinalizer_decompressStream), jlong, jbyteArray, jint, jbyteArray, jint);
N(jlong, Z(ZstdOutputStreamNoFinalizer_recommendedCOutSize));
N(jlong, Z(ZstdOutputStreamNoFinalizer_createCStream));
N(jlong, Z(ZstdOutputStreamNoFinalizer_freeCStream), jlong);
N(jlong, Z(ZstdOutputStreamNoFinalizer_resetCStream), jlong);
N(jlong, Z(ZstdOutputStreamNoFinalizer_compressStream), jlong, jbyteArray, jint, jbyteArray, jint);
N(jlong, Z(ZstdOutputStreamNoFinalizer_endStream), jlong, jbyteArray, jint);
N(jlong, Z(ZstdOutputStreamNoFinalizer_flushStream), jlong, jbyteArray, jint);

N(jlong, Z(ZstdBufferDecompressingStreamNoFinalizer_createDStreamNative));
N(jlong, Z(ZstdBufferDecompressingStreamNoFinalizer_freeDStreamNative), jlong);
N(jlong, Z(ZstdBufferDecompressingStreamNoFinalizer_initDStreamNative), jlong);
N(jlong, Z(ZstdBufferDecompressingStreamNoFinalizer_decompressStreamNative), jlong, jbyteArray, jint, jint, jbyteArray, jint, jint);
N(jlong, Z(ZstdDirectBufferDecompressingStreamNoFinalizer_createDStreamNative));
N(jlong, Z(ZstdDirectBufferDecompressingStreamNoFinalizer_freeDStreamNative), jlong);
N(jlong, Z(ZstdDirectBufferDecompressingStreamNoFinalizer_initDStreamNative), jlong);
N(jlong, Z(ZstdDirectBufferDecompressingStreamNoFinalizer_decompressStreamNative), jlong, jobject, jint, jint, jobject, jint, jint);
N(jlong, Z(ZstdDirectBufferCompressingStreamNoFinalizer_createCStream));
N(jlong, Z(ZstdDirectBufferCompressingStreamNoFinalizer_freeCStream), jlong);
N(jlong, Z(ZstdDirectBufferCompressingStreamNoFinalizer_initCStream), jlong, jint);
N(jlong, Z(ZstdDirectBufferCompressingStreamNoFinalizer_compressDirectByteBuffer), jlong, jobject, jint, jint, jobject, jint, jint);
N(jlong, Z(ZstdDirectBufferCompressingStreamNoFinalizer_endStream), jlong, jobject, jint, jint);
N(jlong, Z(ZstdDirectBufferCompressingStreamNoFinalizer_flushStream), jlong, jobject, jint, jint);

/* ---- fuzz-input reader ---- */
typedef struct { const uint8_t *p; size_t n; } rd_t;
static uint32_t rd_u8(rd_t *r) { if (!r->n) return 0; r->n--; return *r->p++; }
static uint32_t rd_u16(rd_t *r) { uint32_t a = rd_u8(r); return a | (rd_u8(r) << 8); }

#endif
