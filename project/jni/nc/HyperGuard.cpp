#include "HyperGuard.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include <map>

#include "ScopedLocalRef.h"
#include "ScopedPthreadMutexLock.h"
#include "well_known_classes.h"

// ── Fix 1: MemberTriple dùng strcmp thay vì so sánh pointer ──────────────
struct MemberTriple {
    MemberTriple(const char *cls_name, const char *name, const char *sig)
        : class_name_(cls_name), member_name_(name), signautre_(sig) {}

    const char *class_name_;
    const char *member_name_;
    const char *signautre_;

    bool operator<(const MemberTriple &m) const {
        int r = strcmp(class_name_, m.class_name_);
        if (r != 0) return r < 0;
        if (member_name_ && m.member_name_) {
            r = strcmp(member_name_, m.member_name_);
            if (r != 0) return r < 0;
        }
        if (signautre_ && m.signautre_)
            return strcmp(signautre_, m.signautre_) < 0;
        return false;
    }
};

static std::map<MemberTriple, jfieldID>  resvoled_fields;
static std::map<MemberTriple, jmethodID> resvoled_methods;
static std::map<MemberTriple, jclass>    resvoled_classes;
static pthread_mutex_t resovle_method_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t resovle_field_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t resovle_class_mutex  = PTHREAD_MUTEX_INITIALIZER;

static const int max_global_reference = 1500;

static void cache_well_known_classes(JNIEnv *env) {
    d2c::WellKnownClasses::Init(env);

    resvoled_classes[MemberTriple("Int",     nullptr, nullptr)] = d2c::WellKnownClasses::primitive_int;
    resvoled_classes[MemberTriple("Long",    nullptr, nullptr)] = d2c::WellKnownClasses::primitive_long;
    resvoled_classes[MemberTriple("Short",   nullptr, nullptr)] = d2c::WellKnownClasses::primitive_short;
    resvoled_classes[MemberTriple("Char",    nullptr, nullptr)] = d2c::WellKnownClasses::primitive_char;
    resvoled_classes[MemberTriple("Byte",    nullptr, nullptr)] = d2c::WellKnownClasses::primitive_byte;
    resvoled_classes[MemberTriple("Boolean", nullptr, nullptr)] = d2c::WellKnownClasses::primitive_boolean;
    resvoled_classes[MemberTriple("Float",   nullptr, nullptr)] = d2c::WellKnownClasses::primitive_float;
    resvoled_classes[MemberTriple("Double",  nullptr, nullptr)] = d2c::WellKnownClasses::primitive_double;
}

// ── Dùng nội bộ để crash ngầm, không dùng exit() ─────────────────────────
static void __attribute__((noinline)) _hg_terminate() {
    kill(getpid(), SIGKILL);
}

// ─────────────────────────────────────────────────────────────────────────
void d2c_throw_exception(JNIEnv *env, const char *class_name, const char *message) {
    LOGD("d2c_throw_exception %s %s", class_name, message);
    ScopedLocalRef<jclass> c(env, env->FindClass(class_name));
    if (c.get()) {
        env->ThrowNew(c.get(), message);
    }
}

void d2c_filled_new_array(JNIEnv *env, jarray array, const char *type, jint count, ...) {
    va_list args;
    va_start(args, count);
    char ty  = type[0];
    bool ref = (ty == '[' || ty == 'L');
    for (int i = 0; i < count; i++) {
        if (ref) {
            env->SetObjectArrayElement((jobjectArray) array, i, (jobject) va_arg(args, long));
        } else {
            int val = va_arg(args, jint);
            env->SetIntArrayRegion((jintArray) array, i, 1, &val);
        }
    }
    va_end(args);
}

int64_t d2c_double_to_long(double val) {
    if (val != val)                                    return 0;
    if (val > static_cast<double>(INT64_MAX))          return INT64_MAX;
    if (val < static_cast<double>(INT64_MIN))          return INT64_MIN;
    return static_cast<int64_t>(val);
}

int64_t d2c_float_to_long(float val) {
    if (val != val)                                   return 0;
    if (val > static_cast<float>(INT64_MAX))          return INT64_MAX;
    if (val < static_cast<float>(INT64_MIN))          return INT64_MIN;
    return static_cast<int64_t>(val);
}

int32_t d2c_double_to_int(double val) {
    if (val != val)                                    return 0;
    if (val > static_cast<float>(INT32_MAX))           return INT32_MAX;
    if (val < static_cast<float>(INT32_MIN))           return INT32_MIN;
    return static_cast<int32_t>(val);
}

int32_t d2c_float_to_int(float val) {
    if (val != val)                                   return 0;
    if (val > static_cast<float>(INT32_MAX))          return INT32_MAX;
    if (val < static_cast<float>(INT32_MIN))          return INT32_MIN;
    return static_cast<int32_t>(val);
}

bool d2c_is_instance_of(JNIEnv *env, jobject instance, const char *class_name) {
    if (instance == nullptr) return false;
    ScopedLocalRef<jclass> c(env, env->FindClass(class_name));
    if (c.get()) return env->IsInstanceOf(instance, c.get());
    return false;
}

bool d2c_check_cast(JNIEnv *env, jobject instance, jclass clz, const char *class_name) {
    if (env->IsInstanceOf(instance, clz)) return false;
    d2c_throw_exception(env, "java/lang/ClassCastException", class_name);
    return true;
}

bool d2c_resolve_class(JNIEnv *env, jclass *cached_class, const char *class_name) {
    if (*cached_class) return false;

    MemberTriple triple(class_name, nullptr, nullptr);

    if (max_global_reference > 0) {
        ScopedPthreadMutexLock lock(&resovle_class_mutex);
        auto iter = resvoled_classes.find(triple);
        if (iter != resvoled_classes.end()) {
            *cached_class = iter->second;
            return false;
        }
    }

    jclass clz = env->FindClass(class_name);
    if (clz) {
        LOGD("resvoled class %s %zd", class_name, resvoled_classes.size());
        if (max_global_reference > 0 && resvoled_classes.size() < (size_t)max_global_reference) {
            ScopedPthreadMutexLock lock(&resovle_class_mutex);
            *cached_class = (jclass) env->NewGlobalRef(clz);
            resvoled_classes[triple] = *cached_class;
            env->DeleteLocalRef(clz);
        } else {
            *cached_class = clz;
        }
        return false;
    }
    return true;
}

bool d2c_resolve_method(JNIEnv *env, jclass *cached_class, jmethodID *cached_method,
                        bool is_static, const char *class_name,
                        const char *method_name, const char *signature) {
    if (*cached_method) return false;
    if (d2c_resolve_class(env, cached_class, class_name)) return true;

    MemberTriple triple(class_name, method_name, signature);
    {
        ScopedPthreadMutexLock lock(&resovle_method_mutex);
        auto iter = resvoled_methods.find(triple);
        if (iter != resvoled_methods.end()) {
            *cached_method = iter->second;
            return false;
        }
    }

    *cached_method = is_static
        ? env->GetStaticMethodID(*cached_class, method_name, signature)
        : env->GetMethodID(*cached_class, method_name, signature);

    if (*cached_method) {
        ScopedPthreadMutexLock lock(&resovle_method_mutex);
        resvoled_methods[triple] = *cached_method;
    }
    return *cached_method == nullptr;
}

bool d2c_resolve_field(JNIEnv *env, jclass *cached_class, jfieldID *cached_field,
                       bool is_static, const char *class_name,
                       const char *field_name, const char *signature) {
    if (*cached_field) return false;
    if (d2c_resolve_class(env, cached_class, class_name)) return true;

    MemberTriple triple(class_name, field_name, signature);
    {
        ScopedPthreadMutexLock lock(&resovle_field_mutex);
        auto iter = resvoled_fields.find(triple);
        if (iter != resvoled_fields.end()) {
            *cached_field = iter->second;
            return false;
        }
    }

    *cached_field = is_static
        ? env->GetStaticFieldID(*cached_class, field_name, signature)
        : env->GetFieldID(*cached_class, field_name, signature);

    if (*cached_field) {
        ScopedPthreadMutexLock lock(&resovle_field_mutex);
        resvoled_fields[triple] = *cached_field;
    }
    return *cached_field == nullptr;
}

// Đặt =1 chỉ sau khi đã test kỹ trên nhiều dòng máy thật — threshold timing
// tuyệt đối không đáng tin cậy giữa hàng nghìn loại CPU/Android khác nhau,
// để mặc định 0 (chỉ log) tránh kill nhầm máy yếu/đang bận lúc cold-start.
#ifndef HG_STRICT_TIMING_CHECK
#define HG_STRICT_TIMING_CHECK 0
#endif

extern "C" {

// ── Fix 2: initCore — anti-debug, đã bỏ ptrace() self-trace ─────────────
// LƯU Ý: ptrace(PTRACE_TRACEME) self-check đã bị XOÁ. Trên Android 8+,
// nhiều OEM/ROM áp seccomp filter chặn syscall ptrace cho app thường —
// chỉ cần GỌI ptrace() (không cần ai debug thật) là kernel kill ngay
// (SIGKILL/SIGSYS), gây crash 100% cho mọi người dùng. Đây là lý do app
// bị văng sau patch trước. TracerPid (đọc file, không gọi syscall nguy
// hiểm) vẫn an toàn và đáng tin cậy hơn nhiều — giữ lại làm hard-kill.
JNIEXPORT void JNICALL
Java_plongdev_HyperGuardPro_Native_initCore(JNIEnv *env, jclass clazz, jobject context) {

    // Check 1: TracerPid trong /proc/self/status — chỉ đọc file, KHÔNG gọi
    // syscall ptrace nào nên an toàn trên mọi Android version/OEM.
    {
        int tracerPid = 0;
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    tracerPid = atoi(line + 10);
                    break;
                }
            }
            fclose(f);
        }
        if (tracerPid != 0) {
            _hg_terminate();
            return;
        }
    }

    // Check 2: Timing — chỉ log, KHÔNG kill theo mặc định. Ngưỡng tuyệt đối
    // không ổn định giữa máy yếu/máy mạnh hoặc lúc app cold-start đang
    // tranh CPU với hệ thống, nên không dùng làm hard-kill trừ khi đã test
    // kỹ và chủ động bật HG_STRICT_TIMING_CHECK.
    {
        struct timespec t1, t2;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        volatile uint64_t dummy = 0;
        for (volatile int i = 0; i < 5000; i++) dummy += (uint64_t)i * i;
        clock_gettime(CLOCK_MONOTONIC, &t2);
        long elapsed_ns = (t2.tv_sec - t1.tv_sec) * 1000000000L
                        + (t2.tv_nsec - t1.tv_nsec);
        if (elapsed_ns > 300000000L) { // 300ms — rất khoan dung
#if HG_STRICT_TIMING_CHECK
            _hg_terminate();
            return;
#else
            LOGD("HyperGuard: timing check vượt ngưỡng (%ld ns), chỉ log", elapsed_ns);
#endif
        }
    }
}

// ── Fix 3: Native.a — per-string key thay vì 0x66 cố định ───────────────
// Java side phải truyền key riêng cho mỗi string
// Key 64-bit, mỗi byte lấy 8 bit theo rotation (giống AY_OBFUSCATE)
JNIEXPORT jstring JNICALL
Java_plongdev_HyperGuardPro_Native_a(JNIEnv *env, jclass clazz,
                                     jbyteArray data, jlong key) {
    if (data == nullptr) return nullptr;

    jsize   len    = env->GetArrayLength(data);
    jbyte  *buffer = env->GetByteArrayElements(data, nullptr);
    char   *plain  = (char *) malloc((size_t)len + 1);
    if (!plain) {
        env->ReleaseByteArrayElements(data, buffer, JNI_ABORT);
        return nullptr;
    }

    for (int i = 0; i < len; i++) {
        uint8_t k  = (uint8_t)((key >> ((i % 8) * 8)) & 0xFF);
        plain[i]   = (char)(buffer[i] ^ k);
    }
    plain[len] = '\0';

    jstring result = env->NewStringUTF(plain);

    // Zero memory trước khi free — tránh leak plaintext
    memset(plain, 0, (size_t)len);
    free(plain);
    env->ReleaseByteArrayElements(data, buffer, JNI_ABORT);
    return result;
}

JNIEXPORT void JNICALL
Java_plongdev_HyperGuardPro_Native_PLongDeveloper_HyperGuard_Pro__(JNIEnv *env, jobject thiz) {
    // Placeholder
}

JNIEXPORT void JNICALL
Java_plongdev_HyperGuardPro_Native__0003cinit_0003e__(JNIEnv *env, jobject thiz) {
    auto instance = (jobject) env->NewLocalRef(thiz);
    jclass    application = env->FindClass("android/app/Application");
    jmethodID init        = env->GetMethodID(application, "<init>", "()V");
    env->CallVoidMethodA(instance, init, {});
}

} // extern "C"

// ── Fix 4: JNI_OnLoad — không dùng exit(1) ───────────────────────────────
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass clz = env->FindClass("plongdev/HyperGuardPro/Loader");
    if (!clz) {
        // Crash ngầm thay vì exit(1) lộ liễu — khó patch hơn
        _hg_terminate();
        return JNI_ERR;
    }

    cache_well_known_classes(env);
    return JNI_VERSION_1_6;
}
