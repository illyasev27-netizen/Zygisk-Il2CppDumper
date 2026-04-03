#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>
#include <chrono>
#include <inttypes.h>
#include <string>

// --- Вспомогательные функции ---

static std::string GetLibDir(JavaVM *vm) {
    JNIEnv *env;
    vm->GetEnv((void **) &env, JNI_VERSION_1_6);
    auto activityThread = env->FindClass("android/app/ActivityThread");
    auto currentActivityThread = env->GetStaticMethodID(activityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    auto at = env->CallStaticObjectMethod(activityThread, currentActivityThread);
    auto getProcessName = env->GetMethodID(activityThread, "getProcessName", "()Ljava/lang/String;");
    auto processName = (jstring) env->CallObjectMethod(at, getProcessName);
    auto name = env->GetStringUTFChars(processName, nullptr);
    std::string libDir = "/data/app/" + std::string(name) + "/lib/arm64";
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->ReleaseStringUTFChars(processName, name);
    return libDir;
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version;
    void *initialize;
    void *(*loadLibrary)(const char *libpath, int flag);
    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
    void *isSupported;
    void *getAppEnv;
    void *isCompatibleWith;
    void *getSignalHandler;
    void *unloadLibrary;
    void *getError;
    void *isPathSupported;
    void *initAnonymousNamespace;
    void *createNamespace;
    void *linkNamespaces;
    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

// --- Основная логика поиска и дампа ---

#include <sys/uio.h> // Обязательно добавь этот инклуд в начало файла

void hack_start(const char *game_data_dir) {
    if (game_data_dir == nullptr) return;

    std::string log_p = std::string(game_data_dir) + "/sys_dump_log.txt";
    FILE *log = fopen(log_p.c_str(), "w");
    
    fprintf(log, "--- INITIATING SYSTEM-LEVEL DUMP ---\n");

    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, "libil2cpp.so") && strstr(line, "r-xp")) {
                uintptr_t start, end;
                sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end);
                size_t total_size = end - start;
                pid_t pid = getpid();

                fprintf(log, "Target: %" PRIxPTR " | Size: %zu\n", start, total_size);

                std::string out_path = std::string(game_data_dir) + "/libil2cpp_sys.so";
                FILE *out = fopen(out_path.c_str(), "wb");
                
                if (out) {
                    char* buffer = (char*)malloc(1024 * 1024); // Буфер 1МБ
                    size_t copied = 0;

                    while (copied < total_size) {
                        size_t to_copy = (total_size - copied < 1024 * 1024) ? (total_size - copied) : 1024 * 1024;
                        
                        struct iovec local[1];
                        struct iovec remote[1];
                        local[0].iov_base = buffer;
                        local[0].iov_len = to_copy;
                        remote[0].iov_base = (void*)(start + copied);
                        remote[0].iov_len = to_copy;

                        // Прямое чтение из памяти процесса через ядро
                        ssize_t nread = process_vm_readv(pid, local, 1, remote, 1, 0);
                        
                        if (nread > 0) {
                            fwrite(buffer, 1, nread, out);
                            copied += nread;
                        } else {
                            // Если чтение не удалось, пишем нули, чтобы не ломать структуру файла
                            char* zeros = (char*)calloc(1, to_copy);
                            fwrite(zeros, 1, to_copy, out);
                            free(zeros);
                            copied += to_copy;
                            fprintf(log, "Skip failed block at: %zu\n", copied);
                        }
                    }
                    free(buffer);
                    fclose(out);
                    fprintf(log, "DUMP FINISHED. Result in: libil2cpp_sys.so\n");
                }
                break;
            }
        }
        fclose(maps);
    }
    fclose(log);
}

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    auto libart = dlopen("libart.so", RTLD_NOW);
    if (!libart) return false;
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    
    JavaVM *vms_buf[1];
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status != JNI_OK || num_vms <= 0) return false;

    auto vms = vms_buf[0];
    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty()) return false;

    void *nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        nb = dlopen(native_bridge.data(), RTLD_NOW);
    }

    if (nb) {
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            int fd = syscall(__NR_memfd_create, "system_buf", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);

            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);

            void *arm_handle;
            if (api_level >= 26) {
                arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
            } else {
                arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
            }

            if (arm_handle) {
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle, "JNI_OnLoad", nullptr, 0);
                if (init) {
                    init(vms, (void *) game_data_dir);
                    return true;
                }
            }
            close(fd);
        }
    }
    return false;
}

// ЕДИНСТВЕННАЯ ФУНКЦИЯ hack_prepare
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    int api_level = android_get_device_api_level();
#if defined(__i386__) || defined(__x86_64__)
    // В LDPlayer сработает эта часть
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
        hack_start(game_data_dir);
    }
#else
    hack_start(game_data_dir);
#endif
}
