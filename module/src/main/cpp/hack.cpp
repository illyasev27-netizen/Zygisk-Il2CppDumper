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

#include <unistd.h> // для fsync

void hack_start(const char *game_data_dir) {
    if (game_data_dir == nullptr) return;

    std::string log_p = std::string(game_data_dir) + "/meta_hunt_log.txt";
    FILE *log = fopen(log_p.c_str(), "w");
    if (!log) return;

    fprintf(log, "--- SEARCHING FOR METADATA MAGIC ---\n");
    fflush(log);

    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            // Метаданные обычно лежат в регионах r--p (только чтение) или rw-p
            if (strstr(line, "r--p") || strstr(line, "rw-p")) {
                uintptr_t start, end;
                sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end);
                
                // Проверяем только начало регионов, так как файл метаданных 
                // всегда начинается с магического числа
                unsigned char* memory = (unsigned char*)start;
                
                // Нам нужно проверить доступность памяти, чтобы не вылететь
                // Сигнатура: AF 1B B1 FA
                if (memory[0] == 0xAF && memory[1] == 0x1B && memory[2] == 0xB1 && memory[3] == 0xFA) {
                    size_t size = end - start;
                    fprintf(log, "!!! METADATA FOUND !!!\nAddr: %" PRIxPTR "\nSize: %zu bytes\nRegion: %s", start, size, line);
                    fflush(log);

                    // Копируем метаданные в файл
                    std::string out_path = std::string(game_data_dir) + "/global-metadata.dat";
                    FILE *out = fopen(out_path.c_str(), "wb");
                    if (out) {
                        fwrite(memory, 1, size, out);
                        fclose(out);
                        fprintf(log, "SUCCESS: global-metadata.dat saved!\n");
                    }
                    break; 
                }
            }
        }
        fclose(maps);
    }
    fprintf(log, "--- Hunt Finished ---\n");
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
