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

    std::string log_p = std::string(game_data_dir) + "/header_dump_log.txt";
    FILE *log = fopen(log_p.c_str(), "w");
    if (!log) return;

    fprintf(log, "--- STARTING AGGRESSIVE HEADER HUNT ---\n");
    fflush(log);

    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            // Ищем исполняемый регион (r-xp)
            // Мы игнорируем системные пути (/system, /vendor, /apex)
            if (strstr(line, "r-xp") && !strstr(line, "/system") && !strstr(line, "/vendor") && !strstr(line, "/apex")) {
                uintptr_t start, end;
                sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start, &end);
                size_t region_size = end - start;

                // Наша цель — большой регион (от 60 до 120 МБ)
                // Именно столько занимает расшифрованная libil2cpp.so
                if (region_size > 60 * 1024 * 1024 && region_size < 120 * 1024 * 1024) {
                    fprintf(log, "Candidate found! Size: %zu MB | Region: %s", region_size / 1024 / 1024, line);
                    
                    // Проверяем, что это ELF (даже если имя скрыто)
                    unsigned char* mem = (unsigned char*)start;
                    if (mem[0] == 0x7F && mem[1] == 'E' && mem[2] == 'L' && mem[3] == 'F') {
                        fprintf(log, "ELF Signature confirmed at %" PRIxPTR "\n", start);
                        
                        std::string out_path = std::string(game_data_dir) + "/libil2cpp_header.so";
                        FILE *out = fopen(out_path.c_str(), "wb");
                        if (out) {
                            // Сохраняем первые 15 МБ
                            fwrite((void*)start, 1, 15 * 1024 * 1024, out);
                            fclose(out);
                            fprintf(log, "SUCCESS: Header saved from anonymous region!\n");
                            fclose(maps);
                            goto end;
                        }
                    }
                }
            }
        }
        fclose(maps);
    } else {
        fprintf(log, "ERROR: Could not open /proc/self/maps\n");
    }

end:
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
