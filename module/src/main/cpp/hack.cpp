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

// Вспомогательная функция для эмуляторов
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
    env->ReleaseStringUTFChars(processName, name);
    return libDir;
}

void hack_start(const char *game_data_dir) {
    uintptr_t base = 0;
    std::string found_name = "";

    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            // Ищем любые упоминания il2cpp, даже если они переименованы или скрыты
            if ((strstr(line, "il2cpp") || strstr(line, "boot.art")) && strstr(line, "r-xp")) {
                char path[256];
                if (sscanf(line, "%" SCNxPTR "-%*x %*s %*s %*s %*s %s", &base, path) == 2) {
                    found_name = path;
                    break;
                }
            }
        }
        fclose(maps);
    }

    // Создаем файл лога в ПАПКЕ ИГРЫ (туда запись разрешена всегда)
    std::string log_path = std::string(game_data_dir) + "/module_log.txt";
    FILE *log = fopen(log_path.c_str(), "w");
    
    if (log) {
        if (base > 0) {
            fprintf(log, "Status: Library Found!\nBase: %p\nPath: %s\n", (void*)base, found_name.c_str());
            
            // Пробуем запустить основной дамп
            // ПРИМЕЧАНИЕ: Если il2cpp_dump не работает, мы хотя бы получим адрес из лога
            il2cpp_dump(game_data_dir); 
            fprintf(log, "Status: Dump function called.\n");
        } else {
            fprintf(log, "Status: Library NOT found in maps.\n");
        }
        fclose(log);
    }
}
    if (base > 0) {
        // Если нашли адрес, пробуем сделать ПРЯМОЙ дамп без инициализации API
        // Используем встроенный в дампер метод, но с жестким ограничением
        il2cpp_dump("/sdcard/Download/"); 
        
        // Создаем маркер успеха
        std::string marker_path = std::string(game_data_dir) + "/DUMP_ATTEMPT.txt";
        FILE *f = fopen(marker_path.c_str(), "w");
        if (f) {
            fprintf(f, "Found libil2cpp at: %p", (void*)base);
            fclose(f);
        }
    }
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

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    std::this_thread::sleep_for(std::chrono::seconds(7));

    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    
    JavaVM *vms_buf[1];
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status != JNI_OK || num_vms <= 0) return false;

    auto vms = vms_buf[0];
    auto lib_dir = GetLibDir(vms);
    
    if (lib_dir.empty()) return false;

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
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
            munmap(data, length);

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

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    int api_level = android_get_device_api_level();
#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
        hack_start(game_data_dir);
    }
#else
    hack_start(game_data_dir);
#endif
}
