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

void hack_start(const char *game_data_dir) {
    bool load = false;
    LOGI("Stealth monitoring active. Waiting for game decryption...");

    // УЛУЧШЕНИЕ: Динамическая задержка. 
    // Первые 10 секунд спим глубоко, так как NCGuard проверяет память при старте.
    sleep(10); 

    for (int i = 0; i < 40; i++) {
        // Используем XDL_DEFAULT для поиска даже скрытых символов
        void *handle = xdl_open("libil2cpp.so", XDL_DEFAULT); 
        
        if (handle) {
            LOGI("[+] Target decrypted in memory. Starting extraction...");
            load = true;
            
            // Даем игре 2 секунды "продышаться" после расшифровки библиотеки
            std::this_thread::sleep_for(std::chrono::seconds(2));
            
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            
            // После дампа обязательно закрываем хендл, чтобы не оставлять следов
            xdl_close(handle); 
            break;
        }
        sleep(1);
    }
    
    if (!load) {
        LOGE("[!] Timeout: Game logic is too heavily protected or not Unity-based.");
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
static std::string GetLibDir(JavaVM *vm) {
    JNIEnv *env;
    vm->GetEnv((void **) &env, JNI_VERSION_1_6);
    auto activityThread = env->FindClass("android/app/ActivityThread");
    auto currentActivityThread = env->GetStaticMethodID(activityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    auto at = env->CallStaticObjectMethod(activityThread, currentActivityThread);
    auto getProcessName = env->GetMethodID(activityThread, "getProcessName", "()Ljava/lang/String;");
    auto processName = (jstring) env->CallObjectMethod(at, getProcessName);
    auto name = env->GetStringUTFChars(processName, nullptr);
    std::string libDir = "/data/app/" + std::string(name) + "/lib/arm64"; // или arm в зависимости от системы
    env->ReleaseStringUTFChars(processName, name);
    return libDir;
}
bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    // УЛУЧШЕНИЕ: Ждем инициализацию Houdini дольше. 
    // В эмуляторах на Windows это часто узкое место.
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
    if (lib_dir.find("/lib/x86") != std::string::npos) {
        LOGI("Native x86 detected, bypassing bridge.");
        munmap(data, length);
        return false;
    }

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        nb = dlopen(native_bridge.data(), RTLD_NOW);
    }

    if (nb) {
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            // УЛУЧШЕНИЕ: Используем менее подозрительное имя для файлового дескриптора
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
    
    // В эмуляторах x86 всегда пытаемся пробросить через Native Bridge
#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
        LOGW("NativeBridgeLoad failed, falling back to direct start.");
#endif
        hack_start(game_data_dir);
#if defined(__i386__) || defined(__x86_64__)
    }
#endif
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    // Запускаем в отдельном потоке, чтобы не блокировать основной поток игры
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
