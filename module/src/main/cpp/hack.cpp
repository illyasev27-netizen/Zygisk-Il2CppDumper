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
    // Мы уже подождали 100 секунд в main.cpp, здесь спим еще 2 секунды для страховки
    std::this_thread::sleep_for(std::chrono::seconds(2)); 

    // Используем самый быстрый способ открытия без доп. флагов
    void *handle = xdl_open("libil2cpp.so", 0); 
    if (handle) {
        // Инициализация API
        il2cpp_api_init(handle);
        
        // Мгновенный дамп в загрузки
        // Мы используем /sdcard/Download/ так как туда запись идет быстрее всего
        il2cpp_dump("/sdcard/Download/"); 
        
        // Сразу закрываем хендл
        xdl_close(handle);
    }
    // После этого пусть игра вылетает — файл уже должен быть записан
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
