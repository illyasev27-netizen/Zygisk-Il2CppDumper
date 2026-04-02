#include <cstring>
#include <thread>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cinttypes>
#include "hack.h"
#include "zygisk.hpp"
#include "game.h"
#include "log.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        auto package_name = env->GetStringUTFChars(args->nice_name, nullptr);
        auto app_data_dir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        preSpecialize(package_name, app_data_dir);
        env->ReleaseStringUTFChars(args->nice_name, package_name);
        env->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
    }

   void postAppSpecialize(const AppSpecializeArgs *) override {
    if (enable_hack) {
        std::thread t([this]() {
            // Полная тишина, никаких логов
            std::this_thread::sleep_for(std::chrono::seconds(30)); 
            hack_prepare(game_data_dir, data, length);
        });
        // Маскируем имя потока под системный компонент Unity
        pthread_setname_np(t.native_handle(), "UnityMain"); 
        t.detach();
    }
}

private:
    Api *api;
    JNIEnv *env;
    bool enable_hack = false;
    char *game_data_dir;
    void *data;
    size_t length;

    void preSpecialize(const char *package_name, const char *app_data_dir) {
        // УЛУЧШЕНИЕ 3: Динамическая проверка пакета
        // Мы используем GamePackageName из твоего файла game.h
        if (package_name && strcmp(package_name, GamePackageName) == 0) {
            LOGI("Target game detected: %s. Initializing stealth dump...", package_name);
            enable_hack = true;
            game_data_dir = new char[strlen(app_data_dir) + 1];
            strcpy(game_data_dir, app_data_dir);

            // Маскировка: подгружаем ARM-библиотеки только если мы в эмуляторе (x86)
#if defined(__i386__)
            auto path = "zygisk/armeabi-v7a.so";
#endif
#if defined(__x86_64__)
            auto path = "zygisk/arm64-v8a.so";
#endif
#if defined(__i386__) || defined(__x86_64__)
            int dirfd = api->getModuleDir();
            int fd = openat(dirfd, path, O_RDONLY);
            if (fd != -1) {
                struct stat sb{};
                fstat(fd, &sb);
                length = sb.st_size;
                data = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
                close(fd);
            } else {
                LOGW("Stealth Error: Unable to open arm translation bridge");
            }
#endif
        } else {
            // Если это не наша игра, полностью выгружаем модуль, чтобы античиты других приложений его не видели
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }
};

REGISTER_ZYGISK_MODULE(MyModule)
