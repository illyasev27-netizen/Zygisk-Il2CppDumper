#ifndef ZYGISK_IL2CPPDUMPER_HACK_H
#define ZYGISK_IL2CPPDUMPER_HACK_H

#include <stddef.h>

// Объявляем обе функции, чтобы они были доступны в main.cpp
void hack_prepare(const char *game_data_dir, void *data, size_t length);
void hack_start(const char *game_data_dir);

#endif //ZYGISK_IL2CPPDUMPER_HACK_H
