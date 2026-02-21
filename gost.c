/**
 * Шифрование файла алгоритмом ГОСТ Р 34.12-2018 (Кузнечик) с использованием libakrypt
 * 
 * Программа генерирует случайный ключ и шифрует файл, сохраняя ключ отдельно.
 * 
 * Компиляция: gcc -o gost_encrypt gost_encrypt.c -lakrypt
 * 
 * Использование: ./gost_encrypt <исходный_файл> <зашифрованный_файл> [<файл_ключа>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libakrypt.h>

#define BLOCK_SIZE 16  // Размер блока для Кузнечика: 128 бит = 16 байт
#define KEY_SIZE 32    // Размер ключа для Кузнечика: 256 бит = 32 байта
#define IV_SIZE 16     // Размер вектора инициализации: 128 бит = 16 байт

/**
 * Генерирует случайный ключ для шифрования
 * 
 * @param key Буфер для сгенерированного ключа
 * @return 0 при успехе, -1 при ошибке
 */
int generate_random_key(ak_uint8 *key) {
    struct random rnd;
    int error;
    
    // Инициализация генератора случайных чисел
    if ((error = ak_random_create_lcg(&rnd)) != ak_error_ok) {
        return -1;
    }
    
    // Генерация случайного ключа
    ak_random_ptr(&rnd, key, KEY_SIZE);
    
    // Освобождение ресурсов генератора
    ak_random_destroy(&rnd);
    
    return 0;
}

/**
 * Генерирует случайный вектор инициализации
 * 
 * @param iv Буфер для сгенерированного вектора инициализации
 * @return 0 при успехе, -1 при ошибке
 */
int generate_random_iv(ak_uint8 *iv) {
    struct random rnd;
    int error;
    
    // Инициализация генератора случайных чисел
    if ((error = ak_random_create_lcg(&rnd)) != ak_error_ok) {
        return -1;
    }
    
    // Генерация случайного IV
    ak_random_ptr(&rnd, iv, IV_SIZE);
    
    // Освобождение ресурсов генератора
    ak_random_destroy(&rnd);
    
    return 0;
}

/**
 * Шифрует файл с использованием алгоритма ГОСТ Р 34.12-2018 (Кузнечик)
 * 
 * @param input_file Имя входного файла
 * @param output_file Имя выходного файла
 * @param key Ключ шифрования
 * @return 0 при успехе, коды ошибок при неудаче
 */
int encrypt_file(const char *input_file, const char *output_file, ak_uint8 *key) {
    struct bckey ctx;
    ak_uint8 iv[IV_SIZE];
    ak_uint8 *buffer = NULL;
    FILE *in = NULL, *out = NULL;
    size_t read_size;
    int result = -1;
    
    // Открытие файлов
    if ((in = fopen(input_file, "rb")) == NULL) {
        fprintf(stderr, "Ошибка: Не удалось открыть входной файл %s\n", input_file);
        return -1;
    }
    
    if ((out = fopen(output_file, "wb")) == NULL) {
        fprintf(stderr, "Ошибка: Не удалось открыть выходной файл %s\n", output_file);
        fclose(in);
        return -1;
    }
    
    // Генерация случайного IV
    if (generate_random_iv(iv) != 0) {
        fprintf(stderr, "Ошибка: Не удалось сгенерировать вектор инициализации\n");
        goto cleanup;
    }
    
    // Запись IV в начало выходного файла
    if (fwrite(iv, 1, IV_SIZE, out) != IV_SIZE) {
        fprintf(stderr, "Ошибка: Не удалось записать вектор инициализации в файл\n");
        goto cleanup;
    }
    
    // Инициализация контекста шифрования
    if (ak_bckey_create_kuznechik(&ctx) != ak_error_ok) {
        fprintf(stderr, "Ошибка: Не удалось создать контекст шифрования\n");
        goto cleanup;
    }
    
    // Установка ключа шифрования
    if (ak_bckey_set_key(&ctx, key, KEY_SIZE) != ak_error_ok) {
        fprintf(stderr, "Ошибка: Не удалось установить ключ шифрования\n");
        ak_bckey_destroy(&ctx);
        goto cleanup;
    }
    
    // Выделение буфера для чтения/шифрования данных
    buffer = malloc(BLOCK_SIZE);
    if (buffer == NULL) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для буфера\n");
        ak_bckey_destroy(&ctx);
        goto cleanup;
    }
    
    // Текущий вектор для режима сцепления блоков (CBC)
    ak_uint8 current_iv[IV_SIZE];
    memcpy(current_iv, iv, IV_SIZE);
    
    // Шифрование блоков файла
    while ((read_size = fread(buffer, 1, BLOCK_SIZE, in)) > 0) {
        // Добавление padding, если последний блок неполный
        if (read_size < BLOCK_SIZE) {
            ak_uint8 padding_byte = BLOCK_SIZE - read_size;

        memset(buffer + read_size, padding_byte, padding_byte);
        }
        
        // XOR с текущим вектором для CBC режима
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            buffer[i] ^= current_iv[i];
        }
        
        // Шифрование блока
        if (ak_bckey_encrypt_ecb(&ctx, buffer, buffer, BLOCK_SIZE) != ak_error_ok) {
            fprintf(stderr, "Ошибка: Не удалось зашифровать блок данных\n");
            ak_bckey_destroy(&ctx);
            goto cleanup;
        }
        
        // Обновление текущего вектора для следующего блока
        memcpy(current_iv, buffer, BLOCK_SIZE);
        
        // Запись зашифрованного блока в выходной файл
        if (fwrite(buffer, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
            fprintf(stderr, "Ошибка: Не удалось записать зашифрованный блок в файл\n");
            ak_bckey_destroy(&ctx);
            goto cleanup;
        }
    }
    
    // Освобождение ресурсов шифрования
    ak_bckey_destroy(&ctx);
    
    result = 0;  // Успешное завершение
    
cleanup:
    // Освобождение ресурсов
    if (buffer != NULL) {
        free(buffer);
    }
    if (in != NULL) {
        fclose(in);
    }
    if (out != NULL) {
        fclose(out);
    }
    
    return result;
}

/**
 * Сохраняет ключ в файл
 * 
 * @param key Ключ для сохранения
 * @param key_file Имя файла для сохранения ключа
 * @return 0 при успехе, -1 при ошибке
 */
int save_key_to_file(ak_uint8 *key, const char *key_file) {
    FILE *file = fopen(key_file, "wb");
    if (file == NULL) {
        fprintf(stderr, "Ошибка: Не удалось открыть файл ключа для записи\n");
        return -1;
    }
    
    if (fwrite(key, 1, KEY_SIZE, file) != KEY_SIZE) {
        fprintf(stderr, "Ошибка: Не удалось записать ключ в файл\n");
        fclose(file);
        return -1;
    }
    
    fclose(file);
    return 0;
}

/**
 * Выводит ключ в шестнадцатеричном формате
 * 
 * @param key Ключ для вывода
 */
void print_hex_key(ak_uint8 *key) {
    printf("Ключ шифрования (HEX): ");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    ak_uint8 key[KEY_SIZE];
    
    // Проверка аргументов командной строки
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Использование: %s <исходный_файл> <зашифрованный_файл> [<файл_ключа>]\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    // Инициализация библиотеки libakrypt
    if (ak_libakrypt_create(NULL) != ak_true) {
        fprintf(stderr, "Ошибка: Не удалось инициализировать библиотеку libakrypt\n");
        return EXIT_FAILURE;
    }
    
    // Генерация случайного ключа
    if (generate_random_key(key) != 0) {
        fprintf(stderr, "Ошибка: Не удалось сгенерировать ключ\n");
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    
    // Шифрование файла
    if (encrypt_file(argv[1], argv[2], key) != 0) {
        fprintf(stderr, "Ошибка: Не удалось зашифровать файл\n");
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    
    // Сохранение ключа в файл, если указано имя файла
    if (argc == 4) {
        if (save_key_to_file(key, argv[3]) != 0) {
            fprintf(stderr, "Ошибка: Не удалось сохранить ключ в файл\n");
            ak_libakrypt_destroy();
            return EXIT_FAILURE;
        }
        printf("Ключ сохранен в файл: %s\n", argv[3]);
    }
    
    // Вывод информации о результатах
    printf("Файл успешно зашифрован: %s\n", argv[2]);
    print_hex_key(key);
    printf("ВАЖНО: Сохраните этот ключ для последующей расшифровки!\n");
    
    // Завершение работы с библиотекой
    ak_libakrypt_destroy();
    
    return EXIT_SUCCESS;
}
