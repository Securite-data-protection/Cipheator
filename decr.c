/**
 * Расшифровка файла алгоритмом ГОСТ Р 34.12-2018 (Кузнечик) с использованием libakrypt
 * 
 * Программа расшифровывает файл, используя указанный ключ.
 * 
 * Компиляция: gcc -o gost_decrypt gost_decrypt.c -lakrypt
 * 
 * Использование: ./gost_decrypt <зашифрованный_файл> <расшифрованный_файл> <файл_ключа>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libakrypt.h>

#define BLOCK_SIZE 16  // Размер блока для Кузнечика: 128 бит = 16 байт
#define KEY_SIZE 32    // Размер ключа для Кузнечика: 256 бит = 32 байта
#define IV_SIZE 16     // Размер вектора инициализации: 128 бит = 16 байт

/**
 * Загружает ключ из файла
 * 
 * @param key Буфер для загруженного ключа
 * @param key_file Имя файла с ключом
 * @return 0 при успехе, -1 при ошибке
 */
int load_key_from_file(ak_uint8 *key, const char *key_file) {
    FILE *file = fopen(key_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Ошибка: Не удалось открыть файл ключа для чтения\n");
        return -1;
    }
    
    if (fread(key, 1, KEY_SIZE, file) != KEY_SIZE) {
        fprintf(stderr, "Ошибка: Не удалось прочитать ключ из файла\n");
        fclose(file);
        return -1;
    }
    
    fclose(file);
    return 0;
}

/**
 * Расшифровывает файл с использованием алгоритма ГОСТ Р 34.12-2018 (Кузнечик)
 * 
 * @param input_file Имя входного зашифрованного файла
 * @param output_file Имя выходного расшифрованного файла
 * @param key Ключ расшифрования
 * @return 0 при успехе, коды ошибок при неудаче
 */
int decrypt_file(const char *input_file, const char *output_file, ak_uint8 *key) {
    struct bckey ctx;
    ak_uint8 iv[IV_SIZE];
    ak_uint8 *buffer = NULL, *decrypted_buffer = NULL;
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
    
    // Чтение IV из начала входного файла
    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE) {
        fprintf(stderr, "Ошибка: Не удалось прочитать вектор инициализации из файла\n");
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
    
    // Выделение буферов для чтения/расшифрования данных
    buffer = malloc(BLOCK_SIZE);
    decrypted_buffer = malloc(BLOCK_SIZE);
    if (buffer == NULL || decrypted_buffer == NULL) {
        fprintf(stderr, "Ошибка: Не удалось выделить память для буферов\n");
        ak_bckey_destroy(&ctx);
        goto cleanup;
    }
    
    // Инициализация текущего IV для первого блока
    ak_uint8 current_iv[IV_SIZE];
    memcpy(current_iv, iv, IV_SIZE);
    
    // Буфер для хранения предыдущего зашифрованного блока
    ak_uint8 prev_encrypted_block[BLOCK_SIZE];
    ak_uint8 is_first_block = 1;
    ak_uint8 last_block[BLOCK_SIZE];
    size_t last_block_size = 0;
    
    // Расшифрование блоков файла
    while ((read_size = fread(buffer, 1, BLOCK_SIZE, in)) > 0) {
        if (read_size != BLOCK_SIZE) {
            fprintf(stderr, "Ошибка: Некорректный размер блока данных\n");
            ak_bckey_destroy(&ctx);
            goto cleanup;
        }
        
        // Сохраняем текущий зашифрованный блок перед расшифровкой
        // для использования его как IV для следующего блока
        memcpy(prev_encrypted_block, buffer, BLOCK_SIZE);
        
        // Расшифрование блока


        if (ak_bckey_decrypt_ecb(&ctx, buffer, decrypted_buffer, BLOCK_SIZE) != ak_error_ok) {
            fprintf(stderr, "Ошибка: Не удалось расшифровать блок данных\n");
            ak_bckey_destroy(&ctx);
            goto cleanup;
        }
        
        // XOR с текущим вектором для CBC режима
        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            decrypted_buffer[i] ^= current_iv[i];
        }
        
        // Обновление текущего вектора для следующего блока
        memcpy(current_iv, prev_encrypted_block, BLOCK_SIZE);
        
        // Проверка на наличие следующего блока (для определения padding)
        ak_uint8 next_block[BLOCK_SIZE];
        size_t next_read_size = fread(next_block, 1, BLOCK_SIZE, in);
        
        // Если есть следующий блок, записываем текущий расшифрованный блок как есть
        if (next_read_size > 0) {
            if (fwrite(decrypted_buffer, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
                fprintf(stderr, "Ошибка: Не удалось записать расшифрованный блок в файл\n");
                ak_bckey_destroy(&ctx);
                goto cleanup;
            }
            
            // Возвращаем указатель чтения на позицию следующего блока
            fseek(in, -next_read_size, SEEK_CUR);
        } else {
            // Это последний блок, сохраняем его для последующей обработки
            memcpy(last_block, decrypted_buffer, BLOCK_SIZE);
            last_block_size = BLOCK_SIZE;
        }
    }
    
    // Обработка последнего блока (удаление padding)
    if (last_block_size > 0) {
        // Определение размера padding
        ak_uint8 padding_size = last_block[BLOCK_SIZE - 1];
        
        // Проверка корректности padding
        if (padding_size > 0 && padding_size <= BLOCK_SIZE) {
            int padding_valid = 1; // Используем int вместо ak_bool
            for (size_t i = BLOCK_SIZE - padding_size; i < BLOCK_SIZE; i++) {
                if (last_block[i] != padding_size) {
                    padding_valid = 0;
                    break;
                }
            }
            
            if (padding_valid) {
                // Записываем только данные без padding
                if (fwrite(last_block, 1, BLOCK_SIZE - padding_size, out) != BLOCK_SIZE - padding_size) {
                    fprintf(stderr, "Ошибка: Не удалось записать последний расшифрованный блок в файл\n");
                    ak_bckey_destroy(&ctx);
                    goto cleanup;
                }
            } else {
                // Некорректный padding, записываем блок как есть
                if (fwrite(last_block, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
                    fprintf(stderr, "Ошибка: Не удалось записать последний расшифрованный блок в файл\n");
                    ak_bckey_destroy(&ctx);
                    goto cleanup;
                }
            }
        } else {
            // Некорректный размер padding, записываем блок как есть
            if (fwrite(last_block, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
                fprintf(stderr, "Ошибка: Не удалось записать последний расшифрованный блок в файл\n");
                ak_bckey_destroy(&ctx);
                goto cleanup;
            }
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
    if (decrypted_buffer != NULL) {
        free(decrypted_buffer);
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
 * Выводит ключ в шестнадцатеричном формате
 * 
 * @param key Ключ для вывода
 */
void print_hex_key(ak_uint8 *key) {
    printf("Ключ расшифрования (HEX): ");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    ak_uint8 key[KEY_SIZE];
    
    // Проверка аргументов командной строки
    if (argc != 4) {


    fprintf(stderr, "Использование: %s <зашифрованный_файл> <расшифрованный_файл> <файл_ключа>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    // Инициализация библиотеки libakrypt
    if (ak_libakrypt_create(NULL) != ak_true) {
        fprintf(stderr, "Ошибка: Не удалось инициализировать библиотеку libakrypt\n");
        return EXIT_FAILURE;
    }
    
    // Загрузка ключа из файла
    if (load_key_from_file(key, argv[3]) != 0) {
        fprintf(stderr, "Ошибка: Не удалось загрузить ключ из файла\n");
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    
    // Расшифрование файла
    if (decrypt_file(argv[1], argv[2], key) != 0) {
        fprintf(stderr, "Ошибка: Не удалось расшифровать файл\n");
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    
    // Вывод информации о результатах
    printf("Файл успешно расшифрован: %s\n", argv[2]);
    print_hex_key(key);
    
    // Завершение работы с библиотекой
    ak_libakrypt_destroy();
    
    return EXIT_SUCCESS;
}
