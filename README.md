# Продвинутый многофункциональный программно-аппаратный комплекс шифрования

Проект разделен на 4 конфишгурации:

- `client/` Основанный на Qt6 GUI-интерфейс для оборудования рядового пользователя
- `server/` Сервер, на котором происходят криптографические процессы (внедрен и используется на отдельном аппарате)
- `admin/` Панель администратора для просмотра логов и выдачи ручного разрешения при конфликтах
- `common/` основные конфигируции, общие для всех клиентов

## Зависимости

- CMake 3.20+
- C++17 compiler
- OpenSSL 1.1.1+ (TLS + AES-GCM/ChaCha20-Poly1305 + SHA-2/SHA-3 + PBKDF2)
- Qt 6 (Widgets) для графического интерфейса

## Сборка

```bash
cmake -S . -B build \
  -DBUILD_CLIENT=ON \
  -DBUILD_SERVER=ON \
  -DBUILD_GUI=ON \
  -DBUILD_ADMIN=ON
cmake --build build
```
Для каждой опции нужно выбрать, собрать конфигурацию или нет конкретно для данного устройства.
Если Qt6 не доступен, небходимо установить `-DBUILD_GUI=OFF`, тогда будет доступен CLI-интерйес

<!--
## Установка сервера

1. Create TLS cert and key:

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

2. Place cert/key paths in `config/server.conf`.
3. Initialize a user:

```bash
./cipheator-server --init-user admin StrongPassword123
```
-->
## Запуск

```bash
./cipheator-client
```
На физическом аппарате сервер и панель администратора запускаются сразу после включения в сеть питания

### TLS и сертификаты
Инструкция по выпуску и настройке сертификатов находится в `docs/certificates.md`.

### Шифрование

Зашифрованные файлы содержат в начале метаданные: шифр, хэш, тип хранилища ключа, IV/tag,
ID файла в системе. Корректно используемые файлы расшифровываются обратно гарантированно, если же нарушена целостность, то появится предупреждение об этом

### Поддерживаемые алгоритмы и режимы

Шифрование:
- Кузнечик MGM
- AES-256-GCM

Хеш-функции:
- Стрибог-256, Стрибог-512
- SHA-256, SHA-512
- SHA3-256, SHA3-512
- BLAKE2b-512

<!--
## Admin console

Set `admin_token` in `config/server.conf` and add devices in the admin console.
The admin API runs on `admin_host/admin_port` using TLS and requires the token.
Devices are stored in `config/admin_devices.conf`.
Admin client TLS settings are in `config/admin.conf`.

Alerts include:
- suspicious login time
- 3+ failed logins in a time window
- bulk file operations in a short window

Thresholds are configurable in `config/server.conf`.
-->
## Проверка целостности

При наличии `file_id` сервер проверяет целостность при расшифровке, повторно
вычисляя сохраненный хэш. Если хэш не совпадает, сервер возвращает ошибку и регистрирует
предупреждение `integrity_failed`.

## Поиск аномалий в поведении

Вы можете настроить временные блокировки из-за подозрительного времени, неудачных входов в систему или массовых операций
с помощью параметров `anomaly_*_lock_sec` в `config/server.conf`. Установите значение `0`, чтобы отключить
блокировку (только для оповещений).

## Режим временного файла

Клиент может записывать расшифрованные данные во временный файл (автоматически очищаемый при завершении работы)
чтобы разрешить внешним приложениям (например, инструментам базы данных) доступ к данным. 
<!--
## GOST CLI integration

The server expects GOST CLI tools:
- `enc_magma` and `dec_magma`
- `enc_kuznechik` and `dec_kuznechik` (optional)

Set their paths in `config/server.conf`. The adapter currently assumes:
- Encryption writes `<input>.enc` and `<input>.key`
- Decryption reads encrypted file and key file

Adjust the config or adapter if your tools use different filenames.


## Streebog hashing

Streebog hashing is attempted via OpenSSL digests (`streebog256` or `md_gost12_256`).
If your OpenSSL build does not include GOST engines, Streebog will fail until you add
an engine/provider that implements GOST 34.11-2012.
-->
## Замечания по безопасности

Некоторые элементы управления безопасностью платформы (буфер обмена, скриншоты, брандмауэр) являются наиболее эффективными и ограничены операционной системой.
Более эфективно использовать интегрировать комплекс в систему безопасности. Ограничения приведены в разделе `client/SECURITY_NOTES.md`.
