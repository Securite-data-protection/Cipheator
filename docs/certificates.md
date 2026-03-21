# Сертификаты и TLS: настройка

Проект использует TLS через OpenSSL. Сервер предъявляет сертификат, клиент и админ‑панель
проверяют его по CA-файлу.

## Быстрый вариант (самоподписанный)
1. Сгенерировать сертификат и ключ на сервере:
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```
2. Указать пути в `config/server.conf`:
- `cert_file=/path/to/server.crt`
- `key_file=/path/to/server.key`

3. На клиенте и в админ‑панели указать CA-файл:
- `config/client.conf`: `ca_file=/path/to/server.crt`, `verify_peer=true`
- `config/admin.conf`: `ca_file=/path/to/server.crt`, `verify_peer=true`

## Рекомендуемый вариант (собственный CA)
1. Создать CA:
```bash
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt
```
2. Создать CSR для сервера и подписать:
```bash
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825 -sha256
```
3. В `config/server.conf`:
- `cert_file=/path/to/server.crt`
- `key_file=/path/to/server.key`
- `ca_file=` (можно оставить пустым, если не используется клиентская проверка)

4. На клиенте и админ‑панели:
- `ca_file=/path/to/ca.crt`
- `verify_peer=true`

## Примечания
- Если `verify_peer=true`, клиент и админ‑панель будут отвергать TLS без доверенного CA.
- Для тестовой среды можно временно поставить `verify_peer=false`, но это снижает безопасность.
