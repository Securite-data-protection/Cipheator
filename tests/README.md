# Тесты проекта Cipheator

Этот каталог содержит сценарии тестирования и результаты.

## Структура
- `protocol_client.py` — минимальный клиент протокола (TLS + заголовок + бинарный payload).
- `bench_k1.py` — тест производительности (К-1), шифрование файлов разных размеров.
- `load_k2.py` — нагрузочный тест (К-2), шифрование/расшифрование набора файлов.
- `report.md` — отчет по тестам (Ф-1..Ф-3, К-1..К-2).

## Перед запуском
1. Сервер запущен и доступен по TLS.
2. Пользователь и пароль созданы на сервере.
3. TLS CA-файл известен (например `server.crt`).
4. Если включена жесткая привязка клиента, разрешите тестовый `client_id` или выключите политику.

## К-1 (производительность)
```bash
python3 /Users/ghostmelon/Desktop/Cipheator/tests/bench_k1.py \
  --host 127.0.0.1 --port 7443 \
  --user admin --password StrongPassword123 \
  --cipher aes-256-gcm --hash sha256 \
  --sizes-mb 1,10,100,250 --repeats 5 \
  --ca /Users/ghostmelon/Desktop/Cipheator/server.crt
```

## К-2 (нагрузочный тест)
```bash
python3 /Users/ghostmelon/Desktop/Cipheator/tests/load_k2.py \
  --host 127.0.0.1 --port 7443 \
  --user admin --password StrongPassword123 \
  --files 1000 --min-kb 10 --max-mb 10 --workers 8 \
  --ca /Users/ghostmelon/Desktop/Cipheator/server.crt
```

## Примечания
- Функциональные тесты Ф-1..Ф-3 выполняются вручную в GUI‑клиенте и описаны в отчете.
- Скрипты используют протокол напрямую и не зависят от GUI.
