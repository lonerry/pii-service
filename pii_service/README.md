# PII Security Module

Прокси-сервис для маскирования и демаскирования персональных данных
перед отправкой в LLM и обратно. Реализует контракт POST /process.

## Запуск

    docker compose up --build

Сервис: http://localhost:8000

Для нескольких workers обязательно задайте общий постоянный ключ:

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    export PII_ENCRYPTION_KEY='полученный-ключ'

Без ключа локальный Compose запускает один worker, иначе восстановление между
процессами и после перезапуска невозможно.

## Контракт

    POST /process
    {"payload": "...", "payload_id": "..."}
    -> {"result": "..."}

Первый запрос с новым payload_id — маскирование.
Повторный с тем же payload_id и маской — демаскирование.

## Настройка

Правила систем в config.yaml. Для новой системы добавьте секцию
в systems: enabled, types (список типов ПД или ALL), demask.

## Наблюдаемость

/health — статус, /metrics — Prometheus (latency, rps, ошибки).
