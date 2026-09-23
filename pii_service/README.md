# PII Security Module

Прокси-сервис для маскирования и демаскирования персональных данных
перед отправкой в LLM и обратно. Реализует контракт POST /process.

## Запуск

    docker compose up --build

Сервис: http://localhost:8000

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
