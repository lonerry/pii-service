#!/usr/bin/env bash
# Локальный прогон SonarQube + sonar-scanner (Docker).
# Использование из каталога pii_service:
#   ./scripts/sonar-scan.sh
#   SONAR_ADMIN_PASSWORD='...' ./scripts/sonar-scan.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SONAR_URL="${SONAR_HOST_URL:-http://localhost:9000}"
ADMIN_USER="${SONAR_ADMIN_USER:-admin}"
ADMIN_PASS="${SONAR_ADMIN_PASSWORD:-admin}"
SCANNER_URL="${SONAR_SCANNER_HOST_URL:-http://host.docker.internal:9000}"

echo "==> Поднимаем SonarQube (если ещё не запущен)..."
docker compose -f docker-compose.sonar.yml up -d

echo "==> Ждём готовности SonarQube..."
for i in $(seq 1 90); do
  status="$(curl -s "$SONAR_URL/api/system/status" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || true)"
  if [[ "$status" == "UP" ]]; then
    echo "    SonarQube UP"
    break
  fi
  if [[ "$i" -eq 90 ]]; then
    echo "SonarQube не поднялся за 3 минуты. Проверь: docker logs sonarqube" >&2
    exit 1
  fi
  sleep 2
done

echo "==> Пароль admin (если первый запуск)..."
if ! curl -s -u "$ADMIN_USER:$ADMIN_PASS" "$SONAR_URL/api/authentication/validate" | grep -q '"valid":true'; then
  curl -s -u "$ADMIN_USER:admin" -X POST \
    "$SONAR_URL/api/users/change_password?login=$ADMIN_USER&previousPassword=admin&password=$ADMIN_PASS" >/dev/null || true
fi
if ! curl -s -u "$ADMIN_USER:$ADMIN_PASS" "$SONAR_URL/api/authentication/validate" | grep -q '"valid":true'; then
  echo "Не удалось войти как $ADMIN_USER. Задай SONAR_ADMIN_PASSWORD." >&2
  exit 1
fi

echo "==> Токен сканера..."
TOKEN="$(curl -s -u "$ADMIN_USER:$ADMIN_PASS" -X POST \
  "$SONAR_URL/api/user_tokens/generate?name=local-scan-$(date +%s)" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")"
if [[ -z "$TOKEN" ]]; then
  echo "Не удалось получить token API." >&2
  exit 1
fi

echo "==> Coverage (pytest-cov)..."
python3 -m pip install -q pytest-cov
python3 -m pytest tests/ -q --cov=app --cov-report=xml

echo "==> sonar-scanner-cli..."
docker run --rm \
  -e SONAR_HOST_URL="$SCANNER_URL" \
  -e SONAR_TOKEN="$TOKEN" \
  -v "$ROOT:/usr/src" \
  -w /usr/src \
  sonarsource/sonar-scanner-cli

echo ""
echo "Готово. Отчёт: $SONAR_URL/dashboard?id=pii_service"
