#!/usr/bin/env sh
# Локальный прогон всех гейтов — то же, что делает CI, до первого push.
#
# Единственное расхождение с CI: детектор гонок требует cgo, которого на Windows
# без C-тулчейна нет. Здесь он включается только если доступен, а на ubuntu-раннере
# работает всегда. Расхождение объявлено явно, чтобы «локально зелено, в CI красно»
# не стало сюрпризом.
set -eu
cd "$(git rev-parse --show-toplevel)"

fail=0
vuln_notrun=0
step() { printf '  %-22s' "$1"; }
pass() { printf 'OK\n'; }
bad()  { printf 'FAIL\n'; fail=1; }

# Архив старого проекта исключается по пути, а не фильтрацией вывода: gofmt на
# Windows печатает пути с обратными слэшами, и grep по 'docs/ghost/' их не ловит.
go_files() { find . -name '*.go' -not -path './docs/*' -print; }

# BUILD_TAGS is not optional. sing-box gates uTLS — and with it the Reality client —
# behind with_utls. Without the tag every Reality node fails to construct and is
# silently dropped: sixty-two percent of the real catalogue, looking like upstream
# decay rather than a build mistake. See INV-49.
BUILD_TAGS=with_utls

step "gofmt"
unformatted="$(gofmt -l $(go_files) 2>/dev/null || true)"
if [ -n "$unformatted" ]; then bad; printf '  %s\n' $unformatted; else pass; fi

step "go build"   ; if go build -tags "$BUILD_TAGS" ./... 2>&1; then pass; else bad; fi
step "go vet"     ; if go vet -tags "$BUILD_TAGS" ./... 2>&1; then pass; else bad; fi

if [ "$(go env CGO_ENABLED)" = "1" ]; then
  race="-race"; note="с детектором гонок"
else
  race=""; note="БЕЗ детектора гонок (нет cgo; в CI он включён)"
fi
step "go test"
if go test -tags "$BUILD_TAGS" $race -count=1 ./... >/dev/null 2>&1; then printf 'OK  — %s\n' "$note"; else bad; fi

# C4 предшественника: сюита могла бесшумно исчезнуть, а гейт остаться зелёным.
step "no skipped tests"
if go test -tags "$BUILD_TAGS" -v -count=1 ./... 2>/dev/null | grep -qE '^[[:space:]]*--- SKIP'; then bad; else pass; fi

# SEC-033. Этот гейт CI держит отдельным джобом, а здесь его не было — то есть «все гейты
# пройдены» локально и красный vuln в CI были совместимыми состояниями, ровно то расхождение,
# ради устранения которого скрипт и существует.
#
# @latest, а не пин: гейт уязвимостей, докладывающий про advisories прошлого месяца, — не гейт.
# Вердикт берётся из отчёта самого инструмента, а не из кода возврата: ненулевой код означает
# и «нашёл», и «не смог запуститься», а отсутствие сети не должно читаться как чистый скан.
step "govulncheck"
vuln_out=$(go run golang.org/x/vuln/cmd/govulncheck@latest -tags "$BUILD_TAGS" ./... 2>&1 || true)
case "$vuln_out" in
  *"No vulnerabilities found"*|*"affected by 0 vulnerabilities"*) pass ;;
  *"Your code is affected by"*)
    bad
    printf '%s\n' "$vuln_out" | grep -E '^Vulnerability|Found in:|Fixed in:' || true
    ;;
  *)
    printf 'НЕ ЗАПУСТИЛСЯ (нет сети?) — в CI гейт работает\n'
    vuln_notrun=1
    ;;
esac

step "hygiene"
if sh tools/hygiene.sh >/dev/null 2>&1; then pass; else bad; printf '\n'; sh tools/hygiene.sh || true; fi

step "cli responds"
if go run -tags "$BUILD_TAGS" ./cmd/shellshift version >/dev/null 2>&1; then pass; else bad; fi

printf '\n'
if [ "$fail" -ne 0 ]; then echo "ПРОВАЛЕНО — push делать нельзя"; exit 1; fi
# Незапустившийся гейт не выдаётся за пройденный: иначе финальная строка врёт ровно там, где
# читающий её человек решает, можно ли пушить.
if [ "$vuln_notrun" -ne 0 ]; then
  echo "все гейты пройдены, КРОМЕ govulncheck — он не запускался"
  exit 0
fi
echo "все гейты пройдены"
