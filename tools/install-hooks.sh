#!/usr/bin/env sh
# Ставит pre-commit hook. Запустить один раз после клонирования.
set -eu
root=$(git rev-parse --show-toplevel)
hook="$root/.git/hooks/pre-commit"
cat > "$hook" <<'HOOK'
#!/usr/bin/env sh
set -eu
root=$(git rev-parse --show-toplevel)
"$root/tools/hygiene.sh" --staged
# gofmt только по проиндексированным Go-файлам, архив исключён
staged_go=$(git diff --cached --name-only --diff-filter=ACMR | grep '\.go$' | grep -v '^docs/ghost/_legacy/' || true)
if [ -n "$staged_go" ]; then
  bad=$(gofmt -l $staged_go || true)
  if [ -n "$bad" ]; then
    echo "pre-commit: не отформатировано gofmt:"; echo "$bad"; exit 1
  fi
fi
HOOK
chmod +x "$hook"
echo "pre-commit hook установлен: $hook"
