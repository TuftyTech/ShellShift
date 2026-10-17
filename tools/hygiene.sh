#!/usr/bin/env sh
# Гейты гигиены репозитория.
#
# Репозиторий публичный с первого коммита, поэтому «подчистим перед публикацией»
# не существует как момент: любой коммит виден сразу и остаётся в истории навсегда.
# Эти проверки исполняются и в CI, и как pre-commit hook (tools/install-hooks.sh).
#
# Запуск:  ./tools/hygiene.sh            — по всем отслеживаемым файлам
#          ./tools/hygiene.sh --staged   — только по проиндексированным
set -eu

fail=0
notrun=0
err() { printf '  FAIL  %s\n' "$1"; fail=1; }
ok()  { printf '  ok    %s\n' "$1"; }

if [ "${1:-}" = "--staged" ]; then
  files=$(git diff --cached --name-only --diff-filter=ACMR)
  scope="проиндексированные файлы"
else
  files=$(git ls-files)
  scope="все отслеживаемые файлы"
fi
printf 'гигиена: %s\n' "$scope"
[ -z "$files" ] && { echo "  нечего проверять"; exit 0; }

# --- 1. Сгенерированные артефакты не коммитятся (INV-43, PERF-040) ---------------
gen=$(printf '%s\n' "$files" | grep -E '^(sub_[a-z0-9]+\.txt|index\.html|nodes\.json)$|^(dist|public|site)/' || true)
if [ -n "$gen" ]; then
  err "сгенерированные артефакты в индексе:"; printf '        %s\n' $gen
else
  ok "сгенерированных артефактов нет"
fi

# --- 2. Бинарники не коммитятся -------------------------------------------------
bins=$(printf '%s\n' "$files" | grep -E '\.(exe|dll|so|dylib|a|test)$' || true)
if [ -n "$bins" ]; then err "бинарники в индексе:"; printf '        %s\n' $bins; else ok "бинарников нет"; fi

# --- 3. Секреты высокой уверенности --------------------------------------------
# Форматы: PEM-блок, GitHub PAT, telegram bot token, AWS access key.
#
# Исключения нет, и это отдельное решение. Здесь стояло `docs/ghost/*) continue`, и в этой
# дырке утечка и жила: в архиве предшественника лежал settings.yaml с URL whitelist-баз РКН,
# публичным URL дашборда и тегом канала, и ни один гейт в дереве не мог этого заметить.
# Архив теперь вне дерева (см. /docs/ в .gitignore), а исключение снято, чтобы дырка
# не открылась заново вместе с ним.
hits=""
for f in $files; do
  [ -f "$f" ] || continue
  if grep -lqE '(-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|[0-9]{8,10}:AA[A-Za-z0-9_-]{30,}|AKIA[0-9A-Z]{16})' "$f" 2>/dev/null; then
    hits="$hits $f"
  fi
done
if [ -n "$hits" ]; then err "похоже на секрет:$hits"; else ok "секретов не найдено"; fi

# --- 4. URL источников допустимы ТОЛЬКО в config/ и docs/ -----------------------
# У предшественника health-состояние ключевалось сырыми URL и коммитилось в
# публичный репозиторий, что делало «секретный» список источников читаемым всем.
# В ShellShift список — осознанный публичный конфиг, а состояние прогона URL не несёт.
leak=""
for f in $files; do
  [ -f "$f" ] || continue
  case "$f" in
    config/*|docs/*|README.md|*.md|.github/*|tools/*|go.sum) continue ;;
  esac
  case "$f" in
    *.json|*.yaml|*.yml|*.txt)
      grep -lqE 'https?://[a-zA-Z0-9]' "$f" 2>/dev/null && leak="$leak $f" ;;
  esac
done
if [ -n "$leak" ]; then
  err "URL в файле состояния (ожидались только в config/ или docs/):$leak"
else
  ok "URL только там, где им положено"
fi

# --- 5. SEC-024: каждый uses пинится по 40-символьному SHA, не по тегу ----------
badpin=""
for wf in $(printf '%s
' "$files" | grep -E '^\.github/workflows/.*\.ya?ml$' || true); do
  [ -f "$wf" ] || continue
  refs=$(grep -oE 'uses:[[:space:]]*[^[:space:]]+' "$wf" | awk '{print $2}' || true)
  for r in $refs; do
    case "$r" in
      *@*) sha=${r##*@}
           case "$sha" in
             [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
             *) badpin="$badpin $r" ;;
           esac ;;
      *) badpin="$badpin $r(без версии)" ;;
    esac
  done
done
if [ -n "$badpin" ]; then err "uses не запинен по SHA:$badpin"; else ok "все uses запинены по SHA"; fi

# --- 6. Архив старого проекта не импортируется ----------------------------------
imports=$(grep -rlE '"github\.com/tuftytech/shellshift/docs/' --include='*.go' . 2>/dev/null || true)
if [ -n "$imports" ]; then err "импорт из docs/:"; printf '        %s\n' $imports; else ok "архив не импортируется"; fi

# --- 7. Каждый объявленный инвариант назван в тесте -----------------------------
# Правило проекта: инвариант считается перенесённым только когда тест ссылается на его
# номер. Перенос «по смыслу» — это то, как у предшественника одно и то же правило
# протокола оказалось реализовано трижды, и все три версии расходились.
#
# До этого гейта правило существовало только в CLAUDE.md, то есть не могло упасть: 26 из
# 56 инвариантов не были названы нигде, и отличить «покрыт, но без метки» от «не
# перенесён» можно было только вручную.
#
# Инвариант, для которого теста быть не может, помечается в invariants.md строкой
# «**Не тестируется:** причина» — тогда причина живёт рядом с инвариантом и видна в
# ревью, а не в списке исключений внутри скрипта.
inv_file=docs/ghost/invariants.md
if [ ! -f "$inv_file" ]; then
  # docs/ живёт вне дерева, так что на чистом чекауте объявлений просто нет. Это
  # докладывается, а не проглатывается: гейт, который не запускался, не выдаётся за
  # пройденный — так же поступает verify.sh с govulncheck. Проверяемая половина
  # правила — метки INV-nn в тестах — при этом на месте.
  printf '  ..    инварианты: НЕ ПРОВЕРЕНО (нет %s — docs/ вне дерева)\n' "$inv_file"
  notrun=1
else
  # Объявленные инварианты и наличие у каждого пометки об исключении.
  declared=$(awk '
    /^#+ .*INV-[0-9][0-9] ·/ {
      if (id != "") print id, exempt
      match($0, /INV-[0-9][0-9]/); id = substr($0, RSTART, RLENGTH); exempt = "no"
      next
    }
    /\*\*Не тестируется:\*\*[[:space:]]*[^[:space:]]/ { if (id != "") exempt = "yes" }
    END { if (id != "") print id, exempt }
  ' "$inv_file")

  # Названные в тестах. Метка в невыполняемом коде не считается: она ничего не проверяет.
  named=$(grep -rhoE 'INV-[0-9][0-9]' --include='*_test.go' . 2>/dev/null |
    grep -v '^docs/' | sort -u || true)

  unported=""; stale=""
  for row in $(printf '%s\n' "$declared" | tr ' ' ':'); do
    id=${row%%:*}; exempt=${row##*:}
    if printf '%s\n' "$named" | grep -qx "$id"; then
      [ "$exempt" = "yes" ] && stale="$stale $id"
    else
      [ "$exempt" = "no" ] && unported="$unported $id"
    fi
  done

  if [ -n "$unported" ]; then
    err "инвариант объявлен, но ни один тест не называет его номер:$unported"
    printf '        закройте тестом со ссылкой на номер, либо пометьте в %s\n' "$inv_file"
    printf '        строкой «**Не тестируется:** причина»\n'
  else
    ok "каждый объявленный инвариант назван в тесте или помечен как нетестируемый"
  fi
  # Исключение, которое перестало быть нужным, — это причина, разошедшаяся с кодом.
  if [ -n "$stale" ]; then
    err "помечен как нетестируемый, но тест его называет — снимите пометку:$stale"
  fi
fi

# Гейта «архив _legacy/ не переформатирован» здесь больше нет, и это не упущение: архив
# вне дерева и не может попасть в индекс, так что проверка staged-изменений в нём
# всегда докладывала бы «не изменён». Гейт, который не может упасть, хуже отсутствующего.

printf '\n'
if [ "$fail" -ne 0 ]; then echo "гигиена: ПРОВАЛЕНА"; exit 1; fi
if [ "$notrun" -ne 0 ]; then
  echo "гигиена: пройдена, КРОМЕ проверки инвариантов — она не запускалась"
  exit 0
fi
echo "гигиена: пройдена"
