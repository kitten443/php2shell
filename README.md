# php2shell — чекер уязвимости PHP2Shell (Python 3)

Python 3 порт официального чекера [openai/php2shell-checker](https://github.com/openai/php2shell-checker). Проверяет, уязвима ли версия PHP сайта или локального бинарника к критическим уязвимостям **PHP2Shell** — [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) и [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619) (несанкционированное удалённое выполнение кода в ядре PHP, версии 5.4–8.5).

## Что делает

- **По URL**: отправляет `HEAD`-запрос (при ответе `405/501` повторяет через `GET`), читает заголовки `Server` и `X-Powered-By`, извлекает версию PHP и сверяет её с таблицей уязвимых версий.
- **По списку** (`--file`): сканирует много сайтов разом — синхронно, многопоточно (`--threads N`) или асинхронно (`--async`).
- **Локально** (`--local`): запускает `php -v` и проверяет версию бинарника. Дополнительно — конфигурацию сессий (**CVE-2026-115560**) и версию Brotli в cURL (**CVE-2026-111497**), см. ниже.
- **Никаких эксплойтов**: инструмент только читает версию и конфигурацию. Он ничего не атакует — лишь сообщает, нужно ли обновляться.

## Установка

Требуется Python 3.8+ (только стандартная библиотека, зависимостей нет).

```bash
git clone https://github.com/kitten443/php2shell.git
cd php2shell
```

## Использование

```bash
# Проверить сайт
python3 phpcheck.py https://example.com
python3 phpcheck.py https://example.com --json           # машинный вывод
python3 phpcheck.py https://example.com --timeout 15     # свой таймаут (1–60 с)

# Проверить локальный PHP
python3 phpcheck.py --local
python3 phpcheck.py --local --php /usr/bin/php8.3

# Версия и справка
python3 phpcheck.py --version
python3 phpcheck.py --help
```

### Сканирование списка сайтов

```bash
# Файл со списком: одна строка — один URL, # — комментарии, пустые строки пропускаются
python3 phpcheck.py --file sites.txt

# Многопоточно: N одновременных проверок
python3 phpcheck.py --file sites.txt --threads 10

# Асинхронно (asyncio): --threads задаёт число одновременных задач
python3 phpcheck.py --file sites.txt --threads 50 --async

# Чтение списка из stdin
cat sites.txt | python3 phpcheck.py --file -

# JSON Lines (по одному JSON-объекту на строку)
python3 phpcheck.py --file sites.txt --threads 10 --json
```

Пример файла `sites.txt`:

```
# свои проекты
https://example.com
https://shop.example.com  # интернет-магазин
https://blog.example.com
```

Результаты выводятся по мере завершения проверок:

```
https://shop.example.com — VULNERABLE: PHP 8.3.35
https://example.com — OK: PHP 8.3.36
https://blog.example.com — UNKNOWN: Версия PHP не найдена
```

Код возврата для списка агрегируется: `1` — если хоть один сайт `VULNERABLE`; иначе `3` — если хоть один `UNKNOWN`; иначе `0`.

Примеры вывода:

```
VULNERABLE: PHP 8.3.35
OK: PHP 8.3.36
UNKNOWN: PHP version not found
```

JSON-режим:

```json
{"patch_status": "vulnerable", "php_version": "8.3.35", "reason": "PHP 8.3.35", "exit_code": 1}
```

### Дополнительные проверки (`--local`): CVE-2026-115560 и CVE-2026-111497

С версии 1.2.0 локальная проверка помимо PHP2Shell выводит блок **advisories**:

- **CVE-2026-115560** (session upload progress, advisory PHP от 23.10.2026): читаются
  `session.upload_progress.enabled` и `session.serialize_handler`. Рекомендация PHP до
  выхода полного исправления — `session.upload_progress.enabled = 0`.
- **CVE-2026-111497** (Brotli): читается `curl_version()['brotli_version']` и сверяется
  с таблицей: уязвимы **1.0.3–1.2.0**, исправления — **1.0.10 / 1.1.1 / 1.2.1**.
  Если cURL собран без Brotli, вектор отсутствует.

Пример текстового вывода:

```
OK: PHP 8.3.36
Дополнительные проверки (по конфигурации CLI; у FPM она может отличаться):
  CVE-2026-115560 (session upload progress): OK — session.upload_progress.enabled = 0
  CVE-2026-111497 (Brotli в cURL): OK — brotli/1.2.1 — не уязвим
```

В JSON добавляется массив `advisories` (при ошибке сбора — `advisories_error`):

```json
{"patch_status": "ok", "php_version": "8.3.36", "reason": "PHP 8.3.36", "exit_code": 0, "advisories": [{"cve": "CVE-2026-115560", "title": "session upload progress", "status": "ok", "detail": "session.upload_progress.enabled = 0"}, {"cve": "CVE-2026-111497", "title": "Brotli в cURL", "status": "ok", "detail": "brotli/1.2.1 — не уязвим"}]}
```

Статусы advisories: `ok`, `warning` (нужно действие), `unknown` (не удалось определить),
`not_applicable` (например, cURL не загружен).

> ⚠️ **Advisories не влияют на код возврата** — он по-прежнему отражает только вердикт
> по PHP2Shell. Конфигурация снимается с **CLI**: у PHP-FPM она может отличаться
> (проверяйте на проде в контексте FPM). Удалённо (по URL) эти проверки невозможны:
> ни сессионные настройки, ни версия Brotli в HTTP-заголовках не видны.
> Учтите также, что Brotli может использоваться и другим софтом на сервере
> (nginx, Node.js и т.д.) — чекер смотрит только на Brotli внутри PHP-cURL.

### Коды возврата

| Код | Статус      | Значение |
|-----|-------------|----------|
| 0   | `OK`        | Версия выше cutoff для своей ветки — патч установлен |
| 1   | `VULNERABLE`| Версия ниже или равна cutoff — требуется обновление |
| 3   | `UNKNOWN`   | Версия не определена: скрытые заголовки, неизвестная ветка, сетевая ошибка |
| 2   | —           | Ошибка аргументов командной строки |

Для режима `--file` коды `0/1/3` агрегируются по всем сайтам списка (см. выше).

> ⚠️ **`UNKNOWN` не означает «в безопасности»!** Если заголовки скрыты (CDN/WAF, например DDoS-Guard или Cloudflare), проверяйте версию на самом сервере: `php -v` или `python3 phpcheck.py --local`.

### Таблица уязвимых версий (cutoff проверен 2026-10-27 — новых релизов PHP нет)

| Ветка | Уязвимо ≤ | Безопасно ≥ |
|-------|-----------|-------------|
| 5.4   | 5.4.45    | — (EOL)     |
| 5.5   | 5.5.38    | — (EOL)     |
| 5.6   | 5.6.40    | — (EOL)     |
| 7.0   | 7.0.33    | — (EOL)     |
| 7.1   | 7.1.33    | — (EOL)     |
| 7.2   | 7.2.34    | — (EOL)     |
| 7.3   | 7.3.33    | — (EOL)     |
| 7.4   | 7.4.33    | — (EOL)     |
| 8.0   | 8.0.30    | — (EOL)     |
| 8.1   | 8.1.34    | — (EOL)     |
| 8.2   | 8.2.34    | **8.2.35**  |
| 8.3   | 8.3.35    | **8.3.36**  |
| 8.4   | 8.4.26    | **8.4.27**  |
| 8.5   | 8.5.11    | **8.5.12**  |

## Как защититься

Чекер — только диагностика. Единственная полная защита от PHP2Shell — обновление PHP:

```bash
# Debian/Ubuntu
apt update && apt install --only-upgrade 'php*'
systemctl restart php8.3-fpm    # или ваш SAPI (apache2, php-fpm и т.д.)
```

EOL-ветки (7.4–8.1) официальных бинарных патчей не получили — только апгрейд или бэкпорты дистрибутива.

Дополнительно (не относится к PHP2Shell напрямую):

- **CVE-2026-115560**: до следующего регулярного релиза PHP установите
  `session.upload_progress.enabled = 0` в php.ini или пуле FPM — не через `ini_set()`,
  настройка должна применяться до разбора запроса.
- **CVE-2026-111497**: обновите системную библиотеку Brotli до пропатченной
  (1.0.10 / 1.1.1 / 1.2.1) — в Linux она обновляется отдельно от PHP
  (для Alpine/Debian исправления уже выпущены).

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

## Ограничения

- Проверяет только версию из заголовков `Server`/`X-Powered-By` или из `php -v`. Не выполняет эксплуатацию и не проверяет фактическое наличие фикса.
- `OK` — сравнение версий с предположением, что все стабильные патчи ветки содержат фикс. Сверяйтесь с официальным релизом PHP.
- Заголовки могут быть скрыты или подменены; бэкпорты дистрибутивов могут не менять номер версии.
- Редиректы не отслеживаются.
- Асинхронный режим (`--async`) оркеструется через asyncio, а сами сетевые проверки выполняются в пуле потоков — внешние зависимости при этом не добавляются.
- Advisories (`--local`) снимаются с CLI-конфигурации, а не FPM; Brotli проверяется только в PHP-cURL, а не во всех компонентах сервера.

## Дисклеймер

Инструмент предназначен **только для проверки собственных систем**. Не используйте его для сканирования чужих ресурсов без разрешения владельца.

## Лицензия и атрибуция

Apache License 2.0 (см. [LICENSE](LICENSE)). Это точный порт логики [openai/php2shell-checker](https://github.com/openai/php2shell-checker) © OpenAI (оригинал также под Apache-2.0).
