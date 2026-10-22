#!/usr/bin/env python3
"""
phpcheck.py — Python 3 порт официального чекера openai/php2shell-checker (phpcheck.js).

Проверяет сайт по URL, список сайтов из файла или локальный бинарник PHP
и сообщает, уязвима ли версия к php2shell (CVE-2026-109618 / CVE-2026-109619).

Коды возврата: 0 — OK, 1 — VULNERABLE, 3 — UNKNOWN, 2 — ошибка аргументов.
Для списка сайтов код возврата агрегируется по всем результатам.
Точный порт логики Node.js-версии; оригинал (c) OpenAI, Apache-2.0.
"""

import asyncio
import json
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

VERSION = '1.1.0'

# Пороговые версии уязвимости по веткам (данные на 2026-10-20).
# Новый стабильный патч в перечисленной ветке считается безопасным;
# ветки, которых нет в таблице, дают статус UNKNOWN.
VULNERABLE_THROUGH = {
    '5.4': 45, '5.5': 38, '5.6': 40,
    '7.0': 33, '7.1': 33, '7.2': 34, '7.3': 33, '7.4': 33,
    '8.0': 30, '8.1': 34, '8.2': 34, '8.3': 35, '8.4': 26, '8.5': 11,
}

USAGE = (
    'Использование: python3 phpcheck.py URL [--timeout СЕКУНДЫ] [--json]\n'
    '               python3 phpcheck.py --local [--php ПУТЬ] [--json]\n'
    '               python3 phpcheck.py --file ФАЙЛ [--threads N] [--async] [--timeout СЕКУНДЫ] [--json]\n'
    '               python3 phpcheck.py --version'
)

# Коды возврата по статусу проверки.
EXIT = {'ok': 0, 'vulnerable': 1, 'unknown': 3}

# Шаблон версии X.Y.Z с необязательным суффиксом (-/+...).
_VERSION_RE = re.compile(r'^(\d+)\.(\d+)\.(\d+)([-+~].*)?$')
# Признак предрелизной сборки (dev/alpha/beta/rc) в суффиксе.
_DEV_SUFFIX = re.compile(r'(?:^|[-+~.])(?:dev|alpha|beta|rc)', re.IGNORECASE)
# Извлечение версии PHP из заголовков ответа.
_URL_VERSION_RE = re.compile(r'\bPHP[ /]([^\s,;)]+)', re.IGNORECASE)
# Извлечение версии PHP из вывода `php -v`.
_LOCAL_VERSION_RE = re.compile(r'^PHP (\d[^\s,;)]*)', re.MULTILINE)

# Замок на печать результатов — чтобы строки не перемешивались между потоками.
_print_lock = threading.Lock()


def patch_status(version):
    """Вернуть статус 'ok', 'vulnerable' или 'unknown' для строки версии PHP."""
    m = _VERSION_RE.match(version or '')
    if not m:
        return 'unknown'
    cutoff = VULNERABLE_THROUGH.get(f'{int(m.group(1))}.{int(m.group(2))}')
    if cutoff is None:
        return 'unknown'
    if int(m.group(3)) <= cutoff:
        return 'vulnerable'
    # Предрелизная сборка следующего патча — ещё не доказательство стабильного фикса.
    if m.group(4) and _DEV_SUFFIX.search(m.group(4)):
        return 'unknown'
    return 'ok'


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Вернуть ответ 3xx как есть, не следуя редиректу (аналог manual в Node)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def url_headers(address, timeout):
    """HEAD-запрос к URL (GET при 405/501) и возврат строки 'Server\\nX-Powered-By'."""
    if re.search(r'[\x00-\x20\x7f]', address):
        raise ValueError('URL содержит пробелы или управляющие символы')
    parts = urllib.parse.urlsplit(address)
    if parts.scheme not in ('http', 'https'):
        raise ValueError('Используйте URL вида http:// или https://')
    if parts.username or parts.password or parts.fragment:
        raise ValueError('Учётные данные и фрагменты в URL не поддерживаются')

    opener = urllib.request.build_opener(_NoRedirect())
    headers = []
    for method in ('HEAD', 'GET'):
        req = urllib.request.Request(address, method=method)
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            # urllib оборачивает статусы >= 400 в HTTPError; заголовки в нём есть.
            resp = exc
        headers.append(resp.headers.get('Server') or '')
        headers.append(resp.headers.get('X-Powered-By') or '')
        resp.close()
        if resp.code not in (405, 501):
            break
    return '\n'.join(headers)


def _match_status(text, pattern):
    """Пройти по всем совпадениям версий в тексте и вернуть (version, status)."""
    version = None
    status = 'unknown'
    for match in pattern.finditer(text):
        candidate = patch_status(match.group(1))
        # Баннер OK не должен скрывать уязвимую или нераспознанную версию.
        if version is None or candidate == 'vulnerable' or status == 'ok':
            version = match.group(1)
            status = candidate
        if status == 'vulnerable':
            break
    return version, status


def check_url(address, timeout):
    """Проверить URL и вернуть кортеж (status, version, error)."""
    version = None
    error = None
    status = 'unknown'
    try:
        text = url_headers(address, timeout)
        version, status = _match_status(text, _URL_VERSION_RE)
    except Exception as exc:
        error = str(exc)
    return status, version, error


def check_local(php_bin):
    """Проверить локальный бинарник PHP и вернуть кортеж (status, version, error)."""
    version = None
    error = None
    status = 'unknown'
    try:
        text = subprocess.run(
            [php_bin, '-v'],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout
        # Вывод php -v содержит копирайты и может включать предупреждения.
        version, status = _match_status(text, _LOCAL_VERSION_RE)
    except Exception as exc:
        error = str(exc)
    return status, version, error


def read_urls(path):
    """Прочитать список URL из файла ('-' — stdin).

    Пропускаются пустые строки и комментарии (#), дубликаты убираются.
    """
    if path == '-':
        lines = sys.stdin
        close = False
    else:
        lines = open(path, encoding='utf-8')
        close = True
    try:
        urls = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Поддержка хвостовых комментариев вида: url # заметка
            urls.append(line.split('#', 1)[0].strip())
    finally:
        if close:
            lines.close()
    return list(dict.fromkeys(urls))  # дедупликация с сохранением порядка


def _print_result(url, status, version, error, json_out):
    """Напечатать результат проверки одного URL (человеко- или JSON-читаемо)."""
    code = EXIT[status]
    reason = error or (f'PHP {version}' if version else 'Версия PHP не найдена')
    with _print_lock:
        if json_out:
            print(json.dumps({
                'url': url,
                'patch_status': status,
                'php_version': version,
                'reason': reason,
                'exit_code': code,
            }, ensure_ascii=False))
        else:
            print(f'{url} — {status.upper()}: {reason}')
    return code


async def _run_async(urls, workers, timeout, handle):
    """Асинхронная оркестрация проверок с ограничением одновременности."""
    semaphore = asyncio.Semaphore(workers)
    loop = asyncio.get_running_loop()

    async def one(url):
        async with semaphore:
            # Сетевой вызов блокирующий — выполняется в пуле потоков.
            await loop.run_in_executor(None, handle, url)

    await asyncio.gather(*(one(url) for url in urls))


def run_bulk(urls, threads, timeout, async_mode, json_out):
    """Проверить список URL и вернуть агрегированный код возврата.

    Порядок результатов — по мере завершения проверок (в синхронном режиме
    совпадает с порядком в файле).
    """
    codes = []

    def handle(url):
        status, version, error = check_url(url, timeout)
        codes.append(_print_result(url, status, version, error, json_out))

    if async_mode:
        asyncio.run(_run_async(urls, threads, timeout, handle))
    elif threads > 1:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            list(executor.map(handle, urls))
    else:
        for url in urls:
            handle(url)

    # Агрегация кода возврата: VULNERABLE важнее UNKNOWN, UNKNOWN важнее OK.
    if EXIT['vulnerable'] in codes:
        return EXIT['vulnerable']
    if EXIT['unknown'] in codes:
        return EXIT['unknown']
    return EXIT['ok']


def _usage_error(message):
    """Напечатать ошибку с подсказкой по использованию и вернуть код 2."""
    print(message + '\n' + USAGE, file=sys.stderr)
    return 2


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv

    opts = {
        'local': False,
        'php': 'php',
        'timeout': '10',
        'file': None,
        'threads': '1',
        'threads_set': False,
        'async': False,
        'json': False,
        'version': False,
        'help': False,
    }
    positionals = []
    i = 0
    # Разбор аргументов вручную — чтобы точно контролировать коды возврата.
    while i < len(args):
        arg = args[i]
        if arg in ('-h', '--help'):
            opts['help'] = True
        elif arg == '--local':
            opts['local'] = True
        elif arg == '--async':
            opts['async'] = True
        elif arg == '--json':
            opts['json'] = True
        elif arg == '--version':
            opts['version'] = True
        elif arg in ('--php', '--timeout', '--file', '--threads'):
            i += 1
            if i >= len(args):
                return _usage_error(f'Для {arg} требуется значение')
            key = arg[2:]
            opts[key] = args[i]
            if key == 'threads':
                opts['threads_set'] = True
        elif arg.startswith(('--php=', '--timeout=', '--file=', '--threads=')):
            key, _, value = arg.partition('=')
            key = key[2:]
            opts[key] = value
            if key == 'threads':
                opts['threads_set'] = True
        elif arg.startswith('-') and arg != '-':
            return _usage_error(f'Неизвестная опция: {arg}')
        else:
            positionals.append(arg)
        i += 1

    if opts['version']:
        print(VERSION)
        return 0
    if opts['help']:
        print(USAGE)
        return 0

    address = positionals[0] if positionals else None

    # Проверка сочетаемости режимов.
    if len(positionals) > 1:
        return _usage_error('Можно указать только один URL')
    if (opts['local'] and (address is not None or opts['file'])) \
            or (address is not None and opts['file']):
        return _usage_error('Укажите что-то одно: URL, --file или --local')
    if not opts['local'] and address is None and opts['file'] is None:
        return _usage_error('Укажите URL, --file или --local')
    if opts['async'] and not opts['file']:
        return _usage_error('--async можно использовать только вместе с --file')
    if opts['threads_set'] and not opts['file']:
        return _usage_error('--threads можно использовать только вместе с --file')

    # Число потоков: целое от 1.
    try:
        threads = int(opts['threads'])
    except ValueError:
        threads = 0
    if threads < 1:
        return _usage_error('--threads должен быть целым числом от 1')

    # Таймаут валидируется только для сетевых режимов (URL и --file).
    try:
        timeout = float(opts['timeout'])
    except ValueError:
        timeout = float('nan')
    if not opts['local'] and not (0 < timeout <= 60):
        return _usage_error('--timeout должен быть больше 0 и не больше 60 секунд')

    # Локальная проверка бинарника.
    if opts['local']:
        status, version, error = check_local(opts['php'])
        code = EXIT[status]
        reason = error or (f'PHP {version}' if version else 'Версия PHP не найдена')
        report = {
            'patch_status': status,
            'php_version': version,
            'reason': reason,
            'exit_code': code,
        }
        if opts['json']:
            print(json.dumps(report, ensure_ascii=False))
        else:
            print(f'{status.upper()}: {reason}')
        return code

    # Массовое сканирование списка сайтов.
    if opts['file']:
        try:
            urls = read_urls(opts['file'])
        except OSError as exc:
            # Файл не найден / нет прав / это каталог — аккуратная ошибка вместо traceback.
            return _usage_error(f'Не удалось прочитать файл со списком: {exc}')
        if not urls:
            return _usage_error('Файл не содержит ни одного URL')
        return run_bulk(urls, threads, timeout, opts['async'], opts['json'])

    # Одиночный URL.
    status, version, error = check_url(address, timeout)
    code = EXIT[status]
    reason = error or (f'PHP {version}' if version else 'Версия PHP не найдена')
    report = {
        'patch_status': status,
        'php_version': version,
        'reason': reason,
        'exit_code': code,
    }
    if opts['json']:
        print(json.dumps(report, ensure_ascii=False))
    else:
        print(f'{status.upper()}: {reason}')
    return code


if __name__ == '__main__':
    sys.exit(main())
