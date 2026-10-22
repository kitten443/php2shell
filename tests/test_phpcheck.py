"""Тесты для phpcheck.py (порт openai/php2shell-checker)."""

import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import phpcheck  # noqa: E402


class PatchStatusTests(unittest.TestCase):
    CASES = {
        # уязвимые ветки (EOL)
        '5.4.45': 'vulnerable',
        '5.5.38': 'vulnerable',
        '5.6.40': 'vulnerable',
        '7.0.33': 'vulnerable',
        '7.1.33': 'vulnerable',
        '7.2.34': 'vulnerable',
        '7.3.33': 'vulnerable',
        '7.4.33': 'vulnerable',
        '8.0.30': 'vulnerable',
        '8.1.34': 'vulnerable',
        # поддерживаемые ветки: cutoff и патч
        '8.2.34': 'vulnerable',
        '8.2.35': 'ok',
        '8.3.35': 'vulnerable',
        '8.3.36': 'ok',
        '8.4.26': 'vulnerable',
        '8.4.27': 'ok',
        '8.5.11': 'vulnerable',
        '8.5.12': 'ok',
        # неизвестные ветки / мусор
        '8.6.0': 'unknown',
        '9.0.0': 'unknown',
        'junk': 'unknown',
        '8.3': 'unknown',
        '': 'unknown',
        None: 'unknown',
        # пререлизы и суффиксы дистрибутивов
        '8.1.35rc1': 'unknown',
        '8.2.35+ubuntu': 'ok',
        '8.4.27-1+deb12u1': 'ok',
        '8.3.36-dev': 'unknown',
    }

    def test_patch_status_table(self):
        for version, expected in self.CASES.items():
            with self.subTest(version=version):
                self.assertEqual(phpcheck.patch_status(version), expected)


def make_handler(server_header='Apache/2.4.62 (Debian)', powered_by='PHP/8.3.35'):
    """Фабрика HTTP-обработчиков с заданными заголовками."""
    class H(BaseHTTPRequestHandler):
        def _send(self, status=200):
            self.send_response(status)
            if server_header is not None:
                self.send_header('Server', server_header)
            if powered_by is not None:
                self.send_header('X-Powered-By', powered_by)
            self.end_headers()

        def do_HEAD(self):
            self._send()

        def do_GET(self):
            self._send(405 if self.path == '/fallback' else 200)
            if self.path != '/fallback':
                self.wfile.write(b'ok')

        def log_message(self, *args):
            pass

    return H


def start_server(handler):
    """Запустить тестовый HTTP-сервер в фоновом потоке, вернуть (server, url)."""
    server = HTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f'http://127.0.0.1:{server.server_address[1]}/'


class UrlHeadersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = start_server(make_handler())

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_head_extracts_php_version(self):
        text = phpcheck.url_headers(self.url, 5)
        self.assertIn('PHP/8.3.35', text)

    def test_405_falls_back_to_get(self):
        text = phpcheck.url_headers(self.url + 'fallback', 5)
        self.assertIn('PHP/8.3.35', text)

    def test_rejects_bad_scheme(self):
        with self.assertRaises(ValueError):
            phpcheck.url_headers('ftp://example.com', 5)

    def test_rejects_credentials_and_fragment(self):
        with self.assertRaises(ValueError):
            phpcheck.url_headers(f'http://user:pass@127.0.0.1:{self.server.server_address[1]}/#frag', 5)

    def test_main_detects_vulnerable(self):
        self.assertEqual(phpcheck.main([self.url]), 1)

    def test_main_usage_error_no_args(self):
        self.assertEqual(phpcheck.main([]), 2)

    def test_main_usage_error_both_url_and_local(self):
        self.assertEqual(phpcheck.main(['--local', 'https://example.com']), 2)


class BulkScanTests(unittest.TestCase):
    """Массовое сканирование списка URL: sync, threads, async, агрегация кодов."""

    @classmethod
    def setUpClass(cls):
        cls.servers = []
        # уязвимый / пропатченный / без PHP-заголовков
        for server_header, powered_by in (
            ('Apache', 'PHP/8.3.35'),
            ('Apache', 'PHP/8.3.36'),
            ('nginx', None),
        ):
            server, url = start_server(make_handler(server_header, powered_by))
            cls.servers.append(server)
            cls.urls.append(url)
        # файл со списком: комментарии, пустые строки, дубликат, хвостовой комментарий
        fd, cls.urls_file = tempfile.mkstemp(suffix='.txt')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write('# список для проверки\n\n')
            f.write(f'{cls.urls[0]}\n')
            f.write(f'{cls.urls[1]}\n')
            f.write(f'{cls.urls[0]} # дубликат\n')
            f.write(f'{cls.urls[2]}\n')
        # файл только с UNKNOWN-результатом
        fd, cls.unknown_file = tempfile.mkstemp(suffix='.txt')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(f'{cls.urls[2]}\n')

    urls = []

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
        os.unlink(cls.urls_file)
        os.unlink(cls.unknown_file)

    def test_read_urls_filters_comments_and_dupes(self):
        self.assertEqual(phpcheck.read_urls(self.urls_file), self.urls)

    def test_sync_scan_aggregates_vulnerable(self):
        self.assertEqual(phpcheck.main(['--file', self.urls_file]), 1)

    def test_threads_scan_aggregates_vulnerable(self):
        self.assertEqual(phpcheck.main(['--file', self.urls_file, '--threads', '3']), 1)

    def test_async_scan_aggregates_vulnerable(self):
        self.assertEqual(phpcheck.main(['--file', self.urls_file, '--threads', '3', '--async']), 1)

    def test_only_unknown_aggregates_3(self):
        self.assertEqual(phpcheck.main(['--file', self.unknown_file]), 3)

    def test_usage_async_without_file(self):
        self.assertEqual(phpcheck.main(['--async', 'https://example.com']), 2)

    def test_usage_threads_without_file(self):
        self.assertEqual(phpcheck.main(['--threads', '5', 'https://example.com']), 2)

    def test_usage_threads_zero(self):
        self.assertEqual(phpcheck.main(['--file', self.urls_file, '--threads', '0']), 2)

    def test_usage_file_and_url_together(self):
        self.assertEqual(phpcheck.main(['--file', self.urls_file, 'https://example.com']), 2)

    def test_usage_empty_file(self):
        fd, empty = tempfile.mkstemp(suffix='.txt')
        os.close(fd)
        try:
            self.assertEqual(phpcheck.main(['--file', empty]), 2)
        finally:
            os.unlink(empty)

    def test_usage_missing_file(self):
        self.assertEqual(phpcheck.main(['--file', '/nonexistent/definitely-missing.txt']), 2)


if __name__ == '__main__':
    unittest.main()
