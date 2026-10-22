"""Тесты для phpcheck.py (порт openai/php2shell-checker)."""

import os
import sys
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


class _Handler(BaseHTTPRequestHandler):
    def _send(self, status=200):
        self.send_response(status)
        self.send_header('Server', 'Apache/2.4.62 (Debian)')
        self.send_header('X-Powered-By', 'PHP/8.3.35')
        self.end_headers()

    def do_HEAD(self):
        self._send()

    def do_GET(self):
        self._send(405 if self.path == '/fallback' else 200)
        if self.path != '/fallback':
            self.wfile.write(b'ok')

    def log_message(self, *args):
        pass


class UrlHeadersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_head_extracts_php_version(self):
        text = phpcheck.url_headers(f'http://127.0.0.1:{self.port}/', 5)
        self.assertIn('PHP/8.3.35', text)

    def test_405_falls_back_to_get(self):
        text = phpcheck.url_headers(f'http://127.0.0.1:{self.port}/fallback', 5)
        self.assertIn('PHP/8.3.35', text)

    def test_rejects_bad_scheme(self):
        with self.assertRaises(ValueError):
            phpcheck.url_headers('ftp://example.com', 5)

    def test_rejects_credentials_and_fragment(self):
        with self.assertRaises(ValueError):
            phpcheck.url_headers(f'http://user:pass@127.0.0.1:{self.port}/#frag', 5)

    def test_main_detects_vulnerable(self):
        self.assertEqual(phpcheck.main([f'http://127.0.0.1:{self.port}/']), 1)

    def test_main_usage_error_no_args(self):
        self.assertEqual(phpcheck.main([]), 2)

    def test_main_usage_error_both_url_and_local(self):
        self.assertEqual(phpcheck.main(['--local', 'https://example.com']), 2)


if __name__ == '__main__':
    unittest.main()
