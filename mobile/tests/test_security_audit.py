"""Regression tests for the 2026-09 security audit (trustmux side).

Each class names the finding it pins down.  Everything here runs against the
temp tree the other suites set up; nothing touches a real daemon or tmux.
"""
import hashlib
import base64
import json
import os
import re
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tornado.testing import AsyncHTTPTestCase

import trustmux._daemon as bm
from trustmux import _paths


def _reset_pairing():
    bm._pair_code = ''
    bm._pair_attempts = 0
    bm._pair_attempts_by_ip.clear()
    bm._pair_code_mono_expiry = 0.0
    bm._pair_paired_ip = ''
    bm._sessions.clear()


class TestPairCrossSiteAndBudget(AsyncHTTPTestCase):
    """/pair: a page on another origin must not be able to spend the real
    phone's attempts, and one address must not be able to lock everyone out."""

    def get_app(self):
        return bm._make_app()

    def setUp(self):
        super().setUp()
        _reset_pairing()
        bm._pair_code = '424242'
        bm._pair_code_mono_expiry = time.monotonic() + 300

    def tearDown(self):
        _reset_pairing()
        super().tearDown()

    def _post(self, code='000000', **headers):
        h = {'Content-Type': 'application/json'}
        h.update(headers)
        return self.fetch('/pair', method='POST', body=json.dumps({'code': code}), headers=h)

    def test_form_content_types_are_refused_before_counting(self):
        for ctype in ('text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data'):
            resp = self.fetch('/pair', method='POST', body='{"code":"000000"}',
                              headers={'Content-Type': ctype})
            # tornado itself rejects a boundary-less multipart body with 400;
            # either way it is refused before it can count as a guess.
            self.assertIn(resp.code, (400, 415), ctype)
        self.assertEqual(bm._pair_attempts, 0)

    def test_cross_site_fetch_is_refused_before_counting(self):
        resp = self._post(**{'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(resp.code, 403)
        resp = self._post(Origin='https://evil.example')
        self.assertEqual(resp.code, 403)
        self.assertEqual(bm._pair_attempts, 0)

    def test_same_origin_and_non_browser_requests_are_counted_normally(self):
        host = f'127.0.0.1:{self.get_http_port()}'
        resp = self._post(**{'Sec-Fetch-Site': 'same-origin', 'Origin': f'http://{host}'})
        self.assertEqual(resp.code, 403)          # wrong code, but a real guess
        self.assertEqual(bm._pair_attempts, 1)
        resp = self._post()                       # no browser headers at all
        self.assertEqual(bm._pair_attempts, 2)

    def test_attempts_are_counted_per_source_address(self):
        for _ in range(bm._MAX_PAIR_ATTEMPTS):
            self.assertEqual(self._post().code, 403)
        self.assertEqual(self._post().code, 429)
        # Another address still has its own budget while the total allows.
        self.assertLess(bm._pair_attempts, bm._MAX_PAIR_ATTEMPTS_TOTAL)
        self.assertEqual(bm._pair_attempts_by_ip.get('127.0.0.1'), bm._MAX_PAIR_ATTEMPTS)
        bm._pair_attempts_by_ip['10.0.0.9'] = 0
        # The guard for a fresh address is the total cap only.
        self.assertGreater(bm._MAX_PAIR_ATTEMPTS_TOTAL, bm._pair_attempts)

    def test_generating_a_code_resets_both_counters(self):
        bm._pair_attempts = 4
        bm._pair_attempts_by_ip['1.2.3.4'] = 3
        bm._generate_pair_code()
        self.assertEqual(bm._pair_attempts, 0)
        self.assertEqual(bm._pair_attempts_by_ip, {})

    def test_user_agent_is_sanitised_before_being_stored(self):
        code = bm._generate_pair_code()
        with patch('trustmux._daemon._save_tokens'):
            resp = self._post(code, **{'User-Agent': 'Evil\x1b[2J\x07Agent/1.0 \xe9'})
        self.assertEqual(resp.code, 200)
        label = next(iter(bm._sessions.values()))['label']
        self.assertEqual(label, 'Evil?[2J?Agent/1.0 ?')


class TestCsp(AsyncHTTPTestCase):
    """The inline theme bootstrap must be allowed by hash, never by
    'unsafe-inline', and the directives that do not inherit from default-src
    must be present."""

    def get_app(self):
        return bm._make_app()

    def test_inline_script_hash_matches_the_served_html(self):
        html = (bm.STATIC / 'index.html').read_text(encoding='utf-8')
        blocks = re.findall(r'<script>(.*?)</script>', html, re.S)
        self.assertTrue(blocks, 'expected at least one inline <script> in index.html')
        csp = self.fetch('/').headers.get('Content-Security-Policy', '')
        script_src = csp.split('script-src')[1].split(';')[0]
        for body in blocks:
            digest = base64.b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode()
            self.assertIn(f"'sha256-{digest}'", script_src)
        self.assertNotIn("'unsafe-inline'", script_src)

    def test_non_inheriting_directives_are_present(self):
        csp = self.fetch('/ping').headers.get('Content-Security-Policy', '')
        for directive in ("object-src 'none'", "base-uri 'none'",
                          "form-action 'self'", "frame-ancestors 'none'"):
            self.assertIn(directive, csp)


class TestCertReuse(unittest.TestCase):
    """The keypair survives restarts so a fingerprint can be pinned; only the
    certificate is reissued when the names change; the key is never
    world-readable, not even briefly."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        root = Path(self.td.name) / 'state'
        for attr, value in (('STATE_DIR', root), ('CERT_FILE', root / 'cert.pem'),
                            ('KEY_FILE', root / 'key.pem')):
            p = patch.object(bm, attr, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(bm, '_tailscale_ip', return_value=None)
        p.start()
        self.addCleanup(p.stop)

    def _gen(self, advertised=()):
        with patch('builtins.print'):
            bm._ensure_self_signed_cert('10.0.0.5', advertised)
        return bm.KEY_FILE.read_bytes(), bm.CERT_FILE.read_bytes(), bm._cert_fingerprint

    def test_key_and_cert_are_reused_when_names_are_covered(self):
        k1, c1, f1 = self._gen()
        k2, c2, f2 = self._gen()
        self.assertEqual(k1, k2)
        self.assertEqual(c1, c2)
        self.assertEqual(f1, f2)
        self.assertRegex(f1, r'^([0-9A-F]{2}:){31}[0-9A-F]{2}$')

    def test_new_name_reissues_cert_but_keeps_key(self):
        k1, c1, _ = self._gen()
        k2, c2, _ = self._gen(['tmux.example.com'])
        self.assertEqual(k1, k2)
        self.assertNotEqual(c1, c2)
        # And the reissued cert is then itself reused.
        k3, c3, _ = self._gen(['tmux.example.com'])
        self.assertEqual(c2, c3)

    def test_key_file_is_0600_and_state_dir_0700(self):
        self._gen()
        self.assertEqual(stat.S_IMODE(bm.KEY_FILE.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(bm.STATE_DIR.stat().st_mode), 0o700)

    def test_loose_state_dir_is_tightened_before_the_key_is_written(self):
        bm.STATE_DIR.mkdir(parents=True)
        bm.STATE_DIR.chmod(0o755)
        self._gen()
        self.assertEqual(stat.S_IMODE(bm.STATE_DIR.stat().st_mode), 0o700)

    def test_unreadable_existing_keypair_falls_back_to_a_fresh_one(self):
        bm.STATE_DIR.mkdir(parents=True)
        bm.KEY_FILE.write_text('garbage')
        bm.CERT_FILE.write_text('garbage')
        k, c, f = self._gen()
        self.assertIn(b'PRIVATE KEY', k)
        self.assertIn(b'CERTIFICATE', c)
        self.assertTrue(f)

    def test_write_private_never_passes_through_a_loose_mode(self):
        bm.STATE_DIR.mkdir(parents=True)
        target = bm.STATE_DIR / 'secret'
        old = os.umask(0o000)
        try:
            bm._write_private(target, b'x')
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertFalse(target.with_suffix('.tmp').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
