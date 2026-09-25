import subprocess
import unittest
from unittest.mock import patch
from scanner import Network, parse_windows, parse_linux, scan, command

WINDOWS = '''
Interface name : Wi-Fi
There are 2 networks currently visible.
SSID 1 : Home:Lab
    Authentication : WPA2-Personal
    BSSID 1 : 00:11:22:33:44:55
         Signal : 88%
         Channel : 6
    BSSID 2 : 00:11:22:33:44:66
         Signal : 42%
         Channel : 11
SSID 2 :
    Authentication : Open
    BSSID 1 : 00:11:22:33:44:77
         Signal : 30%
         Channel : 1
'''

class ScannerTests(unittest.TestCase):
    def test_multi_bssid_and_hidden(self):
        rows = parse_windows(WINDOWS)
        self.assertEqual(len(rows), 3)
        self.assertEqual([r.ssid for r in rows], ['Home:Lab', 'Home:Lab', '<hidden>'])
        self.assertEqual([r.signal for r in rows], [88, 42, 30])
        self.assertEqual(rows[1].security, 'WPA2-Personal')
        self.assertEqual(rows[1].channel, '11')
        self.assertIn('no Wi-Fi encryption', rows[2].assessment)

    def test_nmcli_escaping(self):
        raw = r'Home\:Lab:00\:11\:22\:33\:44\:55:81:6:WPA2' + '\n' + r':00\:11\:22\:33\:44\:66:30:11:--'
        rows = parse_linux(raw)
        self.assertEqual(rows[0].ssid, 'Home:Lab')
        self.assertEqual(rows[0].bssid, '00:11:22:33:44:55')
        self.assertEqual(rows[1].ssid, '<hidden>')
        self.assertIn('no Wi-Fi encryption', rows[1].assessment)

    def test_malformed(self):
        self.assertEqual(parse_linux('broken\ndata:a:b:c:d'), [])
        self.assertEqual(parse_windows('Location access is required'), [])

    def test_demo_no_os_commands(self):
        with patch('scanner.command', side_effect=AssertionError('Unexpected OS access')):
            result = scan(True)
        self.assertEqual(result['mode'], 'DEMO')
        self.assertEqual(len(result['networks']), 3)
        self.assertTrue(all(row['ssid'].startswith('DEMO') for row in result['networks']))

    def test_live_windows(self):
        with patch('scanner.platform.system', return_value='Windows'), patch('scanner.command', side_effect=[WINDOWS, 'State : connected']):
            result = scan(False)
        self.assertEqual(result['mode'], 'LIVE')
        self.assertIn('connected', result['connection'])

    def test_live_error_not_demo(self):
        with patch('scanner.platform.system', return_value='Windows'), patch('scanner.command', return_value='Permission denied'):
            with self.assertRaisesRegex(RuntimeError, 'No readable'):
                scan(False)

    def test_zero_networks(self):
        with patch('scanner.platform.system', return_value='Windows'), patch('scanner.command', side_effect=['There are 0 networks currently visible.', 'Disconnected']):
            self.assertEqual(scan()['networks'], [])

    def test_timeout(self):
        with patch('scanner.subprocess.run', side_effect=subprocess.TimeoutExpired('nmcli', 25)):
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                command(['nmcli'])

    def test_missing_command(self):
        with patch('scanner.subprocess.run', side_effect=FileNotFoundError):
            with self.assertRaisesRegex(RuntimeError, 'missing'):
                command(['nmcli'])

    def test_security_labels(self):
        for security, expected in [('WEP', 'Legacy'), ('WPA3', 'WPA3'), ('?', 'Unknown')]:
            self.assertIn(expected, Network('Test', '', 10, '1', security).assessment)

if __name__ == '__main__':
    unittest.main()
