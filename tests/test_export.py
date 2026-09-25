import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from main import Monitor
from scanner import scan

class ExportTests(unittest.TestCase):
    def test_export_json_csv_and_ssid_formula(self):
        monitor = Monitor.__new__(Monitor)
        monitor.snapshot = scan(True)
        monitor.snapshot['networks'][0]['ssid'] = '=1+1'
        monitor.status = Mock()
        with tempfile.TemporaryDirectory() as folder:
            for kind in ('json', 'csv'):
                path = Path(folder) / ('report.'+kind)
                with patch('main.filedialog.asksaveasfilename', return_value=str(path)):
                    monitor.export(kind)
                if kind == 'json':
                    self.assertEqual(json.loads(path.read_text())['mode'], 'DEMO')
                else:
                    with path.open(encoding='utf-8-sig', newline='') as file:
                        rows = list(csv.DictReader(file))
                    self.assertEqual(rows[0]['ssid'], "'=1+1")
                    self.assertEqual(rows[0]['mode'], 'DEMO')

if __name__ == '__main__':
    unittest.main()
