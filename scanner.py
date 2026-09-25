"""Read Wi-Fi metadata from the host OS; no connection or credential changes."""
from dataclasses import dataclass, asdict
import os
import platform
import random
import re
import subprocess
from datetime import datetime, timezone


@dataclass
class Network:
    ssid: str
    bssid: str
    signal: int
    channel: str
    security: str

    @property
    def assessment(self):
        security = self.security.upper()
        if security in ('OPEN', '--', 'NONE'):
            return 'Open network: no Wi-Fi encryption'
        if 'WEP' in security:
            return 'Legacy WEP: upgrade router security'
        if 'WPA3' in security:
            return 'WPA3 advertised; not a security audit'
        if 'WPA2' in security:
            return 'WPA2 advertised; verify router settings'
        if 'WPA' in security:
            return 'Legacy WPA advertised: review settings'
        return 'Unknown: inspect router settings'


def parse_windows(output):
    """Parse English netsh output, preserving distinct BSSIDs per SSID."""
    result, ssid, security, current = [], '', 'Unknown', None
    for line in output.splitlines():
        key, sep, value = line.strip().partition(':')
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if re.fullmatch(r'SSID\s+\d+', key):
            ssid, security, current = value or '<hidden>', 'Unknown', None
        elif key == 'Authentication':
            security = value
        elif re.fullmatch(r'BSSID\s+\d+', key):
            current = Network(ssid, value, 0, '?', security)
            result.append(current)
        elif current and key == 'Signal':
            match = re.search(r'\d+', value)
            current.signal = min(100, int(match.group())) if match else 0
        elif current and key == 'Channel':
            current.channel = value
    return result


def split_nmcli(line):
    fields, field, escaped = [], [], False
    for char in line:
        if escaped:
            field.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == ':':
            fields.append(''.join(field))
            field = []
        else:
            field.append(char)
    if escaped:
        field.append('\\')
    fields.append(''.join(field))
    return fields


def parse_linux(output):
    result = []
    for line in output.splitlines():
        parts = split_nmcli(line)
        if len(parts) != 5:
            continue
        ssid, bssid, signal, channel, security = parts
        if signal.isdigit():
            result.append(Network(ssid or '<hidden>', bssid,
                                  min(100, int(signal)), channel, security or 'Open'))
    return result


def command(args):
    env = os.environ.copy()
    if platform.system() != 'Windows':
        env['LC_ALL'] = 'C'
    try:
        proc = subprocess.run(args, capture_output=True, timeout=25, env=env,
                              creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except FileNotFoundError:
        raise RuntimeError('Scanner command missing. Windows needs netsh; Linux needs NetworkManager/nmcli.') from None
    except subprocess.TimeoutExpired:
        raise RuntimeError('Scan timed out. Check your Wi-Fi adapter and try again.') from None
    encoding = 'oem' if platform.system() == 'Windows' else 'utf-8'
    output = proc.stdout.decode(encoding, errors='replace')
    error = proc.stderr.decode(encoding, errors='replace')
    if proc.returncode:
        raise RuntimeError((error or output or 'OS scanner failed.').strip()[:1600])
    return output


def scan(demo=False):
    if demo:
        rows = [Network('DEMO Home WiFi', '02:00:00:00:00:01', random.randint(72, 95), '6', 'WPA2-Personal'),
                Network('DEMO Lab WPA3', '02:00:00:00:00:02', random.randint(45, 70), '36', 'WPA3-Personal'),
                Network('DEMO Guest Open', '02:00:00:00:00:03', random.randint(20, 42), '11', 'Open')]
        raw, connection = 'Synthetic sample data; no radio scan performed.', 'DEMO MODE — simulated networks only'
    elif platform.system() == 'Windows':
        raw = command(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'])
        rows = parse_windows(raw)
        if not rows and not re.search(r'There (?:are|is) 0 network', raw, re.I):
            raise RuntimeError('No readable Wi-Fi results. Check Wi-Fi adapter, WLAN AutoConfig, and Windows location access. English netsh output is required.\n\n' + raw[:1400])
        try:
            connection = command(['netsh', 'wlan', 'show', 'interfaces'])
        except RuntimeError as exc:
            connection = str(exc)
    elif platform.system() == 'Linux':
        raw = command(['nmcli', '-t', '-e', 'yes', '-f', 'SSID,BSSID,SIGNAL,CHAN,SECURITY', 'device', 'wifi', 'list'])
        rows = parse_linux(raw)
        if raw.strip() and not rows:
            raise RuntimeError('Could not parse nmcli results. Check NetworkManager output.')
        try:
            connection = command(['nmcli', '-f', 'DEVICE,TYPE,STATE,CONNECTION', 'device', 'status'])
        except RuntimeError as exc:
            connection = str(exc)
    else:
        raise RuntimeError('Live scanning supports Windows and Linux. Use Demo mode on this platform.')
    rows.sort(key=lambda row: row.signal, reverse=True)
    return {'timestamp': datetime.now(timezone.utc).isoformat(), 'mode': 'DEMO' if demo else 'LIVE',
            'networks': [{**asdict(row), 'assessment': row.assessment} for row in rows],
            'connection': connection, 'raw': raw}
