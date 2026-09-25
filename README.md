# Sabaz WiFi Monitor — ESP32-style Python edition

**Coded by Cyber Security Engineer Mr Sabaz Ali Khan**

A desktop Wi-Fi observation dashboard inspired by small ESP32 Wi-Fi displays.
It runs on a computer without an ESP32. It is not ESP32 firmware or a hardware
emulator: it uses your computer's Wi-Fi adapter for live results. Demo mode
works without Wi-Fi hardware and always labels synthetic data as DEMO.

## Features

- Dark Tkinter desktop interface, separate BSSIDs and hidden SSID labels.
- Nearby network name, BSSID, signal percentage, channel, advertised security.
- Advertised security notes; these are not vulnerability findings.
- OS connection / adapter status and raw scan output.
- Optional 30-second auto refresh, responsive background scans.
- Six strongest signal bars; timestamped CSV/JSON snapshot export.
- Live errors stay visible; no silent switch to simulated results.
- No pip dependencies, account, API key, or ESP32 purchase required.

## Windows quick start

1. Install Python 3.10 or newer with **Tcl/Tk and IDLE** enabled.
2. Extract the entire ZIP to a folder.
3. Double-click `DEMO_WINDOWS.bat` to try the app without Wi-Fi hardware.
4. Double-click `START_WINDOWS.bat` for the normal app; click **Scan now**.
5. Enable **Demo mode** if you want sample data, then click **Scan now**.

From VS Code: open the extracted project folder, then use its terminal:

```powershell
python main.py
python main.py --demo
```

If `python` is unavailable but the Python launcher is installed, use `py -3`.
A live scan requires a working enabled Wi-Fi adapter, even if internet access
is through Ethernet. Internet access itself is not needed.

Windows live parsing currently supports **English netsh output only**. Non-ASCII
SSID display depends on the Windows command output encoding. Errors or an
unsupported language are displayed rather than replaced by demo data.

## Linux

Install Python, Tkinter and NetworkManager using your distribution's packages.
On Debian/Ubuntu systems where these packages are available:

```bash
sudo apt install python3 python3-tk network-manager
python3 main.py --demo
python3 main.py
```

Live scans require NetworkManager to manage the Wi-Fi interface. Do not change
your network manager merely to use this app; demo mode remains available.
macOS supports demo mode only in this release.

## Command line

```bash
python main.py --demo --cli
python main.py --cli
python main.py --demo --cli > demo_scan.json
python -m unittest discover -s tests -v
```

The GUI and CLI use the same scanner. Tkinter is only needed for the GUI.
Export writes the currently displayed snapshot, including its original mode
and timestamp. If the latest scan failed, any retained snapshot is marked STALE.

## Troubleshooting

- **No Wi-Fi interface:** turn Wi-Fi on and check the adapter driver. A desktop
  with only Ethernet cannot receive nearby Wi-Fi signals; use demo mode or
  an ordinary compatible USB Wi-Fi adapter.
- **Permission / location error:** inspect the OS scan output. Some Windows
  versions require Location services/access for Wi-Fi metadata. Review your
  Windows privacy settings if the OS explicitly asks for it.
- **WLAN service error:** check WLAN AutoConfig in Windows Services.
- **No networks / old results:** OS and driver scans may be cached. Wait, then
  retry. Linux nmcli normally refreshes an access-point list older than 30s.
- **No module named tkinter:** add Tcl/Tk to your Python installation, or install
  your Linux distribution's `python3-tk` package. CLI mode needs no Tkinter.
- **App not opening:** run it in a terminal to see the error message.

## Scope and limitations

Use for your own network learning and permitted diagnostics. The app reads
OS Wi-Fi metadata; it does not recover passwords, capture traffic, disconnect
clients, connect to networks, or configure routers. Nearby scans may involve
normal OS active Wi-Fi discovery. Signal percentage is not distance or an
accurate location measurement. Channel numbers alone do not identify a band.
Security labels describe advertised authentication, not overall router safety.
There is no GPIO, Bluetooth scanner, ESP32 radio emulation, or attached-device
inventory in this edition. Connection status is OS-reported, not an internet
reachability test. Scan exports can contain SSIDs/BSSIDs; review before sharing.

## Project structure

- `main.py`: GUI, signal chart, export, CLI entry point.
- `scanner.py`: platform scanners, parsers, security notes, demo data.
- `START_WINDOWS.bat` / `DEMO_WINDOWS.bat`: Windows launchers.
- `tests/test_scanner.py`: parser, error-path and demo tests.
- `QUICK_START_URDU.txt`: Roman Urdu launch instructions.

## References

- Microsoft netsh WLAN: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan
- NetworkManager nmcli: https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html

## Validation

Automated tests cover multi-BSSID Windows parsing, hidden names, escaped Linux
fields, security notes, subprocess failures/timeouts, and explicit demo results.
All 11 automated tests passed, including JSON/CSV export checks. Demo CLI and Python compilation also passed. The included release was checked in a Linux container without a display; GUI appearance has not been visually verified. Live scanning on a
physical Wi-Fi adapter and a Windows desktop has not been hardware-tested.
