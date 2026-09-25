"""ESP32-style desktop Wi-Fi monitor. Python 3.10+, standard library only."""
import argparse
import csv
import json
from pathlib import Path
import queue
import threading
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ImportError:
    tk = None
from scanner import scan

CREDIT = 'Coded by Cyber Security Engineer Mr Sabaz Ali Khan'


class Monitor:
    def __init__(self, root, demo=False):
        self.root, self.results, self.snapshot = root, queue.Queue(), None
        self.busy, self.closing, self.last_scan = False, False, 0
        self.demo = tk.BooleanVar(value=demo)
        self.auto = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value='Ready — choose LIVE scan or enable DEMO mode.')
        root.title('ESP 32 WiFi Monitor | ESP32-style Python edition')
        root.geometry('1150x760')
        root.minsize(860, 600)
        root.configure(bg='#091320')
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', font=('Segoe UI', 10), background='#101f30', foreground='#e0ebfa')
        style.configure('TFrame', background='#091320')
        style.configure('TLabel', background='#091320')
        style.configure('TButton', padding=(12, 8), background='#18384f')
        style.map('TButton', background=[('active', '#215776')])
        style.configure('Treeview', background='#101f30', fieldbackground='#101f30', rowheight=30)
        style.configure('Treeview.Heading', background='#193448', padding=8)
        style.map('Treeview', background=[('selected', '#1a6680')])
        panel = ttk.Frame(root, padding=20)
        panel.pack(fill='both', expand=True)
        ttk.Label(panel, text='ESP 32 / WiFi Monitor', font=('Segoe UI', 25, 'bold'), foreground='#58e8c0').pack(anchor='w')
        ttk.Label(panel, text='ESP32-inspired dashboard • Runs on your computer • No ESP32 required').pack(anchor='w', pady=(3, 10))
        ttk.Label(panel, text=CREDIT, foreground='#79b9fa').pack(anchor='w')
        toolbar = ttk.Frame(panel)
        toolbar.pack(fill='x', pady=16)
        self.button = ttk.Button(toolbar, text='Scan now', command=self.start_scan)
        self.button.pack(side='left')
        ttk.Checkbutton(toolbar, text='Demo mode', variable=self.demo).pack(side='left', padx=14)
        ttk.Checkbutton(toolbar, text='Auto refresh (30 sec)', variable=self.auto).pack(side='left')
        ttk.Button(toolbar, text='Export JSON', command=lambda: self.export('json')).pack(side='right', padx=4)
        ttk.Button(toolbar, text='Export CSV', command=lambda: self.export('csv')).pack(side='right', padx=4)
        self.summary = ttk.Label(panel, text='No scan yet', font=('Segoe UI', 13, 'bold'))
        self.summary.pack(anchor='w', pady=(0, 8))
        table_frame = ttk.Frame(panel)
        table_frame.pack(fill='both', expand=True)
        columns = ('ssid', 'bssid', 'signal', 'channel', 'security')
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=9)
        for col, title, width in zip(columns, ('Network / SSID', 'BSSID', 'Signal %', 'Channel', 'Security'), (280, 175, 90, 85, 190)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=65)
        scroll = ttk.Scrollbar(table_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.tree.bind('<<TreeviewSelect>>', self.select)
        self.assessment = ttk.Label(panel, text='Select a network to inspect advertised security.', wraplength=1000)
        self.assessment.pack(anchor='w', pady=9)
        self.graph = tk.Canvas(panel, height=95, bg='#101f30', highlightthickness=0)
        self.graph.pack(fill='x')
        self.graph.bind('<Configure>', lambda event: self.draw())
        tabs = ttk.Notebook(panel)
        tabs.pack(fill='both', pady=(12, 6))
        self.connection = self.text_tab(tabs, 'Connection / adapter status')
        self.raw = self.text_tab(tabs, 'OS scan output')
        ttk.Label(panel, textvariable=self.status, wraplength=1000, foreground='#aabed3').pack(anchor='w')
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(150, self.poll)
        root.after(1000, self.auto_tick)
        if demo:
            root.after(200, self.start_scan)

    def text_tab(self, notebook, title):
        widget = tk.Text(notebook, height=6, wrap='word', bg='#101f30', fg='#c8d9ee', insertbackground='white', font=('Consolas', 10))
        widget.configure(state='disabled')
        notebook.add(widget, text=title)
        return widget

    def set_text(self, widget, text):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def start_scan(self):
        if self.busy:
            return
        self.busy = True
        self.button.configure(state='disabled')
        demo = self.demo.get()
        self.status.set(('DEMO' if demo else 'LIVE') + ' scan in progress…')
        threading.Thread(target=self.worker, args=(demo,), daemon=True).start()

    def worker(self, demo):
        try:
            self.results.put((scan(demo), None))
        except Exception as exc:
            self.results.put((None, str(exc)))

    def poll(self):
        if self.closing:
            return
        try:
            result, error = self.results.get_nowait()
        except queue.Empty:
            pass
        else:
            import time
            self.last_scan = time.monotonic()
            self.busy = False
            self.button.configure(state='normal')
            if error:
                self.status.set('Scan failed — previous snapshot, if any, is stale. See OS scan output.')
                self.set_text(self.raw, error)
                if self.snapshot:
                    self.summary.configure(text=f"STALE {self.snapshot['mode']} snapshot — latest scan failed")
            else:
                self.snapshot = result
                self.tree.delete(*self.tree.get_children())
                for i, row in enumerate(result['networks']):
                    self.tree.insert('', 'end', iid=str(i), values=tuple(row[key] for key in ('ssid', 'bssid', 'signal', 'channel', 'security')))
                self.summary.configure(text=f"{result['mode']} / {len(result['networks'])} access points / {result['timestamp'][:19]} UTC")
                self.set_text(self.connection, result['connection'])
                self.set_text(self.raw, result['raw'])
                self.assessment.configure(text='Select a network to inspect advertised security.')
                self.status.set('Demo data only.' if result['mode'] == 'DEMO' else 'OS-reported results; may be cached. Signal is a percentage, not distance. No results means no visible access points reported.')
                self.draw()
        self.root.after(150, self.poll)

    def auto_tick(self):
        import time
        if self.closing:
            return
        if self.auto.get() and not self.busy and time.monotonic() - self.last_scan >= 30:
            self.start_scan()
        self.root.after(1000, self.auto_tick)

    def select(self, event=None):
        selected = self.tree.selection()
        if selected and self.snapshot:
            row = self.snapshot['networks'][int(selected[0])]
            self.assessment.configure(text=f"{row['ssid']}: {row['assessment']}")

    def draw(self):
        self.graph.delete('all')
        if not self.snapshot:
            self.graph.create_text(16, 20, text='Signal strength preview appears after scanning', fill='#aabed3', anchor='w')
            return
        rows = self.snapshot['networks'][:6]
        width = max(self.graph.winfo_width(), 600)
        for i, row in enumerate(rows):
            x = 14 + i * width / max(len(rows), 1)
            height = row['signal'] * .48
            self.graph.create_rectangle(x, 64-height, x+28, 64, fill='#58e8c0', outline='')
            self.graph.create_text(x+35, 45, text=f"{row['signal']}%", fill='#e0ebfa', anchor='w')
            self.graph.create_text(x, 80, text=row['ssid'][:18], fill='#aabed3', anchor='w')

    def export(self, kind):
        if not self.snapshot:
            messagebox.showinfo('Nothing to export', 'Run a scan first.')
            return
        target = filedialog.asksaveasfilename(defaultextension='.'+kind, initialfile='wifi_'+self.snapshot['mode'].lower()+'.'+kind, filetypes=[(kind.upper(), '*.'+kind)])
        if not target:
            return
        try:
            if kind == 'json':
                Path(target).write_text(json.dumps(self.snapshot, indent=2, ensure_ascii=False), encoding='utf-8')
            else:
                fields = ['mode', 'timestamp', 'ssid', 'bssid', 'signal', 'channel', 'security', 'assessment']
                with open(target, 'w', newline='', encoding='utf-8-sig') as file:
                    writer = csv.DictWriter(file, fieldnames=fields)
                    writer.writeheader()
                    for row in self.snapshot['networks']:
                        record = dict(row, mode=self.snapshot['mode'], timestamp=self.snapshot['timestamp'])
                        # Treat hostile SSIDs as text when CSV opens in spreadsheet software.
                        writer.writerow({k: "'"+v if isinstance(v, str) and v.lstrip().startswith(('=', '+', '-', '@')) else v for k, v in record.items()})
            self.status.set('Saved snapshot: '+target)
        except OSError as exc:
            messagebox.showerror('Export failed', str(exc))

    def close(self):
        self.closing = True
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description='Sabaz ESP32-style Wi-Fi monitor; no ESP32 needed.')
    parser.add_argument('--demo', action='store_true', help='Use clearly labeled synthetic networks')
    parser.add_argument('--cli', action='store_true', help='Print one JSON scan instead of opening GUI')
    args = parser.parse_args()
    if args.cli:
        try:
            print(json.dumps(scan(args.demo), indent=2, ensure_ascii=False))
        except Exception as exc:
            parser.exit(1, str(exc)+'\n')
        return
    if tk is None:
        parser.exit(1, 'Tkinter is missing. Install Tcl/Tk or python3-tk, or use --cli.\n')
    root = tk.Tk()
    Monitor(root, args.demo)
    root.mainloop()


if __name__ == '__main__':
    main()
