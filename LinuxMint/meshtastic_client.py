# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
Meshtastic Client (Tkinter)

Improvements vs previous version:
- Thread-safe UI updates (no Tk calls from background threads)
- De-duplicated receive handler (only processes each packet once)
- Added "To selected node (DM)" send target option
- Per-node chat now resolves destinationId correctly before sending
- Connection "connected" fallback when pubsub isn't available
- Theme changes apply to open chat windows too
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import pathlib
import subprocess
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Dict, Optional, Tuple

# Optional deps -------------------------------------------------------
try:
    from pubsub import pub
except Exception:
    pub = None

try:
    from meshtastic.tcp_interface import TCPInterface
except Exception:
    TCPInterface = None

try:
    from meshtastic.serial_interface import SerialInterface
except Exception:
    SerialInterface = None

try:
    from meshtastic.ble_interface import BLEInterface
except Exception:
    BLEInterface = None

try:
    from meshtastic.protobuf import mesh_pb2, portnums_pb2, telemetry_pb2
    import google.protobuf.json_format as _json_format
except Exception:
    mesh_pb2 = None
    portnums_pb2 = None
    telemetry_pb2 = None
    _json_format = None

try:
    from serial.tools import list_ports
except Exception:
    list_ports = None

# Defaults ------------------------------------------------------------
HOST_DEFAULT = "192.168.0.156"
PORT_DEFAULT = 4403

PROJECT_PATH = pathlib.Path(__file__).resolve().parent
ICON_PATH = PROJECT_PATH / "meshtastic.ico"

CONFIG_FILENAME = "meshtastic_client_settings.json"
DEFAULT_GEOMETRY = "1500x820"
DEFAULT_SASH_FRACTION = 0.40

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("meshtastic-client")


def _prefer_chrome(url: str) -> None:
    """Open URL (prefer Chrome on Windows, otherwise default browser)."""
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    for p in chrome_paths:
        if os.path.exists(p):
            subprocess.Popen([p, url])
            return
    webbrowser.open(url)


def _fmt_ago(epoch_seconds: Optional[float]) -> str:
    if not epoch_seconds:
        return "N/A"
    try:
        delta = time.time() - float(epoch_seconds)
    except Exception:
        return "N/A"
    if delta < 0:
        delta = 0
    mins = int(delta // 60)
    hours = int(delta // 3600)
    days = int(delta // 86400)
    if delta < 60:
        return f"{int(delta)}s"
    if mins < 60:
        return f"{mins}m"
    if hours < 24:
        return f"{hours}h"
    if days < 7:
        return f"{days}d"
    dt = datetime.datetime.fromtimestamp(epoch_seconds)
    return dt.strftime("%Y-%m-%d %H:%M")


class MeshtasticGUI:
    def __init__(self, master: Optional[tk.Tk] = None):
        self.root = master or tk.Tk()
        self.root.title("Meshtastic Client")

        try:
            if ICON_PATH.exists():
                self.root.iconbitmap(default=str(ICON_PATH))
        except Exception:
            pass

        self.current_theme = "dark"
        self._pending_channel_choice: Optional[str] = None
        self._startup_sash_fraction: float = DEFAULT_SASH_FRACTION
        self._startup_geometry_applied: bool = False

        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        self.host_var = tk.StringVar(value=HOST_DEFAULT)
        self.port_var = tk.IntVar(value=PORT_DEFAULT)

        # Connection settings (persisted)
        # conn_type: "tcp" | "serial" | "ble"
        self.conn_type_var = tk.StringVar(value="tcp")
        self.serial_port_var = tk.StringVar(value="")  # empty = auto
        self.ble_addr_var = tk.StringVar(value="")

        # State
        self.iface: Optional[object] = None
        self.connected_evt = threading.Event()
        self._last_seen_overrides: Dict[str, float] = {}
        self._last_sort_col: Optional[str] = "since"
        self._last_sort_reverse: bool = True
        self._telemetry: Dict[str, Dict[str, Any]] = {}
        self._per_node_chats: Dict[str, "NodeChatWindow"] = {}
        self._ui_thread_id = threading.get_ident()

        # Menu --------------------------------------------------------
        self.menubar = tk.Menu(self.root)

        m_conn = tk.Menu(self.menubar, tearoff=False)
        m_conn.add_command(label="Connect (Saved settings)", command=self.connect_saved)
        m_conn.add_command(label="Connect (TCP)", command=self.connect_tcp)
        m_conn.add_command(label="Connect via USB/Serial...", command=self.connect_serial_dialog)
        m_conn.add_command(label="Connect via Bluetooth...", command=self.connect_ble_dialog)
        m_conn.add_command(label="Disconnect", command=self.disconnect)
        m_conn.add_separator()
        m_conn.add_command(label="Set IP/Port...", command=self.set_ip_port)
        self.menubar.add_cascade(label="Connection", menu=m_conn)

        m_tools = tk.Menu(self.menubar, tearoff=False)
        m_tools.add_command(label="Clear messages", command=self.clear_messages)
        m_tools.add_separator()
        m_tools.add_command(label="Settings...", command=self.open_settings_dialog)
        self.menubar.add_cascade(label="Tools", menu=m_tools)

        m_view = tk.Menu(self.menubar, tearoff=False)
        m_view.add_command(label="Light theme", command=lambda: self.apply_theme("light"))
        m_view.add_command(label="Dark theme", command=lambda: self.apply_theme("dark"))
        m_view.add_separator()
        m_view.add_command(label="Neighbor table", command=self.show_neighbors_window)
        m_view.add_command(label="Radio config (view)", command=self.show_radio_config_window)
        m_view.add_command(label="Channel editor", command=self.show_channel_editor_window)
        self.menubar.add_cascade(label="View", menu=m_view)

        m_links = tk.Menu(self.menubar, tearoff=False)
        m_links.add_command(label="Meshtastic client", command=lambda: self._open_browser_url("https://github.com/dk98174003/Meshtastic-Client"))
        m_links.add_command(label="Meshtastic org", command=lambda: self._open_browser_url("https://meshtastic.org/"))
        m_links.add_command(label="Meshtastic flasher (Chrome)", command=lambda: self._open_browser_url("https://flasher.meshtastic.org/"))
        m_links.add_command(label="Meshtastic Web Client", command=lambda: self._open_browser_url("https://client.meshtastic.org"))
        m_links.add_command(label="Meshtastic docker client", command=lambda: self._open_browser_url("https://meshtastic.org/docs/software/linux/usage/#usage-with-docker"))
        m_links.add_separator()
        m_links.add_command(label="Meshtastic Facebook Danmark", command=lambda: self._open_browser_url("https://www.facebook.com/groups/1553839535376876/"))
        m_links.add_command(label="Meshtastic Facebook Nordjylland", command=lambda: self._open_browser_url("https://www.facebook.com/groups/1265866668302201/"))
        self.menubar.add_cascade(label="Links", menu=m_links)

        self.root.config(menu=self.menubar)

        # Layout ------------------------------------------------------
        self.rootframe = ttk.Frame(self.root)
        self.rootframe.grid(row=0, column=0, sticky="nsew")
        self.rootframe.rowconfigure(0, weight=1)
        self.rootframe.columnconfigure(0, weight=1)

        self.paned = ttk.Panedwindow(self.rootframe, orient="horizontal")
        self.paned.grid(row=0, column=0, sticky="nsew")

        # Messages pane
        self.msg_frame = ttk.Frame(self.paned)
        self.msg_frame.rowconfigure(1, weight=1)
        self.msg_frame.columnconfigure(0, weight=1)

        ttk.Label(self.msg_frame, text="Messages").grid(row=0, column=0, sticky="w", pady=(2, 0))

        self.txt_messages = tk.Text(self.msg_frame, wrap="word")
        self.txt_messages.grid(row=1, column=0, sticky="nsew", padx=(0, 4), pady=(2, 2))
        yscroll_left = ttk.Scrollbar(self.msg_frame, orient="vertical", command=self.txt_messages.yview)
        self.txt_messages.configure(yscrollcommand=yscroll_left.set)
        yscroll_left.grid(row=1, column=1, sticky="ns")

        self.send_frame = ttk.Frame(self.msg_frame)
        self.send_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(0, 4))
        self.send_frame.columnconfigure(0, weight=1)

        self.ent_message = ttk.Entry(self.send_frame)
        self.ent_message.grid(row=0, column=0, sticky="nsew")
        self.ent_message.bind("<Return>", lambda e: self.send_message())

        self.btn_send = ttk.Button(self.send_frame, text="Send", command=self.send_message)
        self.btn_send.grid(row=0, column=1, padx=4, sticky="nsew")

        # Channel selector
        self.channel_var = tk.StringVar()
        self._channel_map: Dict[str, Dict[str, Any]] = {}
        self.cbo_channel = ttk.Combobox(self.send_frame, textvariable=self.channel_var, state="readonly", width=26)
        self._reset_channel_choices()
        self.cbo_channel.grid(row=0, column=2, padx=4, sticky="w")

        # Nodes pane
        self.nodes_frame = ttk.Labelframe(self.paned, text="Nodes (0)")
        self.nodes_frame.rowconfigure(1, weight=1)
        self.nodes_frame.columnconfigure(0, weight=1)

        self.ent_search = ttk.Entry(self.nodes_frame)
        self.ent_search.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        self.ent_search.bind("<KeyRelease>", lambda e: self.refresh_nodes())

        self.cols_all = (
            "shortname", "longname", "since", "hops",
            "distkm", "speed", "alt", "battery", "voltage",
            "lastheard", "hwmodel", "role",
            "macaddr", "publickey", "isunmessagable", "id"
        )
        self.cols_visible = (
            "shortname", "longname", "since", "hops",
            "distkm", "speed", "alt", "battery", "voltage", "hwmodel", "role"
        )
        self.tv_nodes = ttk.Treeview(
            self.nodes_frame,
            columns=self.cols_all,
            show="headings",
            displaycolumns=self.cols_visible
        )
        self.tv_nodes.grid(row=1, column=0, sticky="nsew", padx=(2, 0), pady=(0, 2))

        headings = {
            "shortname": "Short",
            "longname": "Long",
            "since": "Since",
            "hops": "Hops",
            "distkm": "Dist (km)",
            "speed": "Speed",
            "alt": "Alt (m)",
            "battery": "Batt %",
            "voltage": "Volt",
            "hwmodel": "HW",
            "role": "Role",
            "lastheard": "",
            "macaddr": "MAC",
            "publickey": "Public key",
            "isunmessagable": "Unmsg?",
            "id": "ID",
        }
        for key, text in headings.items():
            self.tv_nodes.heading(key, text=text, command=lambda c=key: self.sort_by_column(c, False))

        widths = {
            "shortname": 90,
            "longname": 200,
            "since": 90,
            "hops": 50,
            "distkm": 70,
            "speed": 70,
            "alt": 70,
            "battery": 70,
            "voltage": 80,
            "hwmodel": 90,
            "role": 110,
        }
        for key, w in widths.items():
            try:
                self.tv_nodes.column(
                    key,
                    width=w,
                    anchor="w",
                    stretch=(key not in ("since", "hops", "distkm", "speed", "alt", "battery", "voltage")),
                )
            except Exception:
                pass

        # Hide technical columns
        for col in ("lastheard", "macaddr", "publickey", "isunmessagable", "id"):
            try:
                self.tv_nodes.column(col, width=0, minwidth=0, stretch=False)
            except Exception:
                pass

        yscroll_nodes = ttk.Scrollbar(self.nodes_frame, orient="vertical", command=self.tv_nodes.yview)
        self.tv_nodes.configure(yscrollcommand=yscroll_nodes.set)
        yscroll_nodes.grid(row=1, column=1, sticky="ns")

        # Node context menu
        self.node_menu = tk.Menu(self.nodes_frame, tearoff=False)
        self.node_menu.add_command(label="Node info", command=self._cm_show_node_details)
        self.node_menu.add_command(label="Map", command=self._cm_open_map)
        self.node_menu.add_command(label="Traceroute", command=self._cm_traceroute)
        self.node_menu.add_command(label="Chat with node", command=self._cm_open_chat)
        self.node_menu.add_separator()
        self.node_menu.add_command(label="Delete node", command=self._cm_delete_node)

        self.tv_nodes.bind("<Button-3>", self._popup_node_menu)
        self.tv_nodes.bind("<Double-1>", lambda e: self._cm_open_chat())

        self.paned.add(self.msg_frame, weight=3)
        self.paned.add(self.nodes_frame, weight=4)
        self.root.after(100, lambda: self._safe_set_sash(self._startup_sash_fraction))

        # PubSub subscriptions ---------------------------------------
        if pub is not None:
            try:
                pub.subscribe(self.on_connection_established, "meshtastic.connection.established")
                pub.subscribe(self.on_connection_lost, "meshtastic.connection.lost")
                pub.subscribe(self.on_receive, "meshtastic.receive")
                pub.subscribe(self.on_node_updated, "meshtastic.node.updated")
            except Exception as e:
                log.warning("pubsub subscribe failed: %s", e)

        # Load persisted settings (from ./meshtastic_client_settings.json) if present
        self.load_settings(silent=True)
        self.apply_theme(self.current_theme)
        self._append("Ready. Connection -> Connect (TCP/USB/BLE)")
        self._update_title_with_host()

    # UI helpers ------------------------------------------------------
    def _ui(self, fn, *args, **kwargs):
        """Run fn in Tk main thread."""
        if threading.get_ident() == self._ui_thread_id:
            fn(*args, **kwargs)
        else:
            self.root.after(0, lambda: fn(*args, **kwargs))

    def clear_messages(self):
        self._ui(lambda: self.txt_messages.delete("1.0", "end"))

    # helpers ---------------------------------------------------------
    def _open_browser_url(self, url: str):
        _prefer_chrome(url)

    def _update_title_with_host(self):
        self.root.title(f"Meshtastic Client - {self.host_var.get()}:{self.port_var.get()}")

    def _safe_set_sash(self, fraction: float = 0.5):
        try:
            w = self.paned.winfo_width() or self.paned.winfo_reqwidth()
            self.paned.sashpos(0, int(w * fraction))
        except Exception:
            pass

    def _node_label(self, node_id: str) -> str:
        if not self.iface or not getattr(self.iface, "nodes", None):
            return node_id
        node = self.iface.nodes.get(node_id, {})  # type: ignore[attr-defined]
        user = (node or {}).get("user") or {}
        shortname = user.get("shortName") or ""
        longname = user.get("longName") or ""
        label = (f"{shortname} {longname}").strip()
        return label or node_id

    # pubsub callbacks ------------------------------------------------
    def _mark_connected(self):
        if self.connected_evt.is_set():
            return
        self.connected_evt.set()
        self._append("[+] Connected")
        self.refresh_nodes()
        try:
            self._update_channels_from_iface()
        except Exception:
            pass

    def on_connection_established(self, interface=None, **kwargs):
        self._ui(self._mark_connected)

    def on_connection_lost(self, interface=None, **kwargs):
        def _lost():
            self.connected_evt.clear()
            self._append("[-] Connection lost")
        self._ui(_lost)

    def on_node_updated(self, node=None, interface=None, **kwargs):
        self._ui(self.refresh_nodes)

    def on_receive(self, packet=None, interface=None, **kwargs):
        self._ui(lambda: self._handle_receive(packet or {}))

    # receive ---------------------------------------------------------
    def _handle_receive(self, packet: dict):
        if not isinstance(packet, dict):
            return

        decoded = packet.get("decoded") or {}
        if not isinstance(decoded, dict):
            decoded = {}

        app_name = decoded.get("app") or ""
        portnum = decoded.get("portnum") or app_name or ""
        sender = packet.get("fromId") or packet.get("from") or packet.get("fromIdShort") or "UNKNOWN"
        sender = str(sender)

        # Mark last seen (for more accurate "Since")
        self._last_seen_overrides[sender] = time.time()

        label = self._node_label(sender)

        # Telemetry parsing (device metrics)
        if portnum == "TELEMETRY_APP" and telemetry_pb2 is not None:
            try:
                payload = decoded.get("payload")
                if isinstance(payload, (bytes, bytearray)):
                    tmsg = telemetry_pb2.Telemetry()
                    tmsg.ParseFromString(payload)
                    if tmsg.HasField("device_metrics"):
                        dm = tmsg.device_metrics
                        entry = self._telemetry.get(sender, {})
                        if getattr(dm, "battery_level", None) is not None:
                            entry["battery"] = dm.battery_level
                        if getattr(dm, "voltage", None) is not None:
                            entry["voltage"] = dm.voltage
                        self._telemetry[sender] = entry
            except Exception:
                pass  # telemetry failures are non-fatal

        # Text message
        if portnum in ("TEXT_MESSAGE_APP", "TEXT_MESSAGE_COMPRESSED_APP"):
            text = decoded.get("text")
            if isinstance(text, bytes):
                text = text.decode("utf-8", errors="ignore")
            if not isinstance(text, str):
                # Some packets provide bytes in decoded.payload
                p = decoded.get("payload")
                if isinstance(p, (bytes, bytearray)):
                    text = p.decode("utf-8", errors="ignore")
                elif isinstance(p, dict):
                    t2 = p.get("text")
                    if isinstance(t2, str):
                        text = t2
                    elif isinstance(t2, (bytes, bytearray)):
                        text = t2.decode("utf-8", errors="ignore")
                else:
                    text = ""

            rssi = packet.get("rxRssi")
            if text:
                self._append(f"[MSG] {label}: {text} (RSSI={rssi})")
                self._append_to_node_chat(sender, text)
            else:
                self._append(f"[MSG] {label} (RSSI={rssi})")

            if text.strip().lower() == "ping":
                self._send_pong(sender, label)
        else:
            # Non-text: keep lightweight log
            tag_map = {
                "POSITION_APP": "POS",
                "TELEMETRY_APP": "TEL",
                "NODEINFO_APP": "INFO",
                "ROUTING_APP": "ROUT",
                "MAP_REPORT_APP": "MAP",
                "ADMIN_APP": "ADM",
                "NEIGHBORINFO_APP": "NEI",
                "STORE_FORWARD_APP": "SFWD",
                "REMOTE_HARDWARE_APP": "RHW",
                "PRIVATE_APP": "PRIV",
            }
            tag = tag_map.get(str(app_name or portnum), "INFO")
            # Avoid spamming for every non-text packet; show only brief line
            self._append(f"[{tag}] {label}")

        self.refresh_nodes()

    def _send_pong(self, dest_id: Optional[str], label: str):
        if not self.iface or not dest_id:
            return
        try:
            self.iface.sendText("pong", destinationId=dest_id, wantAck=False)
            self._append(f"[auto] pong -> {label}")
            self._append_to_node_chat(str(dest_id), "[auto] pong")
        except Exception as e:
            self._append(f"[auto] pong failed: {e}")

    # connection actions ----------------------------------------------
    def set_ip_port(self):
        win = tk.Toplevel(self.root)
        win.title("Set IP/Port")
        self._style_toplevel(win)

        frm = ttk.Frame(win, padding=8)
        frm.grid(row=0, column=0, sticky="nsew")
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)

        ttk.Label(frm, text="Host/IP:").grid(row=0, column=0, sticky="w", pady=4)
        ent_host = ttk.Entry(frm, textvariable=self.host_var, width=28)
        ent_host.grid(row=0, column=1, sticky="ew", pady=4, padx=4)

        ttk.Label(frm, text="Port:").grid(row=1, column=0, sticky="w", pady=4)
        ent_port = ttk.Entry(frm, textvariable=self.port_var, width=10)
        ent_port.grid(row=1, column=1, sticky="w", pady=4, padx=4)

        frm.columnconfigure(1, weight=1)

        def save():
            h = self.host_var.get().strip()
            try:
                p = int(self.port_var.get())
            except Exception:
                messagebox.showerror("Port", "Port must be 1-65535")
                return
            if not h:
                messagebox.showerror("Host", "Host cannot be empty")
                return
            if not (1 <= p <= 65535):
                messagebox.showerror("Port", "Port must be 1-65535")
                return
            self.host_var.set(h)
            self.port_var.set(p)
            self._update_title_with_host()
            win.destroy()

        btnbar = ttk.Frame(frm)
        btnbar.grid(row=2, column=0, columnspan=2, sticky="e")
        ttk.Button(btnbar, text="Cancel", command=win.destroy).grid(row=0, column=0, padx=4)
        ttk.Button(btnbar, text="Save", command=save).grid(row=0, column=1, padx=4)

    def connect_saved(self):
        """Connect using the method selected in Settings."""
        if self.iface:
            return
        method = (self.conn_type_var.get() or "tcp").strip().lower()
        if method == "serial":
            port = (self.serial_port_var.get() or "").strip()
            self.connect_serial(port if port else None)
        elif method in ("ble", "bluetooth"):
            addr = (self.ble_addr_var.get() or "").strip()
            if not addr:
                # If no saved address, fall back to interactive scan
                self.connect_ble_dialog()
            else:
                self.connect_ble(addr)
        else:
            self.connect_tcp()

    def connect_serial(self, port: Optional[str] = None):
        """Connect via USB/Serial. If port is None, auto-detect."""
        if self.iface:
            return
        if SerialInterface is None:
            self._ui(lambda: messagebox.showerror("Unavailable", "meshtastic.serial_interface not installed."))
            return
        self._append(f"Connecting Serial {port or '(auto)'} ...")

        def run():
            try:
                self.iface = SerialInterface(devPath=port) if port else SerialInterface()
                if pub is None:
                    self._ui(self._mark_connected)
                else:
                    self.connected_evt.wait(timeout=6)
            except Exception as e:
                self._ui(lambda: messagebox.showerror("Serial connect failed", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def connect_ble(self, address: str):
        """Connect via Bluetooth (BLE) using a saved address or name filter."""
        if self.iface:
            return
        if BLEInterface is None:
            self._ui(lambda: messagebox.showerror("Unavailable", "meshtastic.ble_interface not installed (needs bleak)."))
            return
        self._append(f"Connecting BLE {address} ...")

        def run():
            try:
                # BLEInterface accepts an address or name filter and will scan for matches.
                self.iface = BLEInterface(address=address)
                if pub is None:
                    self._ui(self._mark_connected)
                else:
                    self.connected_evt.wait(timeout=10)
            except Exception as e:
                self._ui(lambda: messagebox.showerror("BLE connect failed", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def connect_tcp(self):
        if self.iface:
            return
        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get())
        except Exception:
            messagebox.showerror("Port", "Invalid port")
            return
        self._append(f"Connecting TCP {host}:{port} ...")

        def run():
            try:
                if TCPInterface is None:
                    raise RuntimeError("meshtastic.tcp_interface not installed")
                self.iface = TCPInterface(hostname=host, portNumber=port)
                # If pubsub isn't available, we might not get the established event.
                if pub is None:
                    self._ui(self._mark_connected)
                else:
                    self.connected_evt.wait(timeout=6)
            except Exception as e:
                self._ui(lambda: messagebox.showerror("TCP connect failed", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def connect_serial_dialog(self):
        """Interactive serial connect (also stores chosen port in Settings)."""
        if SerialInterface is None:
            messagebox.showerror("Unavailable", "meshtastic.serial_interface not installed.")
            return

        ports = []
        if list_ports:
            try:
                ports = [p.device for p in list_ports.comports()]
            except Exception:
                ports = []

        presets = ["(auto)"] + ports + ["COM4", "/dev/ttyUSB0"]
        initial = "(auto)"
        try:
            saved = (self.serial_port_var.get() or "").strip()
            if saved:
                initial = saved
        except Exception:
            pass

        port = simpledialog.askstring("Serial", "Serial port (or leave '(auto)'):", initialvalue=initial)
        if port is None:
            return
        port = port.strip()
        if port.lower() == "(auto)" or port == "":
            port = None

        # Persist choice
        self.serial_port_var.set(port or "")
        self.conn_type_var.set("serial")

        self.connect_serial(port)

    def connect_ble_dialog(self):
        """Interactive BLE connect (also stores chosen device address in Settings)."""
        if BLEInterface is None:
            messagebox.showerror("Unavailable", "meshtastic.ble_interface not installed (needs bleak).")
            return
        self._append("Scanning BLE for Meshtastic devices ...")
        try:
            devices = BLEInterface.scan()
        except Exception as e:
            messagebox.showerror("BLE scan failed", str(e))
            return
        if not devices:
            messagebox.showinfo("BLE", "No devices found.")
            return

        options = [
            f"{i + 1}. {getattr(d, 'name', '') or '(unnamed)'} [{getattr(d, 'address', '?')}]"
            for i, d in enumerate(devices)
        ]
        choice = simpledialog.askinteger(
            "Select BLE device",
                "Enter number:\n" + "\n".join(options),
            minvalue=1,
            maxvalue=len(devices),
        )
        if not choice:
            return

        addr = getattr(devices[choice - 1], "address", None)
        if not addr:
            messagebox.showerror("BLE", "Selected device has no address.")
            return

        # Persist choice
        self.ble_addr_var.set(str(addr))
        self.conn_type_var.set("ble")

        self.connect_ble(str(addr))

    def disconnect(self):
        try:
            if self.iface:
                self.iface.close()
        except Exception:
            pass
        self.iface = None
        self.connected_evt.clear()
        self._append("[*] Disconnected")

    # send ------------------------------------------------------------
    def _reset_channel_choices(self):
        """Initialize channel selector with Public + To selected (DM)."""
        self._channel_map = {}
        options = []

        label_dm = "To selected node (DM)"
        self._channel_map[label_dm] = {"mode": "selected", "channelIndex": 0}
        options.append(label_dm)

        label_pub = "Public (broadcast)"
        self._channel_map[label_pub] = {"mode": "broadcast", "channelIndex": 0}
        options.append(label_pub)

        self.cbo_channel["values"] = options

        # Apply pending default channel choice if it exists now
        if self._pending_channel_choice:
            if self._pending_channel_choice in options:
                self.channel_var.set(self._pending_channel_choice)
                self._pending_channel_choice = None

        self.channel_var.set(label_pub)

    def _update_channels_from_iface(self):
        """Populate channel selector with channels from the connected device (broadcast channels)."""
        iface = getattr(self, "iface", None)
        if not iface:
            return
        local_node = getattr(iface, "localNode", None)
        if not local_node:
            return

        chans = getattr(local_node, "channels", None)
        try:
            if (not chans) and hasattr(local_node, "requestChannels"):
                local_node.requestChannels()
                time.sleep(1.2)
                chans = getattr(local_node, "channels", None)
        except Exception:
            chans = getattr(local_node, "channels", None)

        try:
            options = list(self.cbo_channel["values"])
        except Exception:
            return

        # Keep DM option first, keep Public second, then channels 1..N
        # Update "Public" label with ch0 name if available.
        try:
            if chans and len(chans) > 0:
                ch0 = chans[0]
                try:
                    ch0_name = (getattr(ch0, "settings", None).name or "").strip()
                except Exception:
                    try:
                        ch0_name = (ch0.settings.name or "").strip()
                    except Exception:
                        ch0_name = ""
                if ch0_name:
                    old_label = None
                    for lbl, meta in list(self._channel_map.items()):
                        if meta.get("mode") == "broadcast" and int(meta.get("channelIndex", 0) or 0) == 0:
                            old_label = lbl
                            break
                    if old_label:
                        new_label = f"Public (ch0: {ch0_name})"
                        if new_label != old_label:
                            self._channel_map[new_label] = self._channel_map.pop(old_label)
                            options = [new_label if v == old_label else v for v in options]
                            if self.channel_var.get() == old_label:
                                self.channel_var.set(new_label)
        except Exception:
            pass

        for idx, ch in enumerate(chans or []):
            if idx == 0:
                continue
            try:
                name = (getattr(ch, "settings", None).name or "").strip()
            except Exception:
                try:
                    name = (ch.settings.name or "").strip()
                except Exception:
                    name = ""
            label = f"Ch {idx}: {name}" if name else f"Ch {idx}"
            if label in self._channel_map:
                continue
            self._channel_map[label] = {"mode": "broadcast_channel", "channelIndex": idx}
            options.append(label)

        self.cbo_channel["values"] = options

    def send_message(self):
        msg = self.ent_message.get().strip()
        if not msg:
            return
        if not self.iface:
            messagebox.showwarning("Not connected", "Connect first.")
            return

        choice = self.channel_var.get() or ""
        info = self._channel_map.get(choice) or {"mode": "broadcast", "channelIndex": 0}
        mode = info.get("mode", "broadcast")
        ch_index = int(info.get("channelIndex", 0) or 0)

        try:
            if mode == "selected":
                nid = self._get_selected_node_id()
                if not nid:
                    messagebox.showinfo("No selection", "Select a node first.")
                    return
                dest = self._resolve_node_dest_id(nid)
                if not dest:
                    messagebox.showerror("Send failed", "Cannot resolve destination for selected node.")
                    return
                self.iface.sendText(msg, destinationId=dest, wantAck=False, channelIndex=ch_index)
                self._append(f"[ME -> {self._node_label(nid)}] {msg}")
                self._append_to_node_chat(nid, "[ME] " + msg)
            else:
                self.iface.sendText(msg, wantAck=False, channelIndex=ch_index)
                if mode == "broadcast_channel" and ch_index:
                    self._append(f"[ME ch{ch_index}] {msg}")
                else:
                    self._append(f"[ME] {msg}")

            self.ent_message.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Send failed", str(e))

    # nodes -----------------------------------------------------------
    def _get_lastheard_epoch(self, node_id: str, node: Dict[str, Any]) -> Optional[float]:
        raw = (node or {}).get("lastHeard")
        ts_iface = None
        if raw is not None:
            try:
                val = float(raw)
                ts_iface = val / 1000.0 if val > 10000000000 else val
            except Exception:
                ts_iface = None
        ts_local = self._last_seen_overrides.get(str(node_id))
        if ts_iface and ts_local:
            return max(ts_iface, ts_local)
        return ts_iface or ts_local

    def _extract_latlon(self, node: dict) -> Tuple[Optional[float], Optional[float]]:
        pos = (node or {}).get("position") or {}
        lat = pos.get("latitude") or pos.get("latitudeI") or pos.get("latitude_i")
        lon = pos.get("longitude") or pos.get("longitudeI") or pos.get("longitude_i")
        try:
            if lat is not None:
                lat = float(lat) * (1e-7 if abs(float(lat)) > 90 else 1.0)
            if lon is not None:
                lon = float(lon) * (1e-7 if abs(float(lon)) > 180 else 1.0)
        except Exception:
            lat = lon = None
        return lat, lon

    def _extract_speed_alt(self, node: dict) -> Tuple[Optional[float], Optional[float]]:
        pos = (node or {}).get("position") or {}
        speed = (
            pos.get("groundSpeedKmh")
            or pos.get("groundSpeedKmhI")
            or pos.get("groundSpeed")
            or pos.get("ground_speed")
        )
        alt = (
            pos.get("altitude")
            or pos.get("altitudeM")
            or pos.get("altitude_i")
            or pos.get("altitudeI")
        )
        try:
            speed = float(speed) if speed is not None else None
            alt = float(alt) if alt is not None else None
        except Exception:
            speed, alt = None, None
        return speed, alt

    def _get_local_latlon(self) -> Tuple[Optional[float], Optional[float]]:
        if not self.iface:
            return (None, None)
        try:
            mi = getattr(self.iface, "myInfo", None)
            nbn = getattr(self.iface, "nodesByNum", None)
            if mi is not None and hasattr(mi, "my_node_num") and nbn:
                n = nbn.get(mi.my_node_num) or {}
                lat, lon = self._extract_latlon(n)
                if lat is not None and lon is not None:
                    return lat, lon
        except Exception:
            pass
        return (None, None)

    def _haversine_km(self, lat1, lon1, lat2, lon2) -> float:
        import math
        R = 6371.0088
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlmb = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    def refresh_nodes(self):
        if not self.iface or not getattr(self.iface, "nodes", None):
            return
        q = self.ent_search.get().strip().lower()

        for iid in self.tv_nodes.get_children(""):
            self.tv_nodes.delete(iid)

        try:
            nodes_snapshot = dict(self.iface.nodes or {})  # type: ignore[attr-defined]
        except Exception:
            nodes_snapshot = {}

        base_lat, base_lon = self._get_local_latlon()

        for node_id, node in nodes_snapshot.items():
            user = (node or {}).get("user") or {}
            shortname = user.get("shortName") or ""
            longname = user.get("longName") or ""
            hwmodel = user.get("hwModel") or ""
            role_raw = user.get("role") or ""
            role = role_raw if str(role_raw).strip() else "CLIENT"
            macaddr = user.get("macaddr") or ""
            publickey = user.get("publicKey") or ""
            unmsg = user.get("isUnmessagable") or user.get("isUnmessageable") or False

            lastheard_epoch = self._get_lastheard_epoch(str(node_id), node)
            since_str = _fmt_ago(lastheard_epoch)
            hops = node.get("hopsAway")

            lat, lon = self._extract_latlon(node)
            dist = None
            if base_lat is not None and base_lon is not None and lat is not None and lon is not None:
                try:
                    dist = self._haversine_km(base_lat, base_lon, lat, lon)
                except Exception:
                    dist = None
            dist_str = f"{dist:.1f}" if isinstance(dist, (int, float)) else "-"

            speed, alt = self._extract_speed_alt(node)
            speed_str = f"{speed:.1f}" if isinstance(speed, (int, float)) else "-"
            alt_str = f"{alt:.0f}" if isinstance(alt, (int, float)) else "-"

            telem = self._telemetry.get(str(node_id), {})
            bat = telem.get("battery")
            volt = telem.get("voltage")
            bat_str = f"{bat:.0f}" if isinstance(bat, (int, float)) else "-"
            volt_str = f"{volt:.2f}" if isinstance(volt, (int, float)) else "-"

            values = (
                shortname,
                longname,
                since_str,
                str(hops) if hops is not None else "-",
                dist_str,
                speed_str,
                alt_str,
                bat_str,
                volt_str,
                f"{(lastheard_epoch or 0):.0f}",
                hwmodel,
                role,
                macaddr,
                publickey,
                str(bool(unmsg)),
                str(node_id),
            )

            if not q or any(q in str(v).lower() for v in values):
                try:
                    self.tv_nodes.insert("", "end", iid=str(node_id), values=values)
                except Exception:
                    self.tv_nodes.insert("", "end", values=values)

        if self._last_sort_col:
            self.sort_by_column(self._last_sort_col, self._last_sort_reverse)

        self.nodes_frame.config(text=f"Nodes ({len(self.tv_nodes.get_children())})")

    def sort_by_column(self, col: str, reverse: bool = False):
        self._last_sort_col = col
        self._last_sort_reverse = reverse

        col_to_sort = "lastheard" if col == "since" else col
        numeric = {"lastheard", "distkm", "hops", "speed", "alt", "battery", "voltage"}

        rows = []
        for iid in self.tv_nodes.get_children(""):
            val = self.tv_nodes.set(iid, col_to_sort)
            if col_to_sort in numeric:
                try:
                    val = float(val if val != "-" else 0.0)
                except Exception:
                    val = 0.0
            else:
                val = str(val).casefold()
            rows.append((val, iid))

        rows.sort(key=lambda t: t[0], reverse=reverse)
        for index, (_, iid) in enumerate(rows):
            self.tv_nodes.move(iid, "", index)

        self.tv_nodes.heading(col, command=lambda: self.sort_by_column(col, not reverse))

    # THEME -----------------------------------------------------------
    def apply_theme(self, mode: str = "light"):
        self.current_theme = mode
        is_dark = mode == "dark"
        bg = "#1e1e1e" if is_dark else "#f5f5f5"
        fg = "#ffffff" if is_dark else "#000000"
        acc = "#2d2d2d" if is_dark else "#ffffff"
        sel = "#555555" if is_dark else "#cce0ff"

        try:
            self.root.configure(bg=bg)
        except Exception:
            pass

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=bg, foreground=fg)
        style.configure("TLabelframe.Label", background=bg, foreground=fg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TButton", background=acc, foreground=fg)
        style.configure("TEntry", fieldbackground=acc, foreground=fg)
        style.configure("TCombobox", fieldbackground=acc, background=acc, foreground=fg, arrowcolor=fg)
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", acc)],
            foreground=[("readonly", fg)],
            background=[("readonly", acc)],
        )
        style.configure("Treeview", background=acc, fieldbackground=acc, foreground=fg, borderwidth=0)
        style.map("Treeview", background=[("selected", sel)], foreground=[("selected", fg)])

        try:
            if self.menubar is not None:
                self.menubar.configure(
                    background=bg,
                    foreground=fg,
                    activebackground=sel,
                    activeforeground=fg,
                    borderwidth=0,
                    relief="flat",
                )
        except Exception:
            pass

        try:
            self.txt_messages.configure(
                bg=acc,
                fg=fg,
                insertbackground=fg,
                selectbackground=sel,
                selectforeground=fg,
            )
        except Exception:
            pass

        try:
            self.root.option_add("*Menu*background", bg)
            self.root.option_add("*Menu*foreground", fg)
            self.root.option_add("*Menu*activeBackground", sel)
            self.root.option_add("*Menu*activeForeground", fg)
            self.root.option_add("*TCombobox*Listbox*background", acc)
            self.root.option_add("*TCombobox*Listbox*foreground", fg)
        except Exception:
            pass

        # Apply to open chat windows
        for win in list(self._per_node_chats.values()):
            try:
                win.apply_theme()
            except Exception:
                pass

    def _style_toplevel(self, win: tk.Toplevel):
        is_dark = self.current_theme == "dark"
        bg = "#1e1e1e" if is_dark else "#f5f5f5"
        try:
            win.configure(bg=bg)
        except Exception:
            pass

    # UTILS / CONTEXT ------------------------------------------------
    def _append(self, text: str):
        def _do():
            self.txt_messages.insert("end", text + "\n")
            self.txt_messages.see("end")
        self._ui(_do)

    def _get_selected_node_id(self) -> Optional[str]:
        sel = self.tv_nodes.selection()
        return sel[0] if sel else None

    def _popup_node_menu(self, event):
        iid = self.tv_nodes.identify_row(event.y)
        if iid:
            self.tv_nodes.selection_set(iid)
        self.node_menu.tk_popup(event.x_root, event.y_root)
        self.node_menu.grab_release()

    def _cm_show_node_details(self):
        self.show_raw_node(friendly=True)

    def _cm_open_map(self):
        nid = self._get_selected_node_id()
        if not nid or not self.iface or not getattr(self.iface, "nodes", None):
            messagebox.showinfo("Map", "No node selected.")
            return
        node = self.iface.nodes.get(nid, {})  # type: ignore[attr-defined]
        lat, lon = self._extract_latlon(node)
        if lat is None or lon is None:
            messagebox.showinfo("Map", "Selected node has no GPS position.")
            return
        url = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
        self._open_browser_url(url)

    def show_raw_node(self, friendly: bool = False):
        nid = self._get_selected_node_id()
        if not nid or not self.iface or not getattr(self.iface, "nodes", None):
            messagebox.showinfo("Node", "No node selected.")
            return
        node = self.iface.nodes.get(nid, {})  # type: ignore[attr-defined]
        win = tk.Toplevel(self.root)
        win.title(f"Node: {self._node_label(nid)}")
        self._style_toplevel(win)
        frm = ttk.Frame(win, padding=8)
        frm.pack(expand=True, fill="both")
        txt = tk.Text(frm, wrap="word")
        txt.pack(expand=True, fill="both")

        is_dark = self.current_theme == "dark"
        txt.configure(
            bg=("#2d2d2d" if is_dark else "#ffffff"),
            fg=("#ffffff" if is_dark else "#000000"),
            insertbackground=("#ffffff" if is_dark else "#000000"),
        )

        if not friendly:
            txt.insert("1.0", json.dumps(node, indent=2, default=str))
            txt.configure(state="disabled")
            return

        def fmt_val(v, indent=0):
            pad = "  " * indent
            if isinstance(v, dict):
                lines = []
                for k, vv in v.items():
                    if isinstance(vv, (dict, list)):
                        lines.append(f"{pad}{k}:")
                        lines.append(fmt_val(vv, indent + 1))
                    else:
                        lines.append(f"{pad}{k}: {vv}")
                return "\n".join(lines)
            if isinstance(v, list):
                lines = []
                for i, item in enumerate(v):
                    if isinstance(item, (dict, list)):
                        lines.append(f"{pad}- [{i}]")
                        lines.append(fmt_val(item, indent + 1))
                    else:
                        lines.append(f"{pad}- {item}")
                return "\n".join(lines)
            return f"{pad}{v}"

        user = (node or {}).get("user") or {}
        pos = (node or {}).get("position") or {}
        caps = (node or {}).get("capabilities") or {}
        config = (node or {}).get("config") or {}

        node_id = user.get("id") or node.get("id") or nid
        macaddr = user.get("macaddr") or node.get("macaddr") or ""
        publickey = user.get("publicKey") or node.get("publicKey") or ""
        hw = user.get("hwModel", "")

        lines = [
            f"Name: {user.get('shortName', '')} {user.get('longName', '')}".strip(),
            f"ID:   {node_id}",
            f"MAC:  {macaddr}",
            f"HW:   {hw}",
            f"Public key: {publickey}",
            "",
            f"Last heard: {_fmt_ago(self._get_lastheard_epoch(nid, node))}",
            "",
            "Position:",
            fmt_val(pos, 1),
        ]
        if caps:
            lines.append("Capabilities:")
            lines.append(fmt_val(caps, 1))
        if config:
            lines.append("Config:")
            lines.append(fmt_val(config, 1))
        lines.append("RAW fields:")
        skip = {"user", "position", "capabilities", "config"}
        other = {k: v for k, v in (node or {}).items() if k not in skip}
        lines.append(fmt_val(other, 1))

        txt.insert("1.0", "\n".join(lines))
        txt.configure(state="disabled")

    def show_neighbors_window(self):
        if not self.iface or not getattr(self.iface, "nodes", None):
            messagebox.showinfo("Neighbors", "No interface or nodes available.")
            return

        win = tk.Toplevel(self.root)
        win.title("Neighbor table")
        self._style_toplevel(win)
        frm = ttk.Frame(win, padding=8)
        frm.pack(expand=True, fill="both")

        tree = ttk.Treeview(frm, columns=("from", "to", "snr", "lastheard"), show="headings")
        for col, txt in (("from", "From node"), ("to", "To node"), ("snr", "SNR"), ("lastheard", "Last heard")):
            tree.heading(col, text=txt)
            tree.column(col, width=160 if col in ("from", "to") else 90, anchor="w")
        tree.pack(side="left", expand=True, fill="both")

        yscroll = ttk.Scrollbar(frm, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")

        try:
            nodes_snapshot = dict(self.iface.nodes or {})  # type: ignore[attr-defined]
        except Exception:
            nodes_snapshot = {}

        rows = 0
        for node_id, node in nodes_snapshot.items():
            from_label = self._node_label(str(node_id))
            neighbors = (node or {}).get("neighbors") or []
            if isinstance(neighbors, dict):
                neighbors = neighbors.values()
            for n in neighbors:
                try:
                    to_id = (n or {}).get("nodeId") or (n or {}).get("id") or ""
                    to_label = self._node_label(str(to_id)) if to_id else str(to_id)
                    snr = (n or {}).get("snr") or (n or {}).get("snrDb")
                    last = (n or {}).get("lastHeard")
                    try:
                        last_epoch = float(last) if last is not None else None
                    except Exception:
                        last_epoch = None
                    last_str = _fmt_ago(last_epoch)
                except Exception:
                    continue
                tree.insert("", "end", values=(from_label, to_label, snr if snr is not None else "-", last_str))
                rows += 1

        if rows == 0:
            messagebox.showinfo("Neighbors", "No neighbor information found on nodes.")

    # admin / traceroute ---------------------------------------------
    def _resolve_node_dest_id(self, nid: str) -> Optional[str]:
        nid = str(nid or "").strip()
        if not nid:
            return None
        if nid.startswith("!") or nid.isdigit():
            return nid
        try:
            if self.iface and getattr(self.iface, "nodes", None):
                node = (self.iface.nodes.get(nid) or {})  # type: ignore[attr-defined]
                user = (node or {}).get("user") or {}
                node_id = user.get("id") or ""
                if node_id:
                    return str(node_id)
        except Exception:
            pass
        return "!" + nid if not nid.startswith("!") else nid

    def _cm_traceroute(self):
        nid = self._get_selected_node_id()
        if not nid:
            messagebox.showinfo("Traceroute", "Select a node first.")
            return
        if not self.iface:
            messagebox.showwarning("Traceroute", "Connect first.")
            return
        dest = self._resolve_node_dest_id(nid)
        if not dest:
            messagebox.showerror("Traceroute", "Cannot determine node ID for traceroute.")
            return
        self._append(f"[trace] Requesting traceroute to {self._node_label(nid)} ({dest})")
        threading.Thread(target=self._do_traceroute, args=(dest,), daemon=True).start()

    def _cm_delete_node(self):
        nid = self._get_selected_node_id()
        if not nid:
            messagebox.showinfo("Delete node", "Select a node first.")
            return
        if not self.iface or not getattr(self.iface, "localNode", None):
            messagebox.showwarning("Delete node", "Connect first.")
            return

        dest = self._resolve_node_dest_id(nid)
        if not dest:
            messagebox.showerror("Delete node", "Cannot determine node ID.")
            return

        label = self._node_label(nid)
        if not messagebox.askyesno(
            "Delete node",
            f"Remove node {label} ({dest}) from the NodeDB on the connected radio?\n\nThe device might reboot after this."
        ):
            return

        try:
            self.iface.localNode.removeNode(dest)  # type: ignore[attr-defined]
            self._append(f"[admin] Requested delete of node {label} ({dest})")
        except Exception as e:
            messagebox.showerror("Delete node", f"Failed to delete node: {e}")
            return

        try:
            self.tv_nodes.delete(nid)
            self.nodes_frame.config(text=f"Nodes ({len(self.tv_nodes.get_children())})")
        except Exception:
            pass

    def _do_traceroute(self, dest: str, hop_limit: int = 10, channel_index: int = 0):
        if self.iface and mesh_pb2 is not None and portnums_pb2 is not None and _json_format is not None and hasattr(self.iface, "sendData"):
            self._do_traceroute_via_interface(dest, hop_limit, channel_index)
        else:
            self._do_traceroute_via_cli(dest)

    def _do_traceroute_via_interface(self, dest: str, hop_limit: int, channel_index: int):
        evt = threading.Event()
        result: Dict[str, Any] = {}

        def _num_to_label(num: int) -> str:
            try:
                nbn = getattr(self.iface, "nodesByNum", None)
                if nbn and num in nbn:
                    n = nbn[num]
                    user = (n or {}).get("user") or {}
                    sid = user.get("id") or f"!{num:08x}"
                    sn = user.get("shortName") or ""
                    ln = user.get("longName") or ""
                    label = (sn or ln or sid).strip()
                    return f"{label} ({sid})" if sid else label
            except Exception:
                pass
            return f"!{int(num):08x}"

        def _on_response(p: dict):
            try:
                rd = mesh_pb2.RouteDiscovery()
                rd.ParseFromString(p["decoded"]["payload"])
                result["packet"] = p
                result["data"] = _json_format.MessageToDict(rd)
            except Exception as e:
                result["error"] = str(e)
            finally:
                evt.set()

        r = mesh_pb2.RouteDiscovery()
        try:
            # Some meshtastic-python versions don't expose hopLimit as a sendData kwarg.
            self.iface.sendData(
                r,
                destinationId=dest,
                portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
                wantResponse=True,
                onResponse=_on_response,
                channelIndex=channel_index,
                hopLimit=hop_limit,
            )
        except TypeError:
            self.iface.sendData(
                r,
                destinationId=dest,
                portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
                wantResponse=True,
                onResponse=_on_response,
                channelIndex=channel_index,
            )
        except Exception as e:
            self._ui(lambda: messagebox.showerror("Traceroute", f"Failed to send traceroute: {e}"))
            return

        if not evt.wait(30.0):
            self._ui(lambda: messagebox.showinfo("Traceroute", "No traceroute response (timeout or unsupported)."))
            return

        if "error" in result:
            self._ui(lambda: messagebox.showerror("Traceroute", f"Failed to decode traceroute: {result['error']}"))
            return

        p = result.get("packet") or {}
        data = result.get("data") or {}
        UNK = -128

        try:
            origin_num = int(p.get("to"))
            dest_num = int(p.get("from"))
        except Exception:
            origin_num = None
            dest_num = None

        def _build_path(title: str, start_num: Optional[int], route_key: str, snr_key: str, end_num: Optional[int]) -> Optional[str]:
            route_nums = []
            for v in data.get(route_key, []):
                try:
                    route_nums.append(int(v))
                except Exception:
                    pass
            snrs = []
            for v in data.get(snr_key, []):
                try:
                    snrs.append(int(v))
                except Exception:
                    pass

            if start_num is None or end_num is None:
                return None
            nodes = [start_num] + route_nums + [end_num]
            if len(nodes) <= 1:
                return None

            parts = []
            for idx, num in enumerate(nodes):
                label = _num_to_label(num)
                if idx == 0:
                    parts.append(label)
                else:
                    snr_txt = "? dB"
                    if (idx - 1) < len(snrs):
                        v = snrs[idx - 1]
                        if v != UNK:
                            snr_txt = f"{v / 4.0:.2f} dB"
                    parts.append(f"{label} ({snr_txt})")
            return title + "\n" + " -> ".join(parts)

        lines = []
        fwd = _build_path("Route towards destination:", origin_num, "route", "snrTowards", dest_num)
        if fwd:
            lines.append(fwd)
        back = _build_path("Route back to us:", dest_num, "routeBack", "snrBack", origin_num)
        if back:
            lines.append(back)

        if not lines:
            self._ui(lambda: messagebox.showinfo("Traceroute", "Traceroute completed but no route data available."))
            return

        text = "\n\n".join(lines)
        self._ui(lambda: self._show_traceroute_window(text))

    def _do_traceroute_via_cli(self, dest: str):
        host = (self.host_var.get() or "").strip() or HOST_DEFAULT
        cmd = ["meshtastic", "--host", host, "--traceroute", dest]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        except Exception as e:
            self._ui(lambda: messagebox.showerror("Traceroute", f"Failed to run meshtastic CLI: {e}"))
            return
        out = (proc.stdout or "") + ("\n" + (proc.stderr or "") if proc.stderr else "")
        if not out.strip():
            self._ui(lambda: messagebox.showinfo("Traceroute", "No output from meshtastic traceroute."))
            return
        self._ui(lambda: self._show_traceroute_window(out))

    def _show_traceroute_window(self, text: str):
        win = tk.Toplevel(self.root)
        win.title("Traceroute")
        self._style_toplevel(win)
        frm = ttk.Frame(win, padding=8)
        frm.pack(expand=True, fill="both")
        txt = tk.Text(frm, wrap="word")
        txt.pack(expand=True, fill="both")
        is_dark = self.current_theme == "dark"
        txt.configure(
            bg=("#2d2d2d" if is_dark else "#ffffff"),
            fg=("#ffffff" if is_dark else "#000000"),
            insertbackground=("#ffffff" if is_dark else "#000000"),
        )
        txt.insert("1.0", text.strip() or "No traceroute data.")
        txt.configure(state="disabled")

    # chat windows ----------------------------------------------------
    def _cm_open_chat(self):
        nid = self._get_selected_node_id()
        if not nid:
            messagebox.showinfo("Chat", "Select a node first.")
            return
        self._open_node_chat(nid)

    def _open_node_chat(self, nid: str):
        key = str(nid)
        if key in self._per_node_chats:
            win = self._per_node_chats[key]
            try:
                win.top.deiconify()
                win.top.lift()
            except Exception:
                pass
            return
        label = self._node_label(nid)
        chat = NodeChatWindow(self, key, label)
        self._per_node_chats[key] = chat

    def _append_to_node_chat(self, node_id: str, line: str):
        key = str(node_id)
        win = self._per_node_chats.get(key)
        if not win:
            return
        win.append(line)

    def _send_text_to_node(self, node_key: str, msg: str) -> bool:
        if not self.iface:
            messagebox.showwarning("Send", "Connect first.")
            return False
        msg = (msg or "").strip()
        if not msg:
            return False

        dest_id = self._resolve_node_dest_id(node_key)
        if not dest_id:
            messagebox.showerror("Send failed", "Cannot resolve destinationId for this node.")
            return False

        # Use currently selected channelIndex (so DM uses the same channel selection)
        choice = self.channel_var.get() or ""
        info = self._channel_map.get(choice) or {"mode": "broadcast", "channelIndex": 0}
        ch_index = int(info.get("channelIndex", 0) or 0)

        try:
            self.iface.sendText(msg, destinationId=dest_id, wantAck=False, channelIndex=ch_index)
            self._append(f"[ME -> {self._node_label(node_key)}] {msg}")
            self._append_to_node_chat(node_key, "[ME] " + msg)
            return True
        except Exception as e:
            messagebox.showerror("Send failed", str(e))
            return False

    # config viewers/editors -----------------------------------------
    def show_radio_config_window(self):
        if not self.iface or not getattr(self.iface, "localNode", None):
            messagebox.showinfo("Radio config", "Connect to a device first.")
            return
        ln = self.iface.localNode
        try:
            if getattr(ln, "localConfig", None) is None and hasattr(ln, "waitForConfig"):
                ln.waitForConfig("localConfig")
        except Exception:
            pass
        cfg = getattr(ln, "localConfig", None)
        mod = getattr(ln, "moduleConfig", None)
        if cfg is None and mod is None:
            messagebox.showinfo("Radio config", "No config available yet from device.")
            return

        win = tk.Toplevel(self.root)
        win.title("Radio + module config (read-only)")
        self._style_toplevel(win)
        frm = ttk.Frame(win, padding=8)
        frm.pack(expand=True, fill="both")
        txt = tk.Text(frm, wrap="none")
        txt.pack(side="left", expand=True, fill="both")
        yscroll = ttk.Scrollbar(frm, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")

        is_dark = self.current_theme == "dark"
        txt.configure(
            bg=("#2d2d2d" if is_dark else "#ffffff"),
            fg=("#ffffff" if is_dark else "#000000"),
            insertbackground=("#ffffff" if is_dark else "#000000"),
        )

        lines = []
        if cfg is not None:
            lines.append("localConfig:")
            try:
                lines.append(str(cfg))
            except Exception:
                lines.append(repr(cfg))
        if mod is not None:
            lines.append("\nmoduleConfig:")
            try:
                lines.append(str(mod))
            except Exception:
                lines.append(repr(mod))
        txt.insert("1.0", "\n".join(lines))
        txt.configure(state="disabled")

    def show_channel_editor_window(self):
        if not self.iface or not getattr(self.iface, "localNode", None):
            messagebox.showinfo("Channels", "Connect to a device first.")
            return
        ln = self.iface.localNode
        try:
            if getattr(ln, "channels", None) in (None, {}) and hasattr(ln, "waitForConfig"):
                ln.waitForConfig("channels")
        except Exception:
            pass
        chans = getattr(ln, "channels", None)
        if not chans:
            messagebox.showinfo("Channels", "No channels available from device.")
            return

        win = tk.Toplevel(self.root)
        win.title("Channel editor")
        self._style_toplevel(win)
        frm = ttk.Frame(win, padding=8)
        frm.grid(row=0, column=0, sticky="nsew")
        win.rowconfigure(0, weight=1)
        win.columnconfigure(0, weight=1)

        listbox = tk.Listbox(frm, height=10)
        listbox.grid(row=0, column=0, columnspan=2, sticky="nsew")
        frm.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        for idx, ch in enumerate(chans):
            if ch is None:
                label = f"Ch {idx} (empty)"
            else:
                try:
                    name = (getattr(ch, "settings", None).name or "").strip()
                except Exception:
                    try:
                        name = (ch.settings.name or "").strip()
                    except Exception:
                        name = ""
                label = f"{idx}: {name or '(no name)'}"
            listbox.insert("end", label)

        ttk.Label(frm, text="Channel name:").grid(row=1, column=0, sticky="w", pady=(6, 2))
        name_var = tk.StringVar()
        ent_name = ttk.Entry(frm, textvariable=name_var, width=40)
        ent_name.grid(row=2, column=0, columnspan=2, sticky="ew")

        def on_select(evt=None):
            sel = listbox.curselection()
            if not sel:
                return
            i = sel[0]
            ch = chans[i]
            if ch is None:
                name_var.set("")
                return
            try:
                nm = (getattr(ch, "settings", None).name or "").strip()
            except Exception:
                try:
                    nm = (ch.settings.name or "").strip()
                except Exception:
                    nm = ""
            name_var.set(nm)

        listbox.bind("<<ListboxSelect>>", on_select)

        def save_name():
            sel = listbox.curselection()
            if not sel:
                messagebox.showinfo("Channel editor", "Select a channel first.")
                return
            i = sel[0]
            ch = chans[i]
            if ch is None:
                messagebox.showerror("Channel editor", "Selected channel object is empty, cannot rename.")
                return
            new_name = name_var.get().strip()
            try:
                if hasattr(ch, "settings"):
                    ch.settings.name = new_name
                elif hasattr(ch, "name"):
                    ch.name = new_name
                ln.writeChannel(i)
                self._append(f"[admin] Renamed channel {i} to '{new_name}'")
                self._update_channels_from_iface()
                listbox.delete(i)
                label = f"{i}: {new_name or '(no name)'}"
                listbox.insert(i, label)
            except Exception as e:
                messagebox.showerror("Channel editor", f"Failed to write channel: {e}")

        ttk.Button(frm, text="Save name to device", command=save_name).grid(row=3, column=0, sticky="w", pady=(6, 0))


    # SETTINGS (persist to ./meshtastic_client_settings.json) -------------------
    def _settings_path(self) -> pathlib.Path:
        """Return the settings file path in the current working directory ('.')."""
        return pathlib.Path.cwd() / CONFIG_FILENAME

    def load_settings(self, silent: bool = False) -> None:
        """Load settings from JSON if the file exists."""
        path = self._settings_path()
        if not path.exists():
            # Apply defaults if no config file
            if not self._startup_geometry_applied:
                try:
                    self.root.geometry(DEFAULT_GEOMETRY)
                    self._startup_geometry_applied = True
                except Exception:
                    pass
            return

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            if not silent:
                messagebox.showerror("Settings", f"Failed to read settings file:\n{path}\n\n{e}")
            return

        # Host/port
        try:
            host = str(data.get("host", "")).strip()
            if host:
                self.host_var.set(host)
        except Exception:
            pass
        try:
            port = int(data.get("port", PORT_DEFAULT))
            if 1 <= port <= 65535:
                self.port_var.set(port)
        except Exception:
            pass

        # Connection method and params
        try:
            ctype = str(data.get("connection_type", "")).strip().lower()
            if ctype in ("tcp", "serial", "ble", "bluetooth"):
                self.conn_type_var.set("ble" if ctype == "bluetooth" else ctype)
        except Exception:
            pass
        try:
            sp = str(data.get("serial_port", "")).strip()
            self.serial_port_var.set(sp)
        except Exception:
            pass
        try:
            ba = str(data.get("ble_address", "")).strip()
            self.ble_addr_var.set(ba)
        except Exception:
            pass

        # Theme
        try:
            theme = str(data.get("theme", "")).strip().lower()
            if theme in ("light", "dark"):
                self.current_theme = theme
        except Exception:
            pass

        # Default send target / channel choice (label string)
        try:
            ch_choice = str(data.get("channel_choice", "")).strip()
            if ch_choice:
                # only apply if exists now; otherwise keep pending until channels are loaded
                try:
                    values = list(self.cbo_channel["values"])
                except Exception:
                    values = []
                if ch_choice in values:
                    self.channel_var.set(ch_choice)
                else:
                    self._pending_channel_choice = ch_choice
        except Exception:
            pass

        # Window geometry
        try:
            geom = str(data.get("window_geometry", "")).strip()
            if geom:
                self.root.geometry(geom)
                self._startup_geometry_applied = True
        except Exception:
            pass

        # Sash fraction
        try:
            frac = float(data.get("sash_fraction", DEFAULT_SASH_FRACTION))
            if 0.10 <= frac <= 0.90:
                self._startup_sash_fraction = frac
        except Exception:
            pass

        self._update_title_with_host()
        if not silent:
            self._append(f"[settings] Loaded from {path}")

    def save_settings(self, silent: bool = False) -> None:
        """Save settings to JSON in the current working directory ('.')."""
        path = self._settings_path()

        # Best-effort sash fraction
        sash_fraction = DEFAULT_SASH_FRACTION
        try:
            w = self.paned.winfo_width() or self.paned.winfo_reqwidth() or 1
            pos = self.paned.sashpos(0)
            if w > 0:
                sash_fraction = max(0.10, min(0.90, float(pos) / float(w)))
        except Exception:
            pass

        payload = {
            "version": 2,
            "host": (self.host_var.get() or "").strip(),
            "port": int(self.port_var.get() or PORT_DEFAULT),
            "connection_type": (self.conn_type_var.get() or "tcp").strip().lower(),
            "serial_port": (self.serial_port_var.get() or "").strip(),
            "ble_address": (self.ble_addr_var.get() or "").strip(),
            "theme": self.current_theme,
            "channel_choice": (self.channel_var.get() or "").strip(),
            "window_geometry": self.root.winfo_geometry(),
            "sash_fraction": sash_fraction,
        }

        try:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(path)
            if not silent:
                messagebox.showinfo("Settings", f"Saved settings to:\n{path}")
        except Exception as e:
            if not silent:
                messagebox.showerror("Settings", f"Failed to save settings to:\n{path}\n\n{e}")

    def open_settings_dialog(self) -> None:
        """Open a Settings window (loads/saves JSON in the current working dir)."""
        win = tk.Toplevel(self.root)
        win.title("Settings")
        self._style_toplevel(win)

        frm = ttk.Frame(win, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")
        win.rowconfigure(0, weight=1)
        win.columnconfigure(0, weight=1)

        nb = ttk.Notebook(frm)
        nb.grid(row=0, column=0, sticky="nsew")
        frm.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        tab_general = ttk.Frame(nb, padding=10)
        tab_conn = ttk.Frame(nb, padding=10)
        tab_file = ttk.Frame(nb, padding=10)
        nb.add(tab_general, text="General")
        nb.add(tab_conn, text="Connection")
        nb.add(tab_file, text="File")

        # --- General tab ------------------------------------------------
        theme_var = tk.StringVar(value=self.current_theme)

        ttk.Label(tab_general, text="Theme:").grid(row=0, column=0, sticky="w", pady=4)
        cbo_theme = ttk.Combobox(tab_general, textvariable=theme_var, state="readonly", values=["dark", "light"], width=10)
        cbo_theme.grid(row=0, column=1, sticky="w", pady=4, padx=6)

        ttk.Label(tab_general, text="Default send target:").grid(row=1, column=0, sticky="w", pady=4)
        choice_var = tk.StringVar(value=self.channel_var.get())
        try:
            choices = list(self.cbo_channel["values"])
        except Exception:
            choices = []
        cbo_choice = ttk.Combobox(tab_general, textvariable=choice_var, state="readonly", values=choices, width=28)
        cbo_choice.grid(row=1, column=1, sticky="w", pady=4, padx=6)

        tab_general.columnconfigure(1, weight=1)

        # --- Connection tab --------------------------------------------
        # Pretty labels in UI, but we store keys: tcp|serial|ble
        key_to_label = {"tcp": "TCP (WiFi)", "serial": "USB/Serial", "ble": "Bluetooth (BLE)"}
        label_to_key = {v: k for k, v in key_to_label.items()}

        method_label_var = tk.StringVar(value=key_to_label.get((self.conn_type_var.get() or "tcp").strip().lower(), "TCP (WiFi)"))

        ttk.Label(tab_conn, text="Method:").grid(row=0, column=0, sticky="w", pady=4)
        cbo_method = ttk.Combobox(tab_conn, textvariable=method_label_var, state="readonly",
                                 values=[key_to_label["tcp"], key_to_label["serial"], key_to_label["ble"]],
                                 width=18)
        cbo_method.grid(row=0, column=1, sticky="w", pady=4, padx=6)

        # TCP settings
        tcp_box = ttk.Labelframe(tab_conn, text="TCP settings", padding=10)
        ttk.Label(tcp_box, text="Host/IP:").grid(row=0, column=0, sticky="w", pady=4)
        ent_host = ttk.Entry(tcp_box, textvariable=self.host_var, width=32)
        ent_host.grid(row=0, column=1, sticky="ew", pady=4, padx=6)

        ttk.Label(tcp_box, text="Port:").grid(row=1, column=0, sticky="w", pady=4)
        ent_port = ttk.Entry(tcp_box, textvariable=self.port_var, width=10)
        ent_port.grid(row=1, column=1, sticky="w", pady=4, padx=6)

        tcp_box.columnconfigure(1, weight=1)

        # Serial settings
        serial_box = ttk.Labelframe(tab_conn, text="USB/Serial settings", padding=10)
        serial_port_ui = tk.StringVar(value=(self.serial_port_var.get() or "").strip() or "(auto)")

        ttk.Label(serial_box, text="Serial port:").grid(row=0, column=0, sticky="w", pady=4)

        cbo_serial = ttk.Combobox(serial_box, textvariable=serial_port_ui, state="readonly", width=30)
        cbo_serial.grid(row=0, column=1, sticky="w", pady=4, padx=6)

        def refresh_serial_ports():
            ports = []
            if list_ports:
                try:
                    ports = [p.device for p in list_ports.comports()]
                except Exception:
                    ports = []
            vals = ["(auto)"] + ports
            # Ensure saved/manual value is visible
            cur = (serial_port_ui.get() or "").strip()
            if cur and cur not in vals:
                vals.append(cur)
            cbo_serial["values"] = vals
            if not cur:
                serial_port_ui.set("(auto)")

        ttk.Button(serial_box, text="Refresh", command=refresh_serial_ports).grid(row=0, column=2, padx=(6, 0), sticky="w")
        refresh_serial_ports()

        # BLE settings
        ble_box = ttk.Labelframe(tab_conn, text="Bluetooth (BLE) settings", padding=10)
        ble_addr_ui = tk.StringVar(value=(self.ble_addr_var.get() or "").strip())

        ttk.Label(ble_box, text="Device (name or address):").grid(row=0, column=0, sticky="w", pady=4)
        ent_ble = ttk.Entry(ble_box, textvariable=ble_addr_ui, width=36)
        ent_ble.grid(row=0, column=1, sticky="ew", pady=4, padx=6)

        def scan_ble_into_settings():
            if BLEInterface is None:
                messagebox.showerror("Unavailable", "meshtastic.ble_interface not installed (needs bleak).")
                return
            try:
                devices = BLEInterface.scan()
            except Exception as e:
                messagebox.showerror("BLE scan failed", str(e))
                return
            if not devices:
                messagebox.showinfo("BLE", "No devices found.")
                return
            options = [
                f"{i + 1}. {getattr(d, 'name', '') or '(unnamed)'} [{getattr(d, 'address', '?')}]"
                for i, d in enumerate(devices)
            ]
            choice = simpledialog.askinteger(
                "Select BLE device",
                    "Enter number:\n" + "\n".join(options),
                minvalue=1,
                maxvalue=len(devices),
            )
            if not choice:
                return
            addr = getattr(devices[choice - 1], "address", None)
            if not addr:
                messagebox.showerror("BLE", "Selected device has no address.")
                return
            ble_addr_ui.set(str(addr))

        ttk.Button(ble_box, text="Scan...", command=scan_ble_into_settings).grid(row=0, column=2, padx=(6, 0), sticky="w")
        ble_box.columnconfigure(1, weight=1)

        # place boxes (we show/hide depending on method)
        tcp_box.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(10, 6))
        serial_box.grid(row=2, column=0, columnspan=3, sticky="ew", pady=6)
        ble_box.grid(row=3, column=0, columnspan=3, sticky="ew", pady=6)

        tab_conn.columnconfigure(1, weight=1)

        def _show_only(key: str):
            key = key.strip().lower()
            if key == "serial":
                tcp_box.grid_remove()
                ble_box.grid_remove()
                serial_box.grid()
            elif key == "ble":
                tcp_box.grid_remove()
                serial_box.grid_remove()
                ble_box.grid()
            else:
                serial_box.grid_remove()
                ble_box.grid_remove()
                tcp_box.grid()

        def _on_method_change(*_):
            key = label_to_key.get(method_label_var.get(), "tcp")
            _show_only(key)

        cbo_method.bind("<<ComboboxSelected>>", _on_method_change)
        _show_only(label_to_key.get(method_label_var.get(), "tcp"))

        # --- File tab ---------------------------------------------------
        path = self._settings_path()
        ttk.Label(tab_file, text="Settings file:").grid(row=0, column=0, sticky="w")
        lbl_path = ttk.Entry(tab_file, width=60)
        lbl_path.grid(row=1, column=0, sticky="ew", pady=(4, 10))
        lbl_path.insert(0, str(path))
        lbl_path.configure(state="readonly")
        tab_file.columnconfigure(0, weight=1)

        def open_folder():
            folder = str(path.parent)
            try:
                if os.name == "nt":
                    os.startfile(folder)  # type: ignore[attr-defined]
                else:
                    subprocess.Popen(["xdg-open", folder])
            except Exception as e:
                messagebox.showerror("Open folder", str(e))

        ttk.Button(tab_file, text="Open folder", command=open_folder).grid(row=2, column=0, sticky="w")

        # --- Buttons ----------------------------------------------------
        btnbar = ttk.Frame(frm)
        btnbar.grid(row=1, column=0, sticky="e", pady=(10, 0))

        def apply_and_save():
            # Validate port if TCP
            method_key = label_to_key.get(method_label_var.get(), "tcp")
            if method_key == "tcp":
                h = (self.host_var.get() or "").strip()
                if not h:
                    messagebox.showerror("Settings", "Host/IP cannot be empty for TCP.")
                    return
                try:
                    p = int(self.port_var.get())
                    if not (1 <= p <= 65535):
                        raise ValueError
                except Exception:
                    messagebox.showerror("Settings", "Port must be 1-65535")
                    return

            # Persist connection settings
            self.conn_type_var.set(method_key)
            sp = (serial_port_ui.get() or "").strip()
            self.serial_port_var.set("" if sp.lower() == "(auto)" else sp)
            self.ble_addr_var.set((ble_addr_ui.get() or "").strip())

            # Theme
            self.current_theme = theme_var.get()
            self.apply_theme(self.current_theme)

            # Default send target
            selected_choice = (choice_var.get() or "").strip()
            if selected_choice:
                try:
                    values_now = list(self.cbo_channel["values"])
                except Exception:
                    values_now = []
                if selected_choice in values_now:
                    self.channel_var.set(selected_choice)
                else:
                    self._pending_channel_choice = selected_choice

            self.save_settings(silent=False)

        def do_load():
            self.load_settings(silent=False)
            theme_var.set(self.current_theme)
            choice_var.set(self.channel_var.get())
            # Refresh method + params
            method_label_var.set(key_to_label.get((self.conn_type_var.get() or "tcp").strip().lower(), "TCP (WiFi)"))
            serial_port_ui.set((self.serial_port_var.get() or "").strip() or "(auto)")
            ble_addr_ui.set((self.ble_addr_var.get() or "").strip())
            refresh_serial_ports()
            _on_method_change()

        ttk.Button(btnbar, text="Load", command=do_load).grid(row=0, column=0, padx=4)
        ttk.Button(btnbar, text="Save", command=apply_and_save).grid(row=0, column=1, padx=4)
        ttk.Button(btnbar, text="Close", command=win.destroy).grid(row=0, column=2, padx=4)

    def close_app(self) -> None:
        """Graceful close: save settings, disconnect, then destroy."""
        try:
            self.save_settings(silent=True)
        except Exception:
            pass
        try:
            self.disconnect()
        finally:
            try:
                self.root.destroy()
            except Exception:
                pass


class NodeChatWindow:
    def __init__(self, app: MeshtasticGUI, node_key: str, label: str):
        self.app = app
        self.node_key = node_key
        self.label = label
        self.top = tk.Toplevel(app.root)
        self.top.title(f"Chat: {label}")
        app._style_toplevel(self.top)
        self.top.protocol("WM_DELETE_WINDOW", self._on_close)

        frm = ttk.Frame(self.top, padding=8)
        frm.pack(expand=True, fill="both")
        frm.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        self.txt = tk.Text(frm, wrap="word")
        self.txt.grid(row=0, column=0, columnspan=2, sticky="nsew")
        yscroll = ttk.Scrollbar(frm, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=0, column=2, sticky="ns")

        self.entry = ttk.Entry(frm)
        self.entry.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        self.entry.bind("<Return>", self._on_send)
        ttk.Button(frm, text="Send", command=self._on_send).grid(row=1, column=1, sticky="e", padx=(4, 0), pady=(6, 0))

        self.apply_theme()

    def apply_theme(self):
        is_dark = self.app.current_theme == "dark"
        self.txt.configure(
            bg=("#2d2d2d" if is_dark else "#ffffff"),
            fg=("#ffffff" if is_dark else "#000000"),
            insertbackground=("#ffffff" if is_dark else "#000000"),
        )

    def append(self, line: str):
        try:
            self.txt.insert("end", line + "\n")
            self.txt.see("end")
        except Exception:
            pass

    def _on_send(self, *_):
        msg = self.entry.get().strip()
        if not msg:
            return
        ok = self.app._send_text_to_node(self.node_key, msg)
        if ok:
            self.entry.delete(0, "end")

    def _on_close(self):
        try:
            self.app._per_node_chats.pop(str(self.node_key), None)
        except Exception:
            pass
        self.top.destroy()


def main():
    app = MeshtasticGUI()
    app.root.protocol("WM_DELETE_WINDOW", app.close_app)
    app.root.mainloop()


if __name__ == "__main__":
    main()
