# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
Meshtastic Client — TCP + USB/Serial + Bluetooth (BLE)
- Resizable UI, light/dark themes
- Connect via TCP (default), USB/Serial, or Bluetooth (BLE)
- PubSub listeners accept kwargs
- Nodes list: Short | Long | Since | Hops | Dist (km) | HW | Role (+ hidden lastheard)
- Distance via haversine; "My Info" popup; right-click node menu
- Auto "pong" reply to "ping"
"""
from __future__ import annotations
import json, time, datetime, threading, pathlib, tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Any, Dict, Optional

# ---- Meshtastic / pubsub (graceful if not installed) ----
try:
    from pubsub import pub
except Exception:
    pub = None
# Primary interfaces
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

# Optional: list serial ports
try:
    from serial.tools import list_ports
except Exception:
    list_ports = None

HOST_DEFAULT = "192.168.0.156"
PORT_DEFAULT = 4403

PROJECT_PATH = pathlib.Path(__file__).parent
ICON_PATH = PROJECT_PATH / "meshtastic.ico"


def _fmt_ago(epoch_seconds: Optional[float]) -> str:
    if not epoch_seconds:
        return "N/A"
    try:
        delta = time.time() - float(epoch_seconds)
    except Exception:
        return "N/A"
    if delta < 0:
        delta = 0
    mins = int(delta // 60); hours = int(delta // 3600); days = int(delta // 86400)
    if delta < 60: return f"{int(delta)}s"
    if mins < 60:  return f"{mins}m"
    if hours < 24: return f"{hours}h"
    if days < 7:   return f"{days}d"
    dt = datetime.datetime.fromtimestamp(epoch_seconds)
    return dt.strftime("%Y-%m-%d %H:%M")


class MeshtasticGUI:
    def __init__(self, master: Optional[tk.Tk] = None):
        self.root = master or tk.Tk()
        self.root.title("Meshtastic Client")

        # icon
        try:
            if ICON_PATH.exists():
                self.root.iconbitmap(default=str(ICON_PATH))
        except Exception as e:
            print("Icon load failed:", e)

        # resizable
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        # ------- state: connection vars -------
        self.host_var = tk.StringVar(value=HOST_DEFAULT)
        self.port_var = tk.IntVar(value=PORT_DEFAULT)
        self.serial_port_var = tk.StringVar(value="(auto)")
        self.ble_addr_var = tk.StringVar(value="(scan)")

        # ------- MENU -------
        menubar = tk.Menu(self.root)

        m_conn = tk.Menu(menubar, tearoff=False)
        m_conn.add_command(label="Connect (TCP)", command=self.connect_tcp)
        m_conn.add_command(label="Connect via USB/Serial…", command=self.connect_serial_dialog)
        m_conn.add_command(label="Connect via Bluetooth…", command=self.connect_ble_dialog)
        m_conn.add_command(label="Disconnect", command=self.disconnect)
        m_conn.add_separator()
        m_conn.add_command(label="Set IP/Port…", command=self.set_ip_port)
        menubar.add_cascade(label="Connection", menu=m_conn)

        m_tools = tk.Menu(menubar, tearoff=False)
        m_tools.add_command(label="My Info", command=self.show_myinfo)
        m_tools.add_separator()
        m_tools.add_command(label="Clear Messages", command=lambda: self.txt_messages.delete("1.0", "end"))
        menubar.add_cascade(label="Tools", menu=m_tools)

        m_view = tk.Menu(menubar, tearoff=False)
        m_view.add_command(label="Light theme", command=lambda: self.apply_theme("light"))
        m_view.add_command(label="Dark theme", command=lambda: self.apply_theme("dark"))
        menubar.add_cascade(label="View", menu=m_view)
        self.root.config(menu=menubar)

        # ------- ROOT FRAME -------
        self.rootframe = ttk.Frame(self.root)
        self.rootframe.grid(row=0, column=0, sticky="nsew")
        self.rootframe.rowconfigure(0, weight=1)
        self.rootframe.columnconfigure(0, weight=1)

        # ------- PANED -------
        self.paned = ttk.Panedwindow(self.rootframe, orient="horizontal")
        self.paned.grid(row=0, column=0, sticky="nsew")

        # ------- LEFT: messages -------
        self.center_frame = ttk.Frame(self.paned)
        self.center_frame.rowconfigure(1, weight=1)
        self.center_frame.columnconfigure(0, weight=1)
        ttk.Label(self.center_frame, text="Messages: Primary").grid(row=0, column=0, sticky="w", pady=(2, 0))

        self.txt_messages = tk.Text(self.center_frame, wrap="word")
        self.txt_messages.grid(row=1, column=0, sticky="nsew", pady=(2, 2), padx=(0, 4))
        yscroll_left = ttk.Scrollbar(self.center_frame, orient="vertical", command=self.txt_messages.yview)
        self.txt_messages.configure(yscrollcommand=yscroll_left.set)
        yscroll_left.grid(row=1, column=1, sticky="ns")

        self.send_frame = ttk.Frame(self.center_frame)
        self.send_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(0, 4))
        self.send_frame.columnconfigure(0, weight=1)
        self.ent_message = ttk.Entry(self.send_frame)
        self.ent_message.grid(row=0, column=0, sticky="nsew")
        self.ent_message.bind("<Return>", lambda e: self.send_message())
        self.btn_send = ttk.Button(self.send_frame, text="Send", command=self.send_message)
        self.btn_send.grid(row=0, column=1, padx=4, sticky="nsew")
        self.send_to_selected = tk.BooleanVar(value=False)
        self.chk_to_selected = ttk.Checkbutton(self.send_frame, text="To selected", variable=self.send_to_selected)
        self.chk_to_selected.grid(row=0, column=2, padx=4, sticky="w")

        # ------- RIGHT: nodes -------
        self.nodes_frame = ttk.Labelframe(self.paned, text="Nodes")
        self.nodes_frame.rowconfigure(1, weight=1)
        self.nodes_frame.columnconfigure(0, weight=1)

        self.ent_search = ttk.Entry(self.nodes_frame)
        self.ent_search.grid(row=0, column=0, sticky="nsew", pady=2, padx=2)
        self.ent_search.bind("<KeyRelease>", lambda e: self.refresh_nodes())

        self.cols_all = ("shortname", "longname", "since", "hops", "distkm", "lastheard",
                         "macaddr", "hwmodel", "role", "publickey", "isunmessagable", "id")
        self.cols_visible = ("shortname", "longname", "since", "hops", "distkm", "hwmodel", "role")
        self.tv_nodes = ttk.Treeview(self.nodes_frame, columns=self.cols_all, show="headings", displaycolumns=self.cols_visible)
        self.tv_nodes.grid(row=1, column=0, sticky="nsew", padx=(2, 0), pady=(0, 2))

        headings = {
            "shortname": "Short",
            "longname": "Long",
            "since": "Since",
            "hops": "Hops",
            "distkm": "Dist (km)",
            "macaddr": "MAC",
            "hwmodel": "HW",
            "role": "Role",
            "publickey": "Public Key",
            "isunmessagable": "Unmsg?",
            "id": "ID",
        }
        for key, text in headings.items():
            self.tv_nodes.heading(key, text=text, command=lambda c=key: self.sort_by_column(c, False))

        widths = {
            "shortname": 90, "longname": 220, "since": 90, "hops": 60, "distkm": 90,
            "macaddr": 120, "hwmodel": 90, "role": 110,
            "publickey": 420, "isunmessagable": 80, "id": 110,
        }
        for key, w in widths.items():
            try:
                stretch = key not in ("since", "hops", "distkm")
                self.tv_nodes.column(key, width=w, anchor="w", stretch=stretch)
            except Exception:
                pass
        try:
            self.tv_nodes.column("lastheard", width=0, minwidth=0, stretch=False, anchor="w")
            self.tv_nodes.heading("lastheard", text="")
        except Exception:
            pass

        yscroll = ttk.Scrollbar(self.nodes_frame, orient="vertical", command=self.tv_nodes.yview)
        self.tv_nodes.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=1, column=1, sticky="ns")

        # context menu
        self.node_menu = tk.Menu(self.nodes_frame, tearoff=False)
        self.node_menu.add_command(label="Send to this node", command=self._cm_send_to_node)
        self.node_menu.add_command(label="Ping node", command=self._cm_ping_node)
        self.node_menu.add_separator()
        self.node_menu.add_command(label="Copy node ID", command=self._cm_copy_node_id)
        self.node_menu.add_command(label="Show node details", command=self._cm_show_node_details)

        def _popup_menu(event):
            iid = self.tv_nodes.identify_row(event.y)
            if iid:
                self.tv_nodes.selection_set(iid)
            try:
                self.node_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.node_menu.grab_release()

        self.tv_nodes.bind("<Button-3>", _popup_menu)
        self.tv_nodes.bind("<Double-1>", lambda e: self._toggle_send_target())

        # add panes
        self.paned.add(self.center_frame, weight=3)
        self.paned.add(self.nodes_frame, weight=5)
        self.root.after(80, lambda: self._safe_set_sash(0.45))

        # state
        self.iface: Optional[object] = None
        self.connected_evt = threading.Event()
        self._last_seen_overrides: Dict[str, float] = {}

        # remember last sort
        self._last_sort_col: Optional[str] = None
        self._last_sort_reverse: bool = False

        # subscribe
        if pub is not None:
            try:
                pub.subscribe(self.on_connection_established, "meshtastic.connection.established")
                pub.subscribe(self.on_connection_lost, "meshtastic.connection.lost")
                pub.subscribe(self.on_receive, "meshtastic.receive")
                pub.subscribe(self.on_node_updated, "meshtastic.node.updated")
            except Exception as e:
                print("pubsub subscribe failed:", e)

        self._style = ttk.Style(self.root)
        self.apply_theme("light")
        self._append("Ready. Connection → Set IP/Port… or Connect (TCP/USB/BLE).")

        # show current host:port in title
        self._update_title_with_host()

    # ---------- helpers ----------
    def _node_label(self, node_id: str) -> str:
        """Return a nice label: Short Long [id]."""
        if not self.iface or not getattr(self.iface, "nodes", None):
            return node_id
        try:
            node = self.iface.nodes.get(node_id, {})  # type: ignore[attr-defined]
        except Exception:
            node = {}
        user = (node or {}).get("user") or {}
        shortname = user.get("shortName") or ""
        longname = user.get("longName") or ""
        parts = []
        if shortname:
            parts.append(shortname)
        if longname:
            parts.append(longname)
        label = " ".join(parts).strip()
        if label:
            return f"{label} [{node_id}]"
        return node_id

    def _update_title_with_host(self):
        try:
            self.root.title(f"Meshtastic Client — {self.host_var.get()}:{self.port_var.get()}")
        except Exception:
            pass

    # ---------- layout ----------
    def _safe_set_sash(self, fraction: float = 0.65):
        try:
            w = self.paned.winfo_width() or self.paned.winfo_reqwidth()
            sash = int(w * fraction)
            try:
                self.paned.sashpos(0, sash)
            except Exception:
                self.paned.paneconfigure(self.center_frame, width=sash)
        except Exception:
            pass

    # ---------- pubsub ----------
    def on_connection_established(self, interface=None, **kwargs):
        self.connected_evt.set()
        self._append("[+] Connected")
        try:
            if interface and hasattr(interface, "getNode"):
                interface.getNode(None)
        except Exception:
            pass
        self.refresh_nodes()

    def on_connection_lost(self, interface=None, **kwargs):
        self.connected_evt.clear()
        self._append("[-] Connection lost.")

    def on_node_updated(self, node=None, interface=None, **kwargs):
        self.root.after(0, self.refresh_nodes)

    def on_receive(self, packet=None, interface=None, **kwargs):
        def handle():
            decoded = (packet or {}).get("decoded", {}) if isinstance(packet, dict) else {}
            portnum = decoded.get("portnum")
            sender = (packet or {}).get("fromId") or (packet or {}).get("from") or (packet or {}).get("fromIdShort")
            if sender:
                self._last_seen_overrides[str(sender)] = time.time()

            user = {}
            try:
                if self.iface and getattr(self.iface, "nodes", None):
                    user = (self.iface.nodes.get(sender) or {}).get("user", {})  # type: ignore[attr-defined]
            except Exception:
                user = {}
            shortname = user.get("shortName") or ""
            longname  = user.get("longName") or ""

            text = ""
            p = decoded.get("payload", "")
            if isinstance(p, (bytes, bytearray)):
                try: text = p.decode("utf-8", errors="ignore")
                except Exception: text = repr(p)
            elif isinstance(p, str):
                text = p
            else:
                t = decoded.get("text")
                if isinstance(t, bytes): text = t.decode("utf-8", errors="ignore")
                elif isinstance(t, str): text = t

            rssi = (packet or {}).get("rxRssi"); snr = (packet or {}).get("rxSnr")

            if portnum == "TEXT_MESSAGE_APP":
                self._append(f"<{shortname or sender} {longname}> {text} (RSSI={rssi}, SNR={snr})")
                if isinstance(text, str) and text.strip().lower() == "ping":
                    try:
                        if self.iface and hasattr(self.iface, "sendText"):
                            self.iface.sendText("pong", destinationId=sender, wantAck=False)
                            self._append(f"[auto] Sent 'pong' to {shortname or sender}")
                    except Exception as e:
                        self._append(f"[auto] send failed: {e}")
            else:
                self._append(f"<PKT from {shortname or sender} port={portnum}>")

            self.refresh_nodes()
        self.root.after(0, handle)

    # ---------- actions ----------
    def set_ip_port(self):
        """Popup dialog to edit IP/Port used for TCP connection."""
        win = tk.Toplevel(self.root)
        win.title("Set IP/Port")
        frm = ttk.Frame(win, padding=8)
        frm.grid(row=0, column=0, sticky="nsew")
        win.columnconfigure(0, weight=1); win.rowconfigure(0, weight=1)

        ttk.Label(frm, text="IP / Hostname:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        ent_ip = ttk.Entry(frm, textvariable=self.host_var, width=26)
        ent_ip.grid(row=0, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(frm, text="Port:").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        ent_port = ttk.Entry(frm, textvariable=self.port_var, width=8)
        ent_port.grid(row=1, column=1, sticky="w", padx=4, pady=4)

        frm.columnconfigure(1, weight=1)

        def save_and_close():
            host = self.host_var.get().strip()
            try:
                port = int(self.port_var.get())
            except Exception:
                messagebox.showerror("Invalid port", "Port must be an integer (1-65535).")
                return
            if not host:
                messagebox.showerror("Invalid host", "Host/IP cannot be empty.")
                return
            if not (1 <= port <= 65535):
                messagebox.showerror("Invalid port", "Port must be in range 1-65535.")
                return
            self.host_var.set(host)
            self.port_var.set(port)
            self._update_title_with_host()
            self._append(f"[cfg] Set target {host}:{port}")
            win.destroy()

        btns = ttk.Frame(frm)
        btns.grid(row=2, column=0, columnspan=2, sticky="e", pady=(6, 0))
        ttk.Button(btns, text="Cancel", command=win.destroy).grid(row=0, column=0, padx=4)
        ttk.Button(btns, text="Save", command=save_and_close).grid(row=0, column=1, padx=4)
        ent_ip.focus_set()

    # --- Connectors ---
    def connect_tcp(self):
        if self.iface:
            return
        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get())
        except Exception:
            messagebox.showerror("Invalid port", "Set a valid port (Connection → Set IP/Port…).")
            return
        self._append(f"Connecting TCP {host}:{port} ...")
        def run():
            try:
                if TCPInterface is None:
                    raise RuntimeError("meshtastic.tcp_interface not installed")
                self.iface = TCPInterface(hostname=host, portNumber=port)
                self.connected_evt.wait(timeout=5)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Connect failed", str(e)))
        threading.Thread(target=run, daemon=True).start()

    def connect_serial_dialog(self):
        """Pick a serial port and connect using SerialInterface."""
        if SerialInterface is None:
            messagebox.showerror("Unavailable", "meshtastic.serial_interface not installed.")
            return

        ports = []
        if list_ports:
            try:
                ports = [p.device for p in list_ports.comports()]
            except Exception:
                ports = []
        # Fallback options
        presets = ["(auto)"] + ports + ["COM4", "/dev/ttyUSB0", "/dev/cu.usbmodem*"]
        port = simpledialog.askstring("USB/Serial", "Choose serial port (or leave '(auto)'):", initialvalue=presets[0])
        if port is None:
            return
        port = port.strip()
        if port == "" or port.lower() == "(auto)":
            port = None  # let library auto-detect
        self._append(f"Connecting Serial {port or '(auto-detect)'} ...")
        def run():
            try:
                self.iface = SerialInterface(devPath=port) if port else SerialInterface()
                self.connected_evt.wait(timeout=5)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Serial connect failed", str(e)))
        threading.Thread(target=run, daemon=True).start()

    def connect_ble_dialog(self):
        """Scan for BLE devices and connect using BLEInterface."""
        if BLEInterface is None:
            messagebox.showerror("Unavailable", "meshtastic.ble_interface not installed (requires 'bleak').")
            return

        # Scan
        self._append("Scanning BLE for Meshtastic devices (about 10s)...")
        devices = []
        try:
            devices = BLEInterface.scan()
        except Exception as e:
            messagebox.showerror("BLE scan failed", str(e))
            return
        if not devices:
            messagebox.showinfo("BLE", "No Meshtastic BLE devices found. Ensure Bluetooth is enabled and device is in pairing mode.")
            return

        # Build selection list
        options = [f"{idx+1}. {getattr(d,'name', '') or '(unnamed)'}  [{getattr(d,'address','?')}]" for idx, d in enumerate(devices)]
        choice = simpledialog.askinteger("Select BLE device",
                                         "Enter number:\n" + "\n".join(options),
                                         minvalue=1, maxvalue=len(options))
        if not choice:
            return
        addr = getattr(devices[choice-1], "address", None)
        if not addr:
            messagebox.showerror("BLE", "Selected device has no address.")
            return

        self._append(f"Connecting BLE {addr} ...")
        def run():
            try:
                self.iface = BLEInterface(address=addr)
                self.connected_evt.wait(timeout=8)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("BLE connect failed", str(e)))
        threading.Thread(target=run, daemon=True).start()

    def disconnect(self):
        try:
            if self.iface:
                self.iface.close()
        except Exception:
            pass
        self.iface = None
        self.connected_evt.clear()
        self._append("[*] Disconnected.")

    def send_message(self):
        msg = self.ent_message.get().strip()
        if not msg:
            return
        if not self.iface:
            messagebox.showwarning("Not connected", "Connect first.")
            return
        try:
            if self.send_to_selected.get():
                nid = self._get_selected_node_id()
                if not nid:
                    messagebox.showinfo("No selection", "Select a node (or uncheck 'To selected').")
                    return
                self.iface.sendText(msg, destinationId=nid, wantAck=False)
                self._append(f"[me → {self._node_label(nid)}] {msg}")
            else:
                self.iface.sendText(msg, wantAck=False)
                self._append(f"[me] {msg}")
            self.ent_message.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Send failed", str(e))

    # ---------- nodes ----------
    def _get_lastheard_epoch(self, node_id: str, node: Dict[str, Any]) -> Optional[float]:
        raw = (node or {}).get("lastHeard")
        ts_iface: Optional[float] = None
        if raw is not None:
            try:
                val = float(raw)
                ts_iface = val / 1000.0 if val > 10_000_000_000 else val
            except Exception:
                ts_iface = None
        ts_local = self._last_seen_overrides.get(str(node_id))
        if ts_iface and ts_local:
            return max(ts_iface, ts_local)
        return ts_iface or ts_local

    def _extract_latlon(self, node: dict) -> tuple[float|None, float|None]:
        pos = (node or {}).get("position") or {}
        lat = pos.get("latitude"); lon = pos.get("longitude")
        if lat is None:
            li = pos.get("latitudeI") or pos.get("latitude_i")
            if li is not None:
                try: lat = float(li) * 1e-7
                except Exception: lat = None
        if lon is None:
            li = pos.get("longitudeI") or pos.get("longitude_i")
            if li is not None:
                try: lon = float(li) * 1e-7
                except Exception: lon = None
        try:
            lat = float(lat) if lat is not None else None
            lon = float(lon) if lon is not None else None
        except Exception:
            lat = lon = None
        return lat, lon

    def _get_local_latlon(self) -> tuple[float|None, float|None]:
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
        try:
            ln = getattr(self.iface, "localNode", None)
            if ln is not None and hasattr(ln, "nodeNum"):
                nbn = getattr(self.iface, "nodesByNum", None)
                if nbn:
                    n = nbn.get(getattr(ln, "nodeNum", None)) or {}
                    lat, lon = self._extract_latlon(n)
                    if lat is not None and lon is not None:
                        return lat, lon
        except Exception:
            pass
        try:
            mi = getattr(self.iface, "myInfo", None)
            if mi and hasattr(mi, "my_node"):
                lat = getattr(getattr(mi, "my_node").position, "latitude_i", 0) * 1e-7
                lon = getattr(getattr(mi, "my_node").position, "longitude_i", 0) * 1e-7
                if lat and lon:
                    return float(lat), float(lon)
        except Exception:
            pass
        return (None, None)

    def _haversine_km(self, lat1, lon1, lat2, lon2) -> float:
        import math
        R = 6371.0088
        phi1 = math.radians(lat1); phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1); dlmb = math.radians(lon2 - lon1)
        a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlmb/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
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
            longname  = user.get("longName") or ""
            macaddr   = user.get("macaddr") or user.get("macAddr") or ""
            hwmodel   = user.get("hwModel") or ""
            role      = user.get("role") or ""
            publickey = user.get("publicKey") or ""
            unmsg     = user.get("isUnmessagable")
            if unmsg is None:
                unmsg = user.get("isUnmessageable")
            isunmessagable = bool(unmsg) if unmsg is not None else False

            lastheard_epoch = self._get_lastheard_epoch(node_id, node)
            since_str = _fmt_ago(lastheard_epoch)

            hops = node.get("hopsAway") if isinstance(node, dict) else None

            # distance
            lat, lon = self._extract_latlon(node)
            if base_lat is not None and base_lon is not None and lat is not None and lon is not None:
                try:
                    dist = self._haversine_km(base_lat, base_lon, lat, lon)
                except Exception:
                    dist = None
            else:
                dist = None
            dist_str = f"{dist:.1f}" if isinstance(dist, (int, float)) else "—"

            values = (shortname, longname, since_str, str(hops) if hops is not None else "—", dist_str,
                      f"{lastheard_epoch or 0:.0f}", macaddr, hwmodel, role, publickey, str(isunmessagable), node_id)

            if not q or any(q in str(v).lower() for v in values):
                try:
                    self.tv_nodes.insert("", "end", iid=node_id, values=values)
                except Exception:
                    self.tv_nodes.insert("", "end", values=values)

        # re-apply last sort (if any)
        if self._last_sort_col:
            self.sort_by_column(self._last_sort_col, self._last_sort_reverse)

        # update node count in frame title
        try:
            count = len(self.tv_nodes.get_children())
            self.nodes_frame.config(text=f"Nodes ({count})")
        except Exception:
            pass

    # ---------- sorting ----------
    def sort_by_column(self, col: str, reverse: bool = False):
        # remember current choice
        self._last_sort_col = col
        self._last_sort_reverse = reverse

        col_to_sort = "lastheard" if col == "since" else col
        numeric_cols = {"lastheard", "distkm", "hops"}
        data = []
        for iid in self.tv_nodes.get_children(""):
            if col_to_sort in numeric_cols:
                try:
                    raw = self.tv_nodes.set(iid, col_to_sort) or "0"
                    key = float(raw if raw != "—" else 0.0)
                except Exception:
                    key = 0.0
            else:
                key = (self.tv_nodes.set(iid, col_to_sort) or "").casefold()
            data.append((key, iid))
        data.sort(key=lambda t: t[0], reverse=reverse)
        for idx, (_, iid) in enumerate(data):
            self.tv_nodes.move(iid, "", idx)
        # next click should toggle
        self.tv_nodes.heading(col, command=lambda: self.sort_by_column(col, not reverse))

    # ---------- theme ----------
    def apply_theme(self, mode: str = "light"):
        is_dark = (mode == "dark")
        bg  = "#1e1e1e" if is_dark else "#f5f5f5"
        fg  = "#e6e6e6" if is_dark else "#222222"
        acc = "#2d2d2d" if is_dark else "#ffffff"
        sel = "#3A3F5A" if is_dark else "#cce0ff"
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
        style.configure("Treeview", background=acc, fieldbackground=acc, foreground=fg, borderwidth=0)
        style.map("Treeview", background=[("selected", sel)], foreground=[("selected", fg)])
        try:
            self.txt_messages.configure(bg=acc, fg=fg, insertbackground=fg, selectbackground=sel, selectforeground=fg)
        except Exception:
            pass
        try:
            self.root.option_add("*Menu*background", bg)
            self.root.option_add("*Menu*foreground", fg)
            self.root.option_add("*Menu*activeBackground", sel)
            self.root.option_add("*Menu*activeForeground", fg)
        except Exception:
            pass

    # ---------- utils ----------
    def _append(self, text: str):
        self.txt_messages.insert("end", text + "\n")
        self.txt_messages.see("end")

    def _get_selected_node_id(self) -> str | None:
        sel = self.tv_nodes.selection()
        if not sel:
            return None
        return sel[0]

    def _toggle_send_target(self):
        nid = self._get_selected_node_id()
        self.send_to_selected.set(bool(nid))
        if nid:
            self._append(f"[target] Will send to {self._node_label(nid)}")

    # ---------- context menu ----------
    def _cm_send_to_node(self):
        nid = self._get_selected_node_id()
        if not nid:
            return
        self.send_to_selected.set(True)
        self._append(f"[target] Will send to {self._node_label(nid)}")

    def _cm_ping_node(self):
        nid = self._get_selected_node_id()
        if not nid or not self.iface:
            return
        try:
            self.iface.sendText("ping", destinationId=nid, wantAck=False)
            self._append(f"[ping] to {self._node_label(nid)}")
        except Exception as e:
            self._append(f"[ping] failed: {e}")

    def _cm_copy_node_id(self):
        nid = self._get_selected_node_id()
        if not nid:
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(nid)
            self._append(f"[copy] {self._node_label(nid)}")
        except Exception:
            pass

    def _cm_show_node_details(self):
        nid = self._get_selected_node_id()
        if not nid or not self.iface or not getattr(self.iface, "nodes", None):
            return
        node = self.iface.nodes.get(nid, {})  # type: ignore[attr-defined]
        win = tk.Toplevel(self.root); win.title(f"Node details: {self._node_label(nid)}")
        frm = ttk.Frame(win, padding=8); frm.pack(expand=True, fill="both")
        txt = tk.Text(frm, wrap="word"); txt.pack(expand=True, fill="both")
        txt.insert("1.0", json.dumps(node, indent=2, default=str)); txt.configure(state="disabled")

    # ---------- info ----------
    def show_myinfo(self):
        if not self.iface:
            messagebox.showinfo("Info", "Not connected.")
            return
        def _call(name):
            try:
                f = getattr(self.iface, name, None)
                return f() if callable(f) else {}
            except Exception:
                return {}
        payload = {
            "user": _call("getMyUser"),
            "nodeinfo": _call("getMyNodeInfo"),
            "myInfo": getattr(self.iface, "myInfo", {}) or {},
        }
        # Hop limit (LoRa)
        hop_limit_val = None
        try:
            if self.iface:
                ln = getattr(self.iface, "localNode", None)
                if ln is not None and getattr(ln, "localConfig", None):
                    lc = ln.localConfig
                    if hasattr(lc, "lora") and hasattr(lc.lora, "hop_limit"):
                        hop_limit_val = int(lc.lora.hop_limit)
                if hop_limit_val is None:
                    getnode = getattr(self.iface, "getNode", None)
                    if callable(getnode):
                        n = getnode("^local")
                        if n is not None and getattr(n, "localConfig", None):
                            lc = n.localConfig
                            if hasattr(lc, "lora") and hasattr(lc.lora, "hop_limit"):
                                hop_limit_val = int(lc.lora.hop_limit)
        except Exception:
            pass
        payload["lora_hop_limit"] = hop_limit_val

        win = tk.Toplevel(self.root); win.title("My Info")
        frm = ttk.Frame(win, padding=8); frm.pack(expand=True, fill="both")
        txt = tk.Text(frm, wrap="word", relief="flat", bd=0, highlightthickness=0)
        y = ttk.Scrollbar(frm, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=y.set, state="normal")
        txt.insert("1.0", json.dumps(payload, indent=2, default=str))
        txt.configure(state="disabled")
        txt.grid(row=0, column=0, sticky="nsew"); y.grid(row=0, column=1, sticky="ns")
        frm.rowconfigure(0, weight=1); frm.columnconfigure(0, weight=1)


def main():
    app = MeshtasticGUI()
    app.root.geometry("1400x720")
    app.root.protocol("WM_DELETE_WINDOW", lambda: (app.disconnect(), app.root.destroy()))
    app.root.mainloop()


if __name__ == "__main__":
    main()
