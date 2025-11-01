# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
Meshtastic Client (ASCII only) with theming for ALL windows
- main window dark/light
- "My Info" window themed
- "Details (friendly)" window themed
"""
from __future__ import annotations
import json, time, datetime, threading, pathlib, tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Any, Dict, Optional

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
    mins = int(delta // 60)
    hours = int(delta // 3600)
    days = int(delta // 86400)
    if delta < 60:
        return "%ds" % int(delta)
    if mins < 60:
        return "%dm" % mins
    if hours < 24:
        return "%dh" % hours
    if days < 7:
        return "%dd" % days
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

        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        self.host_var = tk.StringVar(value=HOST_DEFAULT)
        self.port_var = tk.IntVar(value=PORT_DEFAULT)

        menubar = tk.Menu(self.root)
        m_conn = tk.Menu(menubar, tearoff=False)
        m_conn.add_command(label="Connect (TCP)", command=self.connect_tcp)
        m_conn.add_command(label="Connect via USB/Serial...", command=self.connect_serial_dialog)
        m_conn.add_command(label="Connect via Bluetooth...", command=self.connect_ble_dialog)
        m_conn.add_command(label="Disconnect", command=self.disconnect)
        m_conn.add_separator()
        m_conn.add_command(label="Set IP/Port...", command=self.set_ip_port)
        menubar.add_cascade(label="Connection", menu=m_conn)

        m_tools = tk.Menu(menubar, tearoff=False)
        m_tools.add_command(label="My Info", command=self.show_myinfo)

        m_tools.add_separator()
        m_tools.add_command(label="Clear messages", command=lambda: self.txt_messages.delete("1.0", "end"))
        menubar.add_cascade(label="Tools", menu=m_tools)

        m_view = tk.Menu(menubar, tearoff=False)
        m_view.add_command(label="Light theme", command=lambda: self.apply_theme("light"))
        m_view.add_command(label="Dark theme", command=lambda: self.apply_theme("dark"))
        menubar.add_cascade(label="View", menu=m_view)
        self.root.config(menu=menubar)

        self.rootframe = ttk.Frame(self.root)
        self.rootframe.grid(row=0, column=0, sticky="nsew")
        self.rootframe.rowconfigure(0, weight=1)
        self.rootframe.columnconfigure(0, weight=1)

        self.paned = ttk.Panedwindow(self.rootframe, orient="horizontal")
        self.paned.grid(row=0, column=0, sticky="nsew")

        # messages
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
        self.send_to_selected = tk.BooleanVar(value=False)
        self.chk_to_selected = ttk.Checkbutton(self.send_frame, text="To selected", variable=self.send_to_selected)
        self.chk_to_selected.grid(row=0, column=2, padx=4, sticky="w")

        # nodes
        self.nodes_frame = ttk.Labelframe(self.paned, text="Nodes (0)")
        self.nodes_frame.rowconfigure(1, weight=1)
        self.nodes_frame.columnconfigure(0, weight=1)

        self.ent_search = ttk.Entry(self.nodes_frame)
        self.ent_search.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        self.ent_search.bind("<KeyRelease>", lambda e: self.refresh_nodes())

        self.cols_all = (
            "shortname", "longname", "since", "hops", "distkm",
            "lastheard", "hwmodel", "role", "macaddr", "publickey", "isunmessagable", "id"
        )
        self.cols_visible = ("shortname", "longname", "since", "hops", "distkm", "hwmodel", "role")
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
            "hwmodel": 90,
            "role": 110,
        }
        for key, w in widths.items():
            try:
                self.tv_nodes.column(key, width=w, anchor="w", stretch=(key not in ("since", "hops", "distkm")))
            except Exception:
                pass

        for col in ("lastheard", "macaddr", "publickey", "isunmessagable", "id"):
            try:
                self.tv_nodes.column(col, width=0, minwidth=0, stretch=False)
            except Exception:
                pass

        yscroll_nodes = ttk.Scrollbar(self.nodes_frame, orient="vertical", command=self.tv_nodes.yview)
        self.tv_nodes.configure(yscrollcommand=yscroll_nodes.set)
        yscroll_nodes.grid(row=1, column=1, sticky="ns")

        self.node_menu = tk.Menu(self.nodes_frame, tearoff=False)
        self.node_menu.add_command(label="Send to this node", command=self._cm_send_to_node)
        self.node_menu.add_command(label="Show raw node (one)", command=self.show_raw_node)
        self.node_menu.add_separator()
        self.node_menu.add_command(label="Details (friendly)", command=self._cm_show_node_details)

        self.tv_nodes.bind("<Button-3>", self._popup_node_menu)
        self.tv_nodes.bind("<Double-1>", lambda e: self._toggle_send_target())

        self.paned.add(self.msg_frame, weight=3)
        self.paned.add(self.nodes_frame, weight=4)
        self.root.after(100, lambda: self._safe_set_sash(0.48))

        self.iface: Optional[object] = None
        self.connected_evt = threading.Event()
        self._last_seen_overrides: Dict[str, float] = {}
        self._last_sort_col: Optional[str] = "since"
        self._last_sort_reverse: bool = True

        if pub is not None:
            try:
                pub.subscribe(self.on_connection_established, "meshtastic.connection.established")
                pub.subscribe(self.on_connection_lost, "meshtastic.connection.lost")
                pub.subscribe(self.on_receive, "meshtastic.receive")
                pub.subscribe(self.on_node_updated, "meshtastic.node.updated")
            except Exception as e:
                print("pubsub subscribe failed:", e)

        self.apply_theme("light")
        self._append("Ready. Connection -> Connect (TCP/USB/BLE)")
        self._update_title_with_host()

    # helpers ---------------------------------------------------------
    def _update_title_with_host(self):
        self.root.title("Meshtastic Client - %s:%s" % (self.host_var.get(), self.port_var.get()))

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
        label = ("%s %s" % (shortname, longname)).strip()
        if label:
            return label
        return node_id

    # pubsub callbacks ------------------------------------------------
    def on_connection_established(self, interface=None, **kwargs):
        self.connected_evt.set()
        self._append("[+] Connected")
        self.refresh_nodes()

    def on_connection_lost(self, interface=None, **kwargs):
        self.connected_evt.clear()
        self._append("[-] Connection lost")

    def on_node_updated(self, node=None, interface=None, **kwargs):
        self.root.after(0, self.refresh_nodes)

    def on_receive(self, packet=None, interface=None, **kwargs):
        self.root.after(0, lambda: self._handle_receive(packet or {}))

    # receive ---------------------------------------------------------
    def _handle_receive(self, packet: dict):
        """Extended handler: recognize more Meshtastic packet types."""
        decoded = packet.get("decoded", {}) if isinstance(packet, dict) else {}
        app_name = decoded.get("app", "")
        portnum = decoded.get("portnum") or app_name  # some firmwares only set one
        from_id = packet.get("fromId") or packet.get("from") or "UNKNOWN"

        # Try to look up friendly label for the node
        label = self._node_label(from_id) if hasattr(self, "_node_label") else from_id

        # Map: Meshtastic app/port → tag
        tag_map = {
            "TEXT_MESSAGE_APP": "MSG",
            "TEXT_MESSAGE_COMPRESSED_APP": "MSG",
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
        tag = tag_map.get(app_name or portnum, "INFO")

        # dispatch
        if app_name in ("TEXT_MESSAGE_APP", "TEXT_MESSAGE_COMPRESSED_APP"):
            # existing text renderer
            text = decoded.get("text") or decoded.get("payload", {}).get("text", "")
            if text:
                self._append(f"[MSG] {label}: {text}")
            else:
                self._append(f"[MSG] {label}")
        elif app_name == "POSITION_APP":
            pos = decoded.get("payload", {}) or decoded
            lat = pos.get("latitude")
            lon = pos.get("longitude")
            alt = pos.get("altitude")
            spd = pos.get("ground_speed")
            rssi = packet.get("rxRssi") or packet.get("rssi") or "-"
            # format exactly as requested
            self._append(f"[POS] {label}  gps={lat} ,{lon}  alt={alt} m  gs={spd}  rssi={rssi}")
        elif app_name == "TELEMETRY_APP":
            tel = decoded.get("payload", {}) or decoded
            batt = tel.get("battery_level") or tel.get("voltage")
            line = f"[TEL] {label}"
            if batt is not None and str(batt).strip() not in ("", "-", "None", "null"):
                line += f"  batt={batt}"
            self._append(line)
        elif app_name == "NODEINFO_APP":
            ni = decoded.get("payload", {}) or decoded
            sn = ni.get("shortName") or ni.get("short_name") or ""
            ln = ni.get("longName") or ni.get("long_name") or ""
            hw = ni.get("hwModel") or ni.get("hardware") or ""
            self._append(f"[INFO] {label} {sn} {ln} {hw}")
        else:
            # fallback: show raw app/port name
            self._append(f"[{tag}] Packet from {label} on {app_name or portnum}")

        # refresh nodes if list needs to update
        if hasattr(self, "refresh_nodes"):
            self.refresh_nodes()

        decoded = packet.get("decoded", {}) if isinstance(packet, dict) else {}
        portnum = decoded.get("portnum")

        sender = packet.get("fromId") or packet.get("from") or packet.get("fromIdShort")
        if sender:
            self._last_seen_overrides[str(sender)] = time.time()

        user = {}
        if self.iface and getattr(self.iface, "nodes", None) and sender:
            user = (self.iface.nodes.get(sender) or {}).get("user", {})  # type: ignore[attr-defined]
        shortname = user.get("shortName") or ""
        longname = user.get("longName") or ""
        label = (shortname or longname or sender or "Unknown").strip()

        text = ""
        p = decoded.get("payload", "")
        if isinstance(p, (bytes, bytearray)):
            try:
                text = p.decode("utf-8", errors="ignore")
            except Exception:
                text = repr(p)
        elif isinstance(p, str):
            text = p
        else:
            t = decoded.get("text")
            if isinstance(t, bytes):
                text = t.decode("utf-8", errors="ignore")
            elif isinstance(t, str):
                text = t

        rssi = packet.get("rxRssi")

        if portnum == "TEXT_MESSAGE_APP":
            self._append("[MSG] %s: %s (RSSI=%s)" % (label, text, rssi))
            if isinstance(text, str) and text.strip().lower() == "ping":
                self._send_pong(sender, label)

        elif portnum == "POSITION_APP":
            pos = decoded.get("position", {})
            # lat/lon can come as latitude_i / longitude_i (int *1e7) or latitude / longitude (float)
            lat = pos.get("latitude_i") or pos.get("latitudeI") or pos.get("latitude")
            lon = pos.get("longitude_i") or pos.get("longitudeI") or pos.get("longitude")
            lat_str = "-"
            lon_str = "-"
            try:
                if lat is not None:
                    lat_f = float(lat)
                    if abs(lat_f) > 90:  # int format
                        lat_f = lat_f * 1e-7
                    lat_str = "%.6f" % lat_f
            except Exception:
                pass
            try:
                if lon is not None:
                    lon_f = float(lon)
                    if abs(lon_f) > 180:  # int format
                        lon_f = lon_f * 1e-7
                    lon_str = "%.6f" % lon_f
            except Exception:
                pass
            alt = pos.get("altitude") or pos.get("altitudeM") or pos.get("altitude_i")
            gs = pos.get("groundSpeed") or pos.get("ground_speed")
            if gs is not None:
                try:
                    gs_val = float(gs)
                    if gs_val < 60:
                        gs_str = "%.1f km/h" % (gs_val * 3.6)
                    else:
                        gs_str = "%.1f" % gs_val
                except Exception:
                    gs_str = str(gs)
            else:
                gs_str = "-"
            alt_str = "%s m" % alt if alt is not None else "-"
            self._append("[POS] %s %s  gps=%s ,%s  alt=%s  gs=%s  rssi=%s" % (shortname, longname, lat_str, lon_str, alt_str, gs_str, rssi))

        elif portnum == "TELEMETRY_APP":
            tel = decoded.get("telemetry", {})
            dm = tel.get("deviceMetrics", {}) if isinstance(tel, dict) else {}
            em = tel.get("environmentMetrics", {}) if isinstance(tel, dict) else {}
            batt = dm.get("batteryLevel") or dm.get("battery_level") or dm.get("batteryPct")
            batt_str = "%s%%" % batt if batt is not None else "-"
            # only show batt – temp/air often come as '-'
            self._append("[TEL] %s %s  batt=%s" % (shortname, longname, batt_str))

        else:
            self._append("[INFO] Packet from %s on %s" % (label, portnum))

        self.refresh_nodes()

    def _send_pong(self, dest_id: Optional[str], label: str):
        if not self.iface or not dest_id:
            return
        try:
            self.iface.sendText("pong", destinationId=dest_id, wantAck=False)
            self._append("[auto] pong -> %s" % label)
        except Exception as e:
            self._append("[auto] pong failed: %s" % e)

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

    def connect_tcp(self):
        if self.iface:
            return
        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get())
        except Exception:
            messagebox.showerror("Port", "Invalid port")
            return
        self._append("Connecting TCP %s:%s ..." % (host, port))

        def run():
            try:
                if TCPInterface is None:
                    raise RuntimeError("meshtastic.tcp_interface not installed")
                self.iface = TCPInterface(hostname=host, portNumber=port)
                self.connected_evt.wait(timeout=5)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("TCP connect failed", str(e)))
        threading.Thread(target=run, daemon=True).start()

    def connect_serial_dialog(self):
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
        port = simpledialog.askstring("Serial", "Serial port (or leave '(auto)'):", initialvalue=presets[0])
        if port is None:
            return
        port = port.strip()
        if port.lower() == "(auto)" or port == "":
            port = None
        self._append("Connecting Serial %s ..." % (port or "(auto)"))

        def run():
            try:
                self.iface = SerialInterface(devPath=port) if port else SerialInterface()
                self.connected_evt.wait(timeout=5)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Serial connect failed", str(e)))
        threading.Thread(target=run, daemon=True).start()

    def connect_ble_dialog(self):
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
        options = ["%d. %s [%s]" % (i+1, getattr(d, "name", "") or "(unnamed)", getattr(d, "address", "?")) for i, d in enumerate(devices)]
        choice = simpledialog.askinteger("Select BLE device", "Enter number:\n" + "\n".join(options),
                                         minvalue=1, maxvalue=len(devices))
        if not choice:
            return
        addr = getattr(devices[choice - 1], "address", None)
        if not addr:
            messagebox.showerror("BLE", "Selected device has no address.")
            return
        self._append("Connecting BLE %s ..." % addr)

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
        self._append("[*] Disconnected")

    # send ------------------------------------------------------------
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
                    messagebox.showinfo("No selection", "Select a node first.")
                    return
                self.iface.sendText(msg, destinationId=nid, wantAck=False)
                self._append("[ME -> %s] %s" % (self._node_label(nid), msg))
            else:
                self.iface.sendText(msg, wantAck=False)
                self._append("[ME] %s" % msg)
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

    def _extract_latlon(self, node: dict) -> tuple[float | None, float | None]:
        pos = (node or {}).get("position") or {}
        lat = pos.get("latitude") or pos.get("latitudeI") or pos.get("latitude_i")
        lon = pos.get("longitude") or pos.get("longitudeI") or pos.get("longitude_i")
        try:
            if lat is not None:
                lat = float(lat) * (1e-7 if abs(lat) > 90 else 1.0)
            if lon is not None:
                lon = float(lon) * (1e-7 if abs(lon) > 180 else 1.0)
        except Exception:
            lat = lon = None
        return lat, lon

    def _get_local_latlon(self) -> tuple[float | None, float | None]:
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
        phi1 = math.radians(lat1); phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1); dlmb = math.radians(lon2 - lon1)
        a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlmb/2)**2
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
            role = user.get("role") or ""
            macaddr = user.get("macaddr") or ""
            publickey = user.get("publicKey") or ""
            unmsg = user.get("isUnmessagable") or user.get("isUnmessageable") or False

            lastheard_epoch = self._get_lastheard_epoch(node_id, node)
            since_str = _fmt_ago(lastheard_epoch)
            hops = node.get("hopsAway")
            lat, lon = self._extract_latlon(node)
            if base_lat is not None and base_lon is not None and lat is not None and lon is not None:
                try:
                    dist = self._haversine_km(base_lat, base_lon, lat, lon)
                except Exception:
                    dist = None
            else:
                dist = None
            dist_str = "%.1f" % dist if isinstance(dist, (int, float)) else "-"

            values = (
                shortname, longname, since_str,
                str(hops) if hops is not None else "-",
                dist_str,
                "%.0f" % (lastheard_epoch or 0),
                hwmodel,
                role,
                macaddr,
                publickey,
                str(bool(unmsg)),
                node_id,
            )

            if not q or any(q in str(v).lower() for v in values):
                try:
                    self.tv_nodes.insert("", "end", iid=node_id, values=values)
                except Exception:
                    self.tv_nodes.insert("", "end", values=values)

        if self._last_sort_col:
            self.sort_by_column(self._last_sort_col, self._last_sort_reverse)

        self.nodes_frame.config(text="Nodes (%d)" % len(self.tv_nodes.get_children()))

    def sort_by_column(self, col: str, reverse: bool = False):
        self._last_sort_col = col
        self._last_sort_reverse = reverse
        col_to_sort = "lastheard" if col == "since" else col
        numeric = {"lastheard", "distkm", "hops"}
        rows = []
        for iid in self.tv_nodes.get_children(""):
            val = self.tv_nodes.set(iid, col_to_sort)
            if col_to_sort in numeric:
                try:
                    val = float(val if val != "-" else 0.0)
                except Exception:
                    val = 0.0
            else:
                val = val.casefold()
            rows.append((val, iid))
        rows.sort(key=lambda t: t[0], reverse=reverse)
        for index, (_, iid) in enumerate(rows):
            self.tv_nodes.move(iid, "", index)
        self.tv_nodes.heading(col, command=lambda: self.sort_by_column(col, not reverse))

    # THEME -----------------------------------------------------------
    def apply_theme(self, mode: str = "light"):
        self.current_theme = mode
        is_dark = (mode == "dark")
        bg = "#1e1e1e" if is_dark else "#f5f5f5"
        fg = "#ffffff" if is_dark else "#000000"
        acc = "#2d2d2d" if is_dark else "#ffffff"
        sel = "#555555" if is_dark else "#cce0ff"
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

    def _style_toplevel(self, win: tk.Toplevel):
        # apply current theme colors to new windows
        is_dark = (self.current_theme == "dark")
        bg = "#1e1e1e" if is_dark else "#f5f5f5"
        fg = "#ffffff" if is_dark else "#000000"
        win.configure(bg=bg)
        # text widgets etc. can be styled by caller

    # UTILS / CONTEXT ------------------------------------------------
    def _append(self, text: str):
        self.txt_messages.insert("end", text + "\n")
        self.txt_messages.see("end")

    def _get_selected_node_id(self) -> Optional[str]:
        sel = self.tv_nodes.selection()
        if not sel:
            return None
        return sel[0]

    def _toggle_send_target(self):
        nid = self._get_selected_node_id()
        self.send_to_selected.set(bool(nid))
        if nid:
            self._append("[target] will send to %s" % self._node_label(nid))

    def _popup_node_menu(self, event):
        iid = self.tv_nodes.identify_row(event.y)
        if iid:
            self.tv_nodes.selection_set(iid)
        self.node_menu.tk_popup(event.x_root, event.y_root)
        self.node_menu.grab_release()

    def _cm_send_to_node(self):
        nid = self._get_selected_node_id()
        if not nid:
            return
        self.send_to_selected.set(True)
        self._append("[target] will send to %s" % self._node_label(nid))

    def _cm_show_node_details(self):
        self.show_raw_node(friendly=True)

    def show_raw_node(self, friendly: bool = False):
        nid = self._get_selected_node_id()
        if not nid or not self.iface or not getattr(self.iface, "nodes", None):
            messagebox.showinfo("Node", "No node selected.")
            return
        node = self.iface.nodes.get(nid, {})  # type: ignore[attr-defined]
        win = tk.Toplevel(self.root)
        win.title("Node: %s" % self._node_label(nid))
        self._style_toplevel(win)
        frm = ttk.Frame(win, padding=8)
        frm.pack(expand=True, fill="both")
        txt = tk.Text(frm, wrap="word")
        txt.pack(expand=True, fill="both")
        is_dark = (self.current_theme == "dark")
        txt.configure(bg=("#2d2d2d" if is_dark else "#ffffff"),
                      fg=("#ffffff" if is_dark else "#000000"),
                      insertbackground=("#ffffff" if is_dark else "#000000"))
        if friendly:
            user = (node or {}).get("user") or {}
            pos = (node or {}).get("position") or {}
            lines = [
                "Name: %s %s" % (user.get("shortName", ""), user.get("longName", "")),
                "Role: %s" % user.get("role", ""),
                "HW:   %s" % user.get("hwModel", ""),
                "MAC:  %s" % user.get("macaddr", ""),
                "",
                "Last heard: %s" % _fmt_ago(self._get_lastheard_epoch(nid, node)),
                "",
                "Position:",
                json.dumps(pos, indent=2, default=str),
            ]
            txt.insert("1.0", "\n".join(lines))
        else:
            txt.insert("1.0", json.dumps(node, indent=2, default=str))
        txt.configure(state="disabled")

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
        win = tk.Toplevel(self.root)
        win.title("My Info")
        self._style_toplevel(win)
        frm = ttk.Frame(win, padding=8)
        frm.pack(expand=True, fill="both")
        txt = tk.Text(frm, wrap="word")
        y = ttk.Scrollbar(frm, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=y.set)
        txt.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        frm.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)
        is_dark = (self.current_theme == "dark")
        txt.configure(bg=("#2d2d2d" if is_dark else "#ffffff"),
                      fg=("#ffffff" if is_dark else "#000000"),
                      insertbackground=("#ffffff" if is_dark else "#000000"))
        txt.insert("1.0", json.dumps(payload, indent=2, default=str))
        txt.configure(state="disabled")


def main():
    app = MeshtasticGUI()
    app.root.geometry("1500x820")
    app.root.protocol("WM_DELETE_WINDOW", lambda: (app.disconnect(), app.root.destroy()))
    app.root.mainloop()


if __name__ == "__main__":
    main()
