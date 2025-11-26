#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Meshtastic Client - PySide6/Qt full GUI

Qt port of the original Tkinter-based Meshtastic client.

Implemented features (port of Tk version):
- TCP / Serial / BLE connect & disconnect
- Set IP/Port dialog
- Messages view with auto "pong" on 'ping'
- Channel selector:
    * Public (broadcast, ch0)
    * To selected node
    * Extra radio channels (Ch 1..N) with names from the device
- Node list with:
    * Search box
    * Distance, speed, altitude, hops, "since"
    * Right-click menu: Chat with node, Node info, Map, Traceroute, Delete node
    * Double-click: sets "To selected node" as send target
- Per‑node chat windows (direct chat)
- Traceroute (via python-meshtastic if available, else meshtastic CLI)
- Tools menu:
    * Clear messages
    * Radio config (view, read‑only)
- Links menu: client / org / flasher / web / docker / FB DK / FB Nordjylland
- Light/Dark themes for the main UI

Requirements (on target system):
    pip install meshtastic PySide6 pubsub google-api-python-client
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import datetime
import webbrowser
from typing import Any, Dict, Optional, Tuple, List

from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QPoint
from PySide6.QtGui import QIcon, QAction
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QTextEdit,
    QLineEdit,
    QPushButton,
    QLabel,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QMenu,
    QMessageBox,
    QInputDialog,
    QStatusBar,
    QHeaderView,
    QDialog,
    QPlainTextEdit,
    QListWidget,
)

# pubsub + meshtastic imports (same as Tk version)
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
    from meshtastic.protobuf import mesh_pb2, portnums_pb2
    import google.protobuf.json_format as _json_format
except Exception:
    mesh_pb2 = None
    portnums_pb2 = None
    _json_format = None

HOST_DEFAULT = "192.168.0.156"
PORT_DEFAULT = 4403
PROJECT_PATH = Path(__file__).resolve().parent
ICON_PATH = PROJECT_PATH / "meshtastic.png"  # PNG icon works better with Qt


def _prefer_chrome(url: str) -> None:
    """Try to open URL in a browser, preferring Chrome where possible."""
    try:
        webbrowser.open(url)
        return
    except Exception:
        pass

    candidates = [
        "xdg-open",
        "gio open",
        "sensible-browser",
        "google-chrome-stable",
        "chromium",
        r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        r"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    ]
    for cmd in candidates:
        try:
            if os.path.isabs(cmd) and os.path.exists(cmd):
                subprocess.Popen([cmd, url])
                return
            else:
                subprocess.Popen(cmd.split() + [url])
                return
        except Exception:
            continue


def _fmt_ago(epoch_seconds: Optional[float]) -> str:
    """Format 'time since' value similar to Tk app."""
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


class MeshtasticMainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Meshtastic Client (v1)")

        if ICON_PATH.exists():
            try:
                self.setWindowIcon(QIcon(str(ICON_PATH)))
            except Exception:
                pass

        # core state
        self.host: str = HOST_DEFAULT
        self.port: int = PORT_DEFAULT
        self.iface: Optional[object] = None
        self.connected_evt = threading.Event()
        self.current_theme: str = "dark"
        self._last_seen_overrides: Dict[str, float] = {}

        # channel map: label -> {mode: ..., channelIndex: int}
        self._channel_map: Dict[str, Dict[str, Any]] = {}

        # node sorting state
        self._last_sort_col_index: int = 2  # "since"
        self._last_sort_order_desc: bool = True

        # per-node chat windows
        self._per_node_chats: Dict[str, "NodeChatDialog"] = {}

        self._build_ui()
        self._connect_signals()

        # subscribe to Meshtastic pubsub topics
        if pub is not None:
            try:
                pub.subscribe(self.on_connection_established, "meshtastic.connection.established")
                pub.subscribe(self.on_connection_lost, "meshtastic.connection.lost")
                pub.subscribe(self.on_receive, "meshtastic.receive")
                pub.subscribe(self.on_node_updated, "meshtastic.node.updated")
            except Exception as e:
                print("pubsub subscribe failed:", e)

        # periodic refresh of node table (backup to pub events)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(2000)
        self.refresh_timer.timeout.connect(self.refresh_nodes)
        self.refresh_timer.start()

        self.apply_theme("dark")
        self._append("Ready. Connection -> Connect (TCP/USB/BLE)")
        self._update_title_with_host()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        splitter = QSplitter(Qt.Horizontal, self)

        # --- left: messages -------------------------------------------
        left_widget = QWidget(self)
        left_layout = QVBoxLayout(left_widget)
        lbl_msgs = QLabel("Messages", left_widget)
        left_layout.addWidget(lbl_msgs)

        self.txt_messages = QTextEdit(left_widget)
        self.txt_messages.setReadOnly(True)
        left_layout.addWidget(self.txt_messages)

        send_row = QHBoxLayout()
        self.ent_message = QLineEdit(left_widget)
        self.ent_message.setPlaceholderText("Type a message and press Enter…")
        send_row.addWidget(self.ent_message, 1)

        self.btn_send = QPushButton("Send", left_widget)
        send_row.addWidget(self.btn_send)

        # channel selector
        self.cbo_channel = QComboBox(left_widget)
        send_row.addWidget(self.cbo_channel)
        left_layout.addLayout(send_row)

        splitter.addWidget(left_widget)

        # --- right: nodes ---------------------------------------------
        right_widget = QWidget(self)
        right_layout = QVBoxLayout(right_widget)

        header_row = QHBoxLayout()
        self.lbl_nodes_header = QLabel("Nodes (0)", right_widget)
        header_row.addWidget(self.lbl_nodes_header)
        header_row.addStretch(1)
        right_layout.addLayout(header_row)

        self.ent_search = QLineEdit(right_widget)
        self.ent_search.setPlaceholderText("Search in nodes…")
        right_layout.addWidget(self.ent_search)

        # node table
        self.cols_all: List[str] = [
            "shortname",
            "longname",
            "since",
            "hops",
            "distkm",
            "speed",
            "alt",
            "lastheard",
            "hwmodel",
            "role",
            "macaddr",
            "publickey",
            "isunmessagable",
            "id",
        ]
        headings = {
            "shortname": "Short",
            "longname": "Long",
            "since": "Since",
            "hops": "Hops",
            "distkm": "Dist (km)",
            "speed": "Speed",
            "alt": "Alt (m)",
            "hwmodel": "HW",
            "role": "Role",
            "lastheard": "",
            "macaddr": "MAC",
            "publickey": "Public key",
            "isunmessagable": "Unmsg?",
            "id": "ID",
        }
        self.nodes_table = QTableWidget(0, len(self.cols_all), right_widget)
        for idx, name in enumerate(self.cols_all):
            self.nodes_table.setHorizontalHeaderItem(idx, QTableWidgetItem(headings.get(name, name)))

        # set widths like Tk version for visible columns
        widths = {
            "shortname": 90,
            "longname": 200,
            "since": 90,
            "hops": 50,
            "distkm": 70,
            "speed": 70,
            "alt": 70,
            "hwmodel": 90,
            "role": 110,
        }
        for idx, name in enumerate(self.cols_all):
            if name in widths:
                self.nodes_table.setColumnWidth(idx, widths[name])

        # hide technical columns
        for name in ("lastheard", "macaddr", "publickey", "isunmessagable", "id"):
            idx = self.cols_all.index(name)
            self.nodes_table.setColumnHidden(idx, True)

        self.nodes_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.nodes_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.nodes_table.horizontalHeader().setStretchLastSection(False)
        self.nodes_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.nodes_table.setContextMenuPolicy(Qt.CustomContextMenu)

        right_layout.addWidget(self.nodes_table)
        splitter.addWidget(right_widget)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 4)
        main_layout.addWidget(splitter)

        # --- Menubar --------------------------------------------------
        menubar = self.menuBar()

        m_conn = menubar.addMenu("Connection")
        self.act_connect_tcp = QAction("Connect (TCP)", self)
        self.act_connect_serial = QAction("Connect via USB/Serial…", self)
        self.act_connect_ble = QAction("Connect via Bluetooth…", self)
        self.act_disconnect = QAction("Disconnect", self)
        self.act_set_ipport = QAction("Set IP/Port…", self)
        m_conn.addAction(self.act_connect_tcp)
        m_conn.addAction(self.act_connect_serial)
        m_conn.addAction(self.act_connect_ble)
        m_conn.addAction(self.act_disconnect)
        m_conn.addSeparator()
        m_conn.addAction(self.act_set_ipport)

        m_tools = menubar.addMenu("Tools")
        self.act_clear_messages = QAction("Clear messages", self)
        self.act_radio_config = QAction("Radio config (view)", self)
        self.act_neighbors = QAction("Neighbor table", self)
        self.act_channel_editor = QAction("Channel editor", self)
        m_tools.addAction(self.act_clear_messages)
        m_tools.addAction(self.act_radio_config)
        m_tools.addAction(self.act_neighbors)
        m_tools.addAction(self.act_channel_editor)

        m_view = menubar.addMenu("View")
        self.act_light_theme = QAction("Light theme", self)
        self.act_dark_theme = QAction("Dark theme", self)
        m_view.addAction(self.act_light_theme)
        m_view.addAction(self.act_dark_theme)

        m_links = menubar.addMenu("Links")
        self.act_link_client = QAction("Meshtastic client (GitHub)", self)
        self.act_link_org = QAction("Meshtastic org", self)
        self.act_link_flasher = QAction("Meshtastic flasher (Chrome)", self)
        self.act_link_web = QAction("Meshtastic Web Client", self)
        self.act_link_docker = QAction("Meshtastic docker client", self)
        self.act_link_fb_dk = QAction("Meshtastic Facebook Danmark", self)
        self.act_link_fb_nj = QAction("Meshtastic Facebook Nordjylland", self)
        m_links.addAction(self.act_link_client)
        m_links.addAction(self.act_link_org)
        m_links.addAction(self.act_link_flasher)
        m_links.addAction(self.act_link_web)
        m_links.addAction(self.act_link_docker)
        m_links.addSeparator()
        m_links.addAction(self.act_link_fb_dk)
        m_links.addAction(self.act_link_fb_nj)

        m_help = menubar.addMenu("Help")
        self.act_about = QAction("About", self)
        m_help.addAction(self.act_about)

        # --- Statusbar ------------------------------------------------
        status = QStatusBar(self)
        self.setStatusBar(status)
        self.lbl_status_nodes = QLabel("Nodes: 0", self)
        status.addPermanentWidget(self.lbl_status_nodes)

        # Node context menu
        self.node_menu = QMenu(self)
        self.act_node_chat = QAction("Chat with node", self)
        self.act_node_info = QAction("Node info", self)
        self.act_node_map = QAction("Map", self)
        self.act_node_traceroute = QAction("Traceroute", self)
        self.act_node_delete = QAction("Delete node", self)
        self.node_menu.addAction(self.act_node_chat)
        self.node_menu.addAction(self.act_node_info)
        self.node_menu.addAction(self.act_node_map)
        self.node_menu.addAction(self.act_node_traceroute)
        self.node_menu.addSeparator()
        self.node_menu.addAction(self.act_node_delete)

        # initialize channel selector
        self._reset_channel_choices()

    # ------------------------------------------------------------------
    # Signal wiring
    # ------------------------------------------------------------------
    def _connect_signals(self) -> None:
        self.btn_send.clicked.connect(self.send_message)
        self.ent_message.returnPressed.connect(self.send_message)
        self.ent_search.textChanged.connect(self.refresh_nodes)

        self.nodes_table.customContextMenuRequested.connect(self._popup_node_menu)
        self.nodes_table.cellDoubleClicked.connect(self._on_node_double_clicked)
        self.nodes_table.horizontalHeader().sectionClicked.connect(self._on_header_clicked)

        self.act_connect_tcp.triggered.connect(self.connect_tcp)
        self.act_connect_serial.triggered.connect(self.connect_serial_dialog)
        self.act_connect_ble.triggered.connect(self.connect_ble_dialog)
        self.act_disconnect.triggered.connect(self.disconnect)
        self.act_set_ipport.triggered.connect(self.set_ip_port)

        self.act_clear_messages.triggered.connect(self.txt_messages.clear)
        self.act_radio_config.triggered.connect(self.show_radio_config_window)
        self.act_neighbors.triggered.connect(self.show_neighbors_window)
        self.act_channel_editor.triggered.connect(self.show_channel_editor_window)

        self.act_light_theme.triggered.connect(lambda: self.apply_theme("light"))
        self.act_dark_theme.triggered.connect(lambda: self.apply_theme("dark"))

        self.act_link_client.triggered.connect(
            lambda: self._open_browser_url("https://github.com/dk98174003/Meshtastic-Client")
        )
        self.act_link_org.triggered.connect(lambda: self._open_browser_url("https://meshtastic.org/"))
        self.act_link_flasher.triggered.connect(
            lambda: self._open_browser_url("https://flasher.meshtastic.org/")
        )
        self.act_link_web.triggered.connect(
            lambda: self._open_browser_url("https://client.meshtastic.org")
        )
        self.act_link_docker.triggered.connect(
            lambda: self._open_browser_url(
                "https://meshtastic.org/docs/software/linux/usage/#usage-with-docker"
            )
        )
        self.act_link_fb_dk.triggered.connect(
            lambda: self._open_browser_url(
                "https://www.facebook.com/groups/1553839535376876/"
            )
        )
        self.act_link_fb_nj.triggered.connect(
            lambda: self._open_browser_url(
                "https://www.facebook.com/groups/1265866668302201/"
            )
        )

        self.act_about.triggered.connect(self._show_about)

        self.act_node_chat.triggered.connect(self._cm_open_chat)
        self.act_node_info.triggered.connect(self._cm_show_node_details)
        self.act_node_map.triggered.connect(self._cm_open_map)
        self.act_node_traceroute.triggered.connect(self._cm_traceroute)
        self.act_node_delete.triggered.connect(self._cm_delete_node)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _open_browser_url(self, url: str) -> None:
        _prefer_chrome(url)

    def _update_title_with_host(self) -> None:
        self.setWindowTitle("Meshtastic Client (v1) - %s:%s" % (self.host, self.port))

    def _append(self, text: str) -> None:
        self.txt_messages.append(text)

    # ------------------------------------------------------------------
    # Meshtastic-related helpers
    # ------------------------------------------------------------------
    def _node_label(self, node_id: str) -> str:
        iface = self.iface
        if not iface or not getattr(iface, "nodes", None):
            return node_id
        node = getattr(iface, "nodes", {}).get(node_id, {})
        user = (node or {}).get("user") or {}
        shortname = user.get("shortName") or ""
        longname = user.get("longName") or ""
        label = ("%s %s" % (shortname, longname)).strip()
        if label:
            return label
        return node_id

    def _get_lastheard_epoch(self, node_id: str, node: Dict[str, Any]) -> Optional[float]:
        raw = (node or {}).get("lastHeard")
        ts_iface: Optional[float] = None
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
                lat = float(lat)
                if abs(lat) > 90:
                    lat *= 1e-7
            if lon is not None:
                lon = float(lon)
                if abs(lon) > 180:
                    lon *= 1e-7
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
            if speed is not None:
                speed = float(speed)
            if alt is not None:
                alt = float(alt)
        except Exception:
            speed, alt = None, None
        return speed, alt

    def _get_local_latlon(self) -> Tuple[Optional[float], Optional[float]]:
        iface = self.iface
        if not iface:
            return (None, None)
        try:
            mi = getattr(iface, "myInfo", None)
            nbn = getattr(iface, "nodesByNum", None)
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

    # ------------------------------------------------------------------
    # Pubsub callbacks (run in background threads → use QTimer.singleShot)
    # ------------------------------------------------------------------
    def on_connection_established(self, interface=None, **kwargs) -> None:
        self.connected_evt.set()
        QTimer.singleShot(0, self._on_connection_established_ui)

    def _on_connection_established_ui(self) -> None:
        self._append("[+] Connected")
        self.refresh_nodes()
        try:
            self._update_channels_from_iface()
        except Exception:
            pass

    def on_connection_lost(self, interface=None, **kwargs) -> None:
        self.connected_evt.clear()
        QTimer.singleShot(0, lambda: self._append("[-] Connection lost"))

    def on_node_updated(self, node=None, interface=None, **kwargs) -> None:
        QTimer.singleShot(0, self.refresh_nodes)

    def on_receive(self, packet=None, interface=None, **kwargs) -> None:
        pkt = packet or {}
        QTimer.singleShot(0, lambda p=pkt: self._handle_receive(p))

    # ------------------------------------------------------------------
    # Receive handling
    # ------------------------------------------------------------------
    def _handle_receive(self, packet: dict) -> None:
        decoded = packet.get("decoded", {}) if isinstance(packet, dict) else {}
        app_name = decoded.get("app", "")
        portnum = decoded.get("portnum") or app_name
        from_id = packet.get("fromId") or packet.get("from") or "UNKNOWN"
        label = self._node_label(from_id)

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

        if app_name in ("TEXT_MESSAGE_APP", "TEXT_MESSAGE_COMPRESSED_APP"):
            text = decoded.get("text") or decoded.get("payload", {}).get("text", "")
            if text:
                self._append(f"[{tag}] {label}: {text}")
                # also append to per-node chat if open
                self._append_to_node_chat(str(from_id), text)
            else:
                self._append(f"[{tag}] {label}")

        decoded2 = packet.get("decoded", {}) if isinstance(packet, dict) else {}
        portnum2 = decoded2.get("portnum")
        sender = packet.get("fromId") or packet.get("from") or packet.get("fromIdShort")
        if sender:
            self._last_seen_overrides[str(sender)] = time.time()

        user = {}
        iface = self.iface
        if iface and getattr(iface, "nodes", None) and sender:
            user = getattr(iface, "nodes", {}).get(sender, {}).get("user", {})
        shortname = user.get("shortName") or ""
        longname = user.get("longName") or ""
        label2 = str(shortname or longname or sender or "Unknown").strip()

        text2 = ""
        p = decoded2.get("payload", "")
        if isinstance(p, (bytes, bytearray)):
            try:
                text2 = p.decode("utf-8", errors="ignore")
            except Exception:
                text2 = repr(p)
        elif isinstance(p, str):
            text2 = p
        else:
            t = decoded2.get("text")
            if isinstance(t, bytes):
                text2 = t.decode("utf-8", errors="ignore")
            elif isinstance(t, str):
                text2 = t

        rssi = packet.get("rxRssi")

        if portnum2 == "TEXT_MESSAGE_APP":
            self._append(f"[MSG] {label2}: {text2} (RSSI={rssi})")
            self._append_to_node_chat(str(sender), text2)
            if isinstance(text2, str) and text2.strip().lower() == "ping":
                self._send_pong(sender, label2)

        self.refresh_nodes()

    def _send_pong(self, dest_id: Optional[str], label: str) -> None:
        iface = self.iface
        if not iface or not dest_id:
            return
        try:
            iface.sendText("pong", destinationId=dest_id, wantAck=False)
            self._append(f"[auto] pong -> {label}")
            self._append_to_node_chat(str(dest_id), "[auto] pong")
        except Exception as e:
            self._append(f"[auto] pong failed: {e}")

    # ------------------------------------------------------------------
    # Connection actions
    # ------------------------------------------------------------------
    def set_ip_port(self) -> None:
        new_host, ok = QInputDialog.getText(
            self,
            "Set IP/Port",
            "Host/IP:",
            text=self.host,
        )
        if not ok or not new_host.strip():
            return

        new_port, ok = QInputDialog.getInt(
            self,
            "Set IP/Port",
            "Port:",
            value=self.port,
            min=1,
            max=65535,
        )
        if not ok:
            return

        self.host = new_host.strip()
        self.port = int(new_port)
        self._update_title_with_host()

    def connect_tcp(self) -> None:
        if self.iface:
            return
        host = self.host.strip()
        port = int(self.port)
        self._append(f"Connecting TCP {host}:{port} ...")

        def run():
            try:
                if TCPInterface is None:
                    raise RuntimeError("meshtastic.tcp_interface not installed")
                self.iface = TCPInterface(hostname=host, portNumber=port)
                self.connected_evt.wait(timeout=5)
            except Exception as e:
                def _err():
                    QMessageBox.critical(self, "TCP connect failed", str(e))
                QTimer.singleShot(0, _err)

        threading.Thread(target=run, daemon=True).start()

    def connect_serial_dialog(self) -> None:
        if SerialInterface is None:
            QMessageBox.critical(
                self, "Unavailable", "meshtastic.serial_interface not installed."
            )
            return

        port, ok = QInputDialog.getText(
            self,
            "Serial",
            "Serial port (or type '(auto)' for automatic):",
            text="(auto)",
        )
        if not ok:
            return
        port = port.strip()
        dev = None if port.lower() == "(auto)" or not port else port
        self._append(f"Connecting Serial {dev or '(auto)'} ...")

        def run():
            try:
                if dev:
                    self.iface = SerialInterface(devPath=dev)
                else:
                    self.iface = SerialInterface()
                self.connected_evt.wait(timeout=5)
            except Exception as e:
                def _err():
                    QMessageBox.critical(self, "Serial connect failed", str(e))
                QTimer.singleShot(0, _err)

        threading.Thread(target=run, daemon=True).start()

    def connect_ble_dialog(self) -> None:
        if BLEInterface is None:
            QMessageBox.critical(
                self,
                "Unavailable",
                "meshtastic.ble_interface not installed (needs bleak).",
            )
            return
        self._append("Scanning BLE for Meshtastic devices ...")

        def run_scan():
            try:
                devices = BLEInterface.scan()
            except Exception as e:
                def _err():
                    QMessageBox.critical(self, "BLE scan failed", str(e))
                QTimer.singleShot(0, _err)
                return

            if not devices:
                def _info():
                    QMessageBox.information(self, "BLE", "No devices found.")
                QTimer.singleShot(0, _info)
                return

            options = [
                f"{i+1}. {getattr(d, 'name', '') or '(unnamed)'} [{getattr(d, 'address', '?')}]"
                for i, d in enumerate(devices)
            ]

            def _select():
                text, ok = QInputDialog.getItem(
                    self,
                    "Select BLE device",
                    "Select device:",
                    options,
                    editable=False,
                )
                if not ok:
                    return
                idx = options.index(text)
                addr = getattr(devices[idx], "address", None)
                if not addr:
                    QMessageBox.critical(self, "BLE", "Selected device has no address.")
                    return
                self._append(f"Connecting BLE {addr} ...")

                def _run_connect():
                    try:
                        self.iface = BLEInterface(address=addr)
                        self.connected_evt.wait(timeout=8)
                    except Exception as e:
                        def _err2():
                            QMessageBox.critical(self, "BLE connect failed", str(e))
                        QTimer.singleShot(0, _err2)

                threading.Thread(target=_run_connect, daemon=True).start()

            QTimer.singleShot(0, _select)

        threading.Thread(target=run_scan, daemon=True).start()

    def disconnect(self) -> None:
        try:
            if self.iface:
                self.iface.close()
        except Exception:
            pass
        self.iface = None
        self.connected_evt.clear()
        self._append("[*] Disconnected")

    # ------------------------------------------------------------------
    # Channel selector helpers
    # ------------------------------------------------------------------
    def _reset_channel_choices(self) -> None:
        """Reset channel combo to defaults (Public + To selected node)."""
        self._channel_map = {}
        options: List[str] = []

        label_pub = "Public (broadcast)"
        self._channel_map[label_pub] = {"mode": "broadcast", "channelIndex": 0}
        options.append(label_pub)

        # Removed "To selected node" option from channel selector;
        # direct messages are available via the node right-click menu.
        self.cbo_channel.clear()
        self.cbo_channel.addItems(options)
        # Default to Public on a hard reset; user choice will be preserved
        # later by _update_channels_from_iface when channels are refreshed.
        self.cbo_channel.setCurrentIndex(0)

    def _set_channel_choice(self, label: str) -> None:
        idx = self.cbo_channel.findText(label)
        if idx >= 0:
            self.cbo_channel.setCurrentIndex(idx)

    def _update_channels_from_iface(self) -> None:
        iface = self.iface
        if not iface:
            return
        local_node = getattr(iface, "localNode", None)
        if not local_node:
            return

        # Remember current selection so we can keep it after refreshing
        prev_label = self.cbo_channel.currentText().strip()

        chans = getattr(local_node, "channels", None)
        try:
            if (not chans) and hasattr(local_node, "requestChannels"):
                local_node.requestChannels()
                time.sleep(1.5)
                chans = getattr(local_node, "channels", None)
        except Exception:
            chans = getattr(local_node, "channels", None)

        options = [self.cbo_channel.itemText(i) for i in range(self.cbo_channel.count())]

        # update channel 0 name
        try:
            if chans and len(chans) > 0:
                ch0 = chans[0]
                try:
                    name0 = (getattr(ch0, "settings", None).name or "").strip()
                except Exception:
                    try:
                        name0 = (ch0.settings.name or "").strip()
                    except Exception:
                        name0 = ""
                if name0:
                    old_label = None
                    for lbl, meta in list(self._channel_map.items()):
                        if meta.get("mode") == "broadcast" and int(meta.get("channelIndex", 0) or 0) == 0:
                            old_label = lbl
                            break
                    if old_label:
                        new_label = f"Public (ch0: {name0})"
                        self._channel_map[new_label] = self._channel_map.pop(old_label)
                        options = [new_label if v == old_label else v for v in options]
                        if self.cbo_channel.currentText() == old_label:
                            self._set_channel_choice(new_label)
        except Exception:
            pass

        # Add remaining channels (1..N) as broadcast options.
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
            if not name:
                label = f"Ch {idx}"
            else:
                label = f"Ch {idx}: {name}"
            if label in self._channel_map:
                continue
            self._channel_map[label] = {"mode": "broadcast_channel", "channelIndex": idx}
            options.append(label)

        self.cbo_channel.clear()
        self.cbo_channel.addItems(options)

        # Restore previous selection if it still exists
        if prev_label and prev_label in options:
            self._set_channel_choice(prev_label)

    def _send_text_to_node(self, dest_id: str, msg: str) -> bool:
        iface = self.iface
        if not iface:
            QMessageBox.warning(self, "Send", "Connect first.")
            return False
        msg = (msg or "").strip()
        if not msg:
            return False
        try:
            choice = self.cbo_channel.currentText()
            info = self._channel_map.get(choice) or {"mode": "broadcast", "channelIndex": 0}
            ch_index = int(info.get("channelIndex", 0) or 0)
        except Exception:
            ch_index = 0
        try:
            iface.sendText(msg, destinationId=dest_id, wantAck=False, channelIndex=ch_index)
            self._append("[ME -> %s] %s" % (self._node_label(dest_id), msg))
            self._append_to_node_chat(str(dest_id), "[ME] " + msg)
            return True
        except Exception as e:
            QMessageBox.critical(self, "Send failed", str(e))
            return False

    def send_message(self) -> None:
        msg = self.ent_message.text().strip()
        if not msg:
            return
        iface = self.iface
        if not iface:
            QMessageBox.warning(self, "Not connected", "Connect first.")
            return

        try:
            choice = self.cbo_channel.currentText()
            info = self._channel_map.get(choice) or {"mode": "broadcast", "channelIndex": 0}
            mode = info.get("mode", "broadcast")
            ch_index = int(info.get("channelIndex", 0) or 0)
        except Exception:
            mode = "broadcast"
            ch_index = 0

        try:
            if mode == "selected":
                nid = self._get_selected_node_id()
                if not nid:
                    QMessageBox.information(self, "No selection", "Select a node first.")
                    return
                dest = self._resolve_node_dest_id(nid)
                if not dest:
                    QMessageBox.critical(
                        self,
                        "Send failed",
                        "Cannot resolve destination for selected node.",
                    )
                    return
                iface.sendText(msg, destinationId=dest, wantAck=False, channelIndex=ch_index)
                self._append(f"[ME -> {self._node_label(nid)}] {msg}")
                self._append_to_node_chat(str(dest), "[ME] " + msg)
            else:
                iface.sendText(msg, wantAck=False, channelIndex=ch_index)
                if mode == "broadcast_channel" and ch_index:
                    self._append(f"[ME ch{ch_index}] {msg}")
                else:
                    self._append(f"[ME] {msg}")

            self.ent_message.clear()
        except Exception as e:
            QMessageBox.critical(self, "Send failed", str(e))

    # ------------------------------------------------------------------
    # Nodes table
    # ------------------------------------------------------------------
    def _get_selected_node_id(self) -> Optional[str]:
        rows = self.nodes_table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        item = self.nodes_table.item(row, 0)  # shortname column
        if not item:
            return None
        return item.data(Qt.UserRole)

    def refresh_nodes(self) -> None:
        iface = self.iface
        # Also refresh available channels when we have a local node,
        # in case they appear after initial connection.
        if iface and getattr(iface, "localNode", None):
            try:
                self._update_channels_from_iface()
            except Exception:
                pass

        if not iface or not getattr(iface, "nodes", None):
            self.nodes_table.setRowCount(0)
            self.lbl_nodes_header.setText("Nodes (0)")
            self.lbl_status_nodes.setText("Nodes: 0")
            return

        q = self.ent_search.text().strip().lower()

        try:
            nodes_snapshot = dict(getattr(iface, "nodes", {}) or {})
        except Exception:
            nodes_snapshot = {}

        base_lat, base_lon = self._get_local_latlon()

        self.nodes_table.setRowCount(0)
        for node_id, node in nodes_snapshot.items():
            user = (node or {}).get("user") or {}
            shortname = user.get("shortName") or ""
            longname = user.get("longName") or ""
            hwmodel = user.get("hwModel") or ""
            role = user.get("role")
            if not role:
                # Many nodes don't explicitly report a role; treat missing as default CLIENT
                role = "CLIENT"
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

            speed, alt = self._extract_speed_alt(node)
            speed_str = "%.1f" % speed if isinstance(speed, (int, float)) else "-"
            alt_str = "%.0f" % alt if isinstance(alt, (int, float)) else "-"

            lastheard_val = f"{int(lastheard_epoch or 0):015d}"

            values = {
                "shortname": shortname,
                "longname": longname,
                "since": since_str,
                "hops": str(hops) if hops is not None else "-",
                "distkm": dist_str,
                "speed": speed_str,
                "alt": alt_str,
                "lastheard": lastheard_val,
                "hwmodel": hwmodel,
                "role": role,
                "macaddr": macaddr,
                "publickey": publickey,
                "isunmessagable": str(bool(unmsg)),
                "id": node_id,
            }

            if q and not any(q in str(v).lower() for v in values.values()):
                continue

            row = self.nodes_table.rowCount()
            self.nodes_table.insertRow(row)
            for col_idx, col_name in enumerate(self.cols_all):
                item = QTableWidgetItem(str(values[col_name]))
                if col_name in {"lastheard", "distkm", "hops", "speed", "alt"}:
                    try:
                        item.setData(Qt.UserRole, float(values[col_name]) if values[col_name] not in {"-", ""} else 0.0)
                    except Exception:
                        item.setData(Qt.UserRole, 0.0)
                if col_name == "shortname":
                    item.setData(Qt.UserRole, node_id)  # store node id
                self.nodes_table.setItem(row, col_idx, item)

        count = self.nodes_table.rowCount()
        self.lbl_nodes_header.setText(f"Nodes ({count})")
        self.lbl_status_nodes.setText(f"Nodes: {count}")

        if count > 0:
            order = Qt.DescendingOrder if self._last_sort_order_desc else Qt.AscendingOrder

            sort_col = self._last_sort_col_index
            try:
                # When 'Since' is the active sort column, actually sort by hidden 'lastheard'
                if self.cols_all[self._last_sort_col_index] == "since":
                    sort_col = self.cols_all.index("lastheard")
            except Exception:
                sort_col = self._last_sort_col_index

            self.nodes_table.sortItems(sort_col, order)

    def _on_header_clicked(self, logical_index: int) -> None:
        """Handle clicks on the node-list header.

        Special case: when clicking the visible 'Since' column, we actually sort
        by the hidden 'lastheard' epoch column, so the newest nodes appear first
        in descending order.
        """
        if logical_index == self._last_sort_col_index:
            self._last_sort_order_desc = not self._last_sort_order_desc
        else:
            self._last_sort_col_index = logical_index
            self._last_sort_order_desc = True

        order = Qt.DescendingOrder if self._last_sort_order_desc else Qt.AscendingOrder

        sort_col = logical_index
        try:
            # If user clicked "Since", use the hidden "lastheard" column for sorting
            if self.cols_all[logical_index] == "since":
                sort_col = self.cols_all.index("lastheard")
        except Exception:
            sort_col = logical_index

        self.nodes_table.sortItems(sort_col, order)

    # ------------------------------------------------------------------
    # Node context menu + actions
    # ------------------------------------------------------------------
    def _popup_node_menu(self, pos: QPoint) -> None:
        index = self.nodes_table.indexAt(pos)
        if index.isValid():
            self.nodes_table.selectRow(index.row())
        # Pause auto-refresh while the context menu is open,
        # otherwise the selection can disappear while clicking.
        restarted = False
        try:
            if hasattr(self, "refresh_timer") and self.refresh_timer.isActive():
                self.refresh_timer.stop()
                restarted = True
            self.node_menu.exec(self.nodes_table.viewport().mapToGlobal(pos))
        finally:
            if restarted:
                self.refresh_timer.start()

    def _on_node_double_clicked(self, row: int, column: int) -> None:
        """Double‑click on a node: mark it as target and open chat window."""
        nid = self._get_selected_node_id()
        if not nid:
            return
        # Log in the main message area which node is now the active chat target
        self._append(f"[target] will send to {self._node_label(nid)}")
        # Same behaviour as right‑click -> "Chat with node"
        self._open_node_chat(nid)

    def _cm_open_chat(self) -> None:
        nid = self._get_selected_node_id()
        if not nid:
            QMessageBox.information(self, "Chat", "Select a node first.")
            return
        self._open_node_chat(nid)

    def _open_node_chat(self, nid: str) -> None:
        key = str(nid)
        if key in self._per_node_chats:
            win = self._per_node_chats[key]
            try:
                win.show()
                win.raise_()
                win.activateWindow()
            except Exception:
                pass
            return
        label = self._node_label(nid)
        chat = NodeChatDialog(self, key, label)
        self._per_node_chats[key] = chat
        chat.show()

    def _append_to_node_chat(self, node_id: str, line: str) -> None:
        key = str(node_id)
        win = self._per_node_chats.get(key)
        if not win:
            return
        win.append_line(line)

    def _cm_traceroute(self) -> None:
        nid = self._get_selected_node_id()
        if not nid:
            QMessageBox.information(self, "Traceroute", "Select a node first.")
            return
        iface = self.iface
        if not iface or not getattr(iface, "localNode", None):
            QMessageBox.warning(self, "Traceroute", "Connect first.")
            return
        dest = self._resolve_node_dest_id(nid)
        if not dest:
            QMessageBox.critical(self, "Traceroute", "Cannot determine node ID for traceroute.")
            return
        # Log and run traceroute synchronously on the GUI thread so
        # that result dialogs are guaranteed to show.
        self._append(f"[trace] Requesting traceroute to {self._node_label(nid)} ({dest})")
        self._do_traceroute(dest)

    def _cm_delete_node(self) -> None:
        nid = self._get_selected_node_id()
        iface = self.iface
        if not nid:
            QMessageBox.information(self, "Delete node", "Select a node first.")
            return
        if not iface or not getattr(iface, "localNode", None):
            QMessageBox.warning(self, "Delete node", "Connect first.")
            return
        dest = self._resolve_node_dest_id(nid)
        if not dest:
            QMessageBox.critical(self, "Delete node", "Cannot determine node ID.")
            return
        label = self._node_label(nid)
        ret = QMessageBox.question(
            self,
            "Delete node",
            f"Remove node {label} ({dest}) from the NodeDB on the connected radio?\n\n"
            "The device might reboot after this.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if ret != QMessageBox.Yes:
            return
        try:
            getattr(iface, "localNode").removeNode(dest)
            self._append(f"[admin] Requested delete of node {label} ({dest})")
        except Exception as e:
            QMessageBox.critical(self, "Delete node", f"Failed to delete node: {e}")
            return

        rows = self.nodes_table.selectionModel().selectedRows()
        if rows:
            self.nodes_table.removeRow(rows[0].row())
        count = self.nodes_table.rowCount()
        self.lbl_nodes_header.setText(f"Nodes ({count})")
        self.lbl_status_nodes.setText(f"Nodes: {count}")

    def _resolve_node_dest_id(self, nid: str) -> Optional[str]:
        if nid.startswith("!") or nid.isdigit():
            return nid
        iface = self.iface
        try:
            if iface and getattr(iface, "nodes", None):
                node = getattr(iface, "nodes", {}).get(nid) or {}
                user = (node or {}).get("user") or {}
                node_id = user.get("id") or ""
                if node_id:
                    return node_id
        except Exception:
            pass
        if nid:
            return "!" + nid if not nid.startswith("!") else nid
        return None

    # ------------------------------------------------------------------
    # Traceroute
    # ------------------------------------------------------------------
    def _do_traceroute(self, dest: str, hop_limit: int = 10, channel_index: int = 0) -> None:
        """Run traceroute using the meshtastic CLI only (same behaviour as Tk client).

        This avoids protobuf / RouteDiscovery compatibility issues and relies on the
        already working `meshtastic --traceroute` command.
        """
        # Simply delegate to the CLI helper; it will log and open the traceroute window.
        self._do_traceroute_via_cli(dest)
    def _do_traceroute_via_interface(self, dest: str, hop_limit: int, channel_index: int) -> None:
        iface = self.iface
        if not iface or mesh_pb2 is None or portnums_pb2 is None or _json_format is None:
            QTimer.singleShot(
                0, lambda: QMessageBox.information(self, "Traceroute", "Python traceroute not available.")
            )
            return

        evt = threading.Event()
        result: Dict[str, Any] = {}

        def _num_to_label(num: int) -> str:
            try:
                nbn = getattr(iface, "nodesByNum", None)
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
                as_dict = _json_format.MessageToDict(rd)
                result["packet"] = p
                result["data"] = as_dict
            except Exception as e:
                result["error"] = str(e)
            finally:
                evt.set()

        try:
            r = mesh_pb2.RouteDiscovery()
            iface.sendData(
                r,
                destinationId=dest,
                portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
                wantResponse=True,
                onResponse=_on_response,
                channelIndex=channel_index,
                hopLimit=hop_limit,
            )
        except Exception as e:
            QTimer.singleShot(
                0,
                lambda: QMessageBox.critical(self, "Traceroute", f"Failed to send traceroute: {e}"),
            )
            return

        if not evt.wait(10.0):
            QTimer.singleShot(
                0,
                lambda: QMessageBox.information(
                    self, "Traceroute", "No traceroute response (timeout or unsupported)."
                ),
            )
            return

        if "error" in result:
            QTimer.singleShot(
                0,
                lambda: QMessageBox.critical(
                    self, "Traceroute", f"Failed to decode traceroute: {result['error']}"
                ),
            )
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
            if not start_num or not end_num:
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

        lines: List[str] = []
        fwd = _build_path("Route towards destination:", origin_num, "route", "snrTowards", dest_num)
        if fwd:
            lines.append(fwd)
        back = _build_path("Route back to us:", dest_num, "routeBack", "snrBack", origin_num)
        if back:
            lines.append(back)

        if not lines:
            msg = "Traceroute completed but no route data available."
            QTimer.singleShot(
                0,
                lambda: (QMessageBox.information(self, "Traceroute", msg), self._show_traceroute_window(msg)),
            )
            return

        text = "\n\n".join(lines)
        # Show traceroute result in both the log and a popup window (like the Tk version)
        QTimer.singleShot(0, lambda: (self._append(text), self._show_traceroute_window(text)))

    def _do_traceroute_via_cli(self, dest: str) -> None:
        host = self.host.strip() or HOST_DEFAULT
        cmd = ["meshtastic", "--host", host, "--traceroute", dest]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        except Exception as e:
            QTimer.singleShot(
                0,
                lambda: QMessageBox.critical(self, "Traceroute", f"Failed to run meshtastic CLI: {e}"),
            )
            return
        out = (proc.stdout or "") + ("\n" + (proc.stderr or "") if proc.stderr else "")
        if not out.strip():
            msg = "No output from meshtastic traceroute."
            QTimer.singleShot(
                0,
                lambda: (QMessageBox.information(self, "Traceroute", msg), self._show_traceroute_window(msg)),
            )
            return
        # Also log traceroute CLI output, then show it in a popup window
        QTimer.singleShot(0, lambda: (self._append(out), self._show_traceroute_window(out)))

    def _show_traceroute_window(self, text: str) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Traceroute")
        layout = QVBoxLayout(dlg)
        view = QPlainTextEdit(dlg)
        view.setReadOnly(True)
        view.setPlainText(text.strip() or "No traceroute data.")
        layout.addWidget(view)
        btn = QPushButton("Close", dlg)
        btn.clicked.connect(dlg.accept)
        layout.addWidget(btn)
        dlg.resize(700, 400)
        dlg.exec()

    # ------------------------------------------------------------------
    # Node details & map
    # ------------------------------------------------------------------
    def _cm_show_node_details(self) -> None:
        self.show_raw_node(friendly=True)

    def _cm_open_map(self) -> None:
        nid = self._get_selected_node_id()
        iface = self.iface
        if not nid or not iface or not getattr(iface, "nodes", None):
            QMessageBox.information(self, "Map", "No node selected.")
            return
        node = getattr(iface, "nodes", {}).get(nid, {})
        lat, lon = self._extract_latlon(node)
        if lat is None or lon is None:
            QMessageBox.information(self, "Map", "Selected node has no GPS position.")
            return
        url = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
        self._open_browser_url(url)

    def show_raw_node(self, friendly: bool = False) -> None:
        nid = self._get_selected_node_id()
        iface = self.iface
        if not nid or not iface or not getattr(iface, "nodes", None):
            QMessageBox.information(self, "Node", "No node selected.")
            return
        node = getattr(iface, "nodes", {}).get(nid, {})

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Node: {self._node_label(nid)}")
        layout = QVBoxLayout(dlg)
        txt = QPlainTextEdit(dlg)
        txt.setReadOnly(True)
        layout.addWidget(txt)
        btn = QPushButton("Close", dlg)
        btn.clicked.connect(dlg.accept)
        layout.addWidget(btn)

        if friendly:
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
                elif isinstance(v, list):
                    lines = []
                    for i, item in enumerate(v):
                        if isinstance(item, (dict, list)):
                            lines.append(f"{pad}- [{i}]")
                            lines.append(fmt_val(item, indent + 1))
                        else:
                            lines.append(f"{pad}- {item}")
                    return "\n".join(lines)
                else:
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
            txt.setPlainText("\n".join(lines))
        else:
            txt.setPlainText(json.dumps(node, indent=2, default=str))

        dlg.resize(700, 500)
        dlg.exec()

    # ------------------------------------------------------------------
    # Radio config (Tools menu)
    # ------------------------------------------------------------------
    def show_radio_config_window(self) -> None:
        iface = self.iface
        if not iface or not getattr(iface, "localNode", None):
            QMessageBox.information(self, "Radio config", "Connect to a device first.")
            return
        ln = getattr(iface, "localNode")
        try:
            if getattr(ln, "localConfig", None) is None and hasattr(ln, "waitForConfig"):
                ln.waitForConfig("localConfig")
        except Exception:
            pass
        cfg = getattr(ln, "localConfig", None)
        mod = getattr(ln, "moduleConfig", None)
        if cfg is None and mod is None:
            QMessageBox.information(self, "Radio config", "No config available yet from device.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Radio + module config (read‑only)")
        layout = QVBoxLayout(dlg)
        txt = QPlainTextEdit(dlg)
        txt.setReadOnly(True)
        layout.addWidget(txt)
        btn = QPushButton("Close", dlg)
        btn.clicked.connect(dlg.accept)
        layout.addWidget(btn)

        lines: List[str] = []
        if cfg is not None:
            lines.append("localConfig:")
            try:
                lines.append(str(cfg))
            except Exception:
                lines.append(repr(cfg))
        if mod is not None:
            lines.append("")
            lines.append("moduleConfig:")
            try:
                lines.append(str(mod))
            except Exception:
                lines.append(repr(mod))

        txt.setPlainText("\n".join(lines))
        dlg.resize(800, 600)
        dlg.exec()

    # ------------------------------------------------------------------
    # Neighbors + channel editor
    # ------------------------------------------------------------------
    def show_neighbors_window(self) -> None:
        iface = self.iface
        if not iface or not getattr(iface, "nodes", None):
            QMessageBox.information(self, "Neighbors", "No interface or nodes available.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Neighbor table")
        layout = QVBoxLayout(dlg)
        table = QTableWidget(0, 4, dlg)
        table.setHorizontalHeaderLabels(["From node", "To node", "SNR", "Last heard"])
        table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(table)

        rows = 0
        try:
            nodes_snapshot = dict(getattr(iface, "nodes", {}) or {})
        except Exception:
            nodes_snapshot = {}

        for node_id, node in nodes_snapshot.items():
            from_label = self._node_label(str(node_id))
            neighbors = (node or {}).get("neighbors") or []
            if isinstance(neighbors, dict):
                neighbors = neighbors.values()
            for n in neighbors:
                try:
                    to_id = (n or {}).get("nodeId") or (n or {}).get("id") or ""
                    to_label = self._node_label(str(to_id)) if to_id else str(to_id)
                    snr = (n or {}).get("snr")
                    last = (n or {}).get("lastHeard")
                    try:
                        last_epoch = float(last) if last is not None else None
                    except Exception:
                        last_epoch = None
                    last_str = _fmt_ago(last_epoch)
                except Exception:
                    continue

                row = table.rowCount()
                table.insertRow(row)
                for col, val in enumerate([from_label, to_label, snr if snr is not None else "-", last_str]):
                    item = QTableWidgetItem(str(val))
                    table.setItem(row, col, item)
                rows += 1

        if rows == 0:
            dlg.close()
            QMessageBox.information(self, "Neighbors", "No neighbor information found on nodes.")
            return

        dlg.resize(700, 400)
        dlg.exec()

    def show_channel_editor_window(self) -> None:
        iface = self.iface
        if not iface or not getattr(iface, "localNode", None):
            QMessageBox.information(self, "Channels", "Connect to a device first.")
            return
        ln = getattr(iface, "localNode")
        try:
            if getattr(ln, "channels", None) in (None, {}) and hasattr(ln, "waitForConfig"):
                ln.waitForConfig("channels")
        except Exception:
            pass
        chans = getattr(ln, "channels", None)
        if not chans:
            QMessageBox.information(self, "Channels", "No channels available from device.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Channel editor")
        layout = QVBoxLayout(dlg)

        row = QHBoxLayout()
        list_widget = QListWidget(dlg)
        row.addWidget(list_widget, 1)

        right = QVBoxLayout()
        lbl = QLabel("Channel name:", dlg)
        right.addWidget(lbl)
        name_edit = QLineEdit(dlg)
        right.addWidget(name_edit)
        row.addLayout(right, 2)

        layout.addLayout(row)

        btn_row = QHBoxLayout()
        btn_save = QPushButton("Save name to device", dlg)
        btn_close = QPushButton("Close", dlg)
        btn_row.addWidget(btn_save)
        btn_row.addStretch(1)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)

        def _channel_name(ch) -> str:
            try:
                s = getattr(ch, "settings", None)
                nm = (getattr(s, "name", "") or "").strip() if s is not None else ""
                if nm:
                    return nm
            except Exception:
                pass
            try:
                nm = (getattr(ch, "name", "") or "").strip()
                if nm:
                    return nm
            except Exception:
                pass
            return ""

        for i, ch in enumerate(chans):
            if ch is None:
                label = f"{i}: (empty)"
            else:
                nm = _channel_name(ch)
                label = f"{i}: {nm or '(no name)'}"
            list_widget.addItem(label)

        def on_select() -> None:
            idx = list_widget.currentRow()
            if idx < 0 or idx >= len(chans):
                name_edit.setText("")
                return
            ch = chans[idx]
            if ch is None:
                name_edit.setText("")
                return
            name_edit.setText(_channel_name(ch))

        list_widget.currentRowChanged.connect(lambda _row: on_select())

        def save_name() -> None:
            idx = list_widget.currentRow()
            if idx < 0 or idx >= len(chans):
                QMessageBox.information(dlg, "Channel editor", "Select a channel first.")
                return
            ch = chans[idx]
            if ch is None:
                QMessageBox.information(dlg, "Channel editor", "Selected channel slot is empty.")
                return
            new_name = name_edit.text().strip()
            try:
                if getattr(ch, "settings", None) is not None and hasattr(ch.settings, "name"):
                    ch.settings.name = new_name
                elif hasattr(ch, "name"):
                    ch.name = new_name
                ln.writeChannel(idx)
                self._append(f"[admin] Renamed channel {idx} to '{new_name}'")
                self._update_channels_from_iface()
                item = list_widget.item(idx)
                if item is not None:
                    item.setText(f"{idx}: {new_name or '(no name)'}")
            except Exception as e:
                QMessageBox.critical(dlg, "Channel editor", f"Failed to write channel: {e}")

        btn_save.clicked.connect(save_name)
        btn_close.clicked.connect(dlg.accept)

        dlg.resize(600, 400)
        dlg.exec()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------
    def apply_theme(self, mode: str = "light") -> None:
        self.current_theme = mode
        is_dark = mode == "dark"
        bg = "#1e1e1e" if is_dark else "#f5f5f5"
        fg = "#ffffff" if is_dark else "#000000"
        acc = "#2d2d2d" if is_dark else "#ffffff"
        sel = "#555555" if is_dark else "#cce0ff"

        style_sheet = f"""
            QMainWindow {{
                background-color: {bg};
                color: {fg};
            }}
            QWidget {{
                background-color: {bg};
                color: {fg};
            }}
            QTextEdit, QPlainTextEdit {{
                background-color: {acc};
                color: {fg};
            }}
            QLineEdit, QComboBox {{
                background-color: {acc};
                color: {fg};
            }}
            QTableWidget {{
                background-color: {acc};
                color: {fg};
                gridline-color: #444444;
            }}
            QHeaderView::section {{
                background-color: {acc};
                color: {fg};
            }}
            QPushButton {{
                background-color: {acc};
                color: {fg};
            }}
            QMenuBar {{
                background-color: {bg};
                color: {fg};
            }}
            QMenuBar::item:selected {{
                background-color: {sel};
                color: {fg};
            }}
            QMenu {{
                background-color: {bg};
                color: {fg};
            }}
            QMenu::item:selected {{
                background-color: {sel};
                color: {fg};
            }}
            QTableWidget::item:selected {{
                background-color: {sel};
                color: {fg};
            }}
        """
        self.setStyleSheet(style_sheet)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------
    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            "About Meshtastic Client (v1)",
            "Meshtastic Client (v1)\n\n"
            "You can find the sourcecode on\nhttps://github.com/dk98174003/Meshtastic-Client\n\n"
            "Have fun\n"
            "Knud Schrøder ;O)",
        )

    def closeEvent(self, event) -> None:  # type: ignore[override]
        try:
            self.disconnect()
        finally:
            super().closeEvent(event)


class NodeChatDialog(QDialog):
    """Simple per-node chat window."""

    def __init__(self, app: MeshtasticMainWindow, node_id: str, label: str) -> None:
        super().__init__(app)
        self.app = app
        self.node_id = node_id
        self.label = label
        self.setWindowTitle(f"Chat: {label}")

        layout = QVBoxLayout(self)
        self.txt = QPlainTextEdit(self)
        self.txt.setReadOnly(True)
        layout.addWidget(self.txt)

        row = QHBoxLayout()
        self.entry = QLineEdit(self)
        self.entry.setPlaceholderText("Type message and press Enter…")
        row.addWidget(self.entry, 1)
        self.btn_send = QPushButton("Send", self)
        row.addWidget(self.btn_send)
        layout.addLayout(row)

        self.btn_send.clicked.connect(self._send)
        self.entry.returnPressed.connect(self._send)

        self.resize(500, 350)

    def append_line(self, line: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.txt.appendPlainText(f"[{ts}] {line}")

    def _send(self) -> None:
        msg = self.entry.text().strip()
        if not msg:
            return
        ok = self.app._send_text_to_node(self.node_id, msg)
        if ok:
            self.entry.clear()

    def closeEvent(self, event) -> None:  # type: ignore[override]
        key = str(self.node_id)
        try:
            if key in self.app._per_node_chats:
                del self.app._per_node_chats[key]
        except Exception:
            pass
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    win = MeshtasticMainWindow()
    win.resize(1500, 820)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
