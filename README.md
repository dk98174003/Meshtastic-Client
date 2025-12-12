### 🛰️ Meshtastic Client for Windows and Linux

**A modern Python-based desktop client for managing Meshtastic networks on Windows and Linux.**
This project provides an intuitive graphical interface to connect via IP, USB or Bluetooth to Meshtastic devices, monitor nodes in real time, send and receive messages, and manage network settings — all without using the command line.

Built entirely in **Python**, it features:

* Real-time node list with shortname, longname, since, hops, dist, speed, alt, hw, role
* Message send/receive for the channels public, direct and private (all channels)
* Support for light and dark themes and config save.
* Direct IP, USB and Bluetooth connection support
* Auto-refresh and title with node count default sort since
* Automatic “Ping → Pong” reply function — the client automatically responds to incoming “ping” with “pong” on a direct message
* Node count, node filter, and sorting by short name, long name, since, hops, distance, hardware, and role.
* Right click menu on the node to Show node info, Show node on Map and Traceroute the node, delete node, direct node chat in window.
* Links menu to Meshtastic internet sites.
* Status bar with POS, TEL, INFO.

Standalone Windows GUI for their Meshtastic devices.

<img width="1801" height="1100" alt="image" src="https://github.com/user-attachments/assets/53b3b18a-edd2-45fb-8ac3-9eb901b2acde" />

---
### 🧰 Installation & Setup (Windows)
You can also download the ready to use Mestastic_Client.exe or the .deb file to install it on Linux Mint 22 or Debian 13.
New also a flatpak is available for other linux distributions.
---

1. **Install Python 3.10 or newer**

   * Download from [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)
   * ✅ During setup, **check “Add Python to PATH”**.
   * After installation, open **Command Prompt** and verify:

     ```cmd
     python --version
     pip --version
     ```

2. **Upgrade pip and install all required dependencies**

   ```cmd
   python -m pip install --upgrade pip
   pip install --upgrade meshtastic pyserial bleak pypubsub dotmap timeago requests pyyaml tabulate packaging
   ```

   **Dependency overview**

   | Package      | Purpose                                      |
   | ------------ | -------------------------------------------- |
   | `meshtastic` | Core library for TCP / USB / BLE connections |
   | `pyserial`   | Enables USB / Serial communication           |
   | `bleak`      | Bluetooth Low Energy support                 |
   | `pypubsub`   | Event/pub-sub messaging used by the library  |
   | `dotmap`     | Easy access to nested dictionaries           |
   | `timeago`    | Human-readable time display                  |
   | `requests`   | HTTP utilities (used internally)             |
   | `pyyaml`     | Configuration and serialization              |
   | `tabulate`   | CLI table output                             |
   | `packaging`  | Version comparison utilities                 |

3. **Install USB drivers (if using Serial/USB connection)**

   * Install **Silicon Labs CP210x** or **CH9102** drivers, depending on your device.
   * Official driver links:

     * [CP210x Windows Drivers](https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers)
     * [CH9102 Windows Drivers](https://www.wch.cn/downloads/CH9102_Windows_Driver.html)

4. **(Optional) Clone the official Meshtastic Python repository**

   ```cmd
   git clone https://github.com/meshtastic/python.git
   ```

   👉 [https://github.com/meshtastic/python](https://github.com/meshtastic/python)

5. **Download this GUI client**
   Place `meshtastic_client.py` (your version) in a folder such as
   `C:\Users\<YourName>\MeshtasticClient`

6. **Run the program**

   ```cmd
   cd C:\Users\<YourName>\MeshtasticClient
   python meshtastic_client.py
   ```

7. **Connect your Meshtastic device**

   * **Connection → Connect (TCP)** — for Wi-Fi / Ethernet connections
   * **Connection → Connect via USB/Serial…** — for direct cable connection
   * **Connection → Connect via Bluetooth…** — scan and pair over BLE

8. **Enable Bluetooth in Windows Settings → Bluetooth & devices → “Add device” to ensure permissions.



Here’s a short **GitHub installation & run description** for your `meshtastic_client.py` on Raspberry Pi OS (Trixie):

---

### 🐍 Meshtastic Client for Raspberry Pi OS Trixie (linux)

**Description:**
A Python GUI client for Meshtastic devices running fully offline on Raspberry Pi OS Trixie (Debian 13).
Connect via USB or Bluetooth, send and receive messages, and view node info in real time.

<img width="1817" height="922" alt="image" src="https://github.com/user-attachments/assets/36f2117a-4d44-48f1-99d8-295b8c98091b" />


### ⚙️ Installation

```bash
sudo apt update
sudo apt install -y python3-full python3-venv bluetooth bluez bluez-tools python3-serial git
git clone https://github.com/<yourname>/meshtastic_client.git
cd meshtastic_client
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install "meshtastic[cli]" pyserial bleak pypubsub dotmap timeago requests pyyaml tabulate packaging
```

Add user to serial groups:

```bash
sudo usermod -aG dialout $USER
sudo usermod -aG tty $USER
# log out and back in
```

### ▶️ Run

```bash
source venv/bin/activate
python3 meshtastic_client.py
```

### 🧩 Notes

* Works on Raspberry Pi 4/5 with Raspberry Pi OS Bookworm/Trixie.
* No internet connection required after setup.
* To exit the virtual environment: `deactivate`.


Have fun

PS. Use IP or serial - bluetooth is slow.
PPS. tkinter must be installed to run the program.

Knud ;O)
