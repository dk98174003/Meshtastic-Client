### 🛰️ Meshtastic Client for Windows

**A modern Python-based desktop client for managing Meshtastic networks on Windows.**
This project provides an intuitive graphical interface to connect via IP, USB or Bluetooth to Meshtastic devices, monitor nodes in real time, send and receive messages, and manage network settings — all without using the command line.

Built entirely in **Python**, it features:

* Real-time node list with distance, hops, and last-heard info
* Message send/receive for the channels public and direct
* Support for light and dark themes
* Direct IP, USB and Bluetooth connection support
* Auto-refresh and status bar with node count
* Automatic “Ping → Pong” reply function — the client automatically responds to incoming “ping” with “pong” on a direct message
* Displays telemetry and position status messages directly in the message feed
* Node count, node filter, and sorting by short name, long name, since, hops, distance, hardware, and role.
* Right click menu on the nodes SendTo, Ping, Show node details.

Standalone Windows GUI for their Meshtastic devices.

<img width="1509" height="876" alt="billede" src="https://github.com/user-attachments/assets/87a91097-e709-4be9-b605-9b58bceecfcf" />


### 🧰 Installation & Setup (Windows)

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


The exe file is also available ready to use (you not need to install Python first).

Have fun

PS. Use IP or serial - bluetooth is slow.

Knud ;O)
