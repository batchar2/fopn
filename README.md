<div align="center">

<H1>FPTN</H1>
<H6>Custom VPN technology</H6>

[\[English\]](README.md)
•
[\[Русский\]](README_RU.md)


[![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://github.com/batchar2/fptn/releases/latest)
[![Mac OS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)](https://github.com/batchar2/fptn/releases/latest)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/batchar2/fptn/releases/latest)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-8A2BE2?style=for-the-badge&logo=openwrt&logoColor=white)](https://github.com/batchar2/fptn/releases/latest)
[![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/batchar2/FptnClient-Android/releases/latest)
[![Build and Test](https://img.shields.io/github/actions/workflow/status/batchar2/fptn/main.yml?style=for-the-badge&logo=github-actions&logoColor=white&label=Build&labelColor=2088FF)](https://github.com/batchar2/fptn/actions/workflows/main.yml)
[![GitHub All Releases](https://img.shields.io/github/downloads/batchar2/fptn/total.svg?style=for-the-badge&logo=github&logoColor=white&label=Downloads&labelColor=181717)](https://github.com/batchar2/fptn/releases)
</div>

---

### Core Features of FPTN

FPTN is a VPN technology engineered from the ground up to provide secure, robust, and censorship-resistant connections capable of bypassing network filtering and deep packet inspection (DPI).

Project website: [https://storage.googleapis.com/fptn.org/index.html](https://storage.googleapis.com/fptn.org/index.html)

Key Technical Features:

1. **L3 Tunnel (Network Layer)**
  - **IP Packet Tunneling:** Encapsulates and transmits raw IP packets (IPv4/IPv6) over a secure tunnel to the VPN server.
  - **Split Tunneling:** Provides granular control over routing policies. Users can define rules (based on domains or IP networks) to specify which traffic is routed through the VPN tunnel; all other traffic uses the direct internet connection.
  - **Server-side NAT:** Implements Network Address Translation (NAT) on the server. Future roadmap includes support for user grouping into virtual LANs (VLANs) for peer-to-peer communication within the VPN.

2. **Traffic Obfuscation and Blocking Evasion**
  - **Resistance to active Deep Packet Inspection (DPI):** The server can identify FPTN clients during the TLS handshake by analyzing the session_id (which the FPTN client can set using a special time-based method). If the client is not recognized as an FPTN client, the server acts as a transparent proxy and returns legitimate content for the requested domain.
  - The VPN connection is masqueraded as regular HTTPS traffic (a mode for short-lived HTTPS connections is also under development).
  - Three implemented methods for bypassing blocks:
    - **SNI Spoofing:** A fake domain name is set in the TLS ClientHello packet that initiates the connection. Traffic analysis systems observe a legitimate TLS connection, while the traffic is actually routed to the VPN server.
    - **Obfuscation:** The traffic is disguised as an already established TLS session, hiding the initial TLS handshake and preventing detection by DPI systems.
    - **Reality Mode with SNI Spoofing:** The client initiates a connection to the VPN server using a spoofed Server Name Indication (SNI), receives a genuine TLS handshake response from the actual (spoofed) website, and then continues data exchange with the VPN server within the same connection.
  - The desktop client includes an integrated `SNI scanner utility`.

3. Transport Protocol
  - Uses a proprietary transport protocol based on Protocol Buffers (Protobuf) for data exchange between the client and server.
  - **Protocol-level padding:** Data packets are padded with random data to randomize traffic patterns and complicate analysis.
  - The server provides a **REST API** for client authentication and retrieving specific configuration settings.

4. **Advanced Functionality**
  - Built-in filtering of unwanted traffic (e.g., the BitTorrent protocol).
  - Per-user bandwidth and traffic control: The server employs a traffic shaper based on the **Leaky Bucket** algorithm, allowing for granular bandwidth policy configuration.
  - Support for a multi-server architecture with a single master server that stores all user data and configuration.
  - System monitoring via **Prometheus** and visualization dashboards in **Grafana**.
  - Ability for users to connect and manage their service via a **Telegram bot**.

5. **Cross-Platform Clients**
  - A cross-platform core library, **libfptn**, has been developed for use across various operating systems. It implements the FPTN network protocol, connection management, and data transmission mechanisms for the VPN tunnel.
  - **Desktop Clients**: Windows, macOS, Linux — a minimalist client focused on ease of use.
  - **Mobile Clients**: Android, iOS (under development).

6. **Simple Token-Based Configuration**
  - A **Token** is a specially generated configuration file containing all necessary settings for the system.
  - Enables connection to the VPN without manual configuration: the user simply imports the token into the client application to begin using the service.

---

### Demonstration

Download the FPTN client from the [website](http://batchar2.github.io/fptn/) or [GitHub](https://github.com/batchar2/fptn/releases). After downloading, install and launch the client.

The client is a compact application whose icon resides in the system tray.

Simply click the icon to open the context menu.

<img style="max-height: 100px" class="img-center" src="docs/images/macos/en/client.png" alt="Application"/>

Navigate to the "Settings" menu, where you need to add an access token.
Obtain a token by contacting our <a target="_blank" href="https://t.me/fptn_bot">Telegram bot</a>,

<img style="max-height: 200px" class="img-center" src="docs/images/telegram_token_en.png" alt="Settings"/>

Copy the token, click the "Add Token" button, paste it into the form, and save.

<img style="max-height: 250px" class="img-center" src="docs/images/macos/en/settings-2.png" alt="Settings"/>

After this, available servers will appear in the list.

<img style="max-height: 250px" class="img-center" src="docs/images/macos/en/settings-3.png" alt="Settings"/>

Ease of use:

<img style="max-height: 250px" class="img-center" src="docs/images/macos/en/running-client.png" alt="Settings"/>

You can also easily turn your Raspberry Pi or Orange Pi into a WiFi access point and install the FPTN client on it.
In this case, all devices connected to this WiFi network will be able to access the internet, bypassing any restrictions.
[Read more here](https://github.com/batchar2/fptn/blob/master/deploy/linux/wifi/README.md)

<img style="max-height: 350px" class="img-center" src="docs/images/orangepi.jpg" alt="Settings"/>

---

### Installation, Building, and Configuration


<details>
  <summary><strong>Installing and Configuring the FPTN Server</strong></summary>

Setting up and running your own FPTN server is done via Docker.
This ensures easy deployment, convenient updates, and environment isolation.
Instructions are available on [DockerHub](https://hub.docker.com/r/fptnvpn/fptn-vpn-server).

You can also deploy your own management and monitoring tools:
- **Telegram bot** – issuing tokens to users [sysadmin-tools/telegram-bot/README.md](sysadmin-tools/telegram-bot/README.md).
- **Grafana + Prometheus** – monitoring server and user status [sysadmin-tools/grafana/README.md](sysadmin-tools/grafana/README.md)

</details>




<details>
  <summary><strong>Installing FPTN on an OpenWrt router</strong></summary>

The router package carries the client, a service that starts it at boot, and a page in the router web interface. Everything on the network goes through the VPN, and nothing has to be installed on the phones and laptops themselves.

Two OpenWrt branches are supported. They differ in package manager, so the file differs too:

| Branch | Package manager | File |
|---|---|---|
| 25.12.x | apk | `.apk` |
| 24.10.x | opkg | `.ipk` |

What matters is the package architecture, not the exact model — one package serves every device sharing it:

| Package arch | OpenWrt targets | Example devices |
|---|---|---|
| `aarch64_generic` | armsr/armv8, rockchip/armv8 | virtual machines, NanoPi R2S / R4S / R5S |
| `aarch64_cortex-a53` | mediatek/filogic, qualcommax/ipq807x | Xiaomi AX3000T, Cudy TR3000, Xiaomi AX3600 / AX9000 |
| `arm_cortex-a7_neon-vfpv4` | ipq40xx | GL.iNet GL-A1300 Slate Plus, GL-B1300, ZyXEL NBG6617 |
| `x86_64` | x86/64 | mini PCs, Proxmox and other virtual machines |

Ask the router what it needs:

```bash
apk --print-arch
```

On 24.10 use `opkg print-architecture` instead.

Both the branch and the architecture are in the file name, so take the matching one from [Releases](https://github.com/batchar2/fptn/releases) — for example `fptn-client-0.4.4-openwrt-25.12.x-aarch64_generic.apk`. Building it yourself is described in *Building for OpenWrt*.

Copy the package to the router and install it. On 25.12:

```bash
scp fptn-client-*.apk root@192.168.1.1:/tmp/
```

```bash
apk add --allow-untrusted /tmp/fptn-client-*.apk
```

On 24.10:

```bash
scp fptn-client-*.ipk root@192.168.1.1:/tmp/
```

```bash
opkg update && opkg install /tmp/fptn-client-*.ipk
```

The router needs working internet during installation: `kmod-tun` and `ip-full` are pulled from the OpenWrt repository.

Installing sets up everything else on its own: it creates the firewall zone that masquerades LAN traffic into the tunnel, enables the service for boot, and reloads `rpcd` so the web page appears.

Open `VPN` → `FPTN` in the router web interface, paste the access token from [@fptn_bot](https://t.me/fptn_bot), tick `Enabled` and press `Save & Apply` — the service starts right there. The same from the shell:

```bash
uci set fptn.config.access_token='<token>'; uci set fptn.config.enabled='1'; uci commit fptn; /etc/init.d/fptn restart
```

If you administer the router remotely, add your own public address to `Routing` → `Exclude tunnel networks` (for example `203.0.113.45/32`) **before** connecting. Otherwise the tunnel takes over the default route, replies to your session leave through it, and you lose access to the router.

The `Diagnostics` button on the FPTN page checks the tunnel, routes, firewall zone and DNS, and reports what is broken. The full picture is in the system log:

```bash
logread -e fptn -f
```

Removing the package stops the client and disables autostart:

```bash
apk del fptn-client
```

On 24.10 the same is done with `opkg remove fptn-client`.

</details>







<details>
  <summary><strong>Building for Linux, Windows and macOS</strong></summary>

1. Install required dependencies
- For [Windows](deploy/windows/README.md)
- For [Ubuntu](deploy/linux/deb/README.md)
- For [macOS](deploy/macos/README.md)

2. Install Conan (version 2.24.0):

```bash
pip install conan
```

3. Detect and configure the Conan profile:

```bash
conan profile detect --force
```

4. Install dependencies, build, and install:

*(For debugging and development purposes, use Debug instead of Release.)*

- Linux:

```bash
conan install . --output-folder=build --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Debug -c "tools.build:defines=['QT_NO_INT128']"

cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build . --config Debug
ctest
```

- macOS:

```bash
conan install . --output-folder=build --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Debug

cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Debug
cmake --build . --config Debug
ctest
```

- Windows:

```bash
conan install . --output-folder=build --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Debug

cd build
cmake .. -G "Visual Studio 17 2022" -DCMAKE_TOOLCHAIN_FILE="conan_toolchain.cmake" -DCMAKE_BUILD_TYPE=Debug
cmake --build . --config Debug
ctest
```

5. Building the Installer

*(For debugging and development purposes, use Debug instead of Release.)*

- Windows

  ```bash
  cmake --build . --config Release --target build-installer
  ```

- Ubuntu

  ```bash
  cmake --build . --config Release --target build-deb-gui
  ```
  
- macOS

  ```bash
  cmake --build . --target build-pkg
  ```

</details>




<details>
  <summary><strong>Building for OpenWrt</strong></summary>

The router client is cross-compiled inside Docker: the image ships the OpenWrt SDK, builds the CLI client and packs it, the procd service and the LuCI page into a single package. Nothing has to be installed on the host except Docker itself. Installing and using the result is described in *Installing FPTN on an OpenWrt router*.

Dockerfiles are laid out as `deploy/openwrt/target-<architecture>/<OpenWrt branch>`. The 25.12.5 directories produce an `.apk`, the 24.10.7 ones an `.ipk`:

| Package arch | Directory | Devices |
|---|---|---|
| `aarch64_generic` | `target-armsr-armv8` | virtual machines, NanoPi R2S / R4S / R5S |
| `aarch64_cortex-a53` | `target-mediatek-filogic` | Xiaomi AX3000T, Cudy TR3000, Xiaomi AX3600 / AX9000 |
| `arm_cortex-a7_neon-vfpv4` | `target-ipq40xx` | GL.iNet GL-A1300 Slate Plus, GL-B1300, ZyXEL NBG6617 |
| `x86_64` | `target-x86-64` | mini PCs, Proxmox and other virtual machines |

Run the block matching your device and your OpenWrt branch — it builds the image and copies the package into the current directory.

**OpenWrt 25.12.x, `.apk`**

`aarch64_generic`:

```bash
docker build -t openwrt-armv8-25.12.5 -f ./deploy/openwrt/target-armsr-armv8/25.12.5/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-armv8-25.12.5 cp -av /out/. /dst/
```

`aarch64_cortex-a53`:

```bash
docker build -t openwrt-filogic-25.12.5 -f ./deploy/openwrt/target-mediatek-filogic/25.12.5/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-filogic-25.12.5 cp -av /out/. /dst/
```

`arm_cortex-a7_neon-vfpv4`:

```bash
docker build -t openwrt-ipq40xx-25.12.5 -f ./deploy/openwrt/target-ipq40xx/25.12.5/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-ipq40xx-25.12.5 cp -av /out/. /dst/
```

`x86_64`:

```bash
docker build -t openwrt-x86-64-25.12.5 -f ./deploy/openwrt/target-x86-64/25.12.5/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-x86-64-25.12.5 cp -av /out/. /dst/
```

**OpenWrt 24.10.x, `.ipk`**

`aarch64_generic`:

```bash
docker build -t openwrt-armv8-24.10.7 -f ./deploy/openwrt/target-armsr-armv8/24.10.7/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-armv8-24.10.7 cp -av /out/. /dst/
```

`aarch64_cortex-a53`:

```bash
docker build -t openwrt-filogic-24.10.7 -f ./deploy/openwrt/target-mediatek-filogic/24.10.7/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-filogic-24.10.7 cp -av /out/. /dst/
```

`arm_cortex-a7_neon-vfpv4`:

```bash
docker build -t openwrt-ipq40xx-24.10.7 -f ./deploy/openwrt/target-ipq40xx/24.10.7/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-ipq40xx-24.10.7 cp -av /out/. /dst/
```
 
`x86_64`:

```bash
docker build -t openwrt-x86-64-24.10.7 -f ./deploy/openwrt/target-x86-64/24.10.7/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-x86-64-24.10.7 cp -av /out/. /dst/
```

Every combination gets its own image tag, so builds do not overwrite each other.

The SDK images are `linux/amd64` only, so on Apple Silicon the build runs through emulation. Expect roughly an hour on the first run — the dependencies are built from source and cached in the image layers afterwards.

The package is named `0.0.0` unless a version is given. For a release build pass it explicitly:

```bash
docker build --build-arg PKG_VERSION=0.4.4 -t openwrt-armv8-25.12.5 -f ./deploy/openwrt/target-armsr-armv8/25.12.5/Dockerfile .
```

Everything that goes into the package lives in `deploy/openwrt/data`: the UCI config, the procd service, the LuCI page, and the packaging scripts for both formats. To target another architecture, copy one of the `target-*` directories and adjust the base image tag, `TOOLCHAIN_DIR`, `CROSS_PREFIX`, `CONAN_ARCH` and `PKG_ARCH`. The toolchain directory name can be read from the SDK image itself:

```bash
docker run --rm openwrt/sdk:mediatek-filogic-25.12.5 ls /builder/staging_dir
```

</details>








<details>

<summary><strong>Using CLion IDE for Development</strong></summary>

Run the following command in the project's root folder:

```bash
conan install . --output-folder=cmake-build-debug --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Debug
```

Open the project in CLion. After opening, the Open Project Wizard window will appear automatically. In it, you need to add the following CMake parameter:

```bash
-DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
```

</details>

---

### About the Project

FPTN is developed by a team of volunteers and independent developers.

If you wish to support the project, you can donate via [Boosty](https://boosty.to/fptn). Project sponsors have speed limits removed on our servers and (optionally) have their usernames published in FPTN clients.

Our Telegram chat for users and developers: [FPTN Project](https://t.me/fptn_project)

Join the community and the development team!

---

## Community Tools

The following tools are built and maintained by the community to extend or simplify working with FPTN.

### fptn-manager ⚠️ Unmaintained

> This tool has not been updated for a long time and may not work with the current version of FPTN.
> For server installation and management, use the official instructions on [DockerHub](https://hub.docker.com/r/fptnvpn/fptn-vpn-server).

A small external management tool built around FPTN, focused on simplifying deployment and common day-to-day administrative tasks.

It provides:
- A Docker-based installer
- An interactive CLI for user, password, and token management
- Easier initial setup and repeated operations

Project repository:  
https://github.com/FarazFe/fptn-manager
