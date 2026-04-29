# mtool Manual (v2.0)

## Overview
`mtool.exe` is a high-precision multicast diagnostic tool designed to bypass standard Windows network restrictions. By leveraging the Npcap driver, it bypasses the Windows QoS scheduler to ensure accurate DSCP (QoS) tagging and microsecond-level latency measurement.

## Key Features
- **Precision DSCP Control**: Guaranteed tagging of DSCP values (0-63) regardless of Windows 10/11 QoS group policies.
- **Full Interactive UI**: Hotkeys to modify Group, Port, Bandwidth, DSCP, etc., on the fly during execution.
- **Dynamic IGMP Management**: Automatically triggers join/leave (IGMP report) when critical network parameters change.
- **Manual IGMP Forging**: Directly constructs IGMP v2/v3 reports to prevent OS-level version fallback.
- **Source IP Spoofing**: Transmits multicast packets with a spoofed source IP, ideal for IGMPv3 SSM testing.

## Setup
1. **Install Npcap**: Download and install from [npcap.com](https://npcap.com/).
   > [!IMPORTANT]
   > During installation, you MUST check the box **"Install Npcap in WinPcap API-compatible mode"**. Without this, `mtool.exe` will fail to find the required libraries and will not start.
2. **Administrator Rights**: This tool operates at the raw network layer and MUST be **Run as Administrator**.

## Protocol Standards & Constraints
`mtool` enforces validation based on the following IETF standards (RFCs) to ensure valid packet generation and diagnostic consistency.

- **DSCP (0-63)**: Based on [RFC 2474](https://tools.ietf.org/html/rfc2474), defining the 6-bit Differentiated Services field.
- **Port Numbers (1-65535)**: Based on [RFC 768 (UDP)](https://tools.ietf.org/html/rfc768), defining the 16-bit source/destination ports.
- **Multicast Group**: Based on [RFC 1112](https://tools.ietf.org/html/rfc1112), specifying Class D addresses (`224.0.0.0` - `239.255.255.255`).
- **TTL (1-255)**: 8-bit Time-To-Live. A value ≥ 2 is recommended for routed environments.
- **Packet Size (Max 1472 bytes)**: The maximum payload size ensuring the UDP packet fits within a standard 1500-byte Ethernet MTU without fragmentation (1500 MTU - 20 IP - 8 UDP).

## Usage

### 1. Wizard Mode (Recommended)
Run without arguments to start the interactive setup:
```cmd
mtool.exe
```

### 2. Command Line Arguments
```text
-m, -Mode      : Operation mode (send / recv)
-i, -Interface : IP address of the NIC to bind
-g, -Group     : Multicast group address (Default: 239.1.1.1)
-p, -Port      : UDP port number (Default: 5001)
-s, -Source    : Source IP address (for IGMPv3 SSM)
-v, -IGMP      : IGMP version (2 / 3)
-q, -QoS       : DSCP value (0-63)
-b, -BW        : Target Bandwidth (Mbps)
-t, -TTL       : TTL value
-sz, -Size     : Packet size (Bytes)
-w, -WebPort   : WebUI port
```

## Interactive Hotkeys
Press these keys while the program is running to adjust settings:
- `G`: Change Group address (triggers Re-Join)
- `S`: Change Source IP (triggers Re-Join/Spoofing)
- `O`: Change Port number
- `V`: Toggle IGMP version (2 ⇔ 3)
- `M`: Toggle IGMP v3 mode (Include ⇔ Exclude)
- `D`: Change DSCP value
- `B`: Change Bandwidth (Mbps)
- `P`: Change Packet Size
- `T`: Change TTL value
- `R`: Restore initial parameters (Restore)
- `C`: Clear statistics
- `Q`: Quit

## Logging & Reporting
`mtool` includes a robust logging feature to capture evidence for network validation.

- **Operation**:
  - Click "Start Logging" in the WebUI to begin logging. A red "LOGGING" indicator will flash during logging.
  - Clicking "Stop & Download CSV" ends the session and automatically downloads a CSV report.
- **Report Content (CSV)**:
  - Captures Timestamp, Event Type (JOIN/LEAVE/QUERY/CONFIG, etc.), Throughput, Latency, Jitter, Loss %, and detailed event descriptions at 1-second intervals or upon specific events.

## Monitor Statistics
- **TX-pps / Mbps**: Transmit packet rate and throughput.
- **RX-pps / Mbps**: Receive packet rate and throughput.
- **Loss%**: Packet loss percentage based on sequence numbers.
- **Lat-Avg / Jitter**: Average latency and jitter in microseconds.
- **DSCP**: Actual DSCP value detected in received packets (`Set(Actual)`). Red text indicates a mismatch.

## Troubleshooting
- **"Malformed Packet"**: Ensure you are using the latest version of `mtool_npcap.exe` to resolve Big Endian alignment issues.
- **No Reception**: Check Windows Firewall or antivirus settings. For SSM, verify the sender's IP matches your `Source IP` setting.
- **Npcap Error**: Verify Npcap installation or ensure no other app is exclusively locking the NIC.
