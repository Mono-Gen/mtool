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
