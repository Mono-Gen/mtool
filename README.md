# mtool - High-Precision Multicast Diagnostic Tool

`mtool` is a high-performance command-line tool designed to bypass standard Windows network restrictions and perform precision multicast transmission, reception, and statistical analysis.

## Key Features
- **Precision DSCP Control**: Guarantees raw DSCP (QoS) tagging (0-63) by bypassing the OS-level Windows QoS scheduler.
- **Real-Time Interaction**: On-the-fly adjustment of bandwidth, group addresses, ports, and source IPs via interactive hotkeys.
- **Web-Based Dashboard**: Built-in Web UI providing real-time throughput charts and remote configuration.
- **Advanced IGMP Management**: Maintains active state tracking to ensure proper Leave/Join packet sequencing during parameter changes.
- **Npcap Integration**: Enables microsecond-level latency tracking and direct packet injection using raw sockets.

## Quick Start

### 1. Install Npcap
This tool requires the [Npcap](https://npcap.com/) driver.
> [!IMPORTANT]
> During installation, you MUST check the box **"Install Npcap in WinPcap API-compatible mode"**. Without this, the tool will fail to locate the required libraries.

### 2. Execution
Open a command prompt as **Administrator** and run:
```cmd
mtool.exe
```
Running without arguments will start an interactive setup wizard.

## Documentation
For detailed usage and command-line arguments, please refer to the following manuals:

- [English Manual (manual_EN.md)](./manual_EN.md)
- [日本語マニュアル (manual_JP.md)](./manual_JP.md)

## Requirements
- **OS**: Windows 10 / 11 (x64)
- **Privilege**: Administrator rights required.
- **Dependency**: Npcap (WinPcap compatibility mode).
