using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using System.IO;

namespace MMulticastTool
{
    class Program
    {
        private const string SIG = "MTOOL";
        private const int HEADER_SIZE = 21;
        private const int IP_ADD_SOURCE_MEMBERSHIP = 15;
        private const int IP_BLOCK_SOURCE = 17;

        static string groupAddr = "239.1.1.1";
        static int port = 5001;
        static string interfaceAddr = "0.0.0.0";
        static string interfaceName = "";
        static int igmpVersion = 2;
        static string sourceAddr = "";
        static string igmpMode = "include";
        static int ttl = 1;
        static int interval = 1000;
        static int packetSize = 64;
        static double bandwidthMbps = 0;
        static int dscp = 0;
        static string mode = "send";
        static int webPort = 8080;

        static volatile bool needsRestart = false;
        static bool isInputMode = false;
        static double targetIntervalMs = 1000.0;
        static bool isAdmin = false;

        static string activeGrp = "", activeSrc = "", activeMode = "";
        static int activeVer = 0;

        static long txCount = 0, txBytes = 0, rxCount = 0, rxBytes = 0, lostCount = 0, lastSeq = -1;
        static List<double> latencies = new List<double>();
        static double maxLat = 0, minLat = double.MaxValue, jitter = 0;
        static int actualDscp = -1;
        static readonly object statsLock = new object();
        
        static string iGrp, iSrc, iMode; static int iPort, iVer, iTtl, iSize, iDscp, iWeb; static double iBw;
        static string lastSrcMac = "-"; static int lastTtl = -1; static DateTime lastQueryTime = DateTime.MinValue; static bool fragDetected = false;

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_findalldevs(ref IntPtr alldevsp, byte[] errbuf);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_freealldevs(IntPtr alldevsp);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int to_ms, byte[] errbuf);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_close(IntPtr p);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_sendpacket(IntPtr p, byte[] buf, int size);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_next_ex(IntPtr p, ref IntPtr pkt_header, ref IntPtr pkt_data);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_compile(IntPtr p, IntPtr fp, string str, int optimize, uint mask);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_setfilter(IntPtr p, IntPtr fp);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_lib_version();

        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_if { public IntPtr next; public IntPtr name; public IntPtr description; public IntPtr addresses; public uint flags; }
        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_addr { public IntPtr next; public IntPtr addr; public IntPtr netmask; public IntPtr broadaddr; public IntPtr dstaddr; }
        [StructLayout(LayoutKind.Sequential)]
        public struct sockaddr_in { public short sin_family; public ushort sin_port; public uint sin_addr; }
        [StructLayout(LayoutKind.Sequential)]
        public struct pcap_pkthdr { public long tv_sec; public int tv_usec; public uint caplen; public uint len; }

        static void Main(string[] args)
        {
            try { MainAsync(args).GetAwaiter().GetResult(); }
            catch (Exception ex) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("\n[!] CRITICAL ERROR: " + ex.ToString()); Console.ResetColor(); Console.ReadKey(); }
        }

        static async Task MainAsync(string[] args)
        {
            if (!CheckNpcap()) return;
            ParseArgs(args); isAdmin = IsAdministrator();
            if (!isAdmin) {
                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("╔══════════════════════════════════════════════════════════════════════════════════════════╗");
                Console.WriteLine("║ [!] ERROR: ADMINISTRATOR PRIVILEGES REQUIRED                                             ║");
                Console.WriteLine("╠══════════════════════════════════════════════════════════════════════════════════════════╣");
                Console.WriteLine("║ Raw Socket (Npcap) & HttpListener operation require Administrator rights.                ║");
                Console.WriteLine("║ Please right-click 'mtool.exe' and select 'Run as Administrator'.                        ║");
                Console.WriteLine("╚══════════════════════════════════════════════════════════════════════════════════════════╝");
                Console.ResetColor();
                Console.WriteLine("\nPress any key to exit..."); Console.ReadKey(); return;
            }

            if (string.IsNullOrEmpty(interfaceName) || port == 0) ShowWizard();
            iGrp = groupAddr; iPort = port; iSrc = sourceAddr; iVer = igmpVersion; iMode = igmpMode; iTtl = ttl; iSize = packetSize; iDscp = dscp; iBw = bandwidthMbps; iWeb = webPort;
            
            Console.Clear();

            using (CancellationTokenSource cts = new CancellationTokenSource())
            {
                List<Task> tasks = new List<Task>();
                tasks.Add(Task.Run(() => MonitorTask(cts.Token)));
                if (mode == "send") tasks.Add(Task.Run(() => SenderTaskNpcap(cts.Token)));
                else if (mode == "recv") tasks.Add(Task.Run(() => ReceiverTaskNpcap(cts.Token)));
                tasks.Add(Task.Run(() => InputTask(cts)));
                tasks.Add(HttpTask(cts.Token));

                Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };
                await Task.WhenAny(Task.WhenAll(tasks), Task.Delay(-1, cts.Token)).ContinueWith(_ => {});
            }
        }

        static void ShowHeader()
        {
            string sType = string.IsNullOrEmpty(sourceAddr) ? "ASM" : sourceAddr;
            if (mode == "send" && !string.IsNullOrEmpty(sourceAddr)) sType = sType + " (SPOOFED)";
            Console.WriteLine("┌──────────────────────────────────────────────────────────────────────────────────────────────┐");
            Console.WriteLine(string.Format("│ Target:{0,-15}:{1,-5} NIC:{2,-15} IGMP:v{3} Src:{4,-15} │", groupAddr, port, interfaceAddr, igmpVersion, sType));
            Console.WriteLine(string.Format("│ Mode: {0,-10} {1,-10} DSCP: {2,-5} BW: {3,-8} Mbps  Size: {4,-8} bytes │", mode.ToUpper(), (igmpVersion == 3 ? igmpMode.ToUpper() : ""), dscp, bandwidthMbps, packetSize));
            Console.WriteLine("└──────────────────────────────────────────────────────────────────────────────────────────────┘\n");
        }

        #region Network Tasks
        static void SenderTaskNpcap(CancellationToken ct)
        {
            byte[] err = new byte[256];
            IntPtr handle = pcap_open_live(interfaceName, 65536, 1, 100, err);
            if (handle == IntPtr.Zero) { Console.WriteLine("\n[!] Failed to open Npcap handle."); return; }

            try {
                while (!ct.IsCancellationRequested)
                {
                    Socket control = null;
                    try {
                        control = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                        control.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                        control.Bind(new IPEndPoint(IPAddress.Any, port));
                        
                        // Initial Join
                        activeGrp = groupAddr; activeSrc = sourceAddr; activeVer = igmpVersion; activeMode = igmpMode;
                        SendManualIgmp(handle); 

                        ulong seq = 0; RecalculateInterval(); long ticksPerMs = Stopwatch.Frequency / 1000;
                        byte[] srcMac = GetLocalMac(interfaceAddr), dstMac = GetMulticastMac(groupAddr);
                        byte[] srcIp = string.IsNullOrEmpty(sourceAddr) ? IPAddress.Parse(interfaceAddr).GetAddressBytes() : IPAddress.Parse(sourceAddr).GetAddressBytes();
                        byte[] dstIp = IPAddress.Parse(groupAddr).GetAddressBytes();
                        int lastPort = port;

                        needsRestart = false;
                        long lastIgmp = Stopwatch.GetTimestamp();
                        while (!ct.IsCancellationRequested && !needsRestart)
                        {
                            if ((Stopwatch.GetTimestamp() - lastIgmp) / (double)Stopwatch.Frequency > 30) { SendManualIgmp(handle); lastIgmp = Stopwatch.GetTimestamp(); }
                            long nowTicks = Stopwatch.GetTimestamp(); int tLen;
                            byte[] pkt = BuildUdpPacket(srcMac, dstMac, srcIp, dstIp, (ushort)lastPort, (ushort)lastPort, seq, nowTicks, out tLen);
                            if (pkt != null) pcap_sendpacket(handle, pkt, tLen); 
                            Interlocked.Increment(ref txCount); Interlocked.Add(ref txBytes, tLen - 42); seq++;
                            if (targetIntervalMs < 15) { while ((double)(Stopwatch.GetTimestamp() - nowTicks) / ticksPerMs < targetIntervalMs) { Thread.Yield(); } }
                            else { Thread.Sleep((int)targetIntervalMs); }
                        }
                        if (needsRestart && !ct.IsCancellationRequested) {
                            SendManualLeave(handle, activeGrp, activeSrc, activeVer, activeMode);
                        }
                    } catch (Exception ex) { if (!ct.IsCancellationRequested) { Console.WriteLine("\n[!] Sender error: " + ex.Message); Thread.Sleep(1000); } }
                    finally { if (control != null) { try { control.Close(); } catch {} } }
                }
            } finally { pcap_close(handle); }
        }

        static void ReceiverTaskNpcap(CancellationToken ct)
        {
            byte[] err = new byte[256];
            IntPtr handle = pcap_open_live(interfaceName, 65536, 1, 10, err);
            if (handle == IntPtr.Zero) { Console.WriteLine("\n[!] Failed to open Npcap handle."); return; }

            try {
                while (!ct.IsCancellationRequested)
                {
                    Socket control = null;
                    try {
                        control = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                        control.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                        control.Bind(new IPEndPoint(IPAddress.Any, port));

                        // Initial Join
                        activeGrp = groupAddr; activeSrc = sourceAddr; activeVer = igmpVersion; activeMode = igmpMode;
                        SendManualIgmp(handle);

                        string filter = string.Format("(udp and dst port {0} and dst host {1}) or igmp", port, groupAddr);
                        if (igmpVersion == 3 && !string.IsNullOrEmpty(sourceAddr)) {
                            if (igmpMode == "include") filter = string.Format("(udp and dst port {0} and dst host {1} and src host {2}) or igmp", port, groupAddr, sourceAddr);
                            else filter = string.Format("(udp and dst port {0} and dst host {1} and not src host {2}) or igmp", port, groupAddr, sourceAddr);
                        }
                        IntPtr fp = Marshal.AllocHGlobal(128);
                        if (pcap_compile(handle, fp, filter, 1, 0) == 0) pcap_setfilter(handle, fp);
                        else Console.WriteLine("\n[!] Warning: pcap_compile failed. Using promiscuous capture.");
                        Marshal.FreeHGlobal(fp);

                        needsRestart = false; double lastLat = -1; IntPtr hPtr = IntPtr.Zero, dPtr = IntPtr.Zero;
                        long lastIgmp = Stopwatch.GetTimestamp();
                        while (!ct.IsCancellationRequested && !needsRestart)
                        {
                            if ((Stopwatch.GetTimestamp() - lastIgmp) / (double)Stopwatch.Frequency > 30) { SendManualIgmp(handle); lastIgmp = Stopwatch.GetTimestamp(); }
                            int res = pcap_next_ex(handle, ref hPtr, ref dPtr);
                            if (res <= 0) continue;
                            long nowTicks = Stopwatch.GetTimestamp(); pcap_pkthdr hdr = (pcap_pkthdr)Marshal.PtrToStructure(hPtr, typeof(pcap_pkthdr));
                            if (hdr.caplen < 42) continue;
                            byte[] pkt = new byte[hdr.caplen]; Marshal.Copy(dPtr, pkt, 0, (int)hdr.caplen);
                            string srcM = BitConverter.ToString(pkt, 6, 6).Replace("-", ":");
                            int ipProt = pkt[23], ttlV = pkt[22];
                            bool isF = (pkt[20] & 0x20) != 0 || (pkt[20] & 0x1F) != 0 || pkt[21] != 0;
                            int payloadOff = 14 + (pkt[14] & 0x0F) * 4 + 8;

                            if (ipProt == 2) { 
                                int igmpOff = 14 + (pkt[14] & 0x0F) * 4;
                                if (pkt.Length > igmpOff && pkt[igmpOff] == 0x11) lock (statsLock) lastQueryTime = DateTime.Now;
                            } else if (pkt.Length - payloadOff >= HEADER_SIZE && Encoding.ASCII.GetString(pkt, payloadOff, 5) == SIG) {
                                byte[] sB = new byte[8], tB = new byte[8]; Buffer.BlockCopy(pkt, payloadOff + 5, sB, 0, 8); Buffer.BlockCopy(pkt, payloadOff + 13, tB, 0, 8);
                                if (BitConverter.IsLittleEndian) { Array.Reverse(sB); Array.Reverse(tB); }
                                long seq = (long)BitConverter.ToUInt64(sB, 0), tsT = BitConverter.ToInt64(tB, 0);
                                double latUs = (double)(nowTicks - tsT) * 1000000.0 / Stopwatch.Frequency;
                                Interlocked.Increment(ref rxCount); Interlocked.Add(ref rxBytes, pkt.Length - payloadOff);
                                lock (statsLock) {
                                    latencies.Add(latUs); if (latencies.Count > 1000) latencies.RemoveAt(0);
                                    if (latUs > maxLat) maxLat = latUs; if (latUs < minLat) minLat = latUs;
                                    if (lastLat >= 0) jitter = jitter == 0 ? Math.Abs(latUs - lastLat) : jitter * 0.9 + Math.Abs(latUs - lastLat) * 0.1;
                                    lastLat = latUs; if (lastSeq != -1 && seq > lastSeq + 1) lostCount += (seq - lastSeq - 1); lastSeq = seq;
                                    actualDscp = pkt[15] >> 2; lastSrcMac = srcM; lastTtl = ttlV; if (isF) fragDetected = true;
                                }
                            }
                        }
                        if (needsRestart && !ct.IsCancellationRequested) {
                            SendManualLeave(handle, activeGrp, activeSrc, activeVer, activeMode);
                        }
                    } catch (Exception ex) { if (!ct.IsCancellationRequested) { Console.WriteLine("\n[!] Receiver error: " + ex.Message); Thread.Sleep(1000); } }
                    finally { if (control != null) { try { control.Close(); } catch {} } }
                }
            } finally { pcap_close(handle); }
        }
        #endregion

        #region IGMP Forging
        static void SendManualIgmp(IntPtr handle)
        {
            byte[] srcMac = GetLocalMac(interfaceAddr), srcIp = IPAddress.Parse(interfaceAddr).GetAddressBytes(), grpIp = IPAddress.Parse(groupAddr).GetAddressBytes();
            if (igmpVersion == 3) {
                byte[] dstMac = new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x16 }, dstIp = new byte[] { 224, 0, 0, 22 };
                int sources = string.IsNullOrEmpty(sourceAddr) ? 0 : 1;
                int len = 40 + (sources * 4); byte[] pkt = new byte[14 + len];
                Buffer.BlockCopy(dstMac, 0, pkt, 0, 6); Buffer.BlockCopy(srcMac, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
                pkt[14] = 0x46; pkt[15] = 0xC0;
                byte[] lB = BitConverter.GetBytes((ushort)len); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, 16, 2);
                pkt[22] = 1; pkt[23] = 2; // TTL=1, Prot=IGMP
                Buffer.BlockCopy(srcIp, 0, pkt, 26, 4); Buffer.BlockCopy(dstIp, 0, pkt, 30, 4);
                pkt[34] = 0x94; pkt[35] = 0x04; pkt[36] = 0x00; pkt[37] = 0x00; // Router Alert Option
                ushort ipC = CalculateChecksum(pkt, 14, 24); byte[] ipCB = BitConverter.GetBytes(ipC); if (BitConverter.IsLittleEndian) Array.Reverse(ipCB); Buffer.BlockCopy(ipCB, 0, pkt, 24, 2);
                int igmpOff = 14 + 24; pkt[igmpOff] = 0x22; pkt[igmpOff + 7] = 1; // Type=0x22 (v3), Records=1
                int recOff = igmpOff + 8; pkt[recOff] = (byte)(igmpMode == "exclude" ? 2 : 1);
                pkt[recOff + 2] = 0; pkt[recOff + 3] = (byte)sources; Buffer.BlockCopy(grpIp, 0, pkt, recOff + 4, 4);
                if (sources > 0) Buffer.BlockCopy(IPAddress.Parse(sourceAddr).GetAddressBytes(), 0, pkt, recOff + 8, 4);
                else {
                    // ASM: Ensure Source List is empty if Exclude and no source specified
                    if (igmpMode == "exclude") { pkt[recOff + 3] = 0; }
                }
                ushort igmpC = CalculateChecksum(pkt, igmpOff, len - 24); byte[] igmpCB = BitConverter.GetBytes(igmpC); if (BitConverter.IsLittleEndian) Array.Reverse(igmpCB); Buffer.BlockCopy(igmpCB, 0, pkt, igmpOff + 2, 2);
                pcap_sendpacket(handle, pkt, pkt.Length);
            } else {
                byte[] dstMac = GetMulticastMac(groupAddr);
                int len = 28; byte[] pkt = new byte[14 + len];
                Buffer.BlockCopy(dstMac, 0, pkt, 0, 6); Buffer.BlockCopy(srcMac, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
                pkt[14] = 0x45; pkt[15] = 0xC0; byte[] lB = BitConverter.GetBytes((ushort)len); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, 16, 2);
                pkt[22] = 1; pkt[23] = 2; Buffer.BlockCopy(srcIp, 0, pkt, 26, 4); Buffer.BlockCopy(grpIp, 0, pkt, 30, 4);
                ushort ipC = CalculateChecksum(pkt, 14, 20); byte[] ipCB = BitConverter.GetBytes(ipC); if (BitConverter.IsLittleEndian) Array.Reverse(ipCB); Buffer.BlockCopy(ipCB, 0, pkt, 24, 2);
                int igmpOff = 14 + 20; pkt[igmpOff] = 0x16; Buffer.BlockCopy(grpIp, 0, pkt, igmpOff + 4, 4);
                ushort igmpC = CalculateChecksum(pkt, igmpOff, 8); byte[] igmpCB = BitConverter.GetBytes(igmpC); if (BitConverter.IsLittleEndian) Array.Reverse(igmpCB); Buffer.BlockCopy(igmpCB, 0, pkt, igmpOff + 2, 2);
                pcap_sendpacket(handle, pkt, pkt.Length);
            }
        }

        static void SendManualLeave(IntPtr handle, string g, string s, int v, string m)
        {
            if (string.IsNullOrEmpty(g)) return;
            byte[] srcMac = GetLocalMac(interfaceAddr), srcIp = IPAddress.Parse(interfaceAddr).GetAddressBytes(), grpIp = IPAddress.Parse(g).GetAddressBytes();
            if (v == 3) {
                byte[] dstMac = new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x16 }, dstIp = new byte[] { 224, 0, 0, 22 };
                // Leave in v3 is CHANGE_TO_INCLUDE_MODE (Type 3) with empty source list
                int len = 40; byte[] pkt = new byte[14 + len];
                Buffer.BlockCopy(dstMac, 0, pkt, 0, 6); Buffer.BlockCopy(srcMac, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
                pkt[14] = 0x46; pkt[15] = 0xC0; byte[] lB = BitConverter.GetBytes((ushort)len); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, 16, 2);
                pkt[22] = 1; pkt[23] = 2; Buffer.BlockCopy(srcIp, 0, pkt, 26, 4); Buffer.BlockCopy(dstIp, 0, pkt, 30, 4);
                pkt[34] = 0x94; pkt[35] = 0x04; pkt[36] = 0x00; pkt[37] = 0x00;
                ushort ipC = CalculateChecksum(pkt, 14, 24); byte[] ipCB = BitConverter.GetBytes(ipC); if (BitConverter.IsLittleEndian) Array.Reverse(ipCB); Buffer.BlockCopy(ipCB, 0, pkt, 24, 2);
                int igmpOff = 14 + 24; pkt[igmpOff] = 0x22; pkt[igmpOff + 7] = 1;
                int recOff = igmpOff + 8; pkt[recOff] = 3; // Type=3 (CHANGE_TO_INCLUDE_MODE)
                pkt[recOff + 2] = 0; pkt[recOff + 3] = 0; Buffer.BlockCopy(grpIp, 0, pkt, recOff + 4, 4);
                ushort igmpC = CalculateChecksum(pkt, igmpOff, len - 24); byte[] igmpCB = BitConverter.GetBytes(igmpC); if (BitConverter.IsLittleEndian) Array.Reverse(igmpCB); Buffer.BlockCopy(igmpCB, 0, pkt, igmpOff + 2, 2);
                pcap_sendpacket(handle, pkt, pkt.Length);
            } else {
                byte[] dstMac = new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x02 }; // All Routers
                byte[] dstIp = new byte[] { 224, 0, 0, 2 };
                int len = 28; byte[] pkt = new byte[14 + len];
                Buffer.BlockCopy(dstMac, 0, pkt, 0, 6); Buffer.BlockCopy(srcMac, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
                pkt[14] = 0x45; pkt[15] = 0xC0; byte[] lB = BitConverter.GetBytes((ushort)len); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, 16, 2);
                pkt[22] = 1; pkt[23] = 2; Buffer.BlockCopy(srcIp, 0, pkt, 26, 4); Buffer.BlockCopy(dstIp, 0, pkt, 30, 4);
                ushort ipC = CalculateChecksum(pkt, 14, 20); byte[] ipCB = BitConverter.GetBytes(ipC); if (BitConverter.IsLittleEndian) Array.Reverse(ipCB); Buffer.BlockCopy(ipCB, 0, pkt, 24, 2);
                int igmpOff = 14 + 20; pkt[igmpOff] = 0x17; // Type=0x17 (Leave Group)
                Buffer.BlockCopy(grpIp, 0, pkt, igmpOff + 4, 4);
                ushort igmpC = CalculateChecksum(pkt, igmpOff, 8); byte[] igmpCB = BitConverter.GetBytes(igmpC); if (BitConverter.IsLittleEndian) Array.Reverse(igmpCB); Buffer.BlockCopy(igmpCB, 0, pkt, igmpOff + 2, 2);
                pcap_sendpacket(handle, pkt, pkt.Length);
            }
        }
        #endregion

        #region Helpers
        static byte[] BuildUdpPacket(byte[] sM, byte[] dM, byte[] sI, byte[] dI, ushort sP, ushort dP, ulong seq, long ts, out int tL)
        {
            byte[] app = new byte[packetSize]; Encoding.ASCII.GetBytes(SIG).CopyTo(app, 0);
            byte[] sB = BitConverter.GetBytes(seq), tB = BitConverter.GetBytes(ts); if (BitConverter.IsLittleEndian) { Array.Reverse(sB); Array.Reverse(tB); }
            sB.CopyTo(app, 5); tB.CopyTo(app, 13); tL = 42 + packetSize; byte[] pkt = new byte[tL];
            Buffer.BlockCopy(dM, 0, pkt, 0, 6); Buffer.BlockCopy(sM, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
            pkt[14] = 0x45; pkt[15] = (byte)(dscp << 2);
            byte[] lB = BitConverter.GetBytes((ushort)(28 + packetSize)); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, 16, 2);
            pkt[22] = (byte)ttl; pkt[23] = 17; Buffer.BlockCopy(sI, 0, pkt, 26, 4); Buffer.BlockCopy(dI, 0, pkt, 30, 4);
            ushort cs = CalculateChecksum(pkt, 14, 20); byte[] cB = BitConverter.GetBytes(cs); if (BitConverter.IsLittleEndian) Array.Reverse(cB); Buffer.BlockCopy(cB, 0, pkt, 24, 2);
            byte[] spB = BitConverter.GetBytes(sP), dpB = BitConverter.GetBytes(dP); if (BitConverter.IsLittleEndian) { Array.Reverse(spB); Array.Reverse(dpB); }
            Buffer.BlockCopy(spB, 0, pkt, 34, 2); Buffer.BlockCopy(dpB, 0, pkt, 36, 2);
            byte[] ulB = BitConverter.GetBytes((ushort)(8 + packetSize)); if (BitConverter.IsLittleEndian) Array.Reverse(ulB); Buffer.BlockCopy(ulB, 0, pkt, 38, 2);
            Buffer.BlockCopy(app, 0, pkt, 42, packetSize); return pkt;
        }
        static ushort CalculateChecksum(byte[] buf, int off, int len) { uint sum = 0; for (int i = 0; i < len; i += 2) sum += (uint)((buf[off + i] << 8) | buf[off + i + 1]); while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16); return (ushort)~sum; }
        static byte[] GetMulticastMac(string ip) { byte[] b = IPAddress.Parse(ip).GetAddressBytes(); return new byte[] { 0x01, 0x00, 0x5E, (byte)(b[1] & 0x7F), b[2], b[3] }; }
        static byte[] GetLocalMac(string ip) { foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()) { foreach (var a in ni.GetIPProperties().UnicastAddresses) { if (a.Address.ToString() == ip) return ni.GetPhysicalAddress().GetAddressBytes(); } } return new byte[6]; }
        #endregion

        #region User Interaction
        static void InputTask(CancellationTokenSource cts)
        {
            while (!cts.IsCancellationRequested)
            {
                if (Console.KeyAvailable)
                {
                    var k = Console.ReadKey(true); isInputMode = true;
                    Console.WriteLine("\n[MENU] (G)roup, (S)ource, (P)ort, (V)ersion, (M)ode, (D)SCP, (B)W, (s)ize, (T)TL, (C)lear, (Q)uit");
                    Console.Write("> Select key to change: ");
                    try {
                        switch (char.ToUpper(k.KeyChar)) {
                            case 'G': Console.Write("New Group: "); var g = Console.ReadLine(); if (!string.IsNullOrEmpty(g)) { groupAddr = g; needsRestart = true; } break;
                            case 'S': Console.Write("New Source: "); var s = Console.ReadLine(); sourceAddr = s; needsRestart = true; break;
                            case 'O': Console.Write("New Port: "); var p = Console.ReadLine(); if (!string.IsNullOrEmpty(p)) { port = int.Parse(p); needsRestart = true; } break;
                            case 'V': Console.Write("IGMP v[2/3]: "); var v = Console.ReadLine(); if (!string.IsNullOrEmpty(v)) { igmpVersion = int.Parse(v); needsRestart = true; } break;
                            case 'M': Console.Write("Mode [i/e]: "); igmpMode = Console.ReadLine().ToLower().StartsWith("e") ? "exclude" : "include"; needsRestart = true; break;
                            case 'D': Console.Write("New DSCP: "); var d = Console.ReadLine(); if (!string.IsNullOrEmpty(d)) dscp = int.Parse(d); break;
                            case 'B': Console.Write("New BW (Mbps): "); var b = Console.ReadLine(); if (!string.IsNullOrEmpty(b)) { bandwidthMbps = double.Parse(b); RecalculateInterval(); } break;
                            case 'P': Console.Write("New Size (Max 1472): "); var sz = Console.ReadLine(); if (!string.IsNullOrEmpty(sz)) { int sIn = int.Parse(sz); packetSize = Math.Max(1, Math.Min(sIn, 1472)); RecalculateInterval(); } break;
                            case 'T': Console.Write("New TTL: "); var t = Console.ReadLine(); if (!string.IsNullOrEmpty(t)) ttl = int.Parse(t); break;
                            case 'C': lock (statsLock) { txCount = 0; txBytes = 0; rxCount = 0; rxBytes = 0; lostCount = 0; lastSeq = -1; latencies.Clear(); jitter = 0; maxLat = 0; minLat = double.MaxValue; } Console.WriteLine("\n[*] Statistics cleared."); break;
                            case 'R': lock (statsLock) { groupAddr = iGrp; port = iPort; sourceAddr = iSrc; igmpVersion = iVer; igmpMode = iMode; ttl = iTtl; packetSize = iSize; dscp = iDscp; bandwidthMbps = iBw; needsRestart = true; RecalculateInterval(); } Console.WriteLine("\n[*] Parameters restored to initial values."); break;
                            case 'Q': cts.Cancel(); break;
                        }
                    } catch (Exception ex) { Console.WriteLine("\n[!] Input error: " + ex.Message); }
                    isInputMode = false; Console.WriteLine("[*] Applied.");
                }
                Thread.Sleep(100);
            }
        }

        static void MonitorTask(CancellationToken ct)
        {
            long lTx = 0, lRx = 0, lTxB = 0, lRxB = 0; ShowHeader();
            Console.WriteLine("┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬──────────┬────────┐");
            Console.WriteLine("│ Time     │ TX-pps   │ TX-Mbps  │ RX-pps   │ RX-Mbps  │ Loss%    │ Lat-Avg  │ Jitter   │ DSCP   │");
            while (!ct.IsCancellationRequested) {
                if (isInputMode) { Thread.Sleep(500); continue; }
                Thread.Sleep(1000); if (isInputMode) continue;
                long tx = Interlocked.Read(ref txCount), rx = Interlocked.Read(ref rxCount), txB = Interlocked.Read(ref txBytes), rxB = Interlocked.Read(ref rxBytes), lost = Interlocked.Read(ref lostCount);
                if (needsRestart) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine("│ RE-JOINING... (Forging IGMP Report)                                                          │"); Console.ResetColor(); ShowHeader(); }
                double txP = tx - lTx, rxP = rx - lRx, txM = (double)(txB - lTxB) * 8 / 1000000, rxM = (double)(rxB - lRxB) * 8 / 1000000, avgL = 0, curJ = 0;
                lock (statsLock) { if (latencies.Count > 0) avgL = latencies.Average(); curJ = jitter; }
                double tExp = (mode == "recv") ? (rx + lost) : tx, lR = tExp > 0 ? (double)lost / tExp * 100 : 0;
                string dDisp; bool dM; lock (statsLock) { dDisp = actualDscp >= 0 ? string.Format("{0}({1})", dscp, actualDscp) : dscp.ToString(); dM = (dscp == actualDscp || actualDscp < 0); }
                Console.Write("│ {0,-8} │", DateTime.Now.ToString("HH:mm:ss"));
                Console.ForegroundColor = txP > 0 ? ConsoleColor.White : ConsoleColor.DarkGray; Console.Write(" {0,8} │ {1,8:F2} │", txP, txM);
                Console.ForegroundColor = rxP > 0 ? ConsoleColor.Green : ConsoleColor.DarkGray; Console.Write(" {0,8} │ {1,8:F2} │", rxP, rxM);
                if (lR > 0.01) Console.ForegroundColor = ConsoleColor.Red; else if (mode == "recv" && rxP > 0) Console.ForegroundColor = ConsoleColor.Green; else Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" {0,7:F2}% │", lR); Console.ForegroundColor = avgL > 10000 ? ConsoleColor.Yellow : (avgL > 0 ? ConsoleColor.Cyan : ConsoleColor.DarkGray);
                Console.Write(" {0,6:F0}us │ {1,6:F0}us │", avgL, curJ);
                if (!dM) Console.ForegroundColor = ConsoleColor.Red; else if (actualDscp >= 0) Console.ForegroundColor = ConsoleColor.Green; else Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(" {0,-6} │", dDisp); Console.ResetColor();
                lTx = tx; lRx = rx; lTxB = txB; lRxB = rxB;
            }
        }

        static async Task HttpTask(CancellationToken ct)
        {
            HttpListener listener = new HttpListener();
            bool started = false;
            for (int i = 0; i < 10; i++) {
                try {
                    listener.Prefixes.Clear();
                    listener.Prefixes.Add(string.Format("http://localhost:{0}/", webPort));
                    listener.Prefixes.Add(string.Format("http://127.0.0.1:{0}/", webPort));
                    listener.Start();
                    started = true; break;
                } catch {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[!] Port {0} is busy, trying {1}...", webPort, webPort + 1);
                    Console.ResetColor(); webPort++;
                }
            }

            if (!started) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] Failed to start WebUI after 10 attempts."); Console.ResetColor(); return; }
            
            Console.ForegroundColor = ConsoleColor.Cyan; Console.WriteLine("[*] WebUI started at http://localhost:{0}", webPort); Console.ResetColor();
            try { Process.Start(new ProcessStartInfo(string.Format("http://localhost:{0}", webPort)) { UseShellExecute = true }); } catch {}

            try {
                using (ct.Register(() => { try { listener.Stop(); } catch {} })) {
                    while (!ct.IsCancellationRequested) {
                        var ctx = await listener.GetContextAsync();
                        Task.Run(() => {
                            try {
                                string path = ctx.Request.Url.AbsolutePath;
                                if (path == "/api/stats") {
                                    double avgL = 0, curJ = 0; string lQ = "-";
                                    lock (statsLock) { 
                                        if (latencies.Count > 0) avgL = latencies.Average(); curJ = jitter; 
                                        if (lastQueryTime != DateTime.MinValue) lQ = (DateTime.Now - lastQueryTime).TotalSeconds.ToString("F0") + "s ago";
                                    }
                                    string json = string.Format("{{\"txCount\":{0},\"txBytes\":{1},\"rxCount\":{2},\"rxBytes\":{3},\"lost\":{4},\"avgLat\":{5},\"jitter\":{6},\"dscp\":{7},\"actualDscp\":{8},\"group\":\"{9}\",\"port\":{10},\"mode\":\"{11}\",\"version\":{12},\"igmpMode\":\"{13}\",\"source\":\"{14}\",\"ttl\":{15},\"size\":{16},\"bw\":{17},\"mac\":\"{18}\",\"actTtl\":{19},\"lastQ\":\"{20}\",\"frag\":{21}}}", 
                                        txCount, txBytes, rxCount, rxBytes, lostCount, avgL, curJ, dscp, actualDscp, groupAddr, port, mode, igmpVersion, igmpMode, sourceAddr, ttl, packetSize, bandwidthMbps, lastSrcMac, lastTtl, lQ, fragDetected ? "true" : "false");
                                    byte[] b = Encoding.UTF8.GetBytes(json); ctx.Response.ContentType = "application/json"; ctx.Response.OutputStream.Write(b, 0, b.Length);
                                } else if (path == "/api/control") {
                                    var q = ctx.Request.QueryString;
                                    if (q["group"] != null) { groupAddr = q["group"]; needsRestart = true; }
                                    if (q["port"] != null) { int p; if (int.TryParse(q["port"], out p)) { port = p; needsRestart = true; } }
                                    if (q["source"] != null) { sourceAddr = q["source"]; needsRestart = true; }
                                    if (q["v"] != null) { int v; if (int.TryParse(q["v"], out v)) { igmpVersion = v; needsRestart = true; } }
                                    if (q["mode"] != null) { igmpMode = q["mode"]; needsRestart = true; }
                                    if (q["dscp"] != null) { int d; if (int.TryParse(q["dscp"], out d)) dscp = d; }
                                    if (q["bw"] != null) { double b; if (double.TryParse(q["bw"], out b)) { bandwidthMbps = b; RecalculateInterval(); } }
                                    if (q["ttl"] != null) { int t; if (int.TryParse(q["ttl"], out t)) ttl = t; }
                                    if (q["size"] != null) { int s; if (int.TryParse(q["size"], out s)) { packetSize = Math.Max(1, Math.Min(s, 1472)); RecalculateInterval(); } }
                                    
                                    Console.WriteLine("\n[*] Parameters updated via WebUI.");
                                    ctx.Response.StatusCode = 200;
                                } else if (path == "/api/resetStats") {
                                    lock (statsLock) {
                                        txCount = 0; txBytes = 0; rxCount = 0; rxBytes = 0; lostCount = 0; lastSeq = -1;
                                        latencies.Clear(); jitter = 0; maxLat = 0; minLat = double.MaxValue;
                                        lastSrcMac = "-"; lastTtl = -1; lastQueryTime = DateTime.MinValue; fragDetected = false;
                                    }
                                    Console.WriteLine("\n[*] Statistics cleared via WebUI."); ctx.Response.StatusCode = 200;
                                } else if (path == "/api/resetParams") {
                                    lock (statsLock) {
                                        groupAddr = iGrp; port = iPort; sourceAddr = iSrc; igmpVersion = iVer; igmpMode = iMode; ttl = iTtl; packetSize = iSize; dscp = iDscp; bandwidthMbps = iBw;
                                        needsRestart = true; RecalculateInterval();
                                    }
                                    Console.WriteLine("\n[*] Parameters restored to initial values via WebUI."); ctx.Response.StatusCode = 200;
                                } else {
                                    byte[] b = Encoding.UTF8.GetBytes(WebUI); ctx.Response.ContentType = "text/html"; ctx.Response.OutputStream.Write(b, 0, b.Length);
                                }
                            } catch (Exception ex) { if (!ct.IsCancellationRequested) Console.WriteLine("\n[!] WebAPI Error: " + ex.Message); }
                            finally { try { ctx.Response.Close(); } catch {} }
                        }, ct);
                    }
                }
            } catch (Exception ex) { if (!ct.IsCancellationRequested) Console.WriteLine("\n[!] HttpListener Error: " + ex.Message); }
            finally { if(listener.IsListening) listener.Close(); }
        }
        #endregion

        static void RecalculateInterval() { if (bandwidthMbps > 0) targetIntervalMs = 1000.0 / (bandwidthMbps * 1000000.0 / (packetSize * 8)); else targetIntervalMs = (double)interval; }
        
        static void ShowWizard() {
            Console.WriteLine("\n=== mtool Visual Setup ===");
            IntPtr alldevs = IntPtr.Zero; byte[] err = new byte[256]; pcap_findalldevs(ref alldevs, err);
            List<IntPtr> dPtrs = new List<IntPtr>(); IntPtr cur = alldevs; while(cur!=IntPtr.Zero){ dPtrs.Add(cur); pcap_if iface=(pcap_if)Marshal.PtrToStructure(cur, typeof(pcap_if)); cur=iface.next; }
            for (int i = 0; i < dPtrs.Count; i++) { pcap_if f = (pcap_if)Marshal.PtrToStructure(dPtrs[i], typeof(pcap_if)); Console.WriteLine(" [{0}] {1} (IP: {2})", i, Marshal.PtrToStringAnsi(f.description), GetIps(f.addresses)); }
            int idx = 0;
            while (true) {
                Console.Write("\nSelect Interface Index [0-{0}, Default: 0]: ", dPtrs.Count - 1);
                var idxIn = Console.ReadLine();
                if (string.IsNullOrEmpty(idxIn)) { idx = 0; break; }
                if (int.TryParse(idxIn, out idx) && idx >= 0 && idx < dPtrs.Count) break;
                Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] Invalid index. Please select from 0 to {0}.", dPtrs.Count - 1); Console.ResetColor();
            }
            pcap_if s = (pcap_if)Marshal.PtrToStructure(dPtrs[idx], typeof(pcap_if));
            interfaceName = Marshal.PtrToStringAnsi(s.name); interfaceAddr = GetFirstIp(s.addresses);
            Console.Write("Mode [Send/Receive, Default: Send]: "); var mVar = Console.ReadLine().ToLower(); mode = mVar.StartsWith("r") ? "recv" : "send";
            Console.Write("Group [Default: 239.1.1.1]: "); var gIn = Console.ReadLine(); if (!string.IsNullOrEmpty(gIn)) groupAddr = gIn;
            
            while (true) {
                Console.Write("Port [Default: 5001]: "); var pIn = Console.ReadLine();
                if (string.IsNullOrEmpty(pIn)) { port = 5001; break; }
                if (int.TryParse(pIn, out port) && port > 0 && port < 65536) break;
                Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] Invalid port number. Please enter 1-65535."); Console.ResetColor();
            }

            int defW = (mode == "recv" ? 8081 : 8080);
            while (true) {
                Console.Write("WebUI Port [Default: {0}]: ", defW); var wIn = Console.ReadLine();
                if (string.IsNullOrEmpty(wIn)) { webPort = defW; break; }
                if (int.TryParse(wIn, out webPort) && webPort > 0 && webPort < 65536) break;
                Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] Invalid WebUI port. Please enter 1-65535."); Console.ResetColor();
            }
            pcap_freealldevs(alldevs);
        }

        static string GetIps(IntPtr a){ List<string> l=new List<string>(); while(a!=IntPtr.Zero){ pcap_addr p=(pcap_addr)Marshal.PtrToStructure(a, typeof(pcap_addr)); if(p.addr!=IntPtr.Zero && Marshal.ReadInt16(p.addr)==2){ sockaddr_in sin=(sockaddr_in)Marshal.PtrToStructure(p.addr, typeof(sockaddr_in)); l.Add(new IPAddress(BitConverter.GetBytes(sin.sin_addr)).ToString()); } a=p.next; } return string.Join(",", l.ToArray()); }
        static string GetFirstIp(IntPtr a){ while(a!=IntPtr.Zero){ pcap_addr p=(pcap_addr)Marshal.PtrToStructure(a, typeof(pcap_addr)); if(p.addr!=IntPtr.Zero && Marshal.ReadInt16(p.addr)==2){ return new IPAddress(BitConverter.GetBytes(((sockaddr_in)Marshal.PtrToStructure(p.addr, typeof(sockaddr_in))).sin_addr)).ToString(); } a=p.next; } return "0.0.0.0"; }
        static void ParseArgs(string[] args) { 
            for(int i=0;i<args.Length;i++){ 
                string a = args[i].ToLower();
                if (i + 1 >= args.Length && a != "-h" && a != "--help") continue;
                switch(a){ 
                    case "-g": case "-group": groupAddr=args[++i]; break; 
                    case "-p": case "-port": port=int.Parse(args[++i]); break; 
                    case "-i": case "-interface": interfaceAddr=args[++i]; interfaceName=FindInterfaceName(interfaceAddr); break; 
                    case "-s": case "-source": sourceAddr=args[++i]; break; 
                    case "-v": case "-igmp": igmpVersion=int.Parse(args[++i]); break; 
                    case "-m": case "-mode": mode=args[++i].ToLower(); break; 
                    case "-q": case "-qos": case "-dscp": dscp=int.Parse(args[++i]); break; 
                    case "-b": case "-bw": case "-bandwidth": bandwidthMbps=double.Parse(args[++i]); break; 
                    case "-t": case "-ttl": ttl=int.Parse(args[++i]); break; 
                    case "-sz": case "-size": packetSize=int.Parse(args[++i]); break; 
                    case "-w": case "-webport": webPort=int.Parse(args[++i]); break; 
                } 
            } 
            RecalculateInterval();
        }
        static string FindInterfaceName(string ip) {
            IntPtr alldevs = IntPtr.Zero; byte[] err = new byte[256]; pcap_findalldevs(ref alldevs, err);
            IntPtr cur = alldevs; while(cur!=IntPtr.Zero){ pcap_if iface=(pcap_if)Marshal.PtrToStructure(cur, typeof(pcap_if)); if(GetIps(iface.addresses).Contains(ip)) { string n = Marshal.PtrToStringAnsi(iface.name); pcap_freealldevs(alldevs); return n; } cur=iface.next; }
            pcap_freealldevs(alldevs); return "";
        }
        static bool IsAdministrator(){ using(WindowsIdentity id=WindowsIdentity.GetCurrent()){ return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator); } }
        static bool CheckNpcap() { try { pcap_lib_version(); return true; } catch { Console.WriteLine("Npcap not found. Please install Npcap."); Console.ReadKey(); return false; } }

        private const string WebUI = @"<!DOCTYPE html><html lang='ja'><head><meta charset='utf-8'><title>MTOOL | Dashboard</title><style>
:root{--bg:#0f172a;--card:#1e293b;--tx:#00f2fe;--lat:#7117ea;--jit:#f6ad55}
body{background:var(--bg);color:#f1f5f9;font-family:system-ui,-apple-system,sans-serif;margin:0;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px}
.card{background:var(--card);border-radius:12px;padding:20px;border:1px solid rgba(255,255,255,0.05);box-shadow:0 10px 15px -3px rgba(0,0,0,0.1)}
.hidden{display:none}
h1,h2{margin:0 0 15px 0;font-size:1.2rem;background:linear-gradient(90deg,var(--tx),#7117ea);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.val{font-size:3.5rem;font-weight:800;font-variant-numeric:tabular-nums;line-height:1}
.unit{font-size:1.2rem;color:#94a3b8;margin-left:8px}
.row{display:flex;justify-content:space-between;margin:8px 0;color:#94a3b8}
input{background:#0f172a;border:1px solid #334155;color:white;padding:8px;border-radius:4px;width:100px}
.btn{background:linear-gradient(135deg,var(--tx),#7117ea);border:none;color:white;padding:12px;border-radius:8px;cursor:pointer;width:100%;font-weight:700;margin-top:15px}
svg{width:100%;height:120px;margin-top:10px;overflow:visible}
polyline{fill:none;stroke-width:2;vector-effect:non-scaling-stroke}
text{fill:#94a3b8;font-size:10px;font-family:monospace}
.guide{stroke:rgba(255,255,255,0.1);stroke-width:1;stroke-dasharray:4}
</style></head><body>
<div style='display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:25px'>
    <h1 style='font-size:1.8rem'>MTOOL <span id='modeBadge' style='font-size:14px;padding:4px 8px;border-radius:99px;background:#334155;color:white;margin-left:10px'>-</span></h1>
    <div style='text-align:right'>
        <div id='info' style='color:#94a3b8;font-size:14px'>Waiting for stats...</div>
        <div id='igmpInfo' style='color:var(--tx);font-size:12px;margin-top:4px;font-family:monospace'>Last IGMP Query: -</div>
    </div>
</div>
<div class='grid'>
    <!-- TX View -->
    <div id='txCard' class='card'><h2>Transmission (TX)</h2><div class='val' id='txMbps'>0.0<span class='unit'>Mbps</span></div><div class='row'><span>Throughput</span><span id='txPps'>0 pps</span></div>
        <svg viewBox='-40 0 440 125'>
            <line x1='0' y1='0' x2='400' y2='0' class='guide' /><line x1='0' y1='50' x2='400' y2='50' class='guide' /><line x1='0' y1='100' x2='400' y2='100' class='guide' />
            <text x='-5' y='5' text-anchor='end' id='txY2'>-</text><text x='-5' y='55' text-anchor='end' id='txY1'>-</text><text x='-5' y='100' text-anchor='end'>0</text>
            <text x='0' y='120'>-100s</text><text x='200' y='120' text-anchor='middle'>-50s</text><text x='400' y='120' text-anchor='end'>Now</text>
            <polyline id='chartTx' style='stroke:var(--tx)' />
        </svg>
    </div>
    <!-- RX View -->
    <div id='rxCard' class='card hidden'><h2>Reception (RX)</h2><div class='val' id='rxMbps'>0.0<span class='unit'>Mbps</span></div><div class='row'><span>Throughput</span><span id='rxPps'>0 pps</span></div>
        <svg viewBox='-40 0 440 125'>
            <line x1='0' y1='0' x2='400' y2='0' class='guide' /><line x1='0' y1='50' x2='400' y2='50' class='guide' /><line x1='0' y1='100' x2='400' y2='100' class='guide' />
            <text x='-5' y='5' text-anchor='end' id='rxY2'>-</text><text x='-5' y='55' text-anchor='end' id='rxY1'>-</text><text x='-5' y='100' text-anchor='end'>0</text>
            <text x='0' y='120'>-100s</text><text x='200' y='120' text-anchor='middle'>-50s</text><text x='400' y='120' text-anchor='end'>Now</text>
            <polyline id='chartRx' style='stroke:var(--tx)' />
        </svg>
    </div>
    <!-- Latency View -->
    <div id='latCard' class='card hidden'><h2>Latency (Average)</h2><div class='val' id='latVal'>0<span class='unit'>us</span></div>
        <svg viewBox='-40 0 440 125'>
            <line x1='0' y1='0' x2='400' y2='0' class='guide' /><line x1='0' y1='50' x2='400' y2='50' class='guide' /><line x1='0' y1='100' x2='400' y2='100' class='guide' />
            <text x='-5' y='5' text-anchor='end' id='latY2'>-</text><text x='-5' y='55' text-anchor='end' id='latY1'>-</text><text x='-5' y='100' text-anchor='end'>0</text>
            <text x='0' y='120'>-100s</text><text x='200' y='120' text-anchor='middle'>-50s</text><text x='400' y='120' text-anchor='end'>Now</text>
            <polyline id='chartLat' style='stroke:var(--lat)' />
        </svg>
    </div>
    <!-- Jitter View -->
    <div id='jitCard' class='card hidden'><h2>Jitter (Variation)</h2><div class='val' id='jitVal'>0<span class='unit'>us</span></div>
        <svg viewBox='-40 0 440 125'>
            <line x1='0' y1='0' x2='400' y2='0' class='guide' /><line x1='0' y1='50' x2='400' y2='50' class='guide' /><line x1='0' y1='100' x2='400' y2='100' class='guide' />
            <text x='-5' y='5' text-anchor='end' id='jitY2'>-</text><text x='-5' y='55' text-anchor='end' id='jitY1'>-</text><text x='-5' y='100' text-anchor='end'>0</text>
            <text x='0' y='120'>-100s</text><text x='200' y='120' text-anchor='middle'>-50s</text><text x='400' y='120' text-anchor='end'>Now</text>
            <polyline id='chartJit' style='stroke:var(--jit)' />
        </svg>
    </div>
    <!-- Quality -->
    <div id='qualCard' class='card hidden'><h2>Packet Quality</h2><div class='val' id='lossVal'>0.00<span class='unit'>% Loss</span></div>
        <div class='row'><span>Detected DSCP</span><span id='dscpTrue'>-</span></div>
        <div class='row'><span>Actual TTL</span><span id='ttlTrue'>-</span></div>
        <div class='row'><span>Source MAC</span><span id='macTrue' style='font-size:11px'>-</span></div>
        <div class='row' id='fragRow' style='color:#f87171'><span>IP Fragmentation</span><span id='fragTrue'>None</span></div>
    </div>
    <!-- Control -->
    <div class='card' style='grid-column:span 2'><h2>Control Panel (<span id='ctrlMode'>-</span>)</h2>
        <div style='display:grid;grid-template-columns:1fr 1fr;gap:20px'>
            <div>
                <div class='row'><span>Target Group</span><input type='text' id='gIn' style='width:160px'></div>
                <div class='row'><span>Target Port</span><input type='number' id='pIn'></div>
                <div class='row'><span>Source IP</span><input type='text' id='sIn' style='width:160px'></div>
                <div id='txOnly1'>
                    <div class='row'><span>Bandwidth (Mbps)</span><input type='number' id='bIn'></div>
                </div>
            </div>
            <div>
                <div class='row'><span>IGMP Version</span><select id='vIn' style='background:#0f172a;color:white;padding:8px;border-radius:4px;width:120px'><option value='2'>v2</option><option value='3'>v3</option></select></div>
                <div class='row'><span>IGMP Mode</span><select id='mIn' style='background:#0f172a;color:white;padding:8px;border-radius:4px;width:120px'><option value='include'>Include</option><option value='exclude'>Exclude</option></select></div>
                <div id='txOnly2'>
                    <div class='row'><span>DSCP (0-63)</span><input type='number' id='dIn' min='0' max='63'></div>
                    <div class='row'><span>TTL</span><input type='number' id='tIn' min='1' max='255'></div>
                    <div class='row'><span>Packet Size (Bytes)</span><input type='number' id='szIn'></div>
                </div>
            </div>
        </div>
        <div style='display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px'>
            <button class='btn' onclick='update()'>Apply Changes</button>
            <button class='btn' style='background:#475569' onclick='resetStats()'>Reset Stats</button>
            <button class='btn' style='background:#334155' onclick='resetParams()'>Restore Defaults</button>
        </div>
    </div>
</div>
<script>
let stats = { tx:[], rx:[], lat:[], jit:[] };
let lTxC = 0, lRxC = 0, lTxB = 0, lRxB = 0;
async function tick() {
    try {
        const r = await fetch('/api/stats'); const d = await r.json();
        const send = d.mode == 'send';
        document.getElementById('modeBadge').innerText = d.mode.toUpperCase();
        document.getElementById('ctrlMode').innerText = send ? 'Sender Settings' : 'Receiver Settings';
        document.getElementById('info').innerText = `Target: ${d.group}:${d.port}`;
        const txPps = d.txCount - lTxC; const rxPps = d.rxCount - lRxC;
        lTxC = d.txCount; lRxC = d.rxCount;
        if(send){
            document.getElementById('txCard').classList.remove('hidden');
            document.getElementById('rxCard').classList.add('hidden');
            document.getElementById('latCard').classList.add('hidden');
            document.getElementById('jitCard').classList.add('hidden');
            document.getElementById('qualCard').classList.add('hidden');
            document.getElementById('txOnly1').classList.remove('hidden');
            document.getElementById('txOnly2').classList.remove('hidden');
            document.getElementById('igmpInfo').style.display = 'none';
            const mbps = (d.txBytes - lTxB)*8/1000000; lTxB = d.txBytes;
            document.getElementById('txMbps').innerHTML = mbps.toFixed(2) + '<span class unit>Mbps</span>';
            document.getElementById('txPps').innerText = txPps + ' pps';
            push(stats.tx, mbps, 'chartTx');
        } else {
            document.getElementById('txCard').classList.add('hidden');
            document.getElementById('rxCard').classList.remove('hidden');
            document.getElementById('latCard').classList.remove('hidden');
            document.getElementById('jitCard').classList.remove('hidden');
            document.getElementById('qualCard').classList.remove('hidden');
            document.getElementById('txOnly1').classList.add('hidden');
            document.getElementById('txOnly2').classList.add('hidden');
            document.getElementById('igmpInfo').style.display = 'block';
            const mbps = (d.rxBytes - lRxB)*8/1000000; lRxB = d.rxBytes;
            document.getElementById('rxMbps').innerHTML = mbps.toFixed(2) + '<span class unit>Mbps</span>';
            document.getElementById('rxPps').innerText = rxPps + ' pps';
            document.getElementById('latVal').innerHTML = Math.round(d.avgLat) + '<span class unit>us</span>';
            document.getElementById('jitVal').innerHTML = Math.round(d.jitter) + '<span class unit>us</span>';
            document.getElementById('lossVal').innerHTML = (d.lost/(d.rxCount+d.lost)*100).toFixed(2) + '<span class unit>% Loss</span>';
            document.getElementById('dscpTrue').innerText = d.actualDscp>=0 ? d.actualDscp : '-';
            document.getElementById('ttlTrue').innerText = d.actTtl>=0 ? d.actTtl : '-';
            document.getElementById('macTrue').innerText = d.mac;
            document.getElementById('fragTrue').innerText = d.frag ? 'DETECTED' : 'None';
            document.getElementById('fragRow').style.visibility = d.frag ? 'visible' : 'hidden';
            document.getElementById('igmpInfo').innerText = 'Last IGMP Query: ' + d.lastQ;
            push(stats.rx, mbps, 'chartRx'); push(stats.lat, d.avgLat, 'chartLat'); push(stats.jit, d.jitter, 'chartJit');
        }
        if(!inputInit) initInputs(d);
    } catch(e) {} setTimeout(tick, 1000);
}
let inputInit = false;
function initInputs(d) {
    document.getElementById('gIn').value = d.group;
    document.getElementById('pIn').value = d.port;
    document.getElementById('sIn').value = d.source || '';
    document.getElementById('bIn').value = d.bw;
    document.getElementById('vIn').value = d.version || '2';
    document.getElementById('mIn').value = d.igmpMode || 'include';
    document.getElementById('dIn').value = d.dscp;
    document.getElementById('tIn').value = d.ttl || 1;
    document.getElementById('szIn').value = d.size || 64;
    inputInit = true;
}
function push(arr, v, id) {
    arr.push(v); if(arr.length>100) arr.shift();
    const max = Math.max(...arr, 1);
    const pts = arr.map((v, i) => i*(400/100) + ',' + (100 - (v/max*90))).join(' ');
    document.getElementById(id).setAttribute('points', pts);
    const prefix = id.replace('chart', '').toLowerCase();
    const y2 = document.getElementById(prefix + 'Y2'), y1 = document.getElementById(prefix + 'Y1');
    if(y2) y2.textContent = Math.round(max); if(y1) y1.textContent = Math.round(max/2);
}
function resetStats() {
    if(!confirm('Reset all statistics?')) return;
    fetch('/api/resetStats').then(r => {
        if(r.ok) { stats = { tx:[], rx:[], lat:[], jit:[] }; lTxC = 0; lRxC = 0; lTxB = 0; lRxB = 0; }
    });
}
function resetParams() {
    if(!confirm('Restore initial parameters?')) return;
    fetch('/api/resetParams').then(r => {
        if(r.ok) { inputInit = false; }
    });
}
function update() {
    const g = document.getElementById('gIn').value, p = document.getElementById('pIn').value, s = document.getElementById('sIn').value;
    const b = document.getElementById('bIn').value, v = document.getElementById('vIn').value, m = document.getElementById('mIn').value;
    const d = document.getElementById('dIn').value, t = document.getElementById('tIn').value, sz = document.getElementById('szIn').value;
    const btn = document.querySelector('.btn'), old = btn.innerText;
    btn.innerText = 'Applying...'; btn.disabled = true;
    fetch(`/api/control?group=${g}&port=${p}&source=${s}&bw=${b}&v=${v}&mode=${m}&dscp=${d}&ttl=${t}&size=${sz}`)
        .then(r => { if(!r.ok) alert('Update Failed'); })
        .catch(e => alert('Network Error'))
        .finally(() => { setTimeout(() => { btn.innerText = old; btn.disabled = false; }, 500); });
}
tick();
</script></body></html>";
    }
}
