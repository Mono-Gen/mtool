using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;

namespace MMulticastTool
{
    public class NetworkEngine
    {
        private readonly AppConfig _config;
        private readonly AppStats _stats;
        private readonly Action<string, string> _logCallback;

        #region P/Invoke Definitions
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
        #endregion

        public NetworkEngine(AppConfig config, AppStats stats, Action<string, string> logCallback)
        {
            _config = config;
            _stats = stats;
            _logCallback = logCallback;
        }

        public static bool CheckNpcap()
        {
            try { pcap_lib_version(); return true; }
            catch { return false; }
        }

        public void SenderTask(CancellationToken ct)
        {
            byte[] err = new byte[256];
            IntPtr handle = pcap_open_live(_config.InterfaceName, 65536, 1, 100, err);
            if (handle == IntPtr.Zero) return;

            try {
                while (!ct.IsCancellationRequested)
                {
                    try {
                        _config.NeedsRestart = false;
                        _config.SyncActive();

                        bool wasRunning = _config.IsRunning;
                        if (_config.IsRunning) {
                            SendManualIgmp(handle);
                            if (_logCallback != null) _logCallback.Invoke("IGMP_JOIN", string.Format("Group:{0}, Ver:v{1}, Mode:{2}, Src:{3}", _config.ActiveGrp, _config.ActiveVer, _config.ActiveIgmpMode, _config.ActiveSrc));
                        }

                        ulong seq = 0; 
                        long ticksPerMs = Stopwatch.Frequency / 1000;
                        byte[] srcMac = GetLocalMac(_config.InterfaceAddr), dstMac = GetMulticastMac(_config.GroupAddr);
                        byte[] srcIp = string.IsNullOrEmpty(_config.SourceAddr) ? IPAddress.Parse(_config.InterfaceAddr).GetAddressBytes() : IPAddress.Parse(_config.SourceAddr).GetAddressBytes();
                        byte[] dstIp = IPAddress.Parse(_config.GroupAddr).GetAddressBytes();
                        long lastIgmp = Stopwatch.GetTimestamp();

                        while (!ct.IsCancellationRequested && !_config.NeedsRestart)
                        {
                            if (wasRunning != _config.IsRunning) {
                                if (_config.IsRunning) { SendManualIgmp(handle); if (_logCallback != null) _logCallback.Invoke("IGMP_JOIN", string.Format("Group:{0}, Ver:v{1}, Mode:{2}, Src:{3}", _config.ActiveGrp, _config.ActiveVer, _config.ActiveIgmpMode, _config.ActiveSrc)); }
                                else { SendManualLeave(handle, _config.ActiveGrp, _config.ActiveSrc, _config.ActiveVer, _config.ActiveIgmpMode); if (_logCallback != null) _logCallback.Invoke("IGMP_LEAVE", string.Format("Group:{0}", _config.ActiveGrp)); }
                                wasRunning = _config.IsRunning;
                            }
                            if (!_config.IsRunning) { Thread.Sleep(100); continue; }

                            if ((Stopwatch.GetTimestamp() - lastIgmp) / (double)Stopwatch.Frequency > 30) { SendManualIgmp(handle); lastIgmp = Stopwatch.GetTimestamp(); }
                            long nowTicks = Stopwatch.GetTimestamp(); int tLen;
                            byte[] pkt = BuildUdpPacket(srcMac, dstMac, srcIp, dstIp, (ushort)_config.Port, (ushort)_config.Port, seq, nowTicks, out tLen);
                            if (pkt != null) pcap_sendpacket(handle, pkt, tLen); 
                            Interlocked.Increment(ref _stats.TxCount); Interlocked.Add(ref _stats.TxBytes, tLen - MToolCore.TOTAL_NETWORK_HEADERS); seq++;
                            
                            _config.ActiveDscp = _config.Dscp; _config.ActiveTtl = _config.Ttl; _config.ActiveSize = _config.PacketSize; _config.ActiveBw = _config.BandwidthMbps;
                            if (_config.TargetIntervalMs < 15) { while ((double)(Stopwatch.GetTimestamp() - nowTicks) / ticksPerMs < _config.TargetIntervalMs) { Thread.Yield(); } }
                            else { Thread.Sleep((int)_config.TargetIntervalMs); }
                        }
                        if (wasRunning && !ct.IsCancellationRequested) {
                            SendManualLeave(handle, _config.ActiveGrp, _config.ActiveSrc, _config.ActiveVer, _config.ActiveIgmpMode);
                            if (_logCallback != null) _logCallback.Invoke("IGMP_LEAVE", string.Format("Group:{0} (Task Stop)", _config.ActiveGrp));
                            Thread.Sleep(100);
                        }
                    } catch (Exception) { if (!ct.IsCancellationRequested) Thread.Sleep(1000); }
                }
            } finally { pcap_close(handle); }
        }

        public void ReceiverTask(CancellationToken ct)
        {
            byte[] err = new byte[256];
            IntPtr handle = pcap_open_live(_config.InterfaceName, 65536, 1, 10, err);
            if (handle == IntPtr.Zero) return;

            try {
                while (!ct.IsCancellationRequested)
                {
                    try {
                        _config.NeedsRestart = false;
                        _config.SyncActive();
                        
                        bool wasRunning = _config.IsRunning;
                        if (_config.IsRunning) { SendManualIgmp(handle); if (_logCallback != null) _logCallback.Invoke("IGMP_JOIN", string.Format("Group:{0}, Ver:v{1}, Mode:{2}, Src:{3}", _config.ActiveGrp, _config.ActiveVer, _config.ActiveIgmpMode, _config.ActiveSrc)); }

                        string filter = string.Format("(udp and dst port {0} and dst host {1}) or igmp", _config.Port, _config.GroupAddr);
                        if (_config.IgmpVersion == 3 && !string.IsNullOrEmpty(_config.SourceAddr)) {
                            if (_config.IgmpMode == "include") filter = string.Format("(udp and dst port {0} and dst host {1} and src host {2}) or igmp", _config.Port, _config.GroupAddr, _config.SourceAddr);
                            else filter = string.Format("(udp and dst port {0} and dst host {1} and not src host {2}) or igmp", _config.Port, _config.GroupAddr, _config.SourceAddr);
                        }
                        IntPtr fp = Marshal.AllocHGlobal(128);
                        if (pcap_compile(handle, fp, filter, 1, 0) == 0) pcap_setfilter(handle, fp);
                        Marshal.FreeHGlobal(fp);

                        double lastLat = -1; IntPtr hPtr = IntPtr.Zero, dPtr = IntPtr.Zero;
                        long lastIgmp = Stopwatch.GetTimestamp();
                        while (!ct.IsCancellationRequested && !_config.NeedsRestart)
                        {
                            if (wasRunning != _config.IsRunning) {
                                if (_config.IsRunning) { SendManualIgmp(handle); if (_logCallback != null) _logCallback.Invoke("IGMP_JOIN", string.Format("Group:{0}, Ver:v{1}, Mode:{2}, Src:{3}", _config.ActiveGrp, _config.ActiveVer, _config.ActiveIgmpMode, _config.ActiveSrc)); }
                                else { SendManualLeave(handle, _config.ActiveGrp, _config.ActiveSrc, _config.ActiveVer, _config.ActiveIgmpMode); if (_logCallback != null) _logCallback.Invoke("IGMP_LEAVE", string.Format("Group:{0}", _config.ActiveGrp)); }
                                wasRunning = _config.IsRunning;
                            }
                            if (!_config.IsRunning) { Thread.Sleep(100); continue; }

                            if ((Stopwatch.GetTimestamp() - lastIgmp) / (double)Stopwatch.Frequency > 30) { SendManualIgmp(handle); lastIgmp = Stopwatch.GetTimestamp(); }
                            int res = pcap_next_ex(handle, ref hPtr, ref dPtr);
                            if (res <= 0) continue;
                            long nowTicks = Stopwatch.GetTimestamp(); pcap_pkthdr hdr = (pcap_pkthdr)Marshal.PtrToStructure(hPtr, typeof(pcap_pkthdr));
                            if (hdr.caplen < MToolCore.TOTAL_NETWORK_HEADERS) continue;
                            byte[] pkt = new byte[hdr.caplen]; Marshal.Copy(dPtr, pkt, 0, (int)hdr.caplen);
                            string srcM = BitConverter.ToString(pkt, 6, 6).Replace("-", ":");
                            int ipProt = pkt[23], ttlV = pkt[22];
                            bool isF = (pkt[20] & 0x20) != 0 || (pkt[20] & 0x1F) != 0 || pkt[21] != 0;
                            int payloadOff = MToolCore.ETHERNET_HEADER_SIZE + (pkt[MToolCore.ETHERNET_HEADER_SIZE] & 0x0F) * 4 + MToolCore.UDP_HEADER_SIZE;

                            if (ipProt == 2) { // IGMP
                                int igmpOff = MToolCore.ETHERNET_HEADER_SIZE + (pkt[MToolCore.ETHERNET_HEADER_SIZE] & 0x0F) * 4;
                                if (pkt.Length > igmpOff && pkt[igmpOff] == 0x11) {
                                    lock (_stats.StatsLock) _stats.LastQueryTime = DateTime.Now;
                                    string sIP = string.Format("{0}.{1}.{2}.{3}", pkt[26], pkt[27], pkt[28], pkt[29]);
                                    if (_logCallback != null) _logCallback.Invoke("IGMP_QUERY", "Received from " + sIP);
                                }
                            } else if (pkt.Length - payloadOff >= MToolCore.HEADER_SIZE && Encoding.ASCII.GetString(pkt, payloadOff, 5) == MToolCore.SIG) {
                                byte[] sB = new byte[8], tB = new byte[8]; Buffer.BlockCopy(pkt, payloadOff + 5, sB, 0, 8); Buffer.BlockCopy(pkt, payloadOff + 13, tB, 0, 8);
                                if (BitConverter.IsLittleEndian) { Array.Reverse(sB); Array.Reverse(tB); }
                                long seq = (long)BitConverter.ToUInt64(sB, 0), tsT = BitConverter.ToInt64(tB, 0);
                                double latUs = (double)(nowTicks - tsT) * 1000000.0 / Stopwatch.Frequency;
                                Interlocked.Increment(ref _stats.RxCount); Interlocked.Add(ref _stats.RxBytes, pkt.Length - payloadOff);
                                lock (_stats.StatsLock) {
                                    _stats.Latencies.Add(latUs); if (_stats.Latencies.Count > 1000) _stats.Latencies.RemoveAt(0);
                                    if (latUs > _stats.MaxLat) _stats.MaxLat = latUs; if (latUs < _stats.MinLat) _stats.MinLat = latUs;
                                    if (lastLat >= 0) _stats.Jitter = _stats.Jitter == 0 ? Math.Abs(latUs - lastLat) : _stats.Jitter * 0.9 + Math.Abs(latUs - lastLat) * 0.1;
                                    lastLat = latUs; if (_stats.LastSeq != -1 && seq > _stats.LastSeq + 1) _stats.LostCount += (seq - _stats.LastSeq - 1); _stats.LastSeq = seq;
                                    _stats.ActualDscp = pkt[15] >> 2; _stats.LastSrcMac = srcM; _stats.LastTtl = ttlV; if (isF) _stats.FragDetected = true;
                                }
                            }
                        }
                        if (wasRunning && !ct.IsCancellationRequested) {
                            SendManualLeave(handle, _config.ActiveGrp, _config.ActiveSrc, _config.ActiveVer, _config.ActiveIgmpMode);
                            Thread.Sleep(100);
                        }
                    } catch (Exception) { if (!ct.IsCancellationRequested) Thread.Sleep(1000); }
                }
            } finally { pcap_close(handle); }
        }

        public void SendManualIgmp(IntPtr handle)
        {
            byte[] srcMac = GetLocalMac(_config.InterfaceAddr), srcIp = IPAddress.Parse(_config.InterfaceAddr).GetAddressBytes(), grpIp = IPAddress.Parse(_config.GroupAddr).GetAddressBytes();
            if (_config.IgmpVersion == 3) {
                byte[] dstMac = new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x16 }, dstIp = new byte[] { 224, 0, 0, 22 };
                int sources = string.IsNullOrEmpty(_config.SourceAddr) ? 0 : 1;
                int len = 40 + (sources * 4); byte[] pkt = new byte[14 + len];
                Buffer.BlockCopy(dstMac, 0, pkt, 0, 6); Buffer.BlockCopy(srcMac, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
                pkt[14] = 0x46; pkt[15] = 0xC0;
                byte[] lB = BitConverter.GetBytes((ushort)len); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, 16, 2);
                byte[] idB = BitConverter.GetBytes((ushort)Interlocked.Increment(ref _config.IpIdInt)); if (BitConverter.IsLittleEndian) Array.Reverse(idB); Buffer.BlockCopy(idB, 0, pkt, 18, 2);
                pkt[22] = 1; pkt[23] = 2; Buffer.BlockCopy(srcIp, 0, pkt, 26, 4); Buffer.BlockCopy(dstIp, 0, pkt, 30, 4);
                pkt[34] = 0x94; pkt[35] = 0x04; pkt[36] = 0x00; pkt[37] = 0x00;
                ushort ipC = CalculateChecksum(pkt, 14, 24); byte[] ipCB = BitConverter.GetBytes(ipC); if (BitConverter.IsLittleEndian) Array.Reverse(ipCB); Buffer.BlockCopy(ipCB, 0, pkt, 24, 2);
                int igmpOff = 14 + 24; pkt[igmpOff] = 0x22; pkt[igmpOff + 7] = 1;
                int recOff = igmpOff + 8; pkt[recOff] = (byte)(_config.IgmpMode == "exclude" ? 2 : 1);
                pkt[recOff + 3] = (byte)sources; Buffer.BlockCopy(grpIp, 0, pkt, recOff + 4, 4);
                if (sources > 0) Buffer.BlockCopy(IPAddress.Parse(_config.SourceAddr).GetAddressBytes(), 0, pkt, recOff + 8, 4);
                ushort igmpC = CalculateChecksum(pkt, igmpOff, len - 24); byte[] igmpCB = BitConverter.GetBytes(igmpC); if (BitConverter.IsLittleEndian) Array.Reverse(igmpCB); Buffer.BlockCopy(igmpCB, 0, pkt, igmpOff + 2, 2);
                pcap_sendpacket(handle, pkt, pkt.Length);
            } else {
                byte[] dstMac = GetMulticastMac(_config.GroupAddr);
                int len = 28; byte[] pkt = new byte[14 + len];
                Buffer.BlockCopy(dstMac, 0, pkt, 0, 6); Buffer.BlockCopy(srcMac, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
                pkt[14] = 0x45; pkt[15] = 0xC0; byte[] lB = BitConverter.GetBytes((ushort)len); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, 16, 2);
                byte[] idB = BitConverter.GetBytes((ushort)Interlocked.Increment(ref _config.IpIdInt)); if (BitConverter.IsLittleEndian) Array.Reverse(idB); Buffer.BlockCopy(idB, 0, pkt, 18, 2);
                pkt[22] = 1; pkt[23] = 2; Buffer.BlockCopy(srcIp, 0, pkt, 26, 4); Buffer.BlockCopy(grpIp, 0, pkt, 30, 4);
                ushort ipC = CalculateChecksum(pkt, 14, 20); byte[] ipCB = BitConverter.GetBytes(ipC); if (BitConverter.IsLittleEndian) Array.Reverse(ipCB); Buffer.BlockCopy(ipCB, 0, pkt, 24, 2);
                int igmpOff = 14 + 20; pkt[igmpOff] = 0x16;
                Buffer.BlockCopy(grpIp, 0, pkt, igmpOff + 4, 4);
                ushort igmpC = CalculateChecksum(pkt, igmpOff, 8); byte[] igmpCB = BitConverter.GetBytes(igmpC); if (BitConverter.IsLittleEndian) Array.Reverse(igmpCB); Buffer.BlockCopy(igmpCB, 0, pkt, igmpOff + 2, 2);
                pcap_sendpacket(handle, pkt, pkt.Length);
            }
        }

        public void SendManualLeave(IntPtr handle, string g, string s, int v, string m)
        {
            if (string.IsNullOrEmpty(g)) return;
            byte[] srcMac = GetLocalMac(_config.InterfaceAddr), srcIp = IPAddress.Parse(_config.InterfaceAddr).GetAddressBytes(), grpIp = IPAddress.Parse(g).GetAddressBytes();
            if (v == 3) {
                byte[] dstMac = new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x16 }, dstIp = new byte[] { 224, 0, 0, 22 };
                int len = 40; byte[] pkt = new byte[14 + len];
                Buffer.BlockCopy(dstMac, 0, pkt, 0, 6); Buffer.BlockCopy(srcMac, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
                pkt[14] = 0x46; pkt[15] = 0xC0; byte[] lB = BitConverter.GetBytes((ushort)len); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, 16, 2);
                byte[] idB = BitConverter.GetBytes((ushort)Interlocked.Increment(ref _config.IpIdInt)); if (BitConverter.IsLittleEndian) Array.Reverse(idB); Buffer.BlockCopy(idB, 0, pkt, 18, 2);
                pkt[22] = 1; pkt[23] = 2; Buffer.BlockCopy(srcIp, 0, pkt, 26, 4); Buffer.BlockCopy(dstIp, 0, pkt, 30, 4);
                pkt[34] = 0x94; pkt[35] = 0x04; pkt[36] = 0x00; pkt[37] = 0x00;
                ushort ipC = CalculateChecksum(pkt, 14, 24); byte[] ipCB = BitConverter.GetBytes(ipC); if (BitConverter.IsLittleEndian) Array.Reverse(ipCB); Buffer.BlockCopy(ipCB, 0, pkt, 24, 2);
                int igmpOff = 14 + 24; pkt[igmpOff] = 0x22; pkt[igmpOff + 7] = 1;
                int recOff = igmpOff + 8; pkt[recOff] = 3; // CHANGE_TO_INCLUDE_MODE
                pkt[recOff + 3] = 0; Buffer.BlockCopy(grpIp, 0, pkt, recOff + 4, 4);
                ushort igmpC = CalculateChecksum(pkt, igmpOff, len - 24); byte[] igmpCB = BitConverter.GetBytes(igmpC); if (BitConverter.IsLittleEndian) Array.Reverse(igmpCB); Buffer.BlockCopy(igmpCB, 0, pkt, igmpOff + 2, 2);
                pcap_sendpacket(handle, pkt, pkt.Length);
            } else {
                byte[] dstMac = new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x02 };
                byte[] dstIp = new byte[] { 224, 0, 0, 2 };
                int len = 28; byte[] pkt = new byte[14 + len];
                Buffer.BlockCopy(dstMac, 0, pkt, 0, 6); Buffer.BlockCopy(srcMac, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
                pkt[14] = 0x45; pkt[15] = 0xC0; byte[] lB = BitConverter.GetBytes((ushort)len); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, 16, 2);
                byte[] idB = BitConverter.GetBytes((ushort)Interlocked.Increment(ref _config.IpIdInt)); if (BitConverter.IsLittleEndian) Array.Reverse(idB); Buffer.BlockCopy(idB, 0, pkt, 18, 2);
                pkt[22] = 1; pkt[23] = 2; Buffer.BlockCopy(srcIp, 0, pkt, 26, 4); Buffer.BlockCopy(dstIp, 0, pkt, 30, 4);
                ushort ipC = CalculateChecksum(pkt, 14, 20); byte[] ipCB = BitConverter.GetBytes(ipC); if (BitConverter.IsLittleEndian) Array.Reverse(ipCB); Buffer.BlockCopy(ipCB, 0, pkt, 24, 2);
                int igmpOff = 14 + 20; pkt[igmpOff] = 0x17; pkt[igmpOff + 1] = 0;
                Buffer.BlockCopy(grpIp, 0, pkt, igmpOff + 4, 4);
                ushort igmpC = CalculateChecksum(pkt, igmpOff, 8); byte[] igmpCB = BitConverter.GetBytes(igmpC); if (BitConverter.IsLittleEndian) Array.Reverse(igmpCB); Buffer.BlockCopy(igmpCB, 0, pkt, igmpOff + 2, 2);
                pcap_sendpacket(handle, pkt, pkt.Length);
            }
        }

        private byte[] BuildUdpPacket(byte[] sM, byte[] dM, byte[] sI, byte[] dI, ushort sP, ushort dP, ulong seq, long ts, out int tL)
        {
            tL = MToolCore.TOTAL_NETWORK_HEADERS + _config.ActiveSize;
            byte[] pkt = new byte[tL];
            byte[] app = new byte[_config.ActiveSize]; Encoding.ASCII.GetBytes(MToolCore.SIG).CopyTo(app, 0);
            byte[] sB = BitConverter.GetBytes(seq), tB = BitConverter.GetBytes(ts); if (BitConverter.IsLittleEndian) { Array.Reverse(sB); Array.Reverse(tB); }
            sB.CopyTo(app, 5); tB.CopyTo(app, 13);
            Buffer.BlockCopy(dM, 0, pkt, 0, 6); Buffer.BlockCopy(sM, 0, pkt, 6, 6); pkt[12] = 0x08; pkt[13] = 0x00;
            pkt[MToolCore.ETHERNET_HEADER_SIZE] = 0x45; pkt[MToolCore.ETHERNET_HEADER_SIZE + 1] = (byte)(_config.ActiveDscp << 2);
            byte[] lB = BitConverter.GetBytes((ushort)(MToolCore.IPV4_HEADER_SIZE + MToolCore.UDP_HEADER_SIZE + _config.ActiveSize)); if (BitConverter.IsLittleEndian) Array.Reverse(lB); Buffer.BlockCopy(lB, 0, pkt, MToolCore.ETHERNET_HEADER_SIZE + 2, 2);
            byte[] idB = BitConverter.GetBytes((ushort)Interlocked.Increment(ref _config.IpIdInt)); if (BitConverter.IsLittleEndian) Array.Reverse(idB); Buffer.BlockCopy(idB, 0, pkt, MToolCore.ETHERNET_HEADER_SIZE + 4, 2);
            pkt[MToolCore.ETHERNET_HEADER_SIZE + 8] = (byte)_config.ActiveTtl; pkt[MToolCore.ETHERNET_HEADER_SIZE + 9] = 17;
            Buffer.BlockCopy(sI, 0, pkt, MToolCore.ETHERNET_HEADER_SIZE + 12, 4); Buffer.BlockCopy(dI, 0, pkt, MToolCore.ETHERNET_HEADER_SIZE + 16, 4);
            ushort cs = CalculateChecksum(pkt, MToolCore.ETHERNET_HEADER_SIZE, MToolCore.IPV4_HEADER_SIZE); byte[] cB = BitConverter.GetBytes(cs); if (BitConverter.IsLittleEndian) Array.Reverse(cB); Buffer.BlockCopy(cB, 0, pkt, MToolCore.ETHERNET_HEADER_SIZE + 10, 2);
            byte[] spB = BitConverter.GetBytes(sP), dpB = BitConverter.GetBytes(dP); if (BitConverter.IsLittleEndian) { Array.Reverse(spB); Array.Reverse(dpB); }
            int udpOff = MToolCore.ETHERNET_HEADER_SIZE + MToolCore.IPV4_HEADER_SIZE;
            Buffer.BlockCopy(spB, 0, pkt, udpOff, 2); Buffer.BlockCopy(dpB, 0, pkt, udpOff + 2, 2);
            byte[] ulB = BitConverter.GetBytes((ushort)(MToolCore.UDP_HEADER_SIZE + _config.ActiveSize)); if (BitConverter.IsLittleEndian) Array.Reverse(ulB); Buffer.BlockCopy(ulB, 0, pkt, udpOff + 4, 2);
            Buffer.BlockCopy(app, 0, pkt, MToolCore.TOTAL_NETWORK_HEADERS, _config.ActiveSize); return pkt;
        }

        private ushort CalculateChecksum(byte[] buf, int off, int len)
        {
            uint sum = 0; int i = 0;
            while (len > 1) { sum += (uint)((buf[off + i] << 8) | buf[off + i + 1]); i += 2; len -= 2; }
            if (len > 0) sum += (uint)(buf[off + i] << 8);
            while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        public byte[] GetMulticastMac(string ip) { byte[] b = IPAddress.Parse(ip).GetAddressBytes(); return new byte[] { 0x01, 0x00, 0x5E, (byte)(b[1] & 0x7F), b[2], b[3] }; }
        public byte[] GetLocalMac(string ip) { foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()) { foreach (var a in ni.GetIPProperties().UnicastAddresses) { if (a.Address.ToString() == ip) return ni.GetPhysicalAddress().GetAddressBytes(); } } return new byte[6]; }
        
        public static string FindInterfaceName(string ip) {
            IntPtr alldevs = IntPtr.Zero; byte[] err = new byte[256]; pcap_findalldevs(ref alldevs, err);
            IntPtr cur = alldevs; while(cur!=IntPtr.Zero){ pcap_if iface=(pcap_if)Marshal.PtrToStructure(cur, typeof(pcap_if)); if(GetIps(iface.addresses).Contains(ip)) { string n = Marshal.PtrToStringAnsi(iface.name); pcap_freealldevs(alldevs); return n; } cur=iface.next; }
            pcap_freealldevs(alldevs); return "";
        }

        public static string GetIps(IntPtr a){ List<string> l=new List<string>(); while(a!=IntPtr.Zero){ pcap_addr p=(pcap_addr)Marshal.PtrToStructure(a, typeof(pcap_addr)); if(p.addr!=IntPtr.Zero && Marshal.ReadInt16(p.addr)==2){ sockaddr_in sin=(sockaddr_in)Marshal.PtrToStructure(p.addr, typeof(sockaddr_in)); l.Add(new IPAddress(BitConverter.GetBytes(sin.sin_addr)).ToString()); } a=p.next; } return string.Join(",", l.ToArray()); }
        public static string GetFirstIp(IntPtr a){ while(a!=IntPtr.Zero){ pcap_addr p=(pcap_addr)Marshal.PtrToStructure(a, typeof(pcap_addr)); if(p.addr!=IntPtr.Zero && Marshal.ReadInt16(p.addr)==2){ return new IPAddress(BitConverter.GetBytes(((sockaddr_in)Marshal.PtrToStructure(p.addr, typeof(sockaddr_in))).sin_addr)).ToString(); } a=p.next; } return "0.0.0.0"; }
    }
}
