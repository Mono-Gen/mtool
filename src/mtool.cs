using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Runtime.InteropServices;

namespace MMulticastTool
{
    class Program
    {
        private static AppConfig _config = new AppConfig();
        private static AppStats _stats = new AppStats();
        private static NetworkEngine _network;
        private static WebDashboard _dashboard;
        private static bool _isAdmin = false;
        private static bool _isInputMode = false;

        static void Main(string[] args)
        {
            try { MainAsync(args).GetAwaiter().GetResult(); }
            catch (Exception ex) { 
                Console.ForegroundColor = ConsoleColor.Red; 
                Console.WriteLine("\n[!] CRITICAL ERROR: " + ex.ToString()); 
                Console.ResetColor(); Console.ReadKey(); 
            }
        }

        static async Task MainAsync(string[] args)
        {
            Console.WriteLine("==========================================================================================");
            Console.WriteLine(" MTOOL v2.0.0 - High-Performance Multicast Testing & Analysis Tool");
            Console.WriteLine(" (C) 2026 Mono-Gen. All rights reserved.");
            Console.WriteLine("==========================================================================================\n");

            if (!NetworkEngine.CheckNpcap()) {
                Console.WriteLine("Npcap not found. Please install Npcap.");
                Console.ReadKey(); return;
            }

            ParseArgs(args);
            _isAdmin = IsAdministrator();

            if (!_isAdmin) {
                ShowAdminWarning();
                return;
            }

            if (string.IsNullOrEmpty(_config.InterfaceName) || _config.Port == 0) ShowWizard();

            _config.SnapshotInitial();

            _network = new NetworkEngine(_config, _stats, (evt, details) => { if (_dashboard != null) _dashboard.AddLog(evt, details); });
            _dashboard = new WebDashboard(_config, _stats);

            Console.Clear();

            using (CancellationTokenSource cts = new CancellationTokenSource())
            {
                List<Task> tasks = new List<Task>();
                tasks.Add(Task.Run(() => MonitorTask(cts.Token)));
                
                tasks.Add(Task.Run(async () => {
                    while (!cts.Token.IsCancellationRequested) {
                        _dashboard.AddLog("STATS", string.Format("TX:{0} RX:{1} Lost:{2} Jitter:{3:F3}", _stats.TxCount, _stats.RxCount, _stats.LostCount, _stats.Jitter));
                        await Task.Delay(1000);
                    }
                }));

                if (_config.Mode == "send") tasks.Add(Task.Run(() => _network.SenderTask(cts.Token)));
                else if (_config.Mode == "recv") tasks.Add(Task.Run(() => _network.ReceiverTask(cts.Token)));
                
                tasks.Add(Task.Run(() => InputTask(cts)));
                tasks.Add(_dashboard.HttpTask(cts.Token));

                Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };
                await Task.WhenAny(Task.WhenAll(tasks), Task.Delay(-1, cts.Token)).ContinueWith(_ => {});
            }
        }

        static void ShowAdminWarning()
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("################################################################################################");
            Console.WriteLine("# [!] ERROR: ADMINISTRATOR PRIVILEGES REQUIRED                                                 #");
            Console.WriteLine("################################################################################################");
            Console.WriteLine("# Raw Socket (Npcap) & HttpListener operation require Administrator rights.                   #");
            Console.WriteLine("# Please right-click 'mtool.exe' and select 'Run as Administrator'.                           #");
            Console.WriteLine("################################################################################################");
            Console.ResetColor();
            Console.WriteLine("\nPress any key to exit..."); Console.ReadKey();
        }

        static void ShowHeader()
        {
            string sType = string.IsNullOrEmpty(_config.SourceAddr) ? "ASM" : _config.SourceAddr;
            if (_config.Mode == "send" && !string.IsNullOrEmpty(_config.SourceAddr)) sType = sType + " (SPOOFED)";
            Console.WriteLine("------------------------------------------------------------------------------------------");
            Console.WriteLine(string.Format("| Target:{0,-15}:{1,-5} NIC:{2,-15} IGMP:v{3} Src:{4,-15} |", _config.GroupAddr, _config.Port, _config.InterfaceAddr, _config.IgmpVersion, sType));
            Console.WriteLine(string.Format("| Mode: {0,-10} {1,-10} DSCP: {2,-5} BW: {3,-8} Mbps  Size: {4,-8} bytes |", _config.Mode.ToUpper(), (_config.IgmpVersion == 3 ? _config.IgmpMode.ToUpper() : ""), _config.Dscp, _config.BandwidthMbps, _config.PacketSize));
            Console.WriteLine("------------------------------------------------------------------------------------------\n");
        }

        static void MonitorTask(CancellationToken ct)
        {
            long lTx = 0, lRx = 0, lTxB = 0, lRxB = 0; ShowHeader();
            Console.WriteLine("------------------------------------------------------------------------------------------------------------");
            Console.WriteLine("| Time     | TX-pps   | TX-Mbps  | RX-pps   | RX-Mbps  | Loss%    | Lat-Avg  | Jitter   | DSCP   |");
            while (!ct.IsCancellationRequested) {
                if (_isInputMode) { Thread.Sleep(500); continue; }
                Thread.Sleep(1000); if (_isInputMode) continue;

                long tx = Interlocked.Read(ref _stats.TxCount), rx = Interlocked.Read(ref _stats.RxCount), txB = Interlocked.Read(ref _stats.TxBytes), rxB = Interlocked.Read(ref _stats.RxBytes), lost = Interlocked.Read(ref _stats.LostCount);
                if (_config.NeedsRestart) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine("| RE-JOINING... (Forging IGMP Report)                                                          |"); Console.ResetColor(); ShowHeader(); }
                double txP = tx - lTx, rxP = rx - lRx, txM = (double)(txB - lTxB) * 8 / 1000000, rxM = (double)(rxB - lRxB) * 8 / 1000000, avgL = 0, curJ = 0;
                lock (_stats.StatsLock) { if (_stats.Latencies.Count > 0) avgL = _stats.Latencies.Average(); curJ = _stats.Jitter; }
                double tExp = (_config.Mode == "recv") ? (rx + lost) : tx, lR = tExp > 0 ? (double)lost / tExp * 100 : 0;
                string dDisp; bool dM; lock (_stats.StatsLock) { dDisp = _stats.ActualDscp >= 0 ? string.Format("{0}({1})", _config.Dscp, _stats.ActualDscp) : _config.Dscp.ToString(); dM = (_config.Dscp == _stats.ActualDscp || _stats.ActualDscp < 0); }
                Console.Write("| {0,-8} |", DateTime.Now.ToString("HH:mm:ss"));
                Console.ForegroundColor = txP > 0 ? ConsoleColor.White : ConsoleColor.DarkGray; Console.Write(" {0,8} | {1,8:F2} |", txP, txM);
                Console.ForegroundColor = rxP > 0 ? ConsoleColor.Green : ConsoleColor.DarkGray; Console.Write(" {0,8} | {1,8:F2} |", rxP, rxM);
                if (lR > 0.01) Console.ForegroundColor = ConsoleColor.Red; else if (_config.Mode == "recv" && rxP > 0) Console.ForegroundColor = ConsoleColor.Green; else Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(" {0,7:F2}% |", lR); Console.ForegroundColor = avgL > 10000 ? ConsoleColor.Yellow : (avgL > 0 ? ConsoleColor.Cyan : ConsoleColor.DarkGray);
                Console.Write(" {0,6:F0}us | {1,6:F0}us |", avgL, curJ);
                if (!dM) Console.ForegroundColor = ConsoleColor.Red; else if (_stats.ActualDscp >= 0) Console.ForegroundColor = ConsoleColor.Green; else Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(" {0,-6} |", dDisp); Console.ResetColor();
                lTx = tx; lRx = rx; lTxB = txB; lRxB = rxB;
            }
        }

        static void InputTask(CancellationTokenSource cts)
        {
            while (!cts.IsCancellationRequested)
            {
                if (Console.KeyAvailable)
                {
                    var k = Console.ReadKey(true); _isInputMode = true;
                    Console.WriteLine("\n[MENU] (G)roup, (S)ource, (P)ort, (V)ersion, (M)ode, (D)SCP, (B)W, si(Z)e, (T)TL, (C)lear, (R)estore, (Q)uit");
                    Console.Write("> Select key to change: ");
                    try {
                        switch (char.ToUpper(k.KeyChar)) {
                            case 'G': Console.Write("New Group: "); var g = Console.ReadLine(); if (!string.IsNullOrEmpty(g)) { _config.GroupAddr = g; _config.NeedsRestart = true; } break;
                            case 'S': Console.Write("New Source: "); var s = Console.ReadLine(); _config.SourceAddr = s; _config.NeedsRestart = true; break;
                            case 'P': Console.Write("New Port: "); var p = Console.ReadLine(); if (!string.IsNullOrEmpty(p)) { _config.Port = int.Parse(p); _config.NeedsRestart = true; } break;
                            case 'V': Console.Write("IGMP v[2/3]: "); var v = Console.ReadLine(); if (!string.IsNullOrEmpty(v)) { _config.IgmpVersion = int.Parse(v); _config.NeedsRestart = true; } break;
                            case 'M': Console.Write("Mode [i/e]: "); _config.IgmpMode = Console.ReadLine().ToLower().StartsWith("e") ? "exclude" : "include"; _config.NeedsRestart = true; break;
                            case 'D': Console.Write("New DSCP: "); var d = Console.ReadLine(); if (!string.IsNullOrEmpty(d)) _config.Dscp = int.Parse(d); break;
                            case 'B': Console.Write("New BW (Mbps): "); var b = Console.ReadLine(); if (!string.IsNullOrEmpty(b)) { _config.BandwidthMbps = double.Parse(b); RecalculateInterval(); } break;
                            case 'Z': Console.Write(string.Format("New Size (Min {0}, Max 1472): ", MToolCore.HEADER_SIZE)); var sz = Console.ReadLine(); if (!string.IsNullOrEmpty(sz)) { int sIn = int.Parse(sz); _config.PacketSize = Math.Max(MToolCore.HEADER_SIZE, Math.Min(sIn, 1472)); RecalculateInterval(); } break;
                            case 'T': Console.Write("New TTL: "); var t = Console.ReadLine(); if (!string.IsNullOrEmpty(t)) _config.Ttl = int.Parse(t); break;
                            case 'C': _stats.Reset(); Console.WriteLine("\n[*] Statistics cleared."); break;
                            case 'R': _config.RestoreInitial(); Console.WriteLine("\n[*] Parameters restored to initial values."); break;
                            case 'Q': cts.Cancel(); break;
                        }
                    } catch (Exception ex) { Console.WriteLine("\n[!] Input error: " + ex.Message); }
                    _isInputMode = false; Console.WriteLine("[*] Applied.");
                }
                Thread.Sleep(100);
            }
        }

        static void ShowWizard() {
            Console.WriteLine("\n=== mtool v2.0.0 Visual Setup ===");
            IntPtr alldevs = IntPtr.Zero; byte[] err = new byte[256]; NetworkEngine.pcap_findalldevs(ref alldevs, err);
            List<IntPtr> dPtrs = new List<IntPtr>(); IntPtr cur = alldevs; while(cur!=IntPtr.Zero){ dPtrs.Add(cur); NetworkEngine.pcap_if iface=(NetworkEngine.pcap_if)Marshal.PtrToStructure(cur, typeof(NetworkEngine.pcap_if)); cur=iface.next; }
            for (int i = 0; i < dPtrs.Count; i++) { NetworkEngine.pcap_if f = (NetworkEngine.pcap_if)Marshal.PtrToStructure(dPtrs[i], typeof(NetworkEngine.pcap_if)); Console.WriteLine(" [{0}] {1} (IP: {2})", i, Marshal.PtrToStringAnsi(f.description), NetworkEngine.GetIps(f.addresses)); }
            int idx = 0;
            while (true) {
                Console.Write("\nSelect Interface Index [0-{0}, Default: 0]: ", dPtrs.Count - 1);
                var idxIn = Console.ReadLine();
                if (string.IsNullOrEmpty(idxIn)) { idx = 0; break; }
                if (int.TryParse(idxIn, out idx) && idx >= 0 && idx < dPtrs.Count) break;
                Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] Invalid index. Please select from 0 to {0}.", dPtrs.Count - 1); Console.ResetColor();
            }
            NetworkEngine.pcap_if s = (NetworkEngine.pcap_if)Marshal.PtrToStructure(dPtrs[idx], typeof(NetworkEngine.pcap_if));
            _config.InterfaceName = Marshal.PtrToStringAnsi(s.name); _config.InterfaceAddr = NetworkEngine.GetFirstIp(s.addresses);
            Console.Write("Mode [Send/Receive, Default: Send]: "); var mVar = Console.ReadLine().ToLower(); _config.Mode = mVar.StartsWith("r") ? "recv" : "send";
            while (true) {
                Console.Write("Group [Default: 239.1.1.1]: "); var gIn = Console.ReadLine();
                if (string.IsNullOrEmpty(gIn)) { _config.GroupAddr = "239.1.1.1"; break; }
                if (MToolCore.IsMulticast(gIn)) { _config.GroupAddr = gIn; break; }
                Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] Invalid Multicast Address."); Console.ResetColor();
            }
            while (true) {
                Console.Write("Port [Default: 5001]: "); var pIn = Console.ReadLine();
                if (string.IsNullOrEmpty(pIn)) { _config.Port = 5001; break; }
                if (int.TryParse(pIn, out _config.Port) && _config.Port > 0 && _config.Port < 65536) break;
                Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] Invalid port number."); Console.ResetColor();
            }
            int defW = (_config.Mode == "recv" ? 8081 : 8080);
            while (true) {
                Console.Write("WebUI Port [Default: {0}]: ", defW); var wIn = Console.ReadLine();
                if (string.IsNullOrEmpty(wIn)) { _config.WebPort = defW; break; }
                if (int.TryParse(wIn, out _config.WebPort) && _config.WebPort > 0 && _config.WebPort < 65536) break;
                Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine("[!] Invalid WebUI port."); Console.ResetColor();
            }
            NetworkEngine.pcap_freealldevs(alldevs);
        }

        static void ParseArgs(string[] args) { 
            for(int i=0;i<args.Length;i++){ 
                string a = args[i].ToLower();
                if (i + 1 >= args.Length) continue;
                switch(a){ 
                    case "-g": case "-group": _config.GroupAddr=args[++i]; break; 
                    case "-p": case "-port": _config.Port=int.Parse(args[++i]); break; 
                    case "-i": case "-interface": _config.InterfaceAddr=args[++i]; _config.InterfaceName=NetworkEngine.FindInterfaceName(_config.InterfaceAddr); break; 
                    case "-s": case "-source": _config.SourceAddr=args[++i]; break; 
                    case "-v": case "-igmp": _config.IgmpVersion=int.Parse(args[++i]); break; 
                    case "-m": case "-mode": _config.Mode=args[++i].ToLower(); break; 
                    case "-q": case "-qos": case "-dscp": _config.Dscp=int.Parse(args[++i]); break; 
                    case "-b": case "-bw": case "-bandwidth": _config.BandwidthMbps=double.Parse(args[++i]); break; 
                    case "-t": case "-ttl": _config.Ttl=int.Parse(args[++i]); break; 
                    case "-sz": case "-size": _config.PacketSize=Math.Max(MToolCore.HEADER_SIZE, Math.Min(int.Parse(args[++i]), 1472)); break;
                    case "-w": case "-webport": _config.WebPort=int.Parse(args[++i]); break; 
                } 
            } 
            RecalculateInterval();
        }

        static void RecalculateInterval() { _config.TargetIntervalMs = MToolCore.CalculateIntervalMs(_config.BandwidthMbps, _config.PacketSize, _config.Interval); }
        static bool IsAdministrator(){ using(WindowsIdentity id=WindowsIdentity.GetCurrent()){ return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator); } }
    }
}
