using System;
using System.Text;
using System.Collections.Generic;

namespace MMulticastTool
{
    /// <summary>
    /// Holds real-time operational statistics.
    /// </summary>
    public class AppStats
    {
        public long TxCount = 0;
        public long TxBytes = 0;
        public long RxCount = 0;
        public long RxBytes = 0;
        public long LostCount = 0;
        public long LastSeq = -1;
        public List<double> Latencies = new List<double>();
        public double MaxLat = 0;
        public double MinLat = double.MaxValue;
        public double Jitter = 0;
        public int ActualDscp = -1;
        public readonly object StatsLock = new object();

        public string LastSrcMac = "-";
        public int LastTtl = -1;
        public DateTime LastQueryTime = DateTime.MinValue;
        public bool FragDetected = false;

        public void Reset()
        {
            lock (StatsLock)
            {
                TxCount = 0; TxBytes = 0; RxCount = 0; RxBytes = 0; LostCount = 0; LastSeq = -1;
                Latencies.Clear(); Jitter = 0; MaxLat = 0; MinLat = double.MaxValue;
                LastSrcMac = "-"; LastTtl = -1; LastQueryTime = DateTime.MinValue; FragDetected = false;
            }
        }
    }

    /// <summary>
    /// Holds application configuration and active parameters.
    /// </summary>
    public class AppConfig
    {
        // Parameters (User defined or wizard)
        public string GroupAddr = "239.1.1.1";
        public int Port = 5001;
        public string InterfaceAddr = "0.0.0.0";
        public string InterfaceName = "";
        public int IgmpVersion = 2;
        public string SourceAddr = "";
        public string IgmpMode = "include";
        public int Ttl = 1;
        public int Interval = 1000;
        public int PacketSize = 64;
        public double BandwidthMbps = 0;
        public int Dscp = 0;
        public string Mode = "send";
        public int WebPort = 8080;

        // Runtime state
        public double TargetIntervalMs = 1000.0;
        public bool IsRunning = false;
        public bool IsRecording = false;
        public volatile bool NeedsRestart = false;

        // Active parameters (Actually in use by engine)
        public string ActiveGrp = "", ActiveSrc = "", ActiveIgmpMode = "";
        public int ActiveVer = 0, ActivePort = 0, ActiveDscp = 0, ActiveTtl = 0, ActiveSize = 0;
        public double ActiveBw = 0;
        public int IpIdInt = 0;

        public void SyncActive()
        {
            ActiveGrp = GroupAddr; ActiveSrc = SourceAddr; ActiveVer = IgmpVersion; ActiveIgmpMode = IgmpMode;
            ActivePort = Port; ActiveDscp = Dscp; ActiveTtl = Ttl; ActiveSize = PacketSize; ActiveBw = BandwidthMbps;
        }

        // Snapshot of parameters as first configured (wizard/CLI args), used by "Restore Defaults".
        private string _iGrp, _iSrc, _iMode;
        private int _iPort, _iVer, _iTtl, _iSize, _iDscp;
        private double _iBw;
        private bool _hasSnapshot = false;

        public void SnapshotInitial()
        {
            _iGrp = GroupAddr; _iSrc = SourceAddr; _iMode = IgmpMode;
            _iPort = Port; _iVer = IgmpVersion; _iTtl = Ttl; _iSize = PacketSize; _iDscp = Dscp;
            _iBw = BandwidthMbps; _hasSnapshot = true;
        }

        public void RestoreInitial()
        {
            if (!_hasSnapshot) return;
            GroupAddr = _iGrp; SourceAddr = _iSrc; IgmpMode = _iMode;
            Port = _iPort; IgmpVersion = _iVer; Ttl = _iTtl; PacketSize = _iSize; Dscp = _iDscp;
            BandwidthMbps = _iBw;
            TargetIntervalMs = MToolCore.CalculateIntervalMs(BandwidthMbps, PacketSize, Interval);
            NeedsRestart = true;
        }
    }
}
