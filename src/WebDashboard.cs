using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Linq;

namespace MMulticastTool
{
    public class WebDashboard
    {
        private readonly AppConfig _config;
        private readonly AppStats _stats;
        private readonly StringBuilder _logBuffer = new StringBuilder();
        private readonly object _logLock = new object();

        public WebDashboard(AppConfig config, AppStats stats)
        {
            _config = config;
            _stats = stats;
        }

        public void AddLog(string evt, string details)
        {
            if (!_config.IsRecording) return;
            string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            double curTx = 0, curRx = 0, curLat = 0, curJit = 0, curLoss = 0;
            lock (_stats.StatsLock) {
                curTx = (_stats.TxBytes * 8.0) / 1000000.0; curRx = (_stats.RxBytes * 8.0) / 1000000.0;
                if (_stats.Latencies.Count > 0) curLat = _stats.Latencies.Average();
                curJit = _stats.Jitter;
                if (_stats.RxCount + _stats.LostCount > 0) curLoss = (double)_stats.LostCount * 100.0 / (_stats.RxCount + _stats.LostCount);
            }
            lock (_logLock) {
                _logBuffer.AppendLine(string.Format("{0},{1},{2:F2},{3:F2},{4:F0},{5:F0},{6:F2},\"{7}\"", ts, evt, curTx, curRx, curLat, curJit, curLoss, details.Replace("\"", "\"\"")));
            }
        }

        public async Task HttpTask(CancellationToken ct)
        {
            HttpListener listener = new HttpListener();
            bool started = false;
            for (int i = 0; i < 10; i++) {
                try {
                    listener.Prefixes.Clear();
                    listener.Prefixes.Add(string.Format("http://localhost:{0}/", _config.WebPort));
                    listener.Prefixes.Add(string.Format("http://127.0.0.1:{0}/", _config.WebPort));
                    listener.Start();
                    started = true; break;
                } catch {
                    _config.WebPort++;
                }
            }

            if (!started) return;
            
            try { Process.Start(new ProcessStartInfo(string.Format("http://localhost:{0}", _config.WebPort)) { UseShellExecute = true }); } catch {}

            try {
                using (ct.Register(() => { try { listener.Stop(); } catch {} })) {
                    while (!ct.IsCancellationRequested) {
                        var ctx = await listener.GetContextAsync();
                        Task.Run(() => HandleRequest(ctx, ct));
                    }
                }
            } catch (Exception) { if (!ct.IsCancellationRequested) Thread.Sleep(1000); }
            finally { if(listener.IsListening) listener.Close(); }
        }

        private void HandleRequest(HttpListenerContext ctx, CancellationToken ct)
        {
            try {
                string path = ctx.Request.Url.AbsolutePath;
                if (path == "/api/stats") {
                    double avgL = 0, curJ = 0; string lQ = "-";
                    lock (_stats.StatsLock) { 
                        if (_stats.Latencies.Count > 0) avgL = _stats.Latencies.Average(); curJ = _stats.Jitter; 
                        if (_stats.LastQueryTime != DateTime.MinValue) lQ = (DateTime.Now - _stats.LastQueryTime).TotalSeconds.ToString("F0") + "s ago";
                    }
                    string json = string.Format("{{\"txCount\":{0},\"txBytes\":{1},\"rxCount\":{2},\"rxBytes\":{3},\"lost\":{4},\"avgLat\":{5},\"jitter\":{6},\"dscp\":{7},\"actualDscp\":{8},\"group\":\"{9}\",\"port\":{10},\"mode\":\"{11}\",\"version\":{12},\"igmpMode\":\"{13}\",\"source\":\"{14}\",\"ttl\":{15},\"size\":{16},\"bw\":{17},\"mac\":\"{18}\",\"actTtl\":{19},\"lastQ\":\"{20}\",\"frag\":{21},\"activeGrp\":\"{22}\",\"activePort\":{23},\"activeSrc\":\"{24}\",\"activeDscp\":{25},\"activeTtl\":{26},\"activeSize\":{27},\"activeBw\":{28},\"activeVer\":{29},\"activeIgmpMode\":\"{30}\",\"isRunning\":{31}}}", 
                        _stats.TxCount, _stats.TxBytes, _stats.RxCount, _stats.RxBytes, _stats.LostCount, avgL, curJ, _config.Dscp, _stats.ActualDscp, _config.GroupAddr, _config.Port, _config.Mode, _config.IgmpVersion, _config.IgmpMode, _config.SourceAddr, _config.Ttl, _config.PacketSize, _config.BandwidthMbps, _stats.LastSrcMac, _stats.LastTtl, lQ, _stats.FragDetected ? "true" : "false",
                        _config.ActiveGrp, _config.ActivePort, _config.ActiveSrc, _config.ActiveDscp, _config.ActiveTtl, _config.ActiveSize, _config.ActiveBw, _config.ActiveVer, _config.ActiveIgmpMode, _config.IsRunning ? "true" : "false");
                    byte[] b = Encoding.UTF8.GetBytes(json); ctx.Response.ContentType = "application/json"; ctx.Response.OutputStream.Write(b, 0, b.Length);
                } else if (path == "/api/control") {
                    var q = ctx.Request.QueryString;
                    if (q["action"] == "stop") { _config.IsRunning = false; AddLog("CONTROL", "STOP command"); }
                    else if (q["action"] == "start") { _config.IsRunning = true; AddLog("CONTROL", "START command"); }
                    if (q["group"] != null && q["group"] != _config.GroupAddr) { AddLog("CONFIG_CHANGE", string.Format("Group: {0} -> {1}", _config.GroupAddr, q["group"])); _config.GroupAddr = q["group"]; _config.NeedsRestart = true; }
                    if (q["port"] != null) { int p; if (int.TryParse(q["port"], out p) && p > 0 && p <= 65535 && p != _config.Port) { AddLog("CONFIG_CHANGE", string.Format("Port: {0} -> {1}", _config.Port, p)); _config.Port = p; _config.NeedsRestart = true; } }
                    if (q["source"] != null && q["source"] != _config.SourceAddr) { AddLog("CONFIG_CHANGE", string.Format("Source: {0} -> {1}", _config.SourceAddr, q["source"])); _config.SourceAddr = q["source"]; _config.NeedsRestart = true; }
                    if (q["v"] != null) { int v; if (int.TryParse(q["v"], out v) && (v == 2 || v == 3) && v != _config.IgmpVersion) { AddLog("CONFIG_CHANGE", string.Format("Version: v{0} -> v{1}", _config.IgmpVersion, v)); _config.IgmpVersion = v; _config.NeedsRestart = true; } }
                    if (q["mode"] != null && q["mode"] != _config.IgmpMode) { AddLog("CONFIG_CHANGE", string.Format("Mode: {0} -> {1}", _config.IgmpMode, q["mode"])); _config.IgmpMode = q["mode"]; _config.NeedsRestart = true; }
                    if (q["dscp"] != null) { int d; if (int.TryParse(q["dscp"], out d) && d >= 0 && d <= 63 && d != _config.Dscp) { AddLog("CONFIG_CHANGE", string.Format("DSCP: {0} -> {1}", _config.Dscp, d)); _config.Dscp = d; } }
                    if (q["bw"] != null) { double b; if (double.TryParse(q["bw"], out b) && b >= 0 && b != _config.BandwidthMbps) { AddLog("CONFIG_CHANGE", string.Format("BW: {0} -> {1} Mbps", _config.BandwidthMbps, b)); _config.BandwidthMbps = b; _config.TargetIntervalMs = MToolCore.CalculateIntervalMs(_config.BandwidthMbps, _config.PacketSize, _config.Interval); } }
                    if (q["ttl"] != null) { int t; if (int.TryParse(q["ttl"], out t) && t > 0 && t <= 255 && t != _config.Ttl) { AddLog("CONFIG_CHANGE", string.Format("TTL: {0} -> {1}", _config.Ttl, t)); _config.Ttl = t; } }
                    if (q["size"] != null) { int s; if (int.TryParse(q["size"], out s) && s > 0 && s <= 1472 && s != _config.PacketSize) { AddLog("CONFIG_CHANGE", string.Format("Size: {0} -> {1}", _config.PacketSize, s)); _config.PacketSize = s; _config.TargetIntervalMs = MToolCore.CalculateIntervalMs(_config.BandwidthMbps, _config.PacketSize, _config.Interval); } }
                    ctx.Response.StatusCode = 200;
                } else if (path == "/api/record") {
                    string action = ctx.Request.QueryString["action"];
                    if (action == "start") {
                        lock (_logLock) {
                            _logBuffer.Clear(); _config.IsRecording = true;
                            _logBuffer.AppendLine("Timestamp,Event,TX_Mbps,RX_Mbps,Lat_us,Jitter,Loss,Details");
                            AddLog("RECORD_START", "Session initialized");
                            AddLog("CONFIG_INITIAL", string.Format("Grp:{0}, Port:{1}, Ver:v{2}, Mode:{3}, Src:{4}, BW:{5}Mbps, Size:{6}", _config.GroupAddr, _config.Port, _config.IgmpVersion, _config.IgmpMode, _config.SourceAddr, _config.BandwidthMbps, _config.PacketSize));
                        }
                    } else if (action == "stop") {
                        lock (_logLock) { AddLog("RECORD_STOP", "Session ended"); _config.IsRecording = false; }
                    } else if (action == "download") {
                        string content; lock (_logLock) { content = _logBuffer.ToString(); }
                        byte[] b = Encoding.UTF8.GetBytes(content); ctx.Response.ContentType = "text/csv";
                        ctx.Response.AddHeader("Content-Disposition", "attachment; filename=\"mtool_report_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".csv\"");
                        ctx.Response.OutputStream.Write(b, 0, b.Length); return;
                    }
                    byte[] resp = Encoding.UTF8.GetBytes("{\"isRecording\":" + _config.IsRecording.ToString().ToLower() + "}"); ctx.Response.ContentType = "application/json"; ctx.Response.OutputStream.Write(resp, 0, resp.Length);
                } else if (path == "/api/resetStats") {
                    _stats.Reset(); ctx.Response.StatusCode = 200;
                } else if (path == "/api/resetParams") {
                    // This will be handled in Program by restoring initial values
                    ctx.Response.StatusCode = 202; // Accepted, needs handling in main loop
                } else {
                    byte[] b = Encoding.UTF8.GetBytes(WebUI); ctx.Response.ContentType = "text/html"; ctx.Response.OutputStream.Write(b, 0, b.Length);
                }
            } catch (Exception) { if (!ct.IsCancellationRequested) ctx.Response.StatusCode = 500; }
            finally { try { ctx.Response.Close(); } catch {} }
        }

        // WebUI Constants
        private const string WebUI_CSS = @"<style>
:root{--bg:#0f172a;--card:#1e293b;--tx:#00f2fe;--lat:#7117ea;--jit:#f6ad55;--confirmed:#10b981;--pending:#f59e0b;--error:#ef4444;--offline:#64748b}
body{background:var(--bg);color:#f1f5f9;font-family:system-ui,-apple-system,sans-serif;margin:0;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px}
.card{background:var(--card);border-radius:12px;padding:20px;border:1px solid rgba(255,255,255,0.05);box-shadow:0 10px 15px -3px rgba(0,0,0,0.1)}
.hidden{display:none}
h1,h2{margin:0 0 15px 0;font-size:1.2rem;background:linear-gradient(90deg,var(--tx),#7117ea);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.val{font-size:3.5rem;font-weight:800;font-variant-numeric:tabular-nums;line-height:1}
.unit{font-size:1.2rem;color:#94a3b8;margin-left:8px}
.row{display:flex;justify-content:space-between;margin:8px 0;color:#94a3b8}
input,select{background:#0f172a;border:1px solid #334155;color:white;padding:8px;border-radius:4px;width:100px}
.btn{background:linear-gradient(135deg,var(--tx),#7117ea);border:none;color:white;padding:12px;border-radius:8px;cursor:pointer;width:100%;font-weight:700;margin-top:15px;transition:0.3s}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px}
.s-confirmed{background:var(--confirmed);box-shadow:0 0 8px var(--confirmed)}
.s-pending{background:var(--pending);animation:blink 1s infinite}
.s-error{background:var(--error)}
.s-offline{background:var(--offline)}
@keyframes blink{50%{opacity:0.3}}
svg{width:100%;height:120px;margin-top:10px;overflow:visible}
polyline{fill:none;stroke-width:2;vector-effect:non-scaling-stroke}
text{fill:#94a3b8;font-size:10px;font-family:monospace}
.guide{stroke:rgba(255,255,255,0.1);stroke-width:1;stroke-dasharray:4}
.rfc-link{color:var(--tx);text-decoration:none;font-size:11px;opacity:0.7}
.rfc-link:hover{opacity:1;text-decoration:underline}
.btn-record{background:#ef4444;border:none;color:white;padding:12px;border-radius:8px;cursor:pointer;width:100%;font-weight:700;margin-top:15px;transition:0.3s}
.btn-record.active{background:#b91c1c;box-shadow:0 0 15px var(--error);animation:rec-blink 1s infinite}
@keyframes rec-blink{50%{opacity:0.7}}
#recStatus{display:none;color:var(--error);font-weight:700;align-items:center;gap:6px;font-size:14px}
.rec-dot{width:10px;height:10px;background:var(--error);border-radius:50%;animation:rec-blink 1s infinite}
</style>";

        private const string WebUI_HTML = @"
<div style='display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:25px'>
    <div>
        <h1 style='font-size:1.8rem'>MTOOL <span id='modeBadge' style='font-size:14px;padding:4px 8px;border-radius:99px;background:#334155;color:white;margin-left:10px'>-</span></h1>
    </div>
    <div style='text-align:right'>
        <div id='info' style='color:#94a3b8;font-size:14px'>Waiting for stats...</div>
        <div id='igmpInfo' style='color:var(--tx);font-size:12px;margin-top:4px;font-family:monospace'>Last IGMP Query: -</div>
    </div>
</div>
<div class='grid'>
    <div class='card' style='grid-column:span 2;display:flex;justify-content:space-between;align-items:center'>
        <div>
            <h2 style='margin:0'>Operational Status</h2>
            <div style='display:flex;align-items:center;gap:15px;margin-top:5px'>
                <div style='display:flex;align-items:center'><span id='statusDot' class='status-dot s-offline'></span><span id='statusText' style='font-size:16px;font-weight:700'>Connecting...</span></div>
                <div id='recStatus' style='display:none;color:var(--error);font-weight:700;align-items:center;gap:6px;font-size:14px'><div style='width:10px;height:10px;background:var(--error);border-radius:50%;animation:rec-blink 1s infinite'></div>LOGGING</div>
            </div>
        </div>
        <div style='display:flex;gap:10px'>
            <button id='startBtn' class='btn' style='margin:0;width:120px;background:var(--confirmed)' onclick='sendAction(""start"")'>START</button>
            <button id='stopBtn' class='btn' style='margin:0;width:120px;background:var(--error)' onclick='sendAction(""stop"")'>STOP</button>
        </div>
    </div>
    <div id='txCard' class='card'><h2>Transmission (TX)</h2><div class='val' id='txMbps'>0.0<span class='unit'>Mbps</span></div><div class='row'><span>Throughput</span><span id='txPps'>0 pps</span></div>
        <svg viewBox='-40 0 440 125'>
            <line x1='0' y1='0' x2='400' y2='0' class='guide' /><line x1='0' y1='50' x2='400' y2='50' class='guide' /><line x1='0' y1='100' x2='400' y2='100' class='guide' />
            <text x='-5' y='5' text-anchor='end' id='txY2'>-</text><text x='-5' y='55' text-anchor='end' id='txY1'>-</text><text x='-5' y='100' text-anchor='end'>0</text>
            <text x='0' y='120'>-100s</text><text x='200' y='120' text-anchor='middle'>-50s</text><text x='400' y='120' text-anchor='end'>Now</text>
            <polyline id='chartTx' style='stroke:var(--tx)' />
        </svg>
    </div>
    <div id='rxCard' class='card hidden'><h2>Reception (RX)</h2><div class='val' id='rxMbps'>0.0<span class='unit'>Mbps</span></div><div class='row'><span>Throughput</span><span id='rxPps'>0 pps</span></div>
        <svg viewBox='-40 0 440 125'>
            <line x1='0' y1='0' x2='400' y2='0' class='guide' /><line x1='0' y1='50' x2='400' y2='50' class='guide' /><line x1='0' y1='100' x2='400' y2='100' class='guide' />
            <text x='-5' y='5' text-anchor='end' id='rxY2'>-</text><text x='-5' y='55' text-anchor='end' id='rxY1'>-</text><text x='-5' y='100' text-anchor='end'>0</text>
            <text x='0' y='120'>-100s</text><text x='200' y='120' text-anchor='middle'>-50s</text><text x='400' y='120' text-anchor='end'>Now</text>
            <polyline id='chartRx' style='stroke:var(--tx)' />
        </svg>
    </div>
    <div id='latCard' class='card hidden'><h2>Latency (Average)</h2><div class='val' id='latVal'>0<span class='unit'>us</span></div>
        <svg viewBox='-40 0 440 125'>
            <line x1='0' y1='0' x2='400' y2='0' class='guide' /><line x1='0' y1='50' x2='400' y2='50' class='guide' /><line x1='0' y1='100' x2='400' y2='100' class='guide' />
            <text x='-5' y='5' text-anchor='end' id='latY2'>-</text><text x='-5' y='55' text-anchor='end' id='latY1'>-</text><text x='-5' y='100' text-anchor='end'>0</text>
            <text x='0' y='120'>-100s</text><text x='200' y='120' text-anchor='middle'>-50s</text><text x='400' y='120' text-anchor='end'>Now</text>
            <polyline id='chartLat' style='stroke:var(--lat)' />
        </svg>
    </div>
    <div id='jitCard' class='card hidden'><h2>Jitter (Variation)</h2><div class='val' id='jitVal'>0<span class='unit'>us</span></div>
        <svg viewBox='-40 0 440 125'>
            <line x1='0' y1='0' x2='400' y2='0' class='guide' /><line x1='0' y1='50' x2='400' y2='50' class='guide' /><line x1='0' y1='100' x2='400' y2='100' class='guide' />
            <text x='-5' y='5' text-anchor='end' id='jitY2'>-</text><text x='-5' y='55' text-anchor='end' id='jitY1'>-</text><text x='-5' y='100' text-anchor='end'>0</text>
            <text x='0' y='120'>-100s</text><text x='200' y='120' text-anchor='middle'>-50s</text><text x='400' y='120' text-anchor='end'>Now</text>
            <polyline id='chartJit' style='stroke:var(--jit)' />
        </svg>
    </div>
    <div id='qualCard' class='card hidden'><h2>Packet Quality</h2><div class='val' id='lossVal'>0.00<span class='unit'>% Loss</span></div>
        <div class='row'><span>Detected DSCP</span><span id='dscpTrue'>-</span></div>
        <div class='row'><span>Actual TTL</span><span id='ttlTrue'>-</span></div>
        <div class='row'><span>Source MAC</span><span id='macTrue' style='font-size:11px'>-</span></div>
        <div class='row' id='fragRow' style='color:#f87171'><span>IP Fragmentation</span><span id='fragTrue'>None</span></div>
    </div>
    <div class='card' style='grid-column:span 2'><h2>Control Panel (<span id='ctrlMode'>-</span>)</h2>
        <div style='display:grid;grid-template-columns:1fr 1fr;gap:20px'>
            <div>
                <div class='row'><span>Group <a href='https://tools.ietf.org/html/rfc1112' class='rfc-link' target='_blank'>RFC 1112</a></span><input type='text' id='gIn' style='width:160px' oninput='updateHint()'></div>
                <div class='row'><span>Port (1-65535) <a href='https://tools.ietf.org/html/rfc768' class='rfc-link' target='_blank'>RFC 768</a></span><input type='number' id='pIn' min='1' max='65535' oninput='updateHint()'></div>
                <div class='row'><span>Source IP</span><input type='text' id='sIn' style='width:160px' oninput='updateHint()'></div>
                <div id='txOnly1'>
                    <div class='row'><span>Bandwidth (Mbps)</span><input type='number' id='bIn' step='0.1'></div>
                </div>
            </div>
            <div>
                <div class='row'><span>IGMP Version</span><select id='vIn' style='width:120px' onchange='updateHint()'><option value='2'>v2</option><option value='3'>v3</option></select></div>
                <div class='row'><span>IGMP Mode</span><select id='mIn' style='width:120px' onchange='updateHint()'><option value='include'>Include</option><option value='exclude'>Exclude</option></select></div>
                <div id='modeHint' style='font-size:11px;color:var(--pending);text-align:right;margin-top:-10px;margin-bottom:10px'></div>
                <div id='txOnly2'>
                    <div class='row'><span>DSCP (0-63) <a href='https://tools.ietf.org/html/rfc2474' class='rfc-link' target='_blank'>RFC 2474</a></span><input type='number' id='dIn' min='0' max='63'></div>
                    <div class='row'><span>TTL (1-255)</span><input type='number' id='tIn' min='1' max='255'></div>
                    <div class='row'><span>Size (1-1472)</span><input type='number' id='szIn' min='1' max='1472'></div>
                </div>
            </div>
        </div>
        <div style='display:flex;gap:10px;grid-column:span 2'>
            <button id='applyBtn' class='btn' onclick='update()'>Apply Changes</button>
            <button id='btnRec' class='btn-record' onclick='toggleRecord()'>Start Logging</button>
            <button class='btn' style='background:#475569' onclick='resetStats()'>Reset Stats</button>
            <button class='btn' style='background:#334155' onclick='resetParams()'>Restore Defaults</button>
        </div>
    </div>
</div>";

        private const string WebUI_JS = @"<script>
let stats = { tx:[], rx:[], lat:[], jit:[] };
let lTxC = 0, lRxC = 0, lTxB = 0, lRxB = 0, offlineCount = 0;
let isApplying = false;

function updateStatus(dot, text, label) {
    const d = document.getElementById('statusDot');
    const t = document.getElementById('statusText');
    if(!d || !t) return;
    d.className = 'status-dot ' + dot;
    t.innerText = text;
    t.style.color = 'var(--' + label + ')';
}

async function tick() {
    try {
        const r = await fetch('/api/stats', { signal: AbortSignal.timeout(2000) });
        const d = await r.json();
        offlineCount = 0;
        
        const isSync = d.group == d.activeGrp && d.port == d.activePort && d.source == d.activeSrc && d.version == d.activeVer && d.igmpMode == d.activeIgmpMode && d.dscp == d.activeDscp && d.ttl == d.activeTtl && d.size == d.activeSize && d.bw == d.activeBw;
        
        if (isApplying && isSync) { isApplying = false; document.getElementById('applyBtn').innerText = 'Apply Changes'; document.getElementById('applyBtn').disabled = false; }
        
        if (!d.isRunning) updateStatus('s-offline', 'STOPPED', 'offline');
        else if (isApplying) updateStatus('s-pending', 'Applying changes...', 'pending');
        else if (isSync) updateStatus('s-confirmed', 'RUNNING (Synced)', 'confirmed');
        else updateStatus('s-pending', 'Syncing with backend...', 'pending');

        document.getElementById('startBtn').disabled = d.isRunning;
        document.getElementById('stopBtn').disabled = !d.isRunning;

        const send = d.mode == 'send';
        document.getElementById('modeBadge').innerText = d.mode.toUpperCase();
        document.getElementById('ctrlMode').innerText = send ? 'Sender Settings' : 'Receiver Settings';
        document.getElementById('info').innerText = 'Target: ' + d.group + ':' + d.port;
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
            document.getElementById('txMbps').innerHTML = mbps.toFixed(2) + '<span class=\'unit\'>Mbps</span>';
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
            document.getElementById('rxMbps').innerHTML = mbps.toFixed(2) + '<span class=\'unit\'>Mbps</span>';
            document.getElementById('rxPps').innerText = rxPps + ' pps';
            document.getElementById('latVal').innerHTML = Math.round(d.avgLat) + '<span class=\'unit\'>us</span>';
            document.getElementById('jitVal').innerHTML = Math.round(d.jitter) + '<span class=\'unit\'>us</span>';
            document.getElementById('lossVal').innerHTML = (d.lost/(d.rxCount+d.lost)*100).toFixed(2) + '<span class=\'unit\'>% Loss</span>';
            document.getElementById('dscpTrue').innerText = d.actualDscp>=0 ? d.actualDscp : '-';
            document.getElementById('ttlTrue').innerText = d.actTtl>=0 ? d.actTtl : '-';
            document.getElementById('macTrue').innerText = d.mac;
            document.getElementById('fragTrue').innerText = d.frag ? 'DETECTED' : 'None';
            document.getElementById('fragRow').style.visibility = d.frag ? 'visible' : 'hidden';
            document.getElementById('igmpInfo').innerText = 'Last IGMP Query: ' + d.lastQ;
            push(stats.rx, mbps, 'chartRx'); push(stats.lat, d.avgLat, 'chartLat'); push(stats.jit, d.jitter, 'chartJit');
        }
        if(!inputInit) initInputs(d);
    } catch(e) {
        offlineCount++;
        if (offlineCount > 3) updateStatus('s-offline', 'Tool Offline', 'offline');
    } 
    fetch('/api/record?action=status').then(r => r.json()).then(d => {
        const b = document.getElementById('btnRec'), s = document.getElementById('recStatus');
        if (d.isRecording) { b.innerText = 'Stop & Download CSV'; b.classList.add('active'); s.style.display = 'flex'; }
        else { b.innerText = 'Start Logging'; b.classList.remove('active'); s.style.display = 'none'; }
    });
    setTimeout(tick, 1000);
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
    window.lastVer = d.version || '2';
    updateHint();
}
function updateHint() {
    const vEl = document.getElementById('vIn'), mEl = document.getElementById('mIn'), s = document.getElementById('sIn').value.trim();
    const v = vEl.value, m = mEl.value, h = document.getElementById('modeHint');
    if (!h) return;

    if (v == '2') {
        mEl.disabled = true;
        h.innerHTML = '\u2705 v2 Join (Any Source)'; h.style.color = 'var(--confirmed)';
    } else {
        mEl.disabled = false;
        if (window.lastVer == '2') { mEl.value = 'exclude'; }
        
        const curM = mEl.value;
        if (curM == 'include') {
            if (s) { h.innerHTML = '\u2705 v3 SSM Join (Source Specific)'; h.style.color = 'var(--confirmed)'; }
            else { h.innerHTML = '\u26A0\uFE0F v3 Leave (Empty Include = RFC 3376)'; h.style.color = 'var(--pending)'; }
        } else {
            if (!s) { h.innerHTML = '\u2705 v3 ASM Join (Exclude None)'; h.style.color = 'var(--confirmed)'; }
            else { h.innerHTML = '\u2139\uFE0F v3 Source Block (Exclude Source)'; h.style.color = 'var(--pending)'; }
        }
    }
    window.lastVer = v;
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
    
    if (p < 1 || p > 65535) { alert('Invalid Port (1-65535)'); return; }
    if (d < 0 || d > 63) { alert('Invalid DSCP (0-63)'); return; }
    if (t < 1 || t > 255) { alert('Invalid TTL (1-255)'); return; }
    if (sz < 1 || sz > 1472) { alert('Invalid Size (1-1472)'); return; }

    const btn = document.getElementById('applyBtn');
    btn.innerText = 'Applying...'; btn.disabled = true;
    isApplying = true;
    
    fetch('/api/control?group=' + g + '&port=' + p + '&source=' + s + '&bw=' + b + '&v=' + v + '&mode=' + m + '&dscp=' + d + '&ttl=' + t + '&size=' + sz)
        .then(r => { if(!r.ok) { alert('Update Failed'); isApplying = false; btn.disabled = false; btn.innerText = 'Apply Changes'; } })
        .catch(e => { alert('Network Error'); isApplying = false; btn.disabled = false; btn.innerText = 'Apply Changes'; });
}
function sendAction(a) {
    fetch('/api/control?action=' + a).then(r => { if(!r.ok) alert('Action Failed'); });
}
function toggleRecord() {
    const isRec = document.getElementById('btnRec').classList.contains('active');
    const action = isRec ? 'stop' : 'start';
    fetch('/api/record?action=' + action).then(r => {
        if (r.ok && isRec) {
            window.location.href = '/api/record?action=download';
        }
    });
}
tick();
</script>";

        private string WebUI { get { return string.Format("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>MTOOL | Dashboard</title>{0}</head><body>{1}{2}</body></html>", WebUI_CSS, WebUI_HTML, WebUI_JS); } }
    }
}
