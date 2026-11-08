import React, { useState, useEffect } from 'react';
import { SentinelApi } from './services/api';
import { Alert, SecurityEvent, AlertStats, AnalyticsOverview } from './types';
import { 
  ShieldAlert, 
  Activity, 
  AlertTriangle, 
  BrainCircuit, 
  Sparkles, 
  FileDown, 
  RefreshCw,
  Send,
  Zap,
  CheckCircle,
  Clock
} from 'lucide-react';

export default function App() {
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [overview, setOverview] = useState<AnalyticsOverview | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [chatMessages, setChatMessages] = useState<Array<{ sender: 'user' | 'ai'; text: string; details?: any }>>([
    {
      sender: 'ai',
      text: 'Sentinel Copilot active. Select an alert from the table to investigate blast radius or ask me about defensive mitigations.'
    }
  ]);
  const [inputMsg, setInputMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    try {
      await SentinelApi.login();
      const [s, o, a, e] = await Promise.all([
        SentinelApi.getStats(),
        SentinelApi.getAnalyticsOverview(),
        SentinelApi.getAlerts(),
        SentinelApi.getEvents()
      ]);
      setStats(s);
      setOverview(o);
      setAlerts(a || []);
      setEvents(e || []);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulate = async (type: string) => {
    let payload: any = {};
    if (type === 'brute_force') {
      payload = {
        event_type: 'LOGIN_FAILED',
        source_ip: '203.0.113.88',
        user_identifier: 'victim_admin',
        location: 'Frankfurt, DE',
        failed_attempts: 7,
        device_info: 'Hydra-BruteForce/9.2'
      };
    } else if (type === 'ip_spray') {
      payload = {
        event_type: 'LOGIN_FAILED',
        source_ip: '198.51.100.42',
        user_identifier: 'target_emp_' + Math.floor(Math.random() * 100),
        location: 'Moscow, RU',
        failed_attempts: 1,
        device_info: 'Python-Requests/2.31'
      };
    } else if (type === 'impossible_travel') {
      payload = {
        event_type: 'LOGIN_SUCCESS',
        source_ip: '114.119.130.5',
        user_identifier: 'sarah_analyst',
        location: 'Tokyo, JP',
        failed_attempts: 0,
        device_info: 'Mozilla/5.0 Mac'
      };
    } else {
      payload = {
        event_type: 'LOGIN_SUCCESS',
        source_ip: '192.168.1.15',
        user_identifier: 'sarah_analyst',
        location: 'New York, US',
        failed_attempts: 0,
        device_info: 'Mozilla/5.0 Windows'
      };
    }

    const res = await SentinelApi.ingestEvent(payload);
    loadData();
    if (res.threat_detected && res.alerts?.length > 0) {
      setChatMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text: `🚨 High-Risk Threat Detected: ${res.alerts[0].title} (Score: ${res.alerts[0].risk_score}/100) via ${res.alerts[0].rule_triggered}.`
        }
      ]);
    }
  };

  const handleResolveAlert = async (id: number) => {
    await SentinelApi.updateAlertStatus(id, 'RESOLVED', 'Mitigated in SOC');
    loadData();
  };

  const handleAnalyzeAlert = async (id: number) => {
    setLoading(true);
    const analysis = await SentinelApi.analyzeAlert(id);
    setLoading(false);
    setChatMessages(prev => [
      ...prev,
      {
        sender: 'ai',
        text: `Analysis for Alert #${id}: ${analysis.title}`,
        details: analysis
      }
    ]);
  };

  const handleSendChat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputMsg.trim()) return;
    const msg = inputMsg;
    setInputMsg('');
    setChatMessages(prev => [...prev, { sender: 'user', text: msg }]);

    const res = await SentinelApi.chatAssistant(msg);
    setChatMessages(prev => [...prev, { sender: 'ai', text: res.reply }]);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-md px-6 py-4 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-xl bg-cyan-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <div>
            <span className="text-xl font-black tracking-wider text-white">SENTINEL<span className="text-cyan-400">.AI</span></span>
            <p className="text-xs text-slate-400">Security, Identity & Risk Intelligence Platform</p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button 
            onClick={() => window.open('/api/v1/analytics/reports/pdf', '_blank')}
            className="flex items-center space-x-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition"
          >
            <FileDown className="w-4 h-4" />
            <span>Export Executive PDF</span>
          </button>
        </div>
      </header>

      {/* Main Workspace */}
      <main className="max-w-7xl mx-auto p-6 space-y-6">
        {/* KPI Cards Grid */}
        <section className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase">
              <span>Ingested Events</span>
              <Activity className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="text-3xl font-black text-white mt-2">{overview?.total_events_ingested ?? 0}</div>
            <p className="text-xs text-slate-500 mt-1">Real-time log ingestion</p>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase">
              <span>Active Alerts</span>
              <AlertTriangle className="w-5 h-5 text-amber-400" />
            </div>
            <div className="text-3xl font-black text-amber-400 mt-2">{stats?.open_alerts ?? 0}</div>
            <p className="text-xs text-slate-500 mt-1">Under investigation</p>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase">
              <span>Critical Threats</span>
              <ShieldAlert className="w-5 h-5 text-rose-500" />
            </div>
            <div className="text-3xl font-black text-rose-500 mt-2">{stats?.critical_alerts ?? 0}</div>
            <p className="text-xs text-slate-500 mt-1">Immediate action required</p>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <div className="flex justify-between items-center text-slate-400 text-xs font-bold uppercase">
              <span>Average Risk Index</span>
              <BrainCircuit className="w-5 h-5 text-indigo-400" />
            </div>
            <div className="text-3xl font-black text-indigo-400 mt-2">
              {overview?.average_alert_risk_score.toFixed(1) ?? '0.0'}
            </div>
            <p className="text-xs text-slate-500 mt-1">Normalized 0–100 scale</p>
          </div>
        </section>

        {/* 2-Column Core Interface */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Attack Simulator & Alerts Table */}
          <div className="lg:col-span-7 space-y-6">
            {/* Simulation Bar */}
            <div className="bg-slate-900 border border-cyan-900/60 rounded-2xl p-5">
              <div className="flex items-center space-x-2 mb-3">
                <Zap className="w-4 h-4 text-cyan-400" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-white">Live Attack Simulator</h2>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <button onClick={() => handleSimulate('brute_force')} className="bg-rose-950/50 hover:bg-rose-900/60 border border-rose-800/80 text-rose-300 text-xs font-medium py-2 rounded-xl transition">
                  Brute Force
                </button>
                <button onClick={() => handleSimulate('ip_spray')} className="bg-amber-950/50 hover:bg-amber-900/60 border border-amber-800/80 text-amber-300 text-xs font-medium py-2 rounded-xl transition">
                  IP Spraying
                </button>
                <button onClick={() => handleSimulate('impossible_travel')} className="bg-indigo-950/50 hover:bg-indigo-900/60 border border-indigo-800/80 text-indigo-300 text-xs font-medium py-2 rounded-xl transition">
                  Geo Velocity
                </button>
                <button onClick={() => handleSimulate('clean')} className="bg-emerald-950/50 hover:bg-emerald-900/60 border border-emerald-800/80 text-emerald-300 text-xs font-medium py-2 rounded-xl transition">
                  Clean Login
                </button>
              </div>
            </div>

            {/* Alerts Table */}
            <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-lg">
              <div className="p-4 border-b border-slate-800 flex justify-between items-center">
                <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  <span>Real-Time Incident Triage</span>
                </h3>
                <button onClick={loadData} className="text-xs text-slate-400 hover:text-cyan-400 flex items-center space-x-1">
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Refresh</span>
                </button>
              </div>

              <div className="overflow-x-auto max-h-[380px] overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider sticky top-0">
                    <tr>
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4">Title</th>
                      <th className="py-3 px-4">Risk</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {alerts.length === 0 ? (
                      <tr><td colSpan={5} className="py-8 text-center text-slate-500">No active alerts. Simulate an attack above!</td></tr>
                    ) : (
                      alerts.map(a => (
                        <tr key={a.id} className="hover:bg-slate-800/50 transition">
                          <td className="py-3 px-4">
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                              a.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border-rose-800' :
                              a.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border-orange-800' :
                              a.severity === 'MEDIUM' ? 'bg-amber-950 text-amber-400 border-amber-800' :
                              'bg-emerald-950 text-emerald-400 border-emerald-800'
                            }`}>
                              {a.severity}
                            </span>
                          </td>
                          <td className="py-3 px-4 font-medium text-slate-200">{a.title}</td>
                          <td className="py-3 px-4 font-bold text-cyan-400">{a.risk_score.toFixed(0)}</td>
                          <td className="py-3 px-4 text-slate-400">{a.status}</td>
                          <td className="py-3 px-4 text-right space-x-1">
                            <button onClick={() => handleAnalyzeAlert(a.id)} className="bg-indigo-950 hover:bg-indigo-900 border border-indigo-700 text-indigo-300 px-2 py-1 rounded text-[11px]">
                              Analyze AI
                            </button>
                            {a.status !== 'RESOLVED' && (
                              <button onClick={() => handleResolveAlert(a.id)} className="bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 px-2 py-1 rounded text-[11px]">
                                Resolve
                              </button>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Right Column: Sentinel Copilot */}
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl flex flex-col h-[650px] shadow-lg">
            <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-center space-x-2">
              <Sparkles className="w-5 h-5 text-indigo-400" />
              <div>
                <h3 className="text-sm font-bold text-white">Sentinel Copilot</h3>
                <p className="text-[11px] text-slate-400">GenAI Security Analyst & MITRE ATT&CK</p>
              </div>
            </div>

            <div className="flex-1 p-4 overflow-y-auto space-y-3 text-xs">
              {chatMessages.map((msg, i) => (
                <div key={i} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`p-3.5 rounded-2xl max-w-[85%] leading-relaxed ${
                    msg.sender === 'user' ? 'bg-cyan-950 text-cyan-200 border border-cyan-800' : 'bg-slate-800 text-slate-200 border border-slate-700'
                  }`}>
                    <div>{msg.text}</div>
                    {msg.details && (
                      <div className="mt-3 space-y-2 border-t border-slate-700 pt-2 text-[11px]">
                        <div className="text-amber-400 font-bold">MITRE ATT&CK: {msg.details.mitre_reference}</div>
                        <div className="text-slate-300"><span className="font-semibold">Blast Radius:</span> {msg.details.blast_radius}</div>
                        <div className="font-bold text-white mt-2">Remediation Runbook:</div>
                        <ul className="list-disc pl-4 space-y-1 text-slate-300">
                          {msg.details.defensive_runbook?.map((r: string, idx: number) => (
                            <li key={idx}>{r}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>

            <form onSubmit={handleSendChat} className="p-3 bg-slate-950 border-t border-slate-800 flex space-x-2">
              <input 
                type="text" 
                value={inputMsg}
                onChange={e => setInputMsg(e.target.value)}
                placeholder="Ask Sentinel Copilot..." 
                className="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
              <button type="submit" className="bg-cyan-600 hover:bg-cyan-500 text-white p-2.5 rounded-xl transition">
                <Send className="w-4 h-4" />
              </button>
            </form>
          </div>
        </div>
      </main>
    </div>
  );
}

