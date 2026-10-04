"use client";

import React, { useEffect, useState, useMemo } from "react";
import {
  ShieldAlert,
  Download,
  RefreshCw,
  LayoutGrid,
  Sliders,
  FileCode,
  Activity,
  Search,
  Database,
  Flag,
  Bell,
  Radio,
  ExternalLink,
  ChevronRight,
  X,
  Plus,
  Trash2,
  Save,
  CheckCircle,
  AlertTriangle,
  Rss,
  EyeOff,
  Send,
  Hash,
  Globe,
  Loader2,
  Pencil,
  Terminal,
} from "lucide-react";
import { TerminalConsole } from "./components/TerminalConsole";

interface Incident {
  id: string;
  source_type: string;
  source_name: string;
  title: string;
  url: string | null;
  summary: string;
  published_at: string | null;
  harvested_at: string;
  severity: string | null;
  japan_relevance: string | null;
  notified_at: string | null;
  enriched_data: string | null;
  enriched_parsed?: {
    title_ja?: string;
    summary_ja?: string;
    impact_analysis_ja?: string;
    victim_orgs?: string[];
    threat_actors?: string[];
    attack_type?: string;
    recommended_actions_ja?: string[];
  } | null;
}

interface SystemStatus {
  status: string;
  timestamp: string;
  database: {
    total_items?: number;
    notified_items?: number;
    japan_direct_items?: number;
    backend?: string;
    database_url?: string;
    db_path?: string;
  };
  tor_proxy: {
    online: boolean;
    url: string;
  };
  ai: {
    configured: boolean;
    model: string;
  };
  sinks: {
    discord: boolean;
    slack: boolean;
    generic_webhook: boolean;
    notion: boolean;
  };
  sources: {
    vendor_rss?: { total: number; active: number };
    telegram?: { total: number; active: number };
    darkweb_onion?: { total: number; active: number };
    x_monitor?: { total: number; active: number };
    web_search?: { total: number; active: number };
    total_active?: number;
  };
}

interface ConfigData {
  version?: string;
  database?: {
    type?: string;
    host?: string;
    port?: number;
    name?: string;
    user?: string;
    sqlite_path?: string;
  };
  ai?: {
    gemini_api_key?: string;
    gemini_model?: string;
  };
  network?: {
    tor_proxy_url?: string;
    request_timeout?: number;
  };
  sources?: {
    vendor_rss?: Array<{ name: string; url: string; category?: string; enabled: boolean }>;
    telegram?: Array<{ channel: string; enabled: boolean }>;
    darkweb_onion?: Array<{ name: string; url: string; type?: string; enabled: boolean }>;
    x_monitor?: Array<{ query: string; enabled: boolean }>;
    web_search?: Array<{ query: string; enabled: boolean }>;
  };
}

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<"incidents" | "sources" | "config" | "status" | "console">("incidents");
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [config, setConfig] = useState<ConfigData | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loadingIncidents, setLoadingIncidents] = useState(false);
  const [harvesting, setHarvesting] = useState(false);
  const [testingNotify, setTestingNotify] = useState(false);
  const [testingNotion, setTestingNotion] = useState(false);

  // Filters
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [japanOnly, setJapanOnly] = useState(false);
  const [sourceTypeFilter, setSourceTypeFilter] = useState("");
  const [sortBy, setSortBy] = useState<"published_at" | "harvested_at">("published_at");

  // Modals & Toast
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [addModal, setAddModal] = useState<{
    visible: boolean;
    type: string;
    form: { name: string; url: string; channel: string; query: string; type: string };
  }>({
    visible: false,
    type: "vendor_rss",
    form: { name: "", url: "", channel: "", query: "", type: "rss" },
  });
  const [editModal, setEditModal] = useState<{
    visible: boolean;
    type: string;
    originalId: string;
    form: { name: string; url: string; category: string; channel: string; query: string; type: string };
  }>({
    visible: false,
    type: "vendor_rss",
    originalId: "",
    form: { name: "", url: "", category: "general", channel: "", query: "", type: "rss" },
  });
  const [toast, setToast] = useState<{ visible: boolean; message: string; type: "info" | "error" }>({
    visible: false,
    message: "",
    type: "info",
  });

  const showToast = (message: string, type: "info" | "error" = "info") => {
    setToast({ visible: true, message, type });
    setTimeout(() => {
      setToast((prev) => ({ ...prev, visible: false }));
    }, 3500);
  };

  const fetchStatus = async () => {
    try {
      const res = await fetch("/api/status");
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      console.error("Status fetch failed:", err);
    }
  };

  const fetchConfig = async () => {
    try {
      const res = await fetch("/api/config");
      if (res.ok) {
        const data = await res.json();
        setConfig(data);
      }
    } catch (err) {
      console.error("Config fetch failed:", err);
    }
  };

  const fetchIncidents = async () => {
    setLoadingIncidents(true);
    try {
      const params = new URLSearchParams();
      if (search) params.append("search", search);
      if (severityFilter) params.append("severity", severityFilter);
      if (japanOnly) params.append("japan_only", "true");
      if (sourceTypeFilter) params.append("source_type", sourceTypeFilter);
      if (sortBy) params.append("sort_by", sortBy);

      const res = await fetch(`/api/incidents?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setIncidents(data.items || []);
      }
    } catch (err) {
      showToast("Failed to fetch incidents", "error");
    } finally {
      setLoadingIncidents(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    fetchConfig();
    fetchIncidents();
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchIncidents();
    }, 300);
    return () => clearTimeout(timer);
  }, [search, severityFilter, japanOnly, sourceTypeFilter, sortBy]);

  const handleHarvestFinished = async () => {
    setHarvesting(false);
    showToast("Threat harvesting pipeline completed.");
    await fetchIncidents();
    await fetchStatus();
  };

  const triggerHarvest = async () => {
    setHarvesting(true);
    setTerminalOpen(true);
    showToast("Threat intelligence harvest started.");
    try {
      const res = await fetch("/api/pipeline/run", { method: "POST" });
      const data = await res.json();
      if (data.status !== "started") {
        showToast(data.message || "A job is already running", "error");
        setHarvesting(false);
      }
    } catch (e) {
      showToast("Failed to trigger harvest pipeline", "error");
      setHarvesting(false);
    }
  };

  const handleToggleSource = async (sourceType: string, identifier: string, enabled: boolean) => {
    try {
      const res = await fetch("/api/config/sources", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_type: sourceType, action: "toggle", identifier, enabled }),
      });
      if (res.ok) {
        showToast(`Source set to ${enabled ? "Active" : "Disabled"}`);
        await fetchConfig();
        await fetchStatus();
      }
    } catch (e) {
      showToast("Failed to toggle source", "error");
    }
  };

  const handleDeleteSource = async (sourceType: string, identifier: string) => {
    if (!window.confirm(`Delete source (${identifier})?`)) return;
    try {
      const res = await fetch("/api/config/sources", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_type: sourceType, action: "delete", identifier }),
      });
      if (res.ok) {
        showToast("Source deleted successfully");
        await fetchConfig();
        await fetchStatus();
      }
    } catch (e) {
      showToast("Failed to delete source", "error");
    }
  };

  const handleAddSource = async () => {
    const type = addModal.type;
    let data: any = {};
    if (type === "vendor_rss") data = { name: addModal.form.name, url: addModal.form.url, enabled: true };
    if (type === "telegram") data = { channel: addModal.form.channel, enabled: true };
    if (type === "darkweb_onion") data = { name: addModal.form.name, url: addModal.form.url, type: addModal.form.type, enabled: true };
    if (type === "x_monitor" || type === "web_search") data = { query: addModal.form.query, enabled: true };

    try {
      const res = await fetch("/api/config/sources", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_type: type, action: "add", data }),
      });
      if (res.ok) {
        showToast("New threat intelligence source added");
        setAddModal((prev) => ({ ...prev, visible: false }));
        await fetchConfig();
        await fetchStatus();
      } else {
        const err = await res.json();
        showToast(err.detail || "Failed to add source", "error");
      }
    } catch (e) {
      showToast("Failed to communicate with API", "error");
    }
  };

  const handleEditSource = async () => {
    const type = editModal.type;
    let data: any = {};
    if (type === "vendor_rss") {
      data = { name: editModal.form.name, url: editModal.form.url, category: editModal.form.category };
    } else if (type === "telegram") {
      data = { channel: editModal.form.channel };
    } else if (type === "darkweb_onion") {
      data = { name: editModal.form.name, url: editModal.form.url, type: editModal.form.type };
    } else if (type === "x_monitor" || type === "web_search") {
      data = { query: editModal.form.query };
    }

    try {
      const res = await fetch("/api/config/sources", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          source_type: type,
          action: "update",
          identifier: editModal.originalId,
          data,
        }),
      });
      if (res.ok) {
        showToast("Threat intelligence source updated successfully");
        setEditModal((prev) => ({ ...prev, visible: false }));
        await fetchConfig();
        await fetchStatus();
      } else {
        const err = await res.json();
        showToast(err.detail || "Failed to update source", "error");
      }
    } catch (e) {
      showToast("Failed to communicate with API", "error");
    }
  };

  const handleSaveConfig = async () => {
    try {
      const res = await fetch("/api/config/save", { method: "POST" });
      if (res.ok) {
        showToast("Configuration saved to config.yaml");
      } else {
        showToast("Failed to save config file", "error");
      }
    } catch (e) {
      showToast("Communication error while saving", "error");
    }
  };

  const handleTestNotify = async () => {
    setTestingNotify(true);
    try {
      const res = await fetch("/api/test/notify", { method: "POST" });
      if (res.ok) {
        showToast("Test alert dispatched to configured Webhooks.");
      }
    } catch (e) {
      showToast("Webhook test failed", "error");
    } finally {
      setTestingNotify(false);
    }
  };

  const handleTestNotion = async () => {
    setTestingNotion(true);
    try {
      const res = await fetch("/api/test/notion", { method: "POST" });
      const data = await res.json();
      if (res.ok) {
        showToast(`Notion page created successfully (ID: ${data.page_id.slice(0, 8)}...)`);
      } else {
        showToast(data.detail || "Notion integration failed", "error");
      }
    } catch (e) {
      showToast("Notion integration test failed", "error");
    } finally {
      setTestingNotion(false);
    }
  };

  const formatDate = (isoStr: string) => {
    if (!isoStr) return "";
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch (e) {
      return isoStr;
    }
  };

  return (
    <div className="flex-1 flex flex-col">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          
          {/* Logo & Brand */}
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-emerald-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <span className="font-bold text-lg tracking-wider text-white">THREAT HARVESTER</span>
              <span className="hidden sm:inline-block text-xs text-slate-400 ml-2 border-l border-slate-700 pl-2">
                Japan Cyber Threat Intelligence
              </span>
            </div>
          </div>

          {/* System Health Indicators */}
          <div className="hidden md:flex items-center space-x-3">
            <span
              className={`px-2.5 py-1 rounded-full text-xs font-mono font-medium border ${
                status?.database?.backend === "postgresql"
                  ? "bg-purple-950/60 text-purple-300 border-purple-800"
                  : "bg-slate-800 text-slate-300 border-slate-700"
              }`}
            >
              <span className="mr-1">DB:</span>
              <span>{status?.database?.backend === "postgresql" ? "PostgreSQL (CNPG)" : "SQLite (Local)"}</span>
            </span>

            <span
              className={`px-2.5 py-1 rounded-full text-xs font-mono font-medium border ${
                status?.tor_proxy?.online
                  ? "bg-emerald-950/60 text-emerald-300 border-emerald-800"
                  : "bg-amber-950/60 text-amber-400 border-amber-800"
              }`}
            >
              <span
                className={`inline-block w-2 h-2 rounded-full mr-1 ${
                  status?.tor_proxy?.online ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
                }`}
              />
              <span>{status?.tor_proxy?.online ? "Tor Active" : "Tor Offline"}</span>
            </span>

            <span className="flex items-center text-xs text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 mr-1.5 animate-ping" />
              Operational
            </span>
          </div>

          {/* Header Action Buttons */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setTerminalOpen(!terminalOpen)}
              className={`inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-medium border transition cursor-pointer ${
                terminalOpen || harvesting
                  ? "bg-slate-800 text-cyan-300 border-cyan-600/80 shadow-sm shadow-cyan-950"
                  : "bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700"
              }`}
              title="Toggle Live Harvesting Terminal Console"
            >
              <Terminal className="w-3.5 h-3.5 mr-1.5 text-cyan-400" />
              <span>Console</span>
              {harvesting && (
                <span className="w-2 h-2 rounded-full bg-emerald-400 ml-1.5 animate-ping" />
              )}
            </button>

            <a
              href="/api/config/export"
              download="config.yaml"
              className="inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
            >
              <Download className="w-3.5 h-3.5 mr-1.5 text-cyan-400" />
              Export YAML
            </a>

            <button
              onClick={triggerHarvest}
              disabled={harvesting}
              className="inline-flex items-center px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/20 disabled:opacity-50 transition"
            >
              {harvesting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                  Harvesting...
                </>
              ) : (
                <>
                  <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
                  Run Harvest
                </>
              )}
            </button>
          </div>

        </div>

        {/* Navigation Tabs */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-8 border-t border-slate-800/80 text-sm font-medium">
          <button
            onClick={() => setActiveTab("incidents")}
            className={`py-3 border-b-2 transition flex items-center space-x-2 ${
              activeTab === "incidents"
                ? "border-cyan-400 text-cyan-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <LayoutGrid className="w-4 h-4" />
            <span>Threat Incidents</span>
          </button>

          <button
            onClick={() => setActiveTab("sources")}
            className={`py-3 border-b-2 transition flex items-center space-x-2 ${
              activeTab === "sources"
                ? "border-cyan-400 text-cyan-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Sliders className="w-4 h-4" />
            <span>Source Management</span>
          </button>

          <button
            onClick={() => setActiveTab("config")}
            className={`py-3 border-b-2 transition flex items-center space-x-2 ${
              activeTab === "config"
                ? "border-cyan-400 text-cyan-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Config & YAML</span>
          </button>

          <button
            onClick={() => setActiveTab("status")}
            className={`py-3 border-b-2 transition flex items-center space-x-2 ${
              activeTab === "status"
                ? "border-cyan-400 text-cyan-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>System Health</span>
          </button>

          <button
            onClick={() => setActiveTab("console")}
            className={`py-3 border-b-2 transition flex items-center space-x-2 ${
              activeTab === "console"
                ? "border-cyan-400 text-cyan-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Live Console</span>
            {harvesting && (
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            )}
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* Toast Alert */}
        {toast.visible && (
          <div
            className={`fixed bottom-5 right-5 z-50 px-4 py-3 rounded-lg shadow-xl border text-sm flex items-center space-x-2 animate-in fade-in duration-200 ${
              toast.type === "error"
                ? "bg-rose-950 border-rose-800 text-rose-200"
                : "bg-slate-900 border-cyan-800 text-cyan-200"
            }`}
          >
            {toast.type === "error" ? <AlertTriangle className="w-4 h-4" /> : <CheckCircle className="w-4 h-4" />}
            <span>{toast.message}</span>
          </div>
        )}

        {/* Live Terminal Console (Collapsible HUD) */}
        {terminalOpen && activeTab !== "console" && (
          <TerminalConsole
            isOpen={terminalOpen}
            onClose={() => setTerminalOpen(false)}
            isHarvesting={harvesting}
            onTriggerHarvest={triggerHarvest}
            onHarvestFinished={handleHarvestFinished}
          />
        )}

        {/* TAB 1: INCIDENTS FEED */}
        {activeTab === "incidents" && (
          <div>
            {/* Overview KPI Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                <div>
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Incidents</div>
                  <div className="text-2xl font-bold font-mono text-white mt-1">
                    {status?.database?.total_items ?? 0}
                  </div>
                </div>
                <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400">
                  <Database className="w-5 h-5" />
                </div>
              </div>

              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                <div>
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Japan Direct 🇯🇵</div>
                  <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
                    {status?.database?.japan_direct_items ?? 0}
                  </div>
                </div>
                <div className="w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400">
                  <Flag className="w-5 h-5" />
                </div>
              </div>

              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                <div>
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Alerts Dispatched</div>
                  <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
                    {status?.database?.notified_items ?? 0}
                  </div>
                </div>
                <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400">
                  <Bell className="w-5 h-5" />
                </div>
              </div>

              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                <div>
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Sources</div>
                  <div className="text-2xl font-bold font-mono text-purple-400 mt-1">
                    {status?.sources?.total_active ?? 0}
                  </div>
                </div>
                <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center text-purple-400">
                  <Radio className="w-5 h-5" />
                </div>
              </div>
            </div>

            {/* Filter Bar */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 mb-6 flex flex-wrap gap-3 items-center justify-between">
              <div className="relative flex-1 min-w-[240px]">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search title, victim, threat actor, or CVE..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="">Severity: All</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>

                <select
                  value={japanOnly ? "true" : "false"}
                  onChange={(e) => setJapanOnly(e.target.value === "true")}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="false">All Relevancy</option>
                  <option value="true">🇯🇵 Japan Direct Only</option>
                </select>

                <select
                  value={sourceTypeFilter}
                  onChange={(e) => setSourceTypeFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="">Source: All</option>
                  <option value="vendor_rss">Vendor & CERT RSS</option>
                  <option value="darkweb_onion">Dark Web & Ransomware</option>
                  <option value="telegram">Telegram</option>
                  <option value="x_monitor">X (Twitter)</option>
                  <option value="web_search">Web Search</option>
                </select>

                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as "published_at" | "harvested_at")}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 font-medium"
                >
                  <option value="published_at">Sort: Source Published Date (Newest)</option>
                  <option value="harvested_at">Sort: Ingestion Date (Newest)</option>
                </select>

                <button
                  onClick={fetchIncidents}
                  title="Refresh list"
                  className="p-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 text-slate-300"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Incidents List */}
            <div className="space-y-3">
              {loadingIncidents && (
                <div className="py-16 text-center text-slate-400">
                  <Loader2 className="w-8 h-8 animate-spin mx-auto mb-2 text-cyan-400" />
                  Loading threat intelligence data...
                </div>
              )}

              {!loadingIncidents && incidents.length === 0 && (
                <div className="py-16 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
                  No threat incidents match the specified filter criteria.
                </div>
              )}

              {incidents.map((item) => (
                <div
                  key={item.id}
                  onClick={() => setSelectedIncident(item)}
                  className="bg-slate-900/90 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition cursor-pointer"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                    <div className="flex items-center space-x-2">
                      {/* Severity Badge */}
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-semibold font-mono ${
                          item.severity === "Critical"
                            ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                            : item.severity === "High"
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                            : item.severity === "Medium"
                            ? "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30"
                            : item.severity === "Low"
                            ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {item.severity || "Unknown"}
                      </span>

                      {/* Japan Relevancy Badge */}
                      {item.japan_relevance === "Direct" && (
                        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center">
                          <span className="mr-1">🇯🇵</span> Japan Direct
                        </span>
                      )}
                      {item.japan_relevance === "Indirect" && (
                        <span className="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300">
                          Indirect Impact
                        </span>
                      )}

                      <span className="text-xs text-slate-400 font-mono">{item.source_name}</span>
                    </div>

                    <div className="text-right">
                      <div className="text-xs text-cyan-400 font-mono font-medium flex items-center justify-end">
                        {item.published_at ? (
                          <>
                            <span className="text-[10px] text-slate-500 mr-1.5 uppercase font-sans font-normal">Source:</span>
                            {formatDate(item.published_at)}
                          </>
                        ) : (
                          <>
                            <span className="text-[10px] text-slate-500 mr-1.5 uppercase font-sans font-normal">Harvested:</span>
                            {formatDate(item.harvested_at)}
                          </>
                        )}
                      </div>
                      {item.published_at && (
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                          Collected: {formatDate(item.harvested_at)}
                        </div>
                      )}
                    </div>
                  </div>

                  <h3 className="text-base font-semibold text-white mb-2 leading-snug hover:text-cyan-400 transition">
                    {item.enriched_parsed?.title_ja || item.title}
                  </h3>

                  <p className="text-xs text-slate-400 line-clamp-2 mb-3">
                    {item.enriched_parsed?.summary_ja || item.summary}
                  </p>

                  <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
                    {item.enriched_parsed?.victim_orgs && item.enriched_parsed.victim_orgs.length > 0 && (
                      <div className="flex items-center space-x-1">
                        <span className="text-slate-500">Victim:</span>
                        {item.enriched_parsed.victim_orgs.map((org) => (
                          <span key={org} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                            {org}
                          </span>
                        ))}
                      </div>
                    )}

                    {item.enriched_parsed?.threat_actors && item.enriched_parsed.threat_actors.length > 0 && (
                      <div className="flex items-center space-x-1 ml-2">
                        <span className="text-slate-500">Actor:</span>
                        {item.enriched_parsed.threat_actors.map((actor) => (
                          <span
                            key={actor}
                            className="px-1.5 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800 font-mono"
                          >
                            {actor}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="ml-auto flex items-center text-cyan-400 font-medium text-xs">
                      View Intelligence <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 2: SOURCE MANAGEMENT */}
        {activeTab === "sources" && (
          <div>
            <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
              <div>
                <h2 className="text-xl font-bold text-white">Threat Intelligence Sources (GUI)</h2>
                <p className="text-xs text-slate-400 mt-1">
                  Manage active threat feeds, dark web targets, Telegram channels, and social search queries.
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={handleSaveConfig}
                  className="inline-flex items-center px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow transition"
                >
                  <Save className="w-3.5 h-3.5 mr-1.5" />
                  Save to config.yaml
                </button>

                <a
                  href="/api/config/export"
                  download="config.yaml"
                  className="inline-flex items-center px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
                >
                  <Download className="w-3.5 h-3.5 mr-1.5 text-cyan-400" />
                  Download YAML
                </a>
              </div>
            </div>

            <div className="space-y-6">
              {/* 1. RSS Feeds */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <Rss className="w-5 h-5 text-amber-400" />
                    <h3 className="font-bold text-white text-base">Vendor & CERT RSS Feeds</h3>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400 font-mono">
                      {config?.sources?.vendor_rss?.length ?? 0}
                    </span>
                  </div>
                  <button
                    onClick={() =>
                      setAddModal({
                        visible: true,
                        type: "vendor_rss",
                        form: { name: "", url: "", channel: "", query: "", type: "rss" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add RSS Feed
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.vendor_rss?.map((feed) => (
                    <div key={feed.url} className="py-3 flex items-center justify-between">
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-medium text-sm text-slate-200">{feed.name}</span>
                          <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-400 font-mono">
                            {feed.category}
                          </span>
                        </div>
                        <div className="text-xs text-slate-500 font-mono truncate max-w-md mt-0.5">{feed.url}</div>
                      </div>

                      <div className="flex items-center space-x-3">
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={feed.enabled}
                            onChange={(e) => handleToggleSource("vendor_rss", feed.url, e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600" />
                        </label>
                        <button
                          onClick={() =>
                            setEditModal({
                              visible: true,
                              type: "vendor_rss",
                              originalId: feed.url,
                              form: {
                                name: feed.name,
                                url: feed.url,
                                category: feed.category || "general",
                                channel: "",
                                query: "",
                                type: "rss",
                              },
                            })
                          }
                          className="p-1 text-slate-500 hover:text-cyan-400 transition"
                          title="Edit Feed"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteSource("vendor_rss", feed.url)}
                          className="p-1 text-slate-500 hover:text-rose-400 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* 2. Dark Web Targets */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <EyeOff className="w-5 h-5 text-rose-400" />
                    <h3 className="font-bold text-white text-base">Dark Web & Ransomware Leaks</h3>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400 font-mono">
                      {config?.sources?.darkweb_onion?.length ?? 0}
                    </span>
                  </div>
                  <button
                    onClick={() =>
                      setAddModal({
                        visible: true,
                        type: "darkweb_onion",
                        form: { name: "", url: "", channel: "", query: "", type: "rss" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Target
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.darkweb_onion?.map((dw) => (
                    <div key={dw.url} className="py-3 flex items-center justify-between">
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="font-medium text-sm text-slate-200">{dw.name}</span>
                          <span className="px-1.5 py-0.2 rounded text-[10px] bg-purple-950 text-purple-300 font-mono uppercase">
                            {dw.type}
                          </span>
                        </div>
                        <div className="text-xs text-slate-500 font-mono truncate max-w-md mt-0.5">{dw.url}</div>
                      </div>

                      <div className="flex items-center space-x-3">
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={dw.enabled}
                            onChange={(e) => handleToggleSource("darkweb_onion", dw.url, e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600" />
                        </label>
                        <button
                          onClick={() =>
                            setEditModal({
                              visible: true,
                              type: "darkweb_onion",
                              originalId: dw.url,
                              form: {
                                name: dw.name,
                                url: dw.url,
                                category: "darkweb",
                                channel: "",
                                query: "",
                                type: dw.type || "rss",
                              },
                            })
                          }
                          className="p-1 text-slate-500 hover:text-cyan-400 transition"
                          title="Edit Target"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteSource("darkweb_onion", dw.url)}
                          className="p-1 text-slate-500 hover:text-rose-400 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* 3. Telegram */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <Send className="w-5 h-5 text-blue-400" />
                    <h3 className="font-bold text-white text-base">Telegram Channels</h3>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400 font-mono">
                      {config?.sources?.telegram?.length ?? 0}
                    </span>
                  </div>
                  <button
                    onClick={() =>
                      setAddModal({
                        visible: true,
                        type: "telegram",
                        form: { name: "", url: "", channel: "", query: "", type: "rss" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Channel
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.telegram?.map((tg) => (
                    <div key={tg.channel} className="py-3 flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-mono text-cyan-300">@{tg.channel}</span>
                        <a
                          href={`https://t.me/s/${tg.channel}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[11px] text-slate-500 hover:text-cyan-400"
                        >
                          <ExternalLink className="w-3.5 h-3.5 inline" />
                        </a>
                      </div>

                      <div className="flex items-center space-x-3">
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={tg.enabled}
                            onChange={(e) => handleToggleSource("telegram", tg.channel, e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600" />
                        </label>
                        <button
                          onClick={() =>
                            setEditModal({
                              visible: true,
                              type: "telegram",
                              originalId: tg.channel,
                              form: {
                                name: "",
                                url: "",
                                category: "",
                                channel: tg.channel,
                                query: "",
                                type: "",
                              },
                            })
                          }
                          className="p-1 text-slate-500 hover:text-cyan-400 transition"
                          title="Edit Channel"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteSource("telegram", tg.channel)}
                          className="p-1 text-slate-500 hover:text-rose-400 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* 4. X (Twitter) Search */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <Hash className="w-5 h-5 text-sky-400" />
                    <h3 className="font-bold text-white text-base">X (Twitter) Grounded Search Queries</h3>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400 font-mono">
                      {config?.sources?.x_monitor?.length ?? 0}
                    </span>
                  </div>
                  <button
                    onClick={() =>
                      setAddModal({
                        visible: true,
                        type: "x_monitor",
                        form: { name: "", url: "", channel: "", query: "", type: "rss" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Query
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.x_monitor?.map((xm) => (
                    <div key={xm.query} className="py-3 flex items-center justify-between">
                      <span className="text-sm font-mono text-slate-300">{xm.query}</span>
                      <div className="flex items-center space-x-3">
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={xm.enabled}
                            onChange={(e) => handleToggleSource("x_monitor", xm.query, e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600" />
                        </label>
                        <button
                          onClick={() =>
                            setEditModal({
                              visible: true,
                              type: "x_monitor",
                              originalId: xm.query,
                              form: {
                                name: "",
                                url: "",
                                category: "",
                                channel: "",
                                query: xm.query,
                                type: "",
                              },
                            })
                          }
                          className="p-1 text-slate-500 hover:text-cyan-400 transition"
                          title="Edit Query"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteSource("x_monitor", xm.query)}
                          className="p-1 text-slate-500 hover:text-rose-400 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* 5. Web Search Grounding */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <Globe className="w-5 h-5 text-emerald-400" />
                    <h3 className="font-bold text-white text-base">Gemini Web Search Queries</h3>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400 font-mono">
                      {config?.sources?.web_search?.length ?? 0}
                    </span>
                  </div>
                  <button
                    onClick={() =>
                      setAddModal({
                        visible: true,
                        type: "web_search",
                        form: { name: "", url: "", channel: "", query: "", type: "rss" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Query
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.web_search?.map((ws) => (
                    <div key={ws.query} className="py-3 flex items-center justify-between">
                      <span className="text-sm font-mono text-slate-300">{ws.query}</span>
                      <div className="flex items-center space-x-3">
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={ws.enabled}
                            onChange={(e) => handleToggleSource("web_search", ws.query, e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600" />
                        </label>
                        <button
                          onClick={() =>
                            setEditModal({
                              visible: true,
                              type: "web_search",
                              originalId: ws.query,
                              form: {
                                name: "",
                                url: "",
                                category: "",
                                channel: "",
                                query: ws.query,
                                type: "",
                              },
                            })
                          }
                          className="p-1 text-slate-500 hover:text-cyan-400 transition"
                          title="Edit Query"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteSource("web_search", ws.query)}
                          className="p-1 text-slate-500 hover:text-rose-400 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: CONFIG & YAML PREVIEW */}
        {activeTab === "config" && (
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-bold text-white">Configuration Preview & YAML Export</h2>
                <p className="text-xs text-slate-400">
                  Export the active configuration file for GitOps, Kubernetes Helm values, or backup.
                </p>
              </div>
              <div className="flex space-x-2">
                <a
                  href="/api/config/export?mask_secrets=true"
                  download="config.yaml"
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                >
                  Download with Masked Secrets
                </a>
                <a
                  href="/api/config/export?mask_secrets=false"
                  download="config.yaml"
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow transition"
                >
                  Download Complete config.yaml
                </a>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                <div className="text-xs text-slate-400 font-semibold mb-1">Database Backend</div>
                <div className="text-sm font-mono text-cyan-400">{config?.database?.type || "sqlite"}</div>
                <div className="text-xs font-mono text-slate-500 mt-1 truncate">
                  {config?.database?.host || config?.database?.sqlite_path}
                </div>
              </div>
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                <div className="text-xs text-slate-400 font-semibold mb-1">Gemini AI Model</div>
                <div className="text-sm font-mono text-emerald-400">{config?.ai?.gemini_model || "gemini-2.5-flash"}</div>
                <div className="text-xs font-mono text-slate-500 mt-1 truncate">
                  Key: {config?.ai?.gemini_api_key || "Configured"}
                </div>
              </div>
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                <div className="text-xs text-slate-400 font-semibold mb-1">Tor Proxy Endpoint</div>
                <div className="text-sm font-mono text-purple-400">{config?.network?.tor_proxy_url}</div>
                <div className="text-xs font-mono text-slate-500 mt-1">
                  Timeout: {config?.network?.request_timeout}s
                </div>
              </div>
            </div>

            <div className="bg-slate-950 rounded-lg border border-slate-800 p-4">
              <pre className="text-xs font-mono text-slate-300 overflow-x-auto max-h-[450px]">
                {JSON.stringify(config, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {/* TAB 4: SYSTEM HEALTH & INTEGRATIONS */}
        {activeTab === "status" && (
          <div className="space-y-6">
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
              <h2 className="text-lg font-bold text-white mb-4">System Service Probes</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-semibold text-slate-200">Database Engine</div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      {status?.database?.database_url || status?.database?.db_path}
                    </div>
                  </div>
                  <span className="px-2.5 py-1 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    Connected
                  </span>
                </div>

                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-semibold text-slate-200">Tor SOCKS5 Proxy</div>
                    <div className="text-xs text-slate-400 mt-0.5">{status?.tor_proxy?.url}</div>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-semibold ${
                      status?.tor_proxy?.online
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        : "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                    }`}
                  >
                    {status?.tor_proxy?.online ? "ONLINE" : "OFFLINE"}
                  </span>
                </div>

                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-semibold text-slate-200">Gemini AI Engine</div>
                    <div className="text-xs text-slate-400 mt-0.5">{status?.ai?.model}</div>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-semibold ${
                      status?.ai?.configured
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    }`}
                  >
                    {status?.ai?.configured ? "Configured" : "Missing API Key"}
                  </span>
                </div>

                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-semibold text-slate-200">Notion Knowledge Base</div>
                    <div className="text-xs text-slate-400 mt-0.5">Database auto-synchronization</div>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-semibold ${
                      status?.sinks?.notion
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {status?.sinks?.notion ? "Configured" : "Unconfigured"}
                  </span>
                </div>
              </div>
            </div>

            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
              <h2 className="text-lg font-bold text-white mb-2">Integration & Notification Probes</h2>
              <p className="text-xs text-slate-400 mb-4">
                Dispatch simulated test payloads to verify connectivity with Webhooks and Notion.
              </p>

              <div className="flex flex-wrap gap-3">
                <button
                  onClick={handleTestNotify}
                  disabled={testingNotify}
                  className="inline-flex items-center px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow disabled:opacity-50 transition"
                >
                  <Bell className="w-4 h-4 mr-1.5" />
                  {testingNotify ? "Sending..." : "Test Webhook Alert (Discord/Slack)"}
                </button>

                <button
                  onClick={handleTestNotion}
                  disabled={testingNotion}
                  className="inline-flex items-center px-4 py-2 rounded-lg text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white shadow disabled:opacity-50 transition"
                >
                  <Database className="w-4 h-4 mr-1.5" />
                  {testingNotion ? "Creating..." : "Test Notion Page Creation"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: LIVE CONSOLE (FULL-PAGE VIEW) */}
        {activeTab === "console" && (
          <div className="w-full">
            <TerminalConsole
              isOpen={true}
              onClose={() => setActiveTab("incidents")}
              isHarvesting={harvesting}
              onTriggerHarvest={triggerHarvest}
              onHarvestFinished={handleHarvestFinished}
              fullTabMode={true}
            />
          </div>
        )}

      </main>

      {/* INCIDENT DETAIL MODAL */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div
            className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 border-b border-slate-800 flex items-start justify-between">
              <div>
                <div className="flex items-center space-x-2 mb-2">
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-semibold font-mono ${
                      selectedIncident.severity === "Critical"
                        ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                        : selectedIncident.severity === "High"
                        ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                        : selectedIncident.severity === "Medium"
                        ? "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30"
                        : "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                    }`}
                  >
                    {selectedIncident.severity || "Unknown"}
                  </span>
                  {selectedIncident.japan_relevance === "Direct" && (
                    <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      🇯🇵 Japan Direct Target
                    </span>
                  )}
                  <span className="text-xs text-slate-400 font-mono">{selectedIncident.source_name}</span>
                </div>
                <h2 className="text-lg font-bold text-white leading-snug">
                  {selectedIncident.enriched_parsed?.title_ja || selectedIncident.title}
                </h2>
                <div className="flex flex-wrap items-center gap-4 mt-2.5 text-xs text-slate-400 font-mono">
                  <div>
                    <span className="text-slate-500 mr-1.5 uppercase font-sans">Source Published:</span>
                    <span className="text-cyan-300 font-medium">
                      {selectedIncident.published_at ? formatDate(selectedIncident.published_at) : "Unknown / Realtime"}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 mr-1.5 uppercase font-sans">Harvest Ingested:</span>
                    <span className="text-slate-300">{formatDate(selectedIncident.harvested_at)}</span>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 overflow-y-auto text-sm">
              <div>
                <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-1">
                  Executive AI Summary
                </h4>
                <p className="text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800 leading-relaxed">
                  {selectedIncident.enriched_parsed?.summary_ja || selectedIncident.summary}
                </p>
              </div>

              {selectedIncident.enriched_parsed?.impact_analysis_ja && (
                <div>
                  <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-1">
                    Impact Assessment & Domestic Scope
                  </h4>
                  <p className="text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800 leading-relaxed">
                    {selectedIncident.enriched_parsed.impact_analysis_ja}
                  </p>
                </div>
              )}

              {selectedIncident.enriched_parsed?.recommended_actions_ja &&
                selectedIncident.enriched_parsed.recommended_actions_ja.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-1">
                      Recommended Mitigations & Action Items
                    </h4>
                    <ul className="list-disc list-inside bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1 text-slate-300">
                      {selectedIncident.enriched_parsed.recommended_actions_ja.map((action, idx) => (
                        <li key={idx}>{action}</li>
                      ))}
                    </ul>
                  </div>
                )}

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 font-semibold block mb-1">Target Sectors / Victims</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedIncident.enriched_parsed?.victim_orgs?.map((v) => (
                      <span key={v} className="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 font-mono">
                        {v}
                      </span>
                    )) ?? <span className="text-xs text-slate-600">None specified</span>}
                  </div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 font-semibold block mb-1">Threat Actors / Groups</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedIncident.enriched_parsed?.threat_actors?.map((a) => (
                      <span
                        key={a}
                        className="px-2 py-0.5 rounded text-xs bg-purple-950 text-purple-300 border border-purple-800 font-mono"
                      >
                        {a}
                      </span>
                    )) ?? <span className="text-xs text-slate-600">None identified</span>}
                  </div>
                </div>
              </div>

              {selectedIncident.url && (
                <div className="pt-2">
                  <a
                    href={selectedIncident.url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center text-xs text-cyan-400 hover:text-cyan-300 font-mono"
                  >
                    <ExternalLink className="w-3.5 h-3.5 mr-1" />
                    Open Source Reference URL
                  </a>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ADD SOURCE MODAL */}
      {addModal.visible && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl">
            <h3 className="text-base font-bold text-white mb-4">Add Threat Intelligence Source</h3>

            <div className="space-y-3 mb-6">
              {addModal.type === "vendor_rss" && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Feed Name</label>
                  <input
                    type="text"
                    value={addModal.form.name}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, name: e.target.value } })}
                    placeholder="e.g. JPCERT/CC Alerts"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">RSS URL</label>
                  <input
                    type="url"
                    value={addModal.form.url}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, url: e.target.value } })}
                    placeholder="https://..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                </div>
              )}

              {addModal.type === "telegram" && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">
                    Channel Identifier (t.me/s/&lt;channel&gt;)
                  </label>
                  <input
                    type="text"
                    value={addModal.form.channel}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, channel: e.target.value } })}
                    placeholder="e.g. redabyss_cti"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                </div>
              )}

              {addModal.type === "darkweb_onion" && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Target Name</label>
                  <input
                    type="text"
                    value={addModal.form.name}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, name: e.target.value } })}
                    placeholder="e.g. RansomFeed RSS"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">
                    URL (http/https/.onion)
                  </label>
                  <input
                    type="text"
                    value={addModal.form.url}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, url: e.target.value } })}
                    placeholder="http://...onion"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">Format Type</label>
                  <select
                    value={addModal.form.type}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, type: e.target.value } })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  >
                    <option value="rss">rss</option>
                    <option value="api">api</option>
                    <option value="onion">onion</option>
                  </select>
                </div>
              )}

              {(addModal.type === "x_monitor" || addModal.type === "web_search") && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Search Query</label>
                  <input
                    type="text"
                    value={addModal.form.query}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, query: e.target.value } })}
                    placeholder="e.g. ransomware breach victim site:x.com"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                </div>
              )}
            </div>

            <div className="flex items-center justify-end space-x-2">
              <button
                onClick={() => setAddModal({ ...addModal, visible: false })}
                className="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={handleAddSource}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow"
              >
                Add Source
              </button>
            </div>
          </div>
        </div>
      )}

      {/* EDIT SOURCE MODAL */}
      {editModal.visible && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-white">Edit Threat Intelligence Source</h3>
              <button
                onClick={() => setEditModal({ ...editModal, visible: false })}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 mb-6">
              {editModal.type === "vendor_rss" && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Feed Name</label>
                  <input
                    type="text"
                    value={editModal.form.name}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, name: e.target.value } })}
                    placeholder="e.g. JPCERT/CC Alerts"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">RSS URL</label>
                  <input
                    type="url"
                    value={editModal.form.url}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, url: e.target.value } })}
                    placeholder="https://..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">Category</label>
                  <input
                    type="text"
                    value={editModal.form.category}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, category: e.target.value } })}
                    placeholder="e.g. general, vendor, cert"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                </div>
              )}

              {editModal.type === "telegram" && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">
                    Channel Identifier (t.me/s/&lt;channel&gt;)
                  </label>
                  <input
                    type="text"
                    value={editModal.form.channel}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, channel: e.target.value } })}
                    placeholder="e.g. redabyss_cti"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                </div>
              )}

              {editModal.type === "darkweb_onion" && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Target Name</label>
                  <input
                    type="text"
                    value={editModal.form.name}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, name: e.target.value } })}
                    placeholder="e.g. RansomFeed RSS"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">
                    URL (http/https/.onion)
                  </label>
                  <input
                    type="text"
                    value={editModal.form.url}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, url: e.target.value } })}
                    placeholder="http://...onion"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">Format Type</label>
                  <select
                    value={editModal.form.type}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, type: e.target.value } })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  >
                    <option value="rss">rss</option>
                    <option value="api">api</option>
                    <option value="onion">onion</option>
                  </select>
                </div>
              )}

              {(editModal.type === "x_monitor" || editModal.type === "web_search") && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Search Query</label>
                  <input
                    type="text"
                    value={editModal.form.query}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, query: e.target.value } })}
                    placeholder="e.g. ransomware breach victim site:x.com"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                </div>
              )}
            </div>

            <div className="flex items-center justify-end space-x-2">
              <button
                onClick={() => setEditModal({ ...editModal, visible: false })}
                className="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                Cancel
              </button>
              <button
                onClick={handleEditSource}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow"
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
