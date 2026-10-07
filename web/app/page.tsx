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
  ChevronLeft,
  ChevronsLeft,
  ChevronsRight,
  ChevronDown,
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
  Sparkles,
  Scale,
  ShieldCheck,
} from "lucide-react";
import { TerminalConsole } from "./components/TerminalConsole";

interface ComplianceTiers {
  commercial_ready: boolean;
  commercial_via_official_api: boolean;
  tos_restricted: boolean;
  darkweb_access: boolean;
}

interface ComplianceConfig {
  mode: string;
  tiers: ComplianceTiers;
}

interface Incident {
  id: string;
  source_type: string;
  source_name: string;
  title: string;
  url: string | null;
  primary_url?: string | null;
  source_urls?: string[];
  sources_detail?: Array<{
    source_type: string;
    source_name: string;
    title: string;
    url: string;
    published_at?: string;
    harvested_at?: string;
  }>;
  victim_org?: string;
  normalized_victim_org?: string;
  report_count?: number;
  first_seen_at?: string;
  last_seen_at?: string;
  child_items?: Incident[];
  summary: string;
  summary_ja?: string;
  impact_analysis_ja?: string;
  raw_content?: string | null;
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
  compliance?: {
    mode: string;
    tiers: ComplianceTiers;
    tier_breakdown?: Record<string, { total: number; active: number }>;
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
  pipeline?: {
    is_running?: boolean;
    last_run_at?: string | null;
    next_run_at?: string | null;
    scheduler_enabled?: boolean;
    interval_hours?: number;
  };
}

interface ConfigData {
  version?: string;
  compliance?: ComplianceConfig;
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
    vendor_rss?: Array<{ name: string; url: string; category?: string; compliance_tier?: string; enabled: boolean }>;
    telegram?: Array<{ channel: string; compliance_tier?: string; enabled: boolean }>;
    darkweb_onion?: Array<{ name: string; url: string; type?: string; compliance_tier?: string; enabled: boolean }>;
    x_monitor?: Array<{ name?: string; directive?: string; query: string; compliance_tier?: string; enabled: boolean }>;
    web_search?: Array<{ name?: string; directive?: string; query: string; compliance_tier?: string; enabled: boolean }>;
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
  const [showRawInModal, setShowRawInModal] = useState<boolean>(false);

  const openIncidentModal = async (item: Incident) => {
    setSelectedIncident(item);
    setShowRawInModal(false);
    try {
      const res = await fetch(`/api/incidents/${encodeURIComponent(item.id)}`);
      if (res.ok) {
        const full = await res.json();
        setSelectedIncident(full);
      }
    } catch {
      // keep initial item data if fetch fails
    }
  };
  const [addModal, setAddModal] = useState<{
    visible: boolean;
    type: string;
    form: {
      name: string;
      url: string;
      channel: string;
      directive?: string;
      query: string;
      type: string;
      compliance_tier?: string;
      mode?: "directive" | "query";
    };
  }>({
    visible: false,
    type: "vendor_rss",
    form: { name: "", url: "", channel: "", directive: "", query: "", type: "rss", compliance_tier: "commercial_ready", mode: "directive" },
  });
  const [editModal, setEditModal] = useState<{
    visible: boolean;
    type: string;
    originalId: string;
    form: {
      name: string;
      url: string;
      category?: string;
      channel: string;
      directive?: string;
      query: string;
      type: string;
      compliance_tier?: string;
      mode?: "directive" | "query";
    };
  }>({
    visible: false,
    type: "vendor_rss",
    originalId: "",
    form: { name: "", url: "", category: "general", channel: "", directive: "", query: "", type: "rss", compliance_tier: "commercial_ready", mode: "directive" },
  });
  const [previewQueries, setPreviewQueries] = useState<string[]>([]);
  const [generatingQueries, setGeneratingQueries] = useState<boolean>(false);

  const handlePreviewAIQueries = async (directive: string, targetType: string) => {
    if (!directive.trim()) {
      showToast("注視指示（文章）を入力してください", "error");
      return;
    }
    setGeneratingQueries(true);
    try {
      const res = await fetch("/api/ai/generate-queries", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ directive, target_type: targetType, count: 3 }),
      });
      if (res.ok) {
        const data = await res.json();
        setPreviewQueries(data.queries || []);
        showToast(`AIが ${data.queries?.length || 0} 件の調査クエリを生成しました`);
      } else {
        const err = await res.json();
        showToast(err.detail || "クエリ生成に失敗しました", "error");
      }
    } catch (e) {
      showToast("クエリ生成中に通信エラーが発生しました", "error");
    } finally {
      setGeneratingQueries(false);
    }
  };

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

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [totalCount, setTotalCount] = useState(0);

  const totalPages = useMemo(() => {
    return Math.max(1, Math.ceil(totalCount / pageSize));
  }, [totalCount, pageSize]);

  const pageNumbers = useMemo(() => {
    const pages: (number | "...")[] = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      if (currentPage <= 4) {
        for (let i = 1; i <= 5; i++) pages.push(i);
        pages.push("...");
        pages.push(totalPages);
      } else if (currentPage >= totalPages - 3) {
        pages.push(1);
        pages.push("...");
        for (let i = totalPages - 4; i <= totalPages; i++) pages.push(i);
      } else {
        pages.push(1);
        pages.push("...");
        pages.push(currentPage - 1);
        pages.push(currentPage);
        pages.push(currentPage + 1);
        pages.push("...");
        pages.push(totalPages);
      }
    }
    return pages;
  }, [currentPage, totalPages]);

  const handlePageChange = (newPage: number) => {
    if (newPage < 1 || newPage > totalPages || newPage === currentPage) return;
    setCurrentPage(newPage);
    fetchIncidents(newPage, pageSize);
    const el = document.getElementById("incident-feed-section");
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize);
    setCurrentPage(1);
    fetchIncidents(1, newSize);
  };

  const fetchIncidents = async (targetPage = currentPage, targetPageSize = pageSize) => {
    setLoadingIncidents(true);
    try {
      const offset = (targetPage - 1) * targetPageSize;
      const params = new URLSearchParams();
      if (search) params.append("search", search);
      if (severityFilter) params.append("severity", severityFilter);
      if (japanOnly) params.append("japan_only", "true");
      if (sourceTypeFilter) params.append("source_type", sourceTypeFilter);
      if (sortBy) params.append("sort_by", sortBy);
      params.append("limit", targetPageSize.toString());
      params.append("offset", offset.toString());

      const res = await fetch(`/api/incidents?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setIncidents(data.items || []);
        if (typeof data.total === "number") {
          setTotalCount(data.total);
        } else {
          setTotalCount(data.count || 0);
        }
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
    fetchIncidents(1, pageSize);
  }, []);

  useEffect(() => {
    setCurrentPage(1);
    const timer = setTimeout(() => {
      fetchIncidents(1, pageSize);
    }, 300);
    return () => clearTimeout(timer);
  }, [search, severityFilter, japanOnly, sourceTypeFilter, sortBy]);

  const handleHarvestFinished = async () => {
    setHarvesting(false);
    showToast("Threat harvesting pipeline completed.");
    await fetchIncidents(currentPage, pageSize);
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

  const handleSetComplianceMode = async (mode: string) => {
    try {
      const res = await fetch("/api/config/compliance", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode }),
      });
      if (res.ok) {
        showToast(`Compliance mode updated to ${mode.toUpperCase()}`);
        await fetchConfig();
        await fetchStatus();
      } else {
        const err = await res.json();
        showToast(err.detail || "Failed to update compliance mode", "error");
      }
    } catch (e) {
      showToast("Network error updating compliance mode", "error");
    }
  };

  const handleToggleComplianceTier = async (tier: string, enabled: boolean) => {
    try {
      const res = await fetch("/api/config/sources", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "toggle_compliance_tier", identifier: tier, enabled }),
      });
      if (res.ok) {
        showToast(`Tier '${tier}' ${enabled ? "enabled" : "disabled"}`);
        await fetchConfig();
        await fetchStatus();
      } else {
        const err = await res.json();
        showToast(err.detail || "Failed to update compliance tier", "error");
      }
    } catch (e) {
      showToast("Network error updating compliance tier", "error");
    }
  };

  const getSourceComplianceTier = (sourceType: string, item: any): string => {
    if (item.compliance_tier) return item.compliance_tier;
    if (sourceType === "vendor_rss") return "commercial_ready";
    if (sourceType === "telegram") return "tos_restricted";
    if (sourceType === "darkweb_onion") {
      return item.type === "api" ? "commercial_via_official_api" : "darkweb_access";
    }
    if (sourceType === "x_monitor" || sourceType === "web_search") return "commercial_via_official_api";
    return "commercial_ready";
  };

  const isTierActive = (tier: string): boolean => {
    const tiers = config?.compliance?.tiers;
    if (!tiers) return true;
    switch (tier) {
      case "commercial_ready":
        return tiers.commercial_ready;
      case "commercial_via_official_api":
        return tiers.commercial_via_official_api;
      case "tos_restricted":
        return tiers.tos_restricted;
      case "darkweb_access":
        return tiers.darkweb_access;
      default:
        return true;
    }
  };

  const renderComplianceBadge = (tier: string, active: boolean) => {
    switch (tier) {
      case "commercial_ready":
        return (
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold border font-mono ${
              active
                ? "bg-emerald-950/80 text-emerald-400 border-emerald-800/80"
                : "bg-slate-900 text-slate-500 border-slate-800 line-through opacity-70"
            }`}
            title="Commercial Ready: Permissive official RSS feeds & APIs"
          >
            <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${active ? "bg-emerald-400" : "bg-slate-600"}`} />
            Commercial Ready
            {!active && <span className="ml-1 text-[9px] text-rose-400 no-underline font-sans">[Disabled]</span>}
          </span>
        );
      case "commercial_via_official_api":
        return (
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold border font-mono ${
              active
                ? "bg-amber-950/80 text-amber-300 border-amber-800/80"
                : "bg-slate-900 text-slate-500 border-slate-800 line-through opacity-70"
            }`}
            title="Commercial via Official API: Requires switching to Twitter API v2, Telegram Bot API, Vertex AI, etc."
          >
            <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${active ? "bg-amber-400" : "bg-slate-600"}`} />
            Commercial via Official API
            {!active && <span className="ml-1 text-[9px] text-rose-400 no-underline font-sans">[Disabled]</span>}
          </span>
        );
      case "tos_restricted":
        return (
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold border font-mono ${
              active
                ? "bg-orange-950/80 text-orange-400 border-orange-800/80"
                : "bg-slate-900 text-slate-500 border-slate-800 line-through opacity-70"
            }`}
            title="Non-Commercial (ToS Scraping): Web preview / scraping violates platform terms of service without official API"
          >
            <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${active ? "bg-orange-400" : "bg-slate-600"}`} />
            Non-Commercial: ToS Scraping
            {!active && <span className="ml-1 text-[9px] text-rose-400 no-underline font-sans">[Disabled]</span>}
          </span>
        );
      case "darkweb_access":
        return (
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold border font-mono ${
              active
                ? "bg-rose-950/80 text-rose-400 border-rose-800/80"
                : "bg-slate-900 text-slate-500 border-slate-800 line-through opacity-70"
            }`}
            title="Non-Commercial (Dark Web): Direct .onion crawler / Tor reachability for security research only"
          >
            <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${active ? "bg-rose-400" : "bg-slate-600"}`} />
            Non-Commercial: Dark Web
            {!active && <span className="ml-1 text-[9px] text-rose-400 no-underline font-sans">[Disabled]</span>}
          </span>
        );
      default:
        return null;
    }
  };

  const handleAddSource = async () => {
    const type = addModal.type;
    let data: any = {};
    if (type === "vendor_rss") data = { name: addModal.form.name, url: addModal.form.url, enabled: true };
    if (type === "telegram") data = { channel: addModal.form.channel, enabled: true };
    if (type === "darkweb_onion") data = { name: addModal.form.name, url: addModal.form.url, type: addModal.form.type, enabled: true };
    if (type === "x_monitor" || type === "web_search") {
      data = {
        name: addModal.form.name,
        directive: addModal.form.mode === "directive" ? addModal.form.directive : "",
        query: addModal.form.mode === "query" ? addModal.form.query : addModal.form.query,
        enabled: true,
      };
    }
    if (addModal.form.compliance_tier) {
      data.compliance_tier = addModal.form.compliance_tier;
    }

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
      data = {
        name: editModal.form.name,
        directive: editModal.form.mode === "directive" ? editModal.form.directive : "",
        query: editModal.form.mode === "query" ? editModal.form.query : editModal.form.query,
      };
    }
    if (editModal.form.compliance_tier) {
      data.compliance_tier = editModal.form.compliance_tier;
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

          {/* Right Section: Status & Action Buttons */}
          <div className="flex items-center space-x-2 sm:space-x-3">
            <span className="hidden sm:inline-flex items-center text-xs text-emerald-400 bg-emerald-950/40 border border-emerald-800/60 px-2.5 py-1 rounded-full">
              <span className="w-2 h-2 rounded-full bg-emerald-400 mr-1.5 animate-ping" />
              Operational
            </span>
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
              href="/api/feed.xml"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition cursor-pointer"
              title="Subscribe to RSS 2.0 Feed (/api/feed.xml)"
            >
              <Rss className="w-3.5 h-3.5 mr-1.5 text-amber-400" />
              <span>RSS Feed</span>
            </a>

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

                <div className="flex items-center space-x-1 text-xs text-slate-400">
                  <span className="text-slate-500 font-sans hidden sm:inline">表示件数:</span>
                  <select
                    value={pageSize}
                    onChange={(e) => handlePageSizeChange(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value={10}>10件/頁</option>
                    <option value={20}>20件/頁</option>
                    <option value={50}>50件/頁</option>
                    <option value={100}>100件/頁</option>
                  </select>
                </div>

                <button
                  onClick={() => fetchIncidents(currentPage, pageSize)}
                  title="Refresh list"
                  className="p-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 text-slate-300 transition"
                >
                  <RefreshCw className={`w-4 h-4 ${loadingIncidents ? "animate-spin" : ""}`} />
                </button>
              </div>
            </div>

            {/* Incident Subheader with Count & Quick Navigation */}
            <div id="incident-feed-section" className="flex flex-wrap items-center justify-between gap-3 mb-4 text-xs">
              <div className="flex items-center space-x-2 text-slate-400">
                <span className="font-semibold text-white">
                  全 {totalCount.toLocaleString()} 件
                </span>
                {totalCount > 0 && (
                  <span className="text-slate-500 font-mono">
                    ({((currentPage - 1) * pageSize) + 1} - {Math.min(currentPage * pageSize, totalCount)} 件目を表示 / {totalPages} ページ中)
                  </span>
                )}
              </div>

              {totalPages > 1 && (
                <div className="flex items-center space-x-1">
                  <button
                    disabled={currentPage <= 1 || loadingIncidents}
                    onClick={() => handlePageChange(currentPage - 1)}
                    className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-40 disabled:pointer-events-none transition flex items-center text-xs"
                  >
                    <ChevronLeft className="w-3.5 h-3.5 mr-0.5" />
                    前へ
                  </button>
                  <span className="px-2 py-1 font-mono text-cyan-400 font-medium">
                    {currentPage} / {totalPages}
                  </span>
                  <button
                    disabled={currentPage >= totalPages || loadingIncidents}
                    onClick={() => handlePageChange(currentPage + 1)}
                    className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-40 disabled:pointer-events-none transition flex items-center text-xs"
                  >
                    次へ
                    <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
                  </button>
                </div>
              )}
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
                  onClick={() => openIncidentModal(item)}
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
                      {/* Cluster / Source Count Badge */}
                      {item.report_count && item.report_count > 1 ? (
                        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-cyan-950 text-cyan-300 border border-cyan-700/80 flex items-center shadow-sm">
                          <Radio className="w-3 h-3 mr-1 text-cyan-400" />
                          {item.report_count} ソース集約
                        </span>
                      ) : null}

                      {item.id.startsWith("incident--") && (
                        <span className="hidden sm:inline-flex px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                          STIX
                        </span>
                      )}

                      <span className="text-xs text-slate-400 font-mono truncate max-w-[150px] sm:max-w-xs">{item.source_name}</span>
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

                    <div className="ml-auto flex items-center space-x-3">
                      {(item.url || item.primary_url) && (
                        <a
                          href={item.url || item.primary_url || "#"}
                          target="_blank"
                          rel="noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="inline-flex items-center text-xs text-cyan-400 hover:text-cyan-300 font-mono hover:underline"
                          title="Open primary source URL"
                        >
                          <ExternalLink className="w-3 h-3 mr-1" />
                          元記事
                        </a>
                      )}
                      <div className="flex items-center text-cyan-400 font-medium text-xs">
                        View Intelligence <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Bottom Pagination Controls */}
            {totalCount > 0 && (
              <div className="mt-6 p-4 bg-slate-900/90 border border-slate-800 rounded-xl flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="text-xs text-slate-400 flex items-center space-x-2">
                  <span>表示中:</span>
                  <span className="font-mono text-slate-200 font-medium">
                    {((currentPage - 1) * pageSize) + 1} - {Math.min(currentPage * pageSize, totalCount)}
                  </span>
                  <span>/</span>
                  <span className="font-mono text-cyan-400 font-semibold">{totalCount.toLocaleString()} 件</span>
                  <span className="text-slate-600">|</span>
                  <span className="font-mono text-slate-400">
                    ページ {currentPage} / {totalPages}
                  </span>
                </div>

                <div className="flex items-center space-x-1">
                  {/* First Page Button */}
                  <button
                    disabled={currentPage <= 1 || loadingIncidents}
                    onClick={() => handlePageChange(1)}
                    title="最初のページへ"
                    className="p-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition"
                  >
                    <ChevronsLeft className="w-4 h-4" />
                  </button>

                  {/* Previous Page Button */}
                  <button
                    disabled={currentPage <= 1 || loadingIncidents}
                    onClick={() => handlePageChange(currentPage - 1)}
                    title="前のページへ"
                    className="px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition flex items-center"
                  >
                    <ChevronLeft className="w-3.5 h-3.5 mr-0.5" />
                    前へ
                  </button>

                  {/* Numbered Page Buttons */}
                  <div className="flex items-center space-x-1 mx-1">
                    {pageNumbers.map((p, idx) =>
                      p === "..." ? (
                        <span key={`ellipsis-${idx}`} className="px-1.5 py-1 text-slate-500 font-mono text-xs">
                          …
                        </span>
                      ) : (
                        <button
                          key={p}
                          disabled={loadingIncidents}
                          onClick={() => handlePageChange(p as number)}
                          className={`min-w-[32px] h-8 px-2 rounded-lg text-xs font-mono font-medium transition ${
                            currentPage === p
                              ? "bg-cyan-500 text-slate-950 font-bold shadow-lg shadow-cyan-500/20"
                              : "bg-slate-950 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800"
                          }`}
                        >
                          {p}
                        </button>
                      )
                    )}
                  </div>

                  {/* Next Page Button */}
                  <button
                    disabled={currentPage >= totalPages || loadingIncidents}
                    onClick={() => handlePageChange(currentPage + 1)}
                    title="次のページへ"
                    className="px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition flex items-center"
                  >
                    次へ
                    <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
                  </button>

                  {/* Last Page Button */}
                  <button
                    disabled={currentPage >= totalPages || loadingIncidents}
                    onClick={() => handlePageChange(totalPages)}
                    title="最後のページへ"
                    className="p-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition"
                  >
                    <ChevronsRight className="w-4 h-4" />
                  </button>
                </div>

                {/* Bottom Page Size Selector */}
                <div className="flex items-center space-x-2 text-xs text-slate-400">
                  <span>表示件数:</span>
                  <select
                    value={pageSize}
                    onChange={(e) => handlePageSizeChange(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value={10}>10件</option>
                    <option value={20}>20件</option>
                    <option value={50}>50件</option>
                    <option value={100}>100件</option>
                  </select>
                </div>
              </div>
            )}
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

            {/* Commercial Compliance & Usage Controls Bar */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 mb-6 shadow-lg">
              <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
                <div>
                  <div className="flex items-center space-x-2">
                    <Scale className="w-5 h-5 text-cyan-400" />
                    <h3 className="font-bold text-white text-base">Commercial Compliance & Usage Controls</h3>
                    <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 uppercase">
                      Mode: {config?.compliance?.mode || "all"}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    Control data harvesting tiers for commercial OSS usage, legal licensing compliance, and security research safety.
                  </p>
                </div>

                {/* Preset Profiles */}
                <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800">
                  <button
                    onClick={() => handleSetComplianceMode("commercial_only")}
                    className={`px-3 py-1 rounded text-xs font-semibold transition ${
                      config?.compliance?.mode === "commercial_only"
                        ? "bg-emerald-600 text-white shadow"
                        : "text-slate-400 hover:text-emerald-300 hover:bg-slate-900"
                    }`}
                    title="Enable only fully commercial-ready sources (Vendor RSS, Official Sinks)"
                  >
                    🏢 Commercial Only
                  </button>
                  <button
                    onClick={() => handleSetComplianceMode("official_api_ready")}
                    className={`px-3 py-1 rounded text-xs font-semibold transition ${
                      config?.compliance?.mode === "official_api_ready"
                        ? "bg-amber-600 text-white shadow"
                        : "text-slate-400 hover:text-amber-300 hover:bg-slate-900"
                    }`}
                    title="Enable Commercial Ready + Official API sources (requires API keys)"
                  >
                    🔑 Official API Ready
                  </button>
                  <button
                    onClick={() => handleSetComplianceMode("all")}
                    className={`px-3 py-1 rounded text-xs font-semibold transition ${
                      config?.compliance?.mode === "all"
                        ? "bg-purple-600 text-white shadow"
                        : "text-slate-400 hover:text-purple-300 hover:bg-slate-900"
                    }`}
                    title="Enable all sources including Darkweb and Web Scraping for security research"
                  >
                    🧪 All / Research
                  </button>
                </div>
              </div>

              {/* 4 Compliance Tiers Grid / Toggles */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mt-4">
                {/* 1. Commercial Ready */}
                <div className={`p-3.5 rounded-lg border transition ${
                  config?.compliance?.tiers?.commercial_ready
                    ? "bg-emerald-950/20 border-emerald-800/60"
                    : "bg-slate-950/60 border-slate-800 opacity-60"
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="inline-flex items-center text-xs font-bold text-emerald-400 font-mono">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 mr-1.5" />
                      Commercial Ready
                    </span>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={config?.compliance?.tiers?.commercial_ready ?? true}
                        onChange={(e) => handleToggleComplianceTier("commercial_ready", e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-8 h-4 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3.5 after:w-3.5 after:transition-all peer-checked:bg-emerald-500" />
                    </label>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-snug">
                    Permissive official RSS/Atom feeds, open CERT DBs, and standard Webhook sinks.
                  </p>
                  <div className="mt-2 text-[10px] font-mono text-emerald-500/80">
                    Active: {status?.compliance?.tier_breakdown?.commercial_ready?.active ?? 0} / {status?.compliance?.tier_breakdown?.commercial_ready?.total ?? 0}
                  </div>
                </div>

                {/* 2. Commercial via Official API */}
                <div className={`p-3.5 rounded-lg border transition ${
                  config?.compliance?.tiers?.commercial_via_official_api
                    ? "bg-amber-950/20 border-amber-800/60"
                    : "bg-slate-950/60 border-slate-800 opacity-60"
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="inline-flex items-center text-xs font-bold text-amber-300 font-mono">
                      <span className="w-2 h-2 rounded-full bg-amber-400 mr-1.5" />
                      Commercial via Official API
                    </span>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={config?.compliance?.tiers?.commercial_via_official_api ?? true}
                        onChange={(e) => handleToggleComplianceTier("commercial_via_official_api", e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-8 h-4 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3.5 after:w-3.5 after:transition-all peer-checked:bg-amber-500" />
                    </label>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-snug">
                    Can be commercialized by plugging in Twitter API v2, Web Search API, or Vertex AI.
                  </p>
                  <div className="mt-2 text-[10px] font-mono text-amber-500/80">
                    Active: {status?.compliance?.tier_breakdown?.commercial_via_official_api?.active ?? 0} / {status?.compliance?.tier_breakdown?.commercial_via_official_api?.total ?? 0}
                  </div>
                </div>

                {/* 3. Non-Commercial: ToS Scraping */}
                <div className={`p-3.5 rounded-lg border transition ${
                  config?.compliance?.tiers?.tos_restricted
                    ? "bg-orange-950/20 border-orange-800/60"
                    : "bg-slate-950/60 border-slate-800 opacity-60"
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="inline-flex items-center text-xs font-bold text-orange-400 font-mono">
                      <span className="w-2 h-2 rounded-full bg-orange-400 mr-1.5" />
                      Non-Commercial: ToS Scraping
                    </span>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={config?.compliance?.tiers?.tos_restricted ?? true}
                        onChange={(e) => handleToggleComplianceTier("tos_restricted", e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-8 h-4 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3.5 after:w-3.5 after:transition-all peer-checked:bg-orange-500" />
                    </label>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-snug">
                    Web preview scraping (e.g. Telegram web) without official API keys.
                  </p>
                  <div className="mt-2 text-[10px] font-mono text-orange-500/80">
                    Active: {status?.compliance?.tier_breakdown?.tos_restricted?.active ?? 0} / {status?.compliance?.tier_breakdown?.tos_restricted?.total ?? 0}
                  </div>
                </div>

                {/* 4. Non-Commercial: Dark Web */}
                <div className={`p-3.5 rounded-lg border transition ${
                  config?.compliance?.tiers?.darkweb_access
                    ? "bg-rose-950/20 border-rose-800/60"
                    : "bg-slate-950/60 border-slate-800 opacity-60"
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="inline-flex items-center text-xs font-bold text-rose-400 font-mono">
                      <span className="w-2 h-2 rounded-full bg-rose-400 mr-1.5" />
                      Non-Commercial: Dark Web
                    </span>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={config?.compliance?.tiers?.darkweb_access ?? true}
                        onChange={(e) => handleToggleComplianceTier("darkweb_access", e.target.checked)}
                        className="sr-only peer"
                      />
                      <div className="w-8 h-4 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-3.5 after:w-3.5 after:transition-all peer-checked:bg-rose-500" />
                    </label>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-snug">
                    Direct Tor .onion crawler reaching ransomware DLS leaks. Research use only.
                  </p>
                  <div className="mt-2 text-[10px] font-mono text-rose-500/80">
                    Active: {status?.compliance?.tier_breakdown?.darkweb_access?.active ?? 0} / {status?.compliance?.tier_breakdown?.darkweb_access?.total ?? 0}
                  </div>
                </div>
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
                        form: { name: "", url: "", channel: "", query: "", type: "rss", compliance_tier: "commercial_ready" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add RSS Feed
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.vendor_rss?.map((feed) => {
                    const tier = getSourceComplianceTier("vendor_rss", feed);
                    const active = isTierActive(tier);
                    return (
                      <div key={feed.url} className={`py-3 flex items-center justify-between transition ${!active ? "opacity-60 bg-slate-950/30 rounded px-2" : ""}`}>
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-medium text-sm text-slate-200">{feed.name}</span>
                            <span className="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-400 font-mono">
                              {feed.category}
                            </span>
                            {renderComplianceBadge(tier, active)}
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
                                  compliance_tier: feed.compliance_tier || tier,
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
                    );
                  })}
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
                        form: { name: "", url: "", channel: "", query: "", type: "rss", compliance_tier: "darkweb_access" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Target
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.darkweb_onion?.map((dw) => {
                    const tier = getSourceComplianceTier("darkweb_onion", dw);
                    const active = isTierActive(tier);
                    return (
                      <div key={dw.url} className={`py-3 flex items-center justify-between transition ${!active ? "opacity-60 bg-slate-950/30 rounded px-2" : ""}`}>
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-medium text-sm text-slate-200">{dw.name}</span>
                            <span className="px-1.5 py-0.2 rounded text-[10px] bg-purple-950 text-purple-300 font-mono uppercase">
                              {dw.type}
                            </span>
                            {renderComplianceBadge(tier, active)}
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
                                  compliance_tier: dw.compliance_tier || tier,
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
                    );
                  })}
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
                        form: { name: "", url: "", channel: "", query: "", type: "rss", compliance_tier: "tos_restricted" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Channel
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.telegram?.map((tg) => {
                    const tier = getSourceComplianceTier("telegram", tg);
                    const active = isTierActive(tier);
                    return (
                      <div key={tg.channel} className={`py-3 flex items-center justify-between transition ${!active ? "opacity-60 bg-slate-950/30 rounded px-2" : ""}`}>
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
                          {renderComplianceBadge(tier, active)}
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
                                  compliance_tier: tg.compliance_tier || tier,
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
                    );
                  })}
                </div>
              </div>

              {/* 4. X (Twitter) Search */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <Hash className="w-5 h-5 text-sky-400" />
                    <h3 className="font-bold text-white text-base">X (Twitter) Grounded Threat Search & Directives</h3>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400 font-mono">
                      {config?.sources?.x_monitor?.length ?? 0}
                    </span>
                  </div>
                  <button
                    onClick={() => {
                      setPreviewQueries([]);
                      setAddModal({
                        visible: true,
                        type: "x_monitor",
                        form: { name: "", url: "", channel: "", directive: "", query: "", type: "rss", compliance_tier: "tos_restricted", mode: "directive" },
                      });
                    }}
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Directive / Query
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.x_monitor?.map((xm, idx) => {
                    const identifier = xm.directive || xm.query || xm.name || `x_${idx}`;
                    const isDirective = Boolean(xm.directive);
                    const tier = getSourceComplianceTier("x_monitor", xm);
                    const active = isTierActive(tier);
                    return (
                      <div key={identifier} className={`py-3 flex items-start justify-between gap-4 transition ${!active ? "opacity-60 bg-slate-950/30 rounded px-2" : ""}`}>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center space-x-2 mb-1">
                            {isDirective ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-sky-950 text-sky-300 border border-sky-800 flex items-center">
                                <Sparkles className="w-3 h-3 mr-1 text-sky-400" />
                                AI注視指示
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 font-mono">
                                固定クエリ
                              </span>
                            )}
                            {xm.name && (
                              <span className="font-semibold text-xs text-slate-200 truncate">
                                {xm.name}
                              </span>
                            )}
                            {renderComplianceBadge(tier, active)}
                          </div>
                          {isDirective ? (
                            <p className="text-xs text-slate-300 leading-relaxed font-sans break-words">
                              {xm.directive}
                            </p>
                          ) : (
                            <p className="text-xs font-mono text-slate-300 break-all">
                              {xm.query}
                            </p>
                          )}
                          {isDirective && xm.query && (
                            <div className="text-[11px] font-mono text-slate-500 mt-1 truncate">
                              固定補助: {xm.query}
                            </div>
                          )}
                        </div>

                        <div className="flex items-center space-x-3 shrink-0 pt-0.5">
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input
                              type="checkbox"
                              checked={xm.enabled}
                              onChange={(e) => handleToggleSource("x_monitor", identifier, e.target.checked)}
                              className="sr-only peer"
                            />
                            <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600" />
                          </label>
                          <button
                            onClick={() => {
                              setPreviewQueries([]);
                              setEditModal({
                                visible: true,
                                type: "x_monitor",
                                originalId: identifier,
                                form: {
                                  name: xm.name || "",
                                  url: "",
                                  category: "",
                                  channel: "",
                                  directive: xm.directive || "",
                                  query: xm.query || "",
                                  type: "",
                                  compliance_tier: xm.compliance_tier || tier,
                                  mode: xm.directive ? "directive" : "query",
                                },
                              });
                            }}
                            className="p-1 text-slate-500 hover:text-cyan-400 transition"
                            title="Edit"
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteSource("x_monitor", identifier)}
                            className="p-1 text-slate-500 hover:text-rose-400 transition"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* 5. Web Search Grounding */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <Globe className="w-5 h-5 text-emerald-400" />
                    <h3 className="font-bold text-white text-base">Gemini Web Search Threat Hunting Directives</h3>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400 font-mono">
                      {config?.sources?.web_search?.length ?? 0}
                    </span>
                  </div>
                  <button
                    onClick={() => {
                      setPreviewQueries([]);
                      setAddModal({
                        visible: true,
                        type: "web_search",
                        form: { name: "", url: "", channel: "", directive: "", query: "", type: "rss", compliance_tier: "commercial_via_official_api", mode: "directive" },
                      });
                    }}
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Directive / Query
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.web_search?.map((ws, idx) => {
                    const identifier = ws.directive || ws.query || ws.name || `ws_${idx}`;
                    const isDirective = Boolean(ws.directive);
                    const tier = getSourceComplianceTier("web_search", ws);
                    const active = isTierActive(tier);
                    return (
                      <div key={identifier} className={`py-3 flex items-start justify-between gap-4 transition ${!active ? "opacity-60 bg-slate-950/30 rounded px-2" : ""}`}>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center space-x-2 mb-1">
                            {isDirective ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center">
                                <Sparkles className="w-3 h-3 mr-1 text-emerald-400" />
                                AI注視指示
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 font-mono">
                                固定クエリ
                              </span>
                            )}
                            {ws.name && (
                              <span className="font-semibold text-xs text-slate-200 truncate">
                                {ws.name}
                              </span>
                            )}
                            {renderComplianceBadge(tier, active)}
                          </div>
                          {isDirective ? (
                            <p className="text-xs text-slate-300 leading-relaxed font-sans break-words">
                              {ws.directive}
                            </p>
                          ) : (
                            <p className="text-xs font-mono text-slate-300 break-all">
                              {ws.query}
                            </p>
                          )}
                          {isDirective && ws.query && (
                            <div className="text-[11px] font-mono text-slate-500 mt-1 truncate">
                              固定補助: {ws.query}
                            </div>
                          )}
                        </div>

                        <div className="flex items-center space-x-3 shrink-0 pt-0.5">
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input
                              type="checkbox"
                              checked={ws.enabled}
                              onChange={(e) => handleToggleSource("web_search", identifier, e.target.checked)}
                              className="sr-only peer"
                            />
                            <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600" />
                          </label>
                          <button
                            onClick={() => {
                              setPreviewQueries([]);
                              setEditModal({
                                visible: true,
                                type: "web_search",
                                originalId: identifier,
                                form: {
                                  name: ws.name || "",
                                  url: "",
                                  category: "",
                                  channel: "",
                                  directive: ws.directive || "",
                                  query: ws.query || "",
                                  type: "",
                                  compliance_tier: ws.compliance_tier || tier,
                                  mode: ws.directive ? "directive" : "query",
                                },
                              });
                            }}
                            className="p-1 text-slate-500 hover:text-cyan-400 transition"
                            title="Edit"
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteSource("web_search", identifier)}
                            className="p-1 text-slate-500 hover:text-rose-400 transition"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
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
                    <div className="text-sm font-semibold text-slate-200">
                      Database Engine ({status?.database?.backend === "postgresql" ? "PostgreSQL" : "SQLite"})
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5 font-mono truncate max-w-sm">
                      {status?.database?.database_url || status?.database?.db_path}
                    </div>
                  </div>
                  <span className="px-2.5 py-1 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    Connected
                  </span>
                </div>

                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-semibold text-slate-200">Tor SOCKS5 Onion Proxy</div>
                    <div className="text-xs text-slate-400 mt-0.5 font-mono">{status?.tor_proxy?.url}</div>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-semibold flex items-center ${
                      status?.tor_proxy?.online
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        : "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                    }`}
                  >
                    <span
                      className={`w-2 h-2 rounded-full mr-1.5 ${
                        status?.tor_proxy?.online ? "bg-emerald-400 animate-pulse" : "bg-rose-400"
                      }`}
                    />
                    {status?.tor_proxy?.online ? "ONLINE" : "OFFLINE"}
                  </span>
                </div>

                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-semibold text-slate-200">Gemini AI Engine</div>
                    <div className="text-xs text-slate-400 mt-0.5 font-mono">{status?.ai?.model}</div>
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

                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-semibold text-slate-200">Auto-Harvest Periodic Scheduler</div>
                    <div className="text-xs text-slate-400 mt-0.5 font-mono">
                      {status?.pipeline?.next_run_at
                        ? `Next run: ${formatDate(status.pipeline.next_run_at)} (Interval: ${status?.pipeline?.interval_hours || 1}h)`
                        : `Interval: ${status?.pipeline?.interval_hours || 1} hour(s)`}
                    </div>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-semibold flex items-center ${
                      status?.pipeline?.scheduler_enabled
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {status?.pipeline?.scheduler_enabled && (
                      <span className="w-2 h-2 rounded-full mr-1.5 bg-emerald-400 animate-pulse" />
                    )}
                    {status?.pipeline?.scheduler_enabled ? "Active (Auto)" : "Inactive"}
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

              {/* RAW SOURCE ACCORDION IN MODAL */}
              <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950/70">
                <button
                  type="button"
                  onClick={() => setShowRawInModal(!showRawInModal)}
                  className="w-full px-3 py-2 flex items-center justify-between text-xs font-semibold text-slate-300 hover:text-white bg-slate-900/80 hover:bg-slate-800/80 transition"
                >
                  <div className="flex items-center space-x-2">
                    <FileCode className="w-4 h-4 text-cyan-400" />
                    <span>原文データ / Raw Source Content</span>
                    {selectedIncident.raw_content ? (
                      <span className="text-[10px] text-slate-500 font-mono">
                        ({selectedIncident.raw_content.length} chars)
                      </span>
                    ) : null}
                  </div>
                  <div className="flex items-center space-x-1.5 text-slate-400">
                    <span className="text-[10px]">{showRawInModal ? "閉じる" : "開いて表示"}</span>
                    <ChevronDown
                      className={`w-3.5 h-3.5 transition-transform duration-200 ${
                        showRawInModal ? "rotate-180" : ""
                      }`}
                    />
                  </div>
                </button>
                {showRawInModal && (
                  <div className="p-3 border-t border-slate-800 bg-slate-950 font-mono text-xs text-slate-300 whitespace-pre-wrap break-words max-h-80 overflow-y-auto select-text leading-relaxed">
                    {selectedIncident.raw_content || selectedIncident.summary || "原文データなし"}
                  </div>
                )}
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

              {/* Preserved Sources & Child Reports Timeline */}
              <div className="pt-2 border-t border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider flex items-center">
                    <Radio className="w-3.5 h-3.5 mr-1.5" />
                    情報ソース・参照URL一覧 ({selectedIncident.sources_detail?.length || selectedIncident.source_urls?.length || (selectedIncident.url ? 1 : 0)} 件)
                  </h4>
                  {selectedIncident.id.startsWith("incident--") && (
                    <span className="text-[10px] font-mono text-slate-500 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      STIX ID: {selectedIncident.id}
                    </span>
                  )}
                </div>

                {selectedIncident.sources_detail && selectedIncident.sources_detail.length > 0 ? (
                  <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                    {selectedIncident.sources_detail.map((src, sIdx) => (
                      <div
                        key={sIdx}
                        className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center space-x-2 mb-1">
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-800 text-cyan-300 border border-slate-700">
                              {src.source_type}
                            </span>
                            <span className="text-xs font-medium text-slate-300 truncate">
                              {src.source_name}
                            </span>
                          </div>
                          <p className="text-xs text-slate-400 truncate">{src.title}</p>
                        </div>
                        <div className="flex items-center space-x-3 shrink-0">
                          {src.published_at && (
                            <span className="text-[10px] font-mono text-slate-500">
                              {formatDate(src.published_at)}
                            </span>
                          )}
                          {src.url ? (
                            <a
                              href={src.url}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center text-xs text-cyan-400 hover:text-cyan-300 hover:underline font-mono bg-cyan-950/40 px-2 py-1 rounded border border-cyan-800/50"
                            >
                              <ExternalLink className="w-3 h-3 mr-1" />
                              元リンク
                            </a>
                          ) : (
                            <span className="text-[10px] text-slate-600 font-mono">No URL</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : selectedIncident.source_urls && selectedIncident.source_urls.length > 0 ? (
                  <div className="space-y-1.5">
                    {selectedIncident.source_urls.map((u, uIdx) => (
                      <div key={uIdx} className="bg-slate-950 p-2 rounded border border-slate-800 flex items-center justify-between">
                        <span className="text-xs text-slate-400 font-mono truncate mr-2">{u}</span>
                        <a
                          href={u}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center text-xs text-cyan-400 hover:text-cyan-300 shrink-0 font-mono"
                        >
                          <ExternalLink className="w-3 h-3 mr-1" />
                          開く
                        </a>
                      </div>
                    ))}
                  </div>
                ) : selectedIncident.url ? (
                  <div className="pt-1">
                    <a
                      href={selectedIncident.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center text-xs text-cyan-400 hover:text-cyan-300 font-mono"
                    >
                      <ExternalLink className="w-3.5 h-3.5 mr-1" />
                      Open Source Reference URL ({selectedIncident.url})
                    </a>
                  </div>
                ) : (
                  <span className="text-xs text-slate-500">No external source URL recorded.</span>
                )}

                {/* Attached Child Reports Timeline */}
                {selectedIncident.child_items && selectedIncident.child_items.length > 1 && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <h5 className="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-2">
                      Child Reports Timeline ({selectedIncident.child_items.length} 件)
                    </h5>
                    <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                      {selectedIncident.child_items.map((c, cIdx) => (
                        <div key={cIdx} className="bg-slate-950/60 p-2 rounded border border-slate-800 text-xs">
                          <div className="flex items-center justify-between text-slate-500 text-[10px] font-mono mb-1">
                            <span>{c.source_name} ({c.source_type})</span>
                            <span>{c.published_at ? formatDate(c.published_at) : formatDate(c.harvested_at)}</span>
                          </div>
                          <p className="text-slate-300 font-medium">{c.title}</p>
                          {c.url && (
                            <a
                              href={c.url}
                              target="_blank"
                              rel="noreferrer"
                              className="text-cyan-400 hover:underline text-[10px] font-mono mt-1 inline-flex items-center"
                            >
                              <ExternalLink className="w-2.5 h-2.5 mr-1" />
                              {c.url}
                            </a>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
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
                <div className="space-y-3">
                  {/* Mode Selector */}
                  <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs font-semibold">
                    <button
                      type="button"
                      onClick={() => setAddModal({ ...addModal, form: { ...addModal.form, mode: "directive" } })}
                      className={`flex-1 py-1.5 rounded-md flex items-center justify-center space-x-1.5 transition ${
                        addModal.form.mode === "directive"
                          ? "bg-cyan-600 text-white shadow-sm"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>AI注視指示 (自然言語)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setAddModal({ ...addModal, form: { ...addModal.form, mode: "query" } })}
                      className={`flex-1 py-1.5 rounded-md flex items-center justify-center space-x-1.5 transition ${
                        addModal.form.mode === "query"
                          ? "bg-cyan-600 text-white shadow-sm"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      <span>固定クエリ</span>
                    </button>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">
                      テーマ名 (管理用・任意)
                    </label>
                    <input
                      type="text"
                      value={addModal.form.name}
                      onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, name: e.target.value } })}
                      placeholder="例: 重要インフラ・サプライチェーン侵害"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600"
                    />
                  </div>

                  {addModal.form.mode === "directive" ? (
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-xs font-semibold text-slate-400">
                          AIへの注視指示・調査方針 (文章で入力)
                        </label>
                        <span className="text-[11px] text-cyan-400 font-mono">Gemini Dynamic Hunting</span>
                      </div>
                      <textarea
                        rows={3}
                        value={addModal.form.directive || ""}
                        onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, directive: e.target.value } })}
                        placeholder="例: 日本国内の医療機関や製薬企業を標的としたランサムウェア被害やシステム停止、二重脅迫の最新動向を注視"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed"
                      />

                      <div className="mt-2 flex items-center justify-between">
                        <button
                          type="button"
                          onClick={() => handlePreviewAIQueries(addModal.form.directive || "", addModal.type)}
                          disabled={generatingQueries || !addModal.form.directive?.trim()}
                          className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs border border-slate-700 transition disabled:opacity-50"
                        >
                          {generatingQueries ? (
                            <>
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              <span>AIクエリ生成中...</span>
                            </>
                          ) : (
                            <>
                              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                              <span>AIクエリ生成テスト</span>
                            </>
                          )}
                        </button>
                        <span className="text-[11px] text-slate-500">
                          巡回時にも自動生成されます
                        </span>
                      </div>

                      {previewQueries.length > 0 && (
                        <div className="mt-2.5 p-2.5 rounded-lg bg-slate-950 border border-cyan-900/60 space-y-1.5">
                          <div className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">
                            AIが生成した調査クエリ例 ({previewQueries.length}件):
                          </div>
                          {previewQueries.map((pq, i) => (
                            <div key={i} className="text-xs font-mono text-slate-300 bg-slate-900/80 px-2 py-1 rounded border border-slate-800 flex items-center space-x-1.5">
                              <span className="text-cyan-500 text-[10px]">#{i + 1}</span>
                              <span className="truncate">{pq}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">
                        固定検索クエリ
                      </label>
                      <input
                        type="text"
                        value={addModal.form.query}
                        onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, query: e.target.value } })}
                        placeholder="例: (from:piyokango OR from:jpcert) site:x.com"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm font-mono text-slate-100 placeholder-slate-600"
                      />
                    </div>
                  )}
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">
                  Compliance Classification Tier
                </label>
                <select
                  value={addModal.form.compliance_tier || "commercial_ready"}
                  onChange={(e) =>
                    setAddModal({
                      ...addModal,
                      form: { ...addModal.form, compliance_tier: e.target.value },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="commercial_ready">🟢 Commercial Ready (Safe for OSS / Commercial distribution)</option>
                  <option value="commercial_via_official_api">🟡 Commercial via Official API (Requires API Key / Official Endpoint)</option>
                  <option value="tos_restricted">🟠 Non-Commercial: ToS Scraping (Research only / Web Scraping)</option>
                  <option value="darkweb_access">🔴 Non-Commercial: Dark Web (Research only / Onion Routing)</option>
                </select>
                <p className="text-[11px] text-slate-500 mt-1">
                  Controls commercial readiness and global tier killswitch behavior.
                </p>
              </div>
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
                <div className="space-y-3">
                  {/* Mode Selector */}
                  <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs font-semibold">
                    <button
                      type="button"
                      onClick={() => setEditModal({ ...editModal, form: { ...editModal.form, mode: "directive" } })}
                      className={`flex-1 py-1.5 rounded-md flex items-center justify-center space-x-1.5 transition ${
                        editModal.form.mode === "directive"
                          ? "bg-cyan-600 text-white shadow-sm"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>AI注視指示 (自然言語)</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setEditModal({ ...editModal, form: { ...editModal.form, mode: "query" } })}
                      className={`flex-1 py-1.5 rounded-md flex items-center justify-center space-x-1.5 transition ${
                        editModal.form.mode === "query"
                          ? "bg-cyan-600 text-white shadow-sm"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      <Terminal className="w-3.5 h-3.5" />
                      <span>固定クエリ</span>
                    </button>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">
                      テーマ名 (管理用・任意)
                    </label>
                    <input
                      type="text"
                      value={editModal.form.name}
                      onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, name: e.target.value } })}
                      placeholder="例: 重要インフラ・サプライチェーン侵害"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600"
                    />
                  </div>

                  {editModal.form.mode === "directive" ? (
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-xs font-semibold text-slate-400">
                          AIへの注視指示・調査方針 (文章で入力)
                        </label>
                        <span className="text-[11px] text-cyan-400 font-mono">Gemini Dynamic Hunting</span>
                      </div>
                      <textarea
                        rows={3}
                        value={editModal.form.directive || ""}
                        onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, directive: e.target.value } })}
                        placeholder="例: 日本国内の医療機関や製薬企業を標的としたランサムウェア被害やシステム停止、二重脅迫の最新動向を注視"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed"
                      />

                      <div className="mt-2 flex items-center justify-between">
                        <button
                          type="button"
                          onClick={() => handlePreviewAIQueries(editModal.form.directive || "", editModal.type)}
                          disabled={generatingQueries || !editModal.form.directive?.trim()}
                          className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs border border-slate-700 transition disabled:opacity-50"
                        >
                          {generatingQueries ? (
                            <>
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                              <span>AIクエリ生成中...</span>
                            </>
                          ) : (
                            <>
                              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                              <span>AIクエリ生成テスト</span>
                            </>
                          )}
                        </button>
                        <span className="text-[11px] text-slate-500">
                          巡回時にも自動生成されます
                        </span>
                      </div>

                      {previewQueries.length > 0 && (
                        <div className="mt-2.5 p-2.5 rounded-lg bg-slate-950 border border-cyan-900/60 space-y-1.5">
                          <div className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">
                            AIが生成した調査クエリ例 ({previewQueries.length}件):
                          </div>
                          {previewQueries.map((pq, i) => (
                            <div key={i} className="text-xs font-mono text-slate-300 bg-slate-900/80 px-2 py-1 rounded border border-slate-800 flex items-center space-x-1.5">
                              <span className="text-cyan-500 text-[10px]">#{i + 1}</span>
                              <span className="truncate">{pq}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">
                        固定検索クエリ
                      </label>
                      <input
                        type="text"
                        value={editModal.form.query}
                        onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, query: e.target.value } })}
                        placeholder="例: (from:piyokango OR from:jpcert) site:x.com"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm font-mono text-slate-100 placeholder-slate-600"
                      />
                    </div>
                  )}
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-1">
                  Compliance Classification Tier
                </label>
                <select
                  value={editModal.form.compliance_tier || "commercial_ready"}
                  onChange={(e) =>
                    setEditModal({
                      ...editModal,
                      form: { ...editModal.form, compliance_tier: e.target.value },
                    })
                  }
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="commercial_ready">🟢 Commercial Ready (Safe for OSS / Commercial distribution)</option>
                  <option value="commercial_via_official_api">🟡 Commercial via Official API (Requires API Key / Official Endpoint)</option>
                  <option value="tos_restricted">🟠 Non-Commercial: ToS Scraping (Research only / Web Scraping)</option>
                  <option value="darkweb_access">🔴 Non-Commercial: Dark Web (Research only / Onion Routing)</option>
                </select>
                <p className="text-[11px] text-slate-500 mt-1">
                  Controls commercial readiness and global tier killswitch behavior.
                </p>
              </div>
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
