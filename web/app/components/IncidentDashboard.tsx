"use client";

import React, { useEffect, useState, useMemo } from "react";
import { usePathname } from "next/navigation";
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
  ChevronUp,
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
  Skull,
  Lock,
  LogOut,
  Key,
  Target,
  Building2,
} from "lucide-react";
import { TerminalConsole } from "./TerminalConsole";
import { withBasePath, isAdminPath } from "./basePath";

interface ActorStat {
  name: string;
  count: number;
  japan_count: number;
  last_seen_at: string;
}

interface VictimStat {
  name: string;
  name_ja?: string;
  name_en?: string;
  count: number;
  japan_count: number;
  last_seen_at: string;
}

interface EntityStats {
  total_unique_actors: number;
  total_unique_victims: number;
  top_actors: ActorStat[];
  top_victims: VictimStat[];
}

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
  title_ja?: string;
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
  attack_type?: string;
  cves?: string[];
  affected_product?: string;
  threat_actors?: string[];
  threat_actor_reasons?: Record<string, string>;
  threat_actor_reasons_ja?: Record<string, string>;
  report_count?: number;
  first_seen_at?: string;
  last_seen_at?: string;
  child_items?: Incident[];
  summary: string;
  summary_ja?: string;
  impact_analysis?: string;
  impact_analysis_ja?: string;
  raw_content?: string | null;
  published_at: string | null;
  harvested_at: string;
  severity: string | null;
  japan_relevance: string | null;
  notified_at: string | null;
  enriched_data: string | null;
  enriched_parsed?: {
    title?: string;
    title_ja?: string;
    summary?: string;
    summary_ja?: string;
    impact_analysis?: string;
    impact_analysis_ja?: string;
    victim_orgs?: string[];
    threat_actors?: string[];
    threat_actor_reasons?: Record<string, string>;
    threat_actor_reasons_ja?: Record<string, string>;
    attack_type?: string;
    cves?: string[];
    affected_products?: string[];
    recommended_actions?: string[];
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
    primary_provider?: string;
    local_llm?: {
      online?: boolean;
      model?: string;
      endpoint?: string;
    };
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
    ransomware_tracker?: { total: number; active: number };
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
    darkweb_onion?: Array<{ name: string; url: string; type?: string; directive?: string; query?: string; compliance_tier?: string; enabled: boolean }>;
    ransomware_tracker?: Array<{ name: string; url: string; type?: string; compliance_tier?: string; enabled: boolean }>;
    x_monitor?: Array<{ name?: string; directive?: string; query: string; compliance_tier?: string; enabled: boolean }>;
    web_search?: Array<{ name?: string; directive?: string; query: string; type?: string; url?: string; engines?: string; categories?: string; timeout_seconds?: number; compliance_tier?: string; enabled: boolean }>;
  };
}

function getRawContentText(inc: Incident | null): string {
  if (!inc) return "";
  if (inc.raw_content && inc.raw_content.trim() !== "") {
    return inc.raw_content.trim();
  }
  if (inc.child_items && inc.child_items.length > 0) {
    const parts = inc.child_items
      .map((c) => {
        const raw = (c.raw_content || c.summary || "").trim();
        if (!raw) return null;
        const header = `=== [${c.source_type || "Source"} / ${c.source_name || "Unknown"}] ${c.title || ""} ===${c.url ? `\nURL: ${c.url}` : ""}`;
        return `${header}\n\n${raw}`;
      })
      .filter((p): p is string => Boolean(p));
    if (parts.length > 0) {
      return parts.join("\n\n---\n\n");
    }
  }
  return "";
}

function getCleanDisplayTitle(
  inc: { title?: string; title_ja?: string; enriched_parsed?: { title?: string; title_ja?: string } | null } | null,
  lang: "en" | "ja" = "en"
): string {
  if (!inc) return "";
  let title = "";
  if (lang === "ja") {
    title = inc.title_ja || inc.enriched_parsed?.title_ja || inc.title || inc.enriched_parsed?.title || "";
  } else {
    title = inc.enriched_parsed?.title || inc.title || inc.title_ja || inc.enriched_parsed?.title_ja || "";
  }
  title = title.replace(/\s*\(\s*\)$/, "").trim();
  return title || "Untitled Incident";
}

function getCleanDisplaySummary(
  inc: { summary?: string; summary_ja?: string; enriched_parsed?: { summary?: string; summary_ja?: string } | null } | null,
  lang: "en" | "ja" = "en"
): string {
  if (!inc) return "";
  if (lang === "ja") {
    const sJa = inc.summary_ja || inc.enriched_parsed?.summary_ja;
    if (sJa && !sJa.startsWith("Group: ") && !sJa.startsWith("Victim: ")) return sJa;
    const s = inc.summary || inc.enriched_parsed?.summary;
    if (s && !s.startsWith("Group: ") && !s.startsWith("Victim: ")) return s;
    return sJa || s || "";
  } else {
    const s = inc.enriched_parsed?.summary || inc.summary;
    if (s && !s.startsWith("Group: ") && !s.startsWith("Victim: ")) return s;
    const sJa = inc.enriched_parsed?.summary_ja || inc.summary_ja;
    if (sJa && !sJa.startsWith("Group: ") && !sJa.startsWith("Victim: ")) return sJa;
    return s || sJa || "";
  }
}

const INVALID_ACTOR_SUBSTRINGS = [
  "not specified", "not explicitly", "not identified", "not provided", "not named", "not known",
  "likely cybercrime", "likely a cybercrime", "targeting japanese", "targeting corporate",
  "unknown threat actor", "threat actor", "cybercrime group", "initial access broker",
  "aiを使用した", "aiエージェント", "ai-driven", "rogue openai", "openai agents",
  "state-sponsored", "state sponsored", "国家支援型", "国家背景", "サイバーエスピオナージ",
  "中国系", "中国国家", "北朝鮮国家", "北朝鮮系", "campaign", "vx-underground",
  "related actor", "関連の攻撃者", "に関連する", "operator", "運用グループ",
  "未確認", "未特定", "不特定", "未詳", "特定なし",
  "未知", "未提及", "未确认", "未确定", "威胁行为者", "犯罪集团",
  "不正アクセスの攻撃者", "悪意のある第三者",
  "it労働者", "it workers", "associated groups", "linked actors", "関連グループ",
  "傘下サイバー部隊", "配下グループ", "関連懸念", "国家安全部", "通用技術研究院",
  "darknet army", "darknetarmy",
];

const INVALID_ACTOR_EXACT = new Set([
  "unknown", "unspecified", "unidentified", "unnamed", "none", "n/a",
  "hackers", "hacker", "cybercriminals", "cybercriminal", "attackers", "attacker", "adversary", "adversaries",
  "automated attack tools", "unauthorized access perpetrators",
  "third-party external server provider", "microsoft (for publishing updates)",
  "chaotic eclipse", "nightmare eclipse", "black kite", "darknet army", "darknetarmy",
  "ghostwire",
  "world leaks", "leakeddata", "contagious interview",
  "外部攻撃者", "攻撃者", "サイバー犯罪者", "サイバー攻撃者", "ハッカー", "侵入者", "悪意のある第三者", "第三者",
  "dprk threat actors", "chinese apt", "china-nexus threat actor", "north korean state-sponsored actors",
  "北朝鮮it労働者", "dprk it workers", "none identified", "none specified", "not available",
  "黑客", "犯罪集团", "未特定", "未確認", "不明", "未知威胁行为者",
]);

export function isValidThreatActor(actor: string | undefined | null): boolean {
  if (!actor) return false;
  const s = actor.trim();
  if (s.length < 2 || s.length > 40) return false;
  const low = s.toLowerCase();
  if (INVALID_ACTOR_EXACT.has(low) || low.startsWith("not ") || low.startsWith("unknown")) {
    return false;
  }
  for (const sub of INVALID_ACTOR_SUBSTRINGS) {
    if (low.includes(sub)) return false;
  }
  return true;
}

export function filterValidThreatActors(actors: string[] | undefined | null): string[] {
  if (!actors || !Array.isArray(actors)) return [];
  const valid: string[] = [];
  const seen = new Set<string>();
  for (const a of actors) {
    if (isValidThreatActor(a)) {
      const low = a.trim().toLowerCase();
      if (!seen.has(low)) {
        seen.add(low);
        valid.push(a.trim());
      }
    }
  }
  return valid;
}

export interface IncidentDashboardProps {
  lang?: "en" | "ja";
}

export default function IncidentDashboard({ lang = "en" }: IncidentDashboardProps) {
  const pathname = usePathname();
  const isAdmin = isAdminPath(pathname);
  const [currentLang, setCurrentLang] = useState<"en" | "ja">(lang);

  useEffect(() => {
    if (lang) {
      setCurrentLang(lang);
    }
  }, [lang]);

  // Admin Authentication State
  const [isAdminAuthenticated, setIsAdminAuthenticated] = useState<boolean>(false);
  const [authChecking, setAuthChecking] = useState<boolean>(true);
  const [adminPasswordInput, setAdminPasswordInput] = useState<string>("");
  const [authError, setAuthError] = useState<string>("");
  const [authLoading, setAuthLoading] = useState<boolean>(false);

  const [activeTab, setActiveTab] = useState<"incidents" | "sources" | "config" | "status" | "console">(
    "incidents"
  );
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

  // Entity Aggregation State
  const [entityStats, setEntityStats] = useState<EntityStats | null>(null);
  const [loadingEntityStats, setLoadingEntityStats] = useState<boolean>(false);
  const [selectedActorFilter, setSelectedActorFilter] = useState<string>("");
  const [selectedVictimFilter, setSelectedVictimFilter] = useState<string>("");
  const [showAllEntitiesModal, setShowAllEntitiesModal] = useState<boolean>(false);
  const [entitiesModalTab, setEntitiesModalTab] = useState<"actors" | "victims">("actors");
  const [entitiesSearch, setEntitiesSearch] = useState<string>("");
  const [allEntityStats, setAllEntityStats] = useState<EntityStats | null>(null);
  const [loadingAllEntities, setLoadingAllEntities] = useState<boolean>(false);
  const [entitiesExpanded, setEntitiesExpanded] = useState<boolean>(false);

  const toggleEntitiesExpanded = () => {
    setEntitiesExpanded((prev) => !prev);
  };

  const fetchEntityStats = async () => {
    setLoadingEntityStats(true);
    try {
      const res = await fetch(withBasePath(`/api/stats/entities?limit=30`, pathname));
      if (res.ok) {
        const data = await res.json();
        setEntityStats(data);
      }
    } catch {
      // non-critical
    } finally {
      setLoadingEntityStats(false);
    }
  };

  const fetchAllEntities = async () => {
    setLoadingAllEntities(true);
    try {
      const res = await fetch(withBasePath(`/api/stats/entities?limit=500`, pathname));
      if (res.ok) {
        const data = await res.json();
        setAllEntityStats(data);
      }
    } catch {
      // non-critical
    } finally {
      setLoadingAllEntities(false);
    }
  };

  useEffect(() => {
    fetch(withBasePath("/api/auth/verify", pathname))
      .then((res) => res.json())
      .then((data) => {
        if (data.authenticated) {
          setIsAdminAuthenticated(true);
        }
      })
      .catch(() => {})
      .finally(() => setAuthChecking(false));
  }, []);

  const handleAdminLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError("");
    try {
      const res = await fetch(withBasePath("/api/auth/verify", pathname), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: adminPasswordInput }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setIsAdminAuthenticated(true);
        showToast("Authenticated as Administrator");
      } else {
        setAuthError(data.error || "Authentication failed");
      }
    } catch {
      setAuthError("Failed to connect to authentication service");
    } finally {
      setAuthLoading(false);
    }
  };

  const handleAdminLogout = async () => {
    await fetch(withBasePath("/api/auth/verify", pathname), { method: "DELETE" });
    setIsAdminAuthenticated(false);
    setAdminPasswordInput("");
    showToast("Logged out from Admin Console");
  };

  // Modals & Toast
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [showRawInModal, setShowRawInModal] = useState<boolean>(false);

  const openIncidentModal = async (item: Incident) => {
    setSelectedIncident(item);
    setShowRawInModal(false);
    try {
      const res = await fetch(withBasePath(`/api/incidents/${encodeURIComponent(item.id)}?lang=${currentLang}`, pathname));
      if (res.ok) {
        const full = await res.json();
        setSelectedIncident(full);
      }
    } catch {
      // keep initial item data if fetch fails
    }
  };

  // Admin Incident Label Editing State
  const [editingLabels, setEditingLabels] = useState<boolean>(false);
  const [editActors, setEditActors] = useState<string[]>([]);
  const [newActorInput, setNewActorInput] = useState<string>("");
  const [editSeverity, setEditSeverity] = useState<string>("");
  const [editJapanRel, setEditJapanRel] = useState<string>("");
  const [editAttackType, setEditAttackType] = useState<string>("");
  const [editVictimOrg, setEditVictimOrg] = useState<string>("");
  const [savingLabels, setSavingLabels] = useState<boolean>(false);

  const startEditLabels = (inc?: Incident) => {
    const target = inc || selectedIncident;
    if (!target) return;
    if (inc && (!selectedIncident || inc.id !== selectedIncident.id)) {
      setSelectedIncident(inc);
    }
    const actors = target.threat_actors || target.enriched_parsed?.threat_actors || [];
    setEditActors([...actors]);
    setEditSeverity(target.severity || "Unknown");
    setEditJapanRel(target.japan_relevance || "Unknown");
    setEditAttackType(target.attack_type || target.enriched_parsed?.attack_type || "");
    setEditVictimOrg(target.victim_org || target.normalized_victim_org || "");
    setNewActorInput("");
    setEditingLabels(true);
  };

  const handleAddActor = () => {
    const trimmed = newActorInput.trim();
    if (!trimmed) return;
    if (!editActors.some((a) => a.toLowerCase() === trimmed.toLowerCase())) {
      setEditActors([...editActors, trimmed]);
    }
    setNewActorInput("");
  };

  const handleRemoveActor = (indexToRemove: number) => {
    setEditActors(editActors.filter((_, idx) => idx !== indexToRemove));
  };

  const handleSaveLabels = async () => {
    if (!selectedIncident) return;
    setSavingLabels(true);
    try {
      const res = await fetch(withBasePath(`/api/incidents/${encodeURIComponent(selectedIncident.id)}/update`, pathname), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          threat_actors: editActors,
          severity: editSeverity,
          japan_relevance: editJapanRel,
          attack_type: editAttackType,
          victim_org: editVictimOrg,
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedIncident((prev) =>
          prev
            ? {
                ...prev,
                ...updated,
                threat_actors: editActors,
                severity: editSeverity as any,
                japan_relevance: editJapanRel as any,
                attack_type: editAttackType,
                victim_org: editVictimOrg,
                enriched_parsed: prev.enriched_parsed
                  ? {
                      ...prev.enriched_parsed,
                      threat_actors: editActors,
                      severity: editSeverity as any,
                      japan_relevance: editJapanRel as any,
                      attack_type: editAttackType,
                    }
                  : null,
              }
            : null
        );

        setIncidents((prev) =>
          prev.map((it) =>
            it.id === selectedIncident.id
              ? {
                  ...it,
                  threat_actors: editActors,
                  severity: editSeverity as any,
                  japan_relevance: editJapanRel as any,
                  attack_type: editAttackType,
                  victim_org: editVictimOrg,
                  enriched_parsed: it.enriched_parsed
                    ? {
                        ...it.enriched_parsed,
                        threat_actors: editActors,
                        severity: editSeverity as any,
                        japan_relevance: editJapanRel as any,
                        attack_type: editAttackType,
                      }
                    : null,
                }
              : it
          )
        );
        showToast(currentLang === "ja" ? "ラベル設定を保存しました" : "Labels updated successfully");
        setEditingLabels(false);
      } else {
        const err = await res.json();
        showToast(err.detail || "Update failed", "error");
      }
    } catch (e: any) {
      showToast(e.message || "Failed to update labels", "error");
    } finally {
      setSavingLabels(false);
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
      engines?: string;
      categories?: string;
      timeout_seconds?: number;
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
      engines?: string;
      categories?: string;
      timeout_seconds?: number;
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
      showToast("Please enter a directive instruction", "error");
      return;
    }
    setGeneratingQueries(true);
    try {
      const res = await fetch(withBasePath("/api/ai/generate-queries", pathname), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ directive, target_type: targetType, count: 3 }),
      });
      if (res.ok) {
        const data = await res.json();
        setPreviewQueries(data.queries || []);
        showToast(`AI generated ${data.queries?.length || 0} hunt queries`);
      } else {
        const err = await res.json();
        showToast(err.detail || "Failed to generate queries", "error");
      }
    } catch (e) {
      showToast("Network error occurred during query generation", "error");
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
      const res = await fetch(withBasePath("/api/status", pathname));
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
      const res = await fetch(withBasePath("/api/config", pathname));
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
      params.append("lang", currentLang);

      const res = await fetch(withBasePath(`/api/incidents?${params.toString()}`, pathname));
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
    fetchEntityStats();
    if (!isAdmin || activeTab === "incidents") {
      fetchIncidents(1, pageSize);
    }
  }, [currentLang, isAdmin, activeTab]);

  useEffect(() => {
    if (!isAdmin || activeTab === "incidents") {
      setCurrentPage(1);
      const timer = setTimeout(() => {
        fetchIncidents(1, pageSize);
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [search, severityFilter, japanOnly, sourceTypeFilter, sortBy, isAdmin, activeTab]);

  const handleHarvestFinished = async () => {
    setHarvesting(false);
    showToast("Threat harvesting pipeline completed.");
    if (!isAdmin || activeTab === "incidents") {
      await fetchIncidents(currentPage, pageSize);
    }
    await fetchStatus();
    await fetchEntityStats();
  };

  const triggerHarvest = async () => {
    setHarvesting(true);
    setTerminalOpen(true);
    showToast("Threat intelligence harvest started.");
    try {
      const res = await fetch(withBasePath("/api/pipeline/run", pathname), { method: "POST" });
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
      const res = await fetch(withBasePath("/api/config/sources", pathname), {
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
      const res = await fetch(withBasePath("/api/config/sources", pathname), {
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
      const res = await fetch(withBasePath("/api/config/compliance", pathname), {
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
      const res = await fetch(withBasePath("/api/config/sources", pathname), {
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
    if (sourceType === "darkweb_onion") return "darkweb_access";
    if (sourceType === "ransomware_tracker") {
      return item.type === "api" ? "commercial_via_official_api" : "commercial_ready";
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
    if (type === "darkweb_onion") {
      const isSearch = addModal.form.type === "search";
      if (!isSearch && !addModal.form.url.includes(".onion")) {
        showToast("Dark Web sources must use a .onion address", "error");
        return;
      }
      data = {
        name: addModal.form.name,
        url: addModal.form.url || (isSearch ? "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion" : ""),
        type: addModal.form.type || (addModal.form.mode === "directive" || addModal.form.query ? "search" : "onion"),
        directive: addModal.form.mode === "directive" ? addModal.form.directive : "",
        query: addModal.form.mode === "query" ? addModal.form.query : addModal.form.query,
        enabled: true,
      };
    }
    if (type === "ransomware_tracker") {
      data = { name: addModal.form.name, url: addModal.form.url, type: addModal.form.type || "api", enabled: true };
    }
    if (type === "x_monitor") {
      data = {
        name: addModal.form.name,
        directive: addModal.form.mode === "directive" ? addModal.form.directive : "",
        query: addModal.form.mode === "query" ? addModal.form.query : addModal.form.query,
        enabled: true,
      };
    }
    if (type === "web_search") {
      data = {
        name: addModal.form.name,
        type: addModal.form.type || "searxng",
        url: addModal.form.type === "searxng" ? (addModal.form.url || "https://searxng.lab.internal/search") : "",
        engines: addModal.form.engines || "",
        categories: addModal.form.categories || (addModal.form.type === "searxng" ? "general,news" : ""),
        directive: addModal.form.mode === "directive" ? addModal.form.directive : "",
        query: addModal.form.mode === "query" ? addModal.form.query : addModal.form.query,
        enabled: true,
      };
    }
    if (addModal.form.compliance_tier) {
      data.compliance_tier = addModal.form.compliance_tier;
    }

    try {
      const res = await fetch(withBasePath("/api/config/sources", pathname), {
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
      const isSearch = editModal.form.type === "search";
      if (!isSearch && !editModal.form.url.includes(".onion")) {
        showToast("Dark Web sources must use a .onion address", "error");
        return;
      }
      data = {
        name: editModal.form.name,
        url: editModal.form.url || (isSearch ? "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion" : ""),
        type: editModal.form.type || (editModal.form.mode === "directive" || editModal.form.query ? "search" : "onion"),
        directive: editModal.form.mode === "directive" ? editModal.form.directive : "",
        query: editModal.form.mode === "query" ? editModal.form.query : editModal.form.query,
      };
    } else if (type === "ransomware_tracker") {
      data = { name: editModal.form.name, url: editModal.form.url, type: editModal.form.type || "api" };
    } else if (type === "x_monitor") {
      data = {
        name: editModal.form.name,
        directive: editModal.form.mode === "directive" ? editModal.form.directive : "",
        query: editModal.form.mode === "query" ? editModal.form.query : editModal.form.query,
      };
    } else if (type === "web_search") {
      data = {
        name: editModal.form.name,
        type: editModal.form.type || "searxng",
        url: editModal.form.type === "searxng" ? (editModal.form.url || "https://searxng.lab.internal/search") : "",
        engines: editModal.form.engines || "",
        categories: editModal.form.categories || (editModal.form.type === "searxng" ? "general,news" : ""),
        directive: editModal.form.mode === "directive" ? editModal.form.directive : "",
        query: editModal.form.mode === "query" ? editModal.form.query : editModal.form.query,
      };
    }
    if (editModal.form.compliance_tier) {
      data.compliance_tier = editModal.form.compliance_tier;
    }

    try {
      const res = await fetch(withBasePath("/api/config/sources", pathname), {
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
      const res = await fetch(withBasePath("/api/config/save", pathname), { method: "POST" });
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
      const res = await fetch(withBasePath("/api/test/notify", pathname), { method: "POST" });
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
      const res = await fetch(withBasePath("/api/test/notion", pathname), { method: "POST" });
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

  if (isAdmin && authChecking) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="flex flex-col items-center space-y-3">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
          <span className="text-sm text-slate-400 font-medium">Verifying administrator session...</span>
        </div>
      </div>
    );
  }

  if (isAdmin && !isAdminAuthenticated) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center px-4 py-12">
        <div className="w-full max-w-md bg-slate-900/90 border border-slate-800 rounded-2xl p-8 shadow-2xl shadow-purple-950/20 backdrop-blur">
          <div className="flex flex-col items-center text-center space-y-3 mb-6">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-purple-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-purple-600/30">
              <Lock className="w-7 h-7 text-white" />
            </div>
            <h1 className="text-xl font-bold text-white tracking-wide">Threat Harvester Admin</h1>
            <p className="text-xs text-slate-400 max-w-xs leading-relaxed">
              Enter administrator password to manage threat intelligence sources, system configurations, and manual harvest jobs.
            </p>
          </div>

          <form onSubmit={handleAdminLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Administrator Password / PIN
              </label>
              <div className="relative">
                <Key className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  value={adminPasswordInput}
                  onChange={(e) => setAdminPasswordInput(e.target.value)}
                  placeholder="Enter administrator password..."
                  autoFocus
                  required
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500 transition"
                />
              </div>
              {authError && (
                <p className="mt-2 text-xs text-rose-400 flex items-center space-x-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                  <span>{authError}</span>
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={authLoading || !adminPasswordInput.trim()}
              className="w-full py-2.5 px-4 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 shadow-md shadow-purple-600/20 disabled:opacity-50 transition flex items-center justify-center cursor-pointer"
            >
              {authLoading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Authenticating...
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4 mr-2" />
                  Unlock Admin Console
                </>
              )}
            </button>
          </form>

          <div className="mt-6 pt-6 border-t border-slate-800 text-center">
            <a
              href="/"
              className="inline-flex items-center text-xs text-slate-400 hover:text-cyan-400 transition"
            >
              <ChevronLeft className="w-3.5 h-3.5 mr-1" />
              Return to Threat Incidents (Public View)
            </a>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          
          {/* Logo & Brand */}
          <div className="flex items-center space-x-3">
            <div className={`w-9 h-9 rounded-lg flex items-center justify-center shadow-lg ${
              isAdmin
                ? "bg-gradient-to-tr from-purple-600 to-indigo-500 shadow-purple-500/20"
                : "bg-gradient-to-tr from-cyan-600 to-emerald-500 shadow-cyan-500/20"
            }`}>
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-wider text-white">THREAT HARVESTER</span>
                {isAdmin && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider bg-purple-950/80 text-purple-300 border border-purple-700/60 uppercase">
                    Admin Portal
                  </span>
                )}
              </div>
              <span className="hidden sm:inline-block text-xs text-slate-400">
                Japan Cyber Threat Intelligence Feeds Collector
              </span>
            </div>
          </div>

          {/* Right Section: Status & Action Buttons */}
          <div className="flex items-center space-x-2 sm:space-x-3">
            <span className="hidden sm:inline-flex items-center text-xs text-emerald-400 bg-emerald-950/40 border border-emerald-800/60 px-2.5 py-1 rounded-full">
              <span className="w-2 h-2 rounded-full bg-emerald-400 mr-1.5 animate-ping" />
              {currentLang === "ja" ? "稼働中" : "Operational"}
            </span>

            {/* Language Switcher */}
            <div className="flex items-center bg-slate-800/90 rounded-lg p-0.5 border border-slate-700 text-xs shadow-sm">
              <a
                href={isAdmin ? "#" : withBasePath("/en", pathname)}
                onClick={(e) => {
                  if (isAdmin) {
                    e.preventDefault();
                    setCurrentLang("en");
                  }
                }}
                className={`px-2 py-0.5 rounded font-mono font-medium transition cursor-pointer ${
                  currentLang === "en"
                    ? "bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40"
                    : "text-slate-400 hover:text-white"
                }`}
                title="Switch to English view"
              >
                EN
              </a>
              <span className="text-slate-600 px-0.5">|</span>
              <a
                href={isAdmin ? "#" : withBasePath("/ja", pathname)}
                onClick={(e) => {
                  if (isAdmin) {
                    e.preventDefault();
                    setCurrentLang("ja");
                  }
                }}
                className={`px-2 py-0.5 rounded font-mono font-medium transition cursor-pointer ${
                  currentLang === "ja"
                    ? "bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40"
                    : "text-slate-400 hover:text-white"
                }`}
                title="日本語表示に切替"
              >
                JA
              </a>
            </div>

            {/* RSS Feed is available to both Public and Admin */}
            <a
              href={withBasePath("/api/feed.xml", pathname)}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition cursor-pointer"
              title="Subscribe to RSS 2.0 Feed (/api/feed.xml)"
            >
              <Rss className="w-3.5 h-3.5 mr-1.5 text-amber-400" />
              <span>{currentLang === "ja" ? "RSS" : "RSS Feed"}</span>
            </a>


            {/* Administrator Only Actions */}
            {isAdmin && (
              <>
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
                  href={withBasePath("/api/config/export", pathname)}
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

                <a
                  href="/"
                  className="inline-flex items-center px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                  title="Return to Public Threat Feed"
                >
                  <LayoutGrid className="w-3.5 h-3.5 mr-1 text-cyan-400" />
                  Public View
                </a>

                <button
                  onClick={handleAdminLogout}
                  className="inline-flex items-center px-2.5 py-1.5 rounded-lg text-xs font-medium bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/60 transition"
                  title="Log out from Admin Console"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </>
            )}
          </div>

        </div>

        {/* Navigation Tabs - Displayed only in Administrator Mode */}
        {isAdmin && (
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
              <span>{currentLang === "ja" ? "インシデント・ラベル管理" : "Incidents & Labels"}</span>
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
        )}
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

        {/* TAB 1: INCIDENTS FEED (Public Viewer & Admin Management) */}
        {activeTab === "incidents" && (
          <div>
            {/* Overview KPI Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex items-center justify-between">
                <div>
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                    {currentLang === "ja" ? "総インシデント数" : "Total Incidents"}
                  </div>
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
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                    {currentLang === "ja" ? "日本に関連する" : "Japan Direct"}
                  </div>
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
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                    {currentLang === "ja" ? "通知送信済み" : "Alerts Dispatched"}
                  </div>
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
                  <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                    {currentLang === "ja" ? "稼働ソース数" : "Active Sources"}
                  </div>
                  <div className="text-2xl font-bold font-mono text-purple-400 mt-1">
                    {status?.sources?.total_active ?? 0}
                  </div>
                </div>
                <div className="w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center text-purple-400">
                  <Radio className="w-5 h-5" />
                </div>
              </div>
            </div>

            {/* Observed Threat Actors & Victims Intelligence Widget */}
            {entityStats && (
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl mb-6 shadow-lg overflow-hidden transition-all duration-200">
                <div
                  onClick={toggleEntitiesExpanded}
                  className={`flex flex-wrap items-center justify-between gap-2 p-4 sm:px-5 cursor-pointer hover:bg-slate-800/40 select-none transition ${
                    entitiesExpanded ? "border-b border-slate-800/80 pb-3.5" : "py-3.5"
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    <span className="p-1.5 rounded-lg bg-cyan-950/60 border border-cyan-800/40 text-cyan-400">
                      <Target className="w-4 h-4" />
                    </span>
                    <div>
                      <div className="flex items-center space-x-2">
                        <h3 className="text-sm font-bold text-white tracking-wide">
                          {currentLang === "ja" ? "観測インテリジェンス集計（脅威アクター & 標的組織）" : "Observed Intelligence: Threat Actors & Target Victims"}
                        </h3>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                          {entityStats.total_unique_actors} Actors / {entityStats.total_unique_victims} Victims
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        {currentLang === "ja"
                          ? `当プラットフォームで観測された ${entityStats.total_unique_actors} 組のアクターと ${entityStats.total_unique_victims} 社の標的組織`
                          : `Tracking ${entityStats.total_unique_actors} active threat actors and ${entityStats.total_unique_victims} targeted entities`}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2" onClick={(e) => e.stopPropagation()}>
                    {(selectedActorFilter || selectedVictimFilter) && (
                      <button
                        onClick={() => {
                          setSelectedActorFilter("");
                          setSelectedVictimFilter("");
                          setSearch("");
                        }}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-semibold bg-rose-950/50 hover:bg-rose-900/50 text-rose-300 border border-rose-800/40 transition"
                      >
                        <X className="w-3 h-3" />
                        <span>{currentLang === "ja" ? "絞り込み解除" : "Clear Filter"}</span>
                      </button>
                    )}
                    <button
                      onClick={() => {
                        fetchAllEntities();
                        setShowAllEntitiesModal(true);
                      }}
                      className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-950/60 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-800/50 transition shadow-sm"
                    >
                      <span>{currentLang === "ja" ? "全件一覧・分析" : "View All Entities"}</span>
                      <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={toggleEntitiesExpanded}
                      className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                      title={entitiesExpanded ? (currentLang === "ja" ? "閉じる" : "Collapse") : (currentLang === "ja" ? "開く" : "Expand")}
                    >
                      <span>{entitiesExpanded ? (currentLang === "ja" ? "閉じる" : "Collapse") : (currentLang === "ja" ? "開く" : "Expand")}</span>
                      {entitiesExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                {entitiesExpanded && (
                  <div className="p-4 sm:p-5 pt-3 animate-fadeIn">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {/* Top Threat Actors Column */}
                      <div className="bg-slate-950/60 border border-slate-800/60 rounded-xl p-3.5 space-y-2.5">
                        <div className="flex items-center justify-between text-xs font-semibold text-purple-300 border-b border-purple-950/50 pb-1.5">
                          <div className="flex items-center space-x-1.5">
                            <Skull className="w-3.5 h-3.5 text-purple-400" />
                            <span>{currentLang === "ja" ? "主要観測アクター (Top Threat Actors)" : "Top Threat Actors"}</span>
                          </div>
                          <span className="text-[11px] text-purple-400/80 font-mono">
                            {entityStats.total_unique_actors} {currentLang === "ja" ? "組 観測" : "Observed"}
                          </span>
                        </div>

                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {entityStats.top_actors.slice(0, 14).map((actor) => {
                            const isSelected = selectedActorFilter.toLowerCase() === actor.name.toLowerCase();
                            return (
                              <button
                                key={actor.name}
                                onClick={() => {
                                  if (isSelected) {
                                    setSelectedActorFilter("");
                                    setSearch("");
                                  } else {
                                    setSelectedActorFilter(actor.name);
                                    setSelectedVictimFilter("");
                                    setSearch(actor.name);
                                  }
                                }}
                                className={`inline-flex items-center space-x-1.5 px-2 py-1 rounded-md text-xs font-mono transition shadow-sm ${
                                  isSelected
                                    ? "bg-purple-600 text-white font-bold ring-2 ring-purple-400 shadow-purple-500/30"
                                    : "bg-purple-950/40 hover:bg-purple-900/60 text-purple-200 border border-purple-800/50 hover:border-purple-600"
                                }`}
                                title={`Click to filter incidents by ${actor.name} (${actor.count} incidents)`}
                              >
                                <span>{actor.name}</span>
                                <span className={`text-[10px] px-1 rounded-full font-sans font-bold ${
                                  isSelected ? "bg-purple-800 text-white" : "bg-purple-900/80 text-purple-300"
                                }`}>
                                  {actor.count}
                                </span>
                                {actor.japan_count > 0 && (
                                  <span className="text-[11px]" title={`Targets Japan: ${actor.japan_count} incidents`}>🇯🇵</span>
                                )}
                              </button>
                            );
                          })}
                        </div>
                      </div>

                      {/* Top Victims Column */}
                      <div className="bg-slate-950/60 border border-slate-800/60 rounded-xl p-3.5 space-y-2.5">
                        <div className="flex items-center justify-between text-xs font-semibold text-cyan-300 border-b border-cyan-950/50 pb-1.5">
                          <div className="flex items-center space-x-1.5">
                            <Building2 className="w-3.5 h-3.5 text-cyan-400" />
                            <span>{currentLang === "ja" ? "主要標的・被害組織 (Targeted Organizations)" : "Top Targeted Organizations"}</span>
                          </div>
                          <span className="text-[11px] text-cyan-400/80 font-mono">
                            {entityStats.total_unique_victims} {currentLang === "ja" ? "社・機関 観測" : "Observed"}
                          </span>
                        </div>

                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {entityStats.top_victims.slice(0, 14).map((victim) => {
                            const displayName = (currentLang === "en" && victim.name_en) ? victim.name_en : victim.name;
                            const isSelected = selectedVictimFilter.toLowerCase() === displayName.toLowerCase();
                            return (
                              <button
                                key={victim.name}
                                onClick={() => {
                                  if (isSelected) {
                                    setSelectedVictimFilter("");
                                    setSearch("");
                                  } else {
                                    setSelectedVictimFilter(displayName);
                                    setSelectedActorFilter("");
                                    setSearch(displayName);
                                  }
                                }}
                                className={`inline-flex items-center space-x-1.5 px-2 py-1 rounded-md text-xs font-mono transition shadow-sm ${
                                  isSelected
                                    ? "bg-cyan-600 text-white font-bold ring-2 ring-cyan-400 shadow-cyan-500/30"
                                    : "bg-cyan-950/40 hover:bg-cyan-900/60 text-cyan-200 border border-cyan-800/50 hover:border-cyan-600"
                                }`}
                                title={`Click to filter incidents by ${displayName} (${victim.count} incidents)`}
                              >
                                <span className="truncate max-w-[170px]">{displayName}</span>
                                <span className={`text-[10px] px-1 rounded-full font-sans font-bold ${
                                  isSelected ? "bg-cyan-800 text-white" : "bg-cyan-900/80 text-cyan-300"
                                }`}>
                                  {victim.count}
                                </span>
                                {victim.japan_count > 0 && (
                                  <span className="text-[11px]" title={`Japan Direct/Indirect: ${victim.japan_count} incidents`}>🇯🇵</span>
                                )}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Filter Bar */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 mb-6 flex flex-wrap gap-3 items-center justify-between">
              <div className="relative flex-1 min-w-[240px]">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder={currentLang === "ja" ? "インシデント、組織名、CVE、製品名で検索..." : "Search title, victim, threat actor, or CVE..."}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="">{currentLang === "ja" ? "重要度: すべて" : "Severity: All"}</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                  <option value="Info">Info</option>
                </select>

                <select
                  value={japanOnly ? "true" : "false"}
                  onChange={(e) => setJapanOnly(e.target.value === "true")}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="false">{currentLang === "ja" ? "全件" : "All Relevancy"}</option>
                  <option value="true">{currentLang === "ja" ? "日本に関連する" : "Japan Direct"}</option>
                </select>

                <select
                  value={sourceTypeFilter}
                  onChange={(e) => setSourceTypeFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="">{currentLang === "ja" ? "ソース: すべて" : "Source: All"}</option>
                  <option value="vendor_rss">{currentLang === "ja" ? "ベンダー・CERT RSS" : "Vendor & CERT RSS"}</option>
                  <option value="ransomware_tracker">{currentLang === "ja" ? "ランサムウェア追跡・DLS" : "Ransomware Trackers & DLS"}</option>
                  <option value="darkweb_onion">{currentLang === "ja" ? "ダークウェブ (.onion)" : "Dark Web (.onion only)"}</option>
                  <option value="telegram">{currentLang === "ja" ? "Telegram" : "Telegram"}</option>
                  <option value="x_monitor">{currentLang === "ja" ? "X (Twitter)" : "X (Twitter)"}</option>
                  <option value="web_search">{currentLang === "ja" ? "Web検索" : "Web Search"}</option>
                </select>

                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as "published_at" | "harvested_at")}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 font-medium"
                >
                  <option value="published_at">{currentLang === "ja" ? "公開日順 (新しい順)" : "Sort: Source Published Date (Newest)"}</option>
                  <option value="harvested_at">{currentLang === "ja" ? "検知日順 (新しい順)" : "Sort: Ingestion Date (Newest)"}</option>
                </select>

                <div className="flex items-center space-x-1 text-xs text-slate-400">
                  <span className="text-slate-500 font-sans hidden sm:inline">{currentLang === "ja" ? "表示数:" : "Per page:"}</span>
                  <select
                    value={pageSize}
                    onChange={(e) => handlePageSizeChange(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value={10}>10 / page</option>
                    <option value={20}>20 / page</option>
                    <option value={50}>50 / page</option>
                    <option value={100}>100 / page</option>
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
                  {currentLang === "ja"
                    ? `合計 ${totalCount.toLocaleString()} 件のインシデント`
                    : `Total ${totalCount.toLocaleString()} incidents`}
                </span>
                {totalCount > 0 && (
                  <span className="text-slate-500 font-mono">
                    {currentLang === "ja"
                      ? `(表示中 ${((currentPage - 1) * pageSize) + 1} 〜 ${Math.min(currentPage * pageSize, totalCount)} 件 / ${currentPage} / ${totalPages} ページ)`
                      : `(Showing ${((currentPage - 1) * pageSize) + 1} - ${Math.min(currentPage * pageSize, totalCount)} / Page ${currentPage} of ${totalPages})`}
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
                    {currentLang === "ja" ? "前へ" : "Prev"}
                  </button>
                  <span className="px-2 py-1 font-mono text-cyan-400 font-medium">
                    {currentPage} / {totalPages}
                  </span>
                  <button
                    disabled={currentPage >= totalPages || loadingIncidents}
                    onClick={() => handlePageChange(currentPage + 1)}
                    className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-40 disabled:pointer-events-none transition flex items-center text-xs"
                  >
                    {currentLang === "ja" ? "次へ" : "Next"}
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
                  {currentLang === "ja" ? "脅威インテリジェンスデータを読み込み中..." : "Loading threat intelligence data..."}
                </div>
              )}

              {!loadingIncidents && incidents.length === 0 && (
                <div className="py-16 text-center text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
                  {currentLang === "ja" ? "条件に一致する脅威インシデントは見つかりませんでした。" : "No threat incidents match the specified filter criteria."}
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
                            : item.severity === "Info"
                            ? "bg-slate-800 text-slate-300 border border-slate-700"
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
                          {currentLang === "ja" ? "波及・間接影響" : "Indirect Impact"}
                        </span>
                      )}
                      {/* Cluster / Source Count Badge */}
                      {item.report_count && item.report_count > 1 ? (
                        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-cyan-950 text-cyan-300 border border-cyan-700/80 flex items-center shadow-sm">
                          <Radio className="w-3 h-3 mr-1 text-cyan-400" />
                          {item.report_count} {currentLang === "ja" ? "件のソース統合" : "Sources Aggregated"}
                        </span>
                      ) : null}

                      <span className="text-xs text-slate-400 font-mono truncate max-w-[150px] sm:max-w-xs">{item.source_name}</span>
                    </div>

                    <div className="text-right">
                      <div className="text-xs text-cyan-400 font-mono font-medium flex items-center justify-end">
                        {item.published_at ? (
                          <>
                            <span className="text-[10px] text-slate-500 mr-1.5 uppercase font-sans font-normal">
                              {currentLang === "ja" ? "情報元:" : "Source:"}
                            </span>
                            {formatDate(item.published_at)}
                          </>
                        ) : (
                          <>
                            <span className="text-[10px] text-slate-500 mr-1.5 uppercase font-sans font-normal">
                              {currentLang === "ja" ? "初検知:" : "Harvested:"}
                            </span>
                            {formatDate(item.harvested_at)}
                          </>
                        )}
                      </div>
                      {item.published_at && (
                        <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                          {currentLang === "ja" ? "収集日:" : "Collected:"} {formatDate(item.harvested_at)}
                        </div>
                      )}
                    </div>
                  </div>

                  <h3 className="text-base font-semibold text-white mb-2 leading-snug hover:text-cyan-400 transition">
                    {getCleanDisplayTitle(item, currentLang)}
                  </h3>

                  <p className="text-xs text-slate-400 line-clamp-2 mb-3">
                    {getCleanDisplaySummary(item, currentLang)}
                  </p>

                  <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
                    {item.enriched_parsed?.victim_orgs && item.enriched_parsed.victim_orgs.length > 0 && (
                      <div className="flex items-center space-x-1">
                        <span className="text-slate-500">{currentLang === "ja" ? "対象組織:" : "Victim:"}</span>
                        {item.enriched_parsed.victim_orgs.map((org) => (
                          <span key={org} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                            {org}
                          </span>
                        ))}
                      </div>
                    )}

                    {(() => {
                      const validActors = filterValidThreatActors(
                        item.enriched_parsed?.threat_actors || item.threat_actors
                      );
                      if (validActors.length === 0) return null;
                      return (
                        <div className="flex items-center space-x-1 ml-2">
                          <span className="text-slate-500">{currentLang === "ja" ? "アクター:" : "Actor:"}</span>
                          {validActors.map((actor) => (
                            <span
                              key={actor}
                              className="px-1.5 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800 font-mono"
                            >
                              {actor}
                            </span>
                          ))}
                        </div>
                      );
                    })()}

                    {(item.affected_product || (item.enriched_parsed?.affected_products && item.enriched_parsed.affected_products.length > 0)) && (
                      <div className="flex items-center space-x-1 ml-1">
                        <span className="text-slate-500">{currentLang === "ja" ? "影響製品:" : "Product:"}</span>
                        <span className="px-1.5 py-0.5 rounded bg-emerald-950/70 text-emerald-300 border border-emerald-800/80 font-mono text-[11px]">
                          {item.affected_product || item.enriched_parsed?.affected_products?.[0]}
                        </span>
                      </div>
                    )}

                    {item.cves && item.cves.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1 ml-1">
                        {item.cves.slice(0, 3).map((cve) => (
                          <span
                            key={cve}
                            className="px-1.5 py-0.5 rounded bg-amber-950/70 text-amber-300 border border-amber-800/80 font-mono text-[11px] font-semibold"
                          >
                            {cve}
                          </span>
                        ))}
                        {item.cves.length > 3 && (
                          <span className="text-[10px] text-amber-500 font-mono">
                            +{item.cves.length - 3}
                          </span>
                        )}
                      </div>
                    )}
                    {isAdmin && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            startEditLabels(item);
                          }}
                          className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 text-xs font-semibold shadow-sm transition"
                          title={currentLang === "ja" ? "自動判定ラベルを管理者が修正" : "Administrator Label Override"}
                        >
                          <Pencil className="w-3 h-3" />
                          <span>{currentLang === "ja" ? "ラベル修正" : "Edit Labels"}</span>
                        </button>
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
                          {currentLang === "ja" ? "情報元" : "Source Article"}
                        </a>
                      )}
                      <div className="flex items-center text-cyan-400 font-medium text-xs">
                        {currentLang === "ja" ? "詳細を見る" : "View Intelligence"} <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
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
                  <span>{currentLang === "ja" ? "表示中:" : "Showing:"}</span>
                  <span className="font-mono text-slate-200 font-medium">
                    {((currentPage - 1) * pageSize) + 1} - {Math.min(currentPage * pageSize, totalCount)}
                  </span>
                  <span>/</span>
                  <span className="font-mono text-cyan-400 font-semibold">{totalCount.toLocaleString()}</span>
                  <span className="text-slate-600">|</span>
                  <span className="font-mono text-slate-400">
                    {currentLang === "ja"
                      ? `${currentPage} / ${totalPages} ページ`
                      : `Page ${currentPage} of ${totalPages}`}
                  </span>
                </div>

                <div className="flex items-center space-x-1">
                  {/* First Page Button */}
                  <button
                    disabled={currentPage <= 1 || loadingIncidents}
                    onClick={() => handlePageChange(1)}
                    title={currentLang === "ja" ? "最初のページ" : "First Page"}
                    className="p-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition"
                  >
                    <ChevronsLeft className="w-4 h-4" />
                  </button>

                  {/* Previous Page Button */}
                  <button
                    disabled={currentPage <= 1 || loadingIncidents}
                    onClick={() => handlePageChange(currentPage - 1)}
                    title={currentLang === "ja" ? "前のページ" : "Previous Page"}
                    className="px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition flex items-center"
                  >
                    <ChevronLeft className="w-3.5 h-3.5 mr-0.5" />
                    {currentLang === "ja" ? "前へ" : "Prev"}
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
                    title={currentLang === "ja" ? "次のページ" : "Next Page"}
                    className="px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition flex items-center"
                  >
                    {currentLang === "ja" ? "次へ" : "Next"}
                    <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
                  </button>

                  {/* Last Page Button */}
                  <button
                    disabled={currentPage >= totalPages || loadingIncidents}
                    onClick={() => handlePageChange(totalPages)}
                    title={currentLang === "ja" ? "最後のページ" : "Last Page"}
                    className="p-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none transition"
                  >
                    <ChevronsRight className="w-4 h-4" />
                  </button>
                </div>

                {/* Bottom Page Size Selector */}
                <div className="flex items-center space-x-2 text-xs text-slate-400">
                  <span>{currentLang === "ja" ? "表示数:" : "Per page:"}</span>
                  <select
                    value={pageSize}
                    onChange={(e) => handlePageSizeChange(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value={10}>10</option>
                    <option value={20}>20</option>
                    <option value={50}>50</option>
                    <option value={100}>100</option>
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
                  href={withBasePath("/api/config/export", pathname)}
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

              {/* 2. Ransomware Trackers & DLS Feeds */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <Skull className="w-5 h-5 text-rose-400" />
                    <div>
                      <h3 className="font-bold text-white text-base">Ransomware Trackers & DLS Feeds</h3>
                      <p className="text-[11px] text-slate-400">Clearnet APIs and aggregators monitoring ransomware leak sites (e.g., Ransomlook, RansomFeed)</p>
                    </div>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400 font-mono">
                      {config?.sources?.ransomware_tracker?.length ?? 0}
                    </span>
                  </div>
                  <button
                    onClick={() =>
                      setAddModal({
                        visible: true,
                        type: "ransomware_tracker",
                        form: { name: "", url: "", channel: "", query: "", type: "api", compliance_tier: "commercial_via_official_api" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Tracker
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.ransomware_tracker?.map((rw) => {
                    const tier = getSourceComplianceTier("ransomware_tracker", rw);
                    const active = isTierActive(tier);
                    return (
                      <div key={rw.url} className={`py-3 flex items-center justify-between transition ${!active ? "opacity-60 bg-slate-950/30 rounded px-2" : ""}`}>
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-medium text-sm text-slate-200">{rw.name}</span>
                            <span className="px-1.5 py-0.2 rounded text-[10px] bg-rose-950 text-rose-300 font-mono uppercase">
                              {rw.type}
                            </span>
                            {renderComplianceBadge(tier, active)}
                          </div>
                          <div className="text-xs text-slate-500 font-mono truncate max-w-md mt-0.5">{rw.url}</div>
                        </div>

                        <div className="flex items-center space-x-3">
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input
                              type="checkbox"
                              checked={rw.enabled}
                              onChange={(e) => handleToggleSource("ransomware_tracker", rw.url, e.target.checked)}
                              className="sr-only peer"
                            />
                            <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600" />
                          </label>
                          <button
                            onClick={() =>
                              setEditModal({
                                visible: true,
                                type: "ransomware_tracker",
                                originalId: rw.url,
                                form: {
                                  name: rw.name,
                                  url: rw.url,
                                  category: "ransomware",
                                  channel: "",
                                  query: "",
                                  type: rw.type || "api",
                                  compliance_tier: rw.compliance_tier || tier,
                                },
                              })
                            }
                            className="p-1 text-slate-500 hover:text-cyan-400 transition"
                            title="Edit Tracker"
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteSource("ransomware_tracker", rw.url)}
                            className="p-1 text-slate-500 hover:text-rose-400 transition"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                  {(!config?.sources?.ransomware_tracker || config.sources.ransomware_tracker.length === 0) && (
                    <div className="py-6 text-center text-xs text-slate-500 font-mono">
                      No ransomware trackers configured. Click "+ Add Tracker" to register one.
                    </div>
                  )}
                </div>
              </div>

              {/* 3. Dark Web Targets (.onion strictly) */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-2">
                    <EyeOff className="w-5 h-5 text-purple-400" />
                    <div>
                      <h3 className="font-bold text-white text-base">Dark Web Hidden Services (.onion only)</h3>
                      <p className="text-[11px] text-slate-400">Direct Tor SOCKS5 crawler reaching .onion leak sites only. Research use only.</p>
                    </div>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-slate-800 text-slate-400 font-mono">
                      {config?.sources?.darkweb_onion?.length ?? 0}
                    </span>
                  </div>
                  <button
                    onClick={() =>
                      setAddModal({
                        visible: true,
                        type: "darkweb_onion",
                        form: { name: "", url: "", channel: "", directive: "", query: "", type: "search", compliance_tier: "darkweb_access", mode: "directive" },
                      })
                    }
                    className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                  >
                    + Add Onion Target
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {config?.sources?.darkweb_onion?.map((dw, dwIdx) => {
                    const tier = getSourceComplianceTier("darkweb_onion", dw);
                    const active = isTierActive(tier);
                    const dwId = dw.name || dw.url;
                    const isSearch = dw.type === "search";
                    return (
                      <div key={`${dw.name}-${dw.url}-${dwIdx}`} className={`py-3 flex items-center justify-between transition ${!active ? "opacity-60 bg-slate-950/30 rounded px-2" : ""}`}>
                        <div className="flex-1 min-w-0 pr-4">
                          <div className="flex items-center space-x-2">
                            <span className="font-medium text-sm text-slate-200">{dw.name}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase ${
                              isSearch
                                ? "bg-cyan-950/80 text-cyan-300 border border-cyan-800/80"
                                : "bg-purple-950 text-purple-300 border border-purple-800/60"
                            }`}>
                              {dw.type || "onion"}
                            </span>
                            {renderComplianceBadge(tier, active)}
                          </div>
                          {isSearch ? (
                            <div className="mt-1 space-y-0.5">
                              {dw.directive && (
                                <div className="text-xs text-slate-300 flex items-start space-x-1.5">
                                  <Sparkles className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                                  <span className="line-clamp-2">{dw.directive}</span>
                                </div>
                              )}
                              {dw.query && (
                                <div className="text-xs text-slate-400 font-mono truncate">
                                  <span className="text-cyan-500 font-semibold">Query:</span> {dw.query}
                                </div>
                              )}
                              <div className="text-[11px] text-slate-500 font-mono truncate">
                                Engine: {dw.url}
                              </div>
                            </div>
                          ) : (
                            <div className="text-xs text-slate-500 font-mono truncate max-w-md mt-0.5">{dw.url}</div>
                          )}
                        </div>

                        <div className="flex items-center space-x-3 shrink-0">
                          <label className="relative inline-flex items-center cursor-pointer">
                            <input
                              type="checkbox"
                              checked={dw.enabled}
                              onChange={(e) => handleToggleSource("darkweb_onion", dwId, e.target.checked)}
                              className="sr-only peer"
                            />
                            <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600" />
                          </label>
                          <button
                            onClick={() =>
                              setEditModal({
                                visible: true,
                                type: "darkweb_onion",
                                originalId: dwId,
                                form: {
                                  name: dw.name,
                                  url: dw.url,
                                  category: "darkweb",
                                  channel: "",
                                  directive: dw.directive || "",
                                  query: dw.query || "",
                                  type: dw.type || "onion",
                                  compliance_tier: dw.compliance_tier || tier,
                                  mode: dw.directive ? "directive" : (dw.query ? "query" : "directive"),
                                },
                              })
                            }
                            className="p-1 text-slate-500 hover:text-cyan-400 transition"
                            title="Edit Target"
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteSource("darkweb_onion", dwId)}
                            className="p-1 text-slate-500 hover:text-rose-400 transition"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                  {(!config?.sources?.darkweb_onion || config.sources.darkweb_onion.length === 0) && (
                    <div className="py-6 text-center text-xs text-slate-500 font-mono">
                      No .onion hidden services configured yet. Click "+ Add Onion Target" to register Tor leak sites.
                    </div>
                  )}
                </div>
              </div>

              {/* 4. Telegram */}
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
                                AI Directive
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 font-mono">
                                Static Query
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
                              Auxiliary Query: {xm.query}
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
                    <h3 className="font-bold text-white text-base">Web Search Threat Hunting (SearXNG / Gemini Grounding)</h3>
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
                        form: {
                          name: "",
                          url: "https://searxng.lab.internal/search",
                          channel: "",
                          directive: "",
                          query: "",
                          type: "searxng",
                          categories: "general,news",
                          engines: "",
                          compliance_tier: "commercial_ready",
                          mode: "directive",
                        },
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
                          <div className="flex items-center space-x-2 mb-1 flex-wrap gap-y-1">
                            {ws.type === "gemini" ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-950 text-indigo-300 border border-indigo-800 flex items-center">
                                <Sparkles className="w-3 h-3 mr-1 text-indigo-400" />
                                Gemini Grounding (4h)
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center">
                                <Globe className="w-3 h-3 mr-1 text-cyan-400" />
                                SearXNG Clearnet
                              </span>
                            )}
                            {isDirective ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center">
                                <Sparkles className="w-3 h-3 mr-1 text-emerald-400" />
                                AI Directive
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 font-mono">
                                Static Query
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
                              Auxiliary Query: {ws.query}
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
                                  url: ws.url || (ws.type !== "gemini" ? "https://searxng.lab.internal/search" : ""),
                                  category: "",
                                  categories: ws.categories || (ws.type !== "gemini" ? "general,news" : ""),
                                  engines: ws.engines || "",
                                  channel: "",
                                  directive: ws.directive || "",
                                  query: ws.query || "",
                                  type: ws.type || "searxng",
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
                  href={withBasePath("/api/config/export?mask_secrets=true", pathname)}
                  download="config.yaml"
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                >
                  Download with Masked Secrets
                </a>
                <a
                  href={withBasePath("/api/config/export?mask_secrets=false", pathname)}
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
                <div className="text-sm font-mono text-emerald-400">{config?.ai?.gemini_model || "gemini-3.5-flash-lite"}</div>
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
                    <div className="text-sm font-semibold text-slate-200">
                      Local LLM Engine (k3s / LiteLLM)
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5 font-mono truncate max-w-xs">
                      {status?.ai?.local_llm?.model || "qwen2.5-3b-instruct"} ({status?.ai?.local_llm?.endpoint || "LiteLLM"})
                    </div>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-semibold flex items-center ${
                      status?.ai?.local_llm?.online
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        : "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                    }`}
                  >
                    <span
                      className={`w-2 h-2 rounded-full mr-1.5 ${
                        status?.ai?.local_llm?.online ? "bg-emerald-400 animate-pulse" : "bg-rose-400"
                      }`}
                    />
                    {status?.ai?.local_llm?.online ? "ONLINE" : "OFFLINE"}
                  </span>
                </div>

                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-semibold text-slate-200">Gemini Cloud AI (Escalation)</div>
                    <div className="text-xs text-slate-400 mt-0.5 font-mono">{status?.ai?.model || "gemini-3.5-flash-lite"}</div>
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
              onClose={() => setActiveTab(isAdmin ? "sources" : "incidents")}
              isHarvesting={harvesting}
              onTriggerHarvest={triggerHarvest}
              onHarvestFinished={handleHarvestFinished}
              fullTabMode={true}
            />
          </div>
        )}

      </main>

      {/* Subtle Footer: Copyright & Non-Commercial / Corporate Usage Disclaimer */}
      <footer className="border-t border-slate-800/70 bg-slate-950/60 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-[11px] text-slate-500 leading-relaxed">
          <div className="space-y-1 max-w-4xl">
            <p className="text-slate-400/90 font-medium">
              {currentLang === "ja"
                ? "【免責事項・商用利用に関するご注意】本ツールおよび公開サイトには商用利用できない収集機能（X / Telegram / ダークウェブ等）が含まれているため、そのまま商用利用することはできません。"
                : "Notice & Disclaimer: This tool and public site include non-commercial collection features (e.g., X, Telegram, Dark Web) and cannot be used for commercial purposes as-is."}
            </p>
            <p>
              {currentLang === "ja"
                ? "法人・商用環境でご利用になる場合は、本リポジトリを Fork の上、X・Telegram・ダークウェブ等の収集モジュールを商用利用可能な公式 API 等へ変換してご利用ください。掲載情報の正確性・完全性について一切の保証を行いません。"
                : "For corporate or commercial use, please fork this repository and replace X, Telegram, and Dark Web collectors with commercially licensed APIs. Provided \"AS IS\" without warranty of any kind."}
            </p>
          </div>
          <div className="flex flex-col sm:items-end shrink-0 text-slate-500 font-mono text-[11px] space-y-0.5">
            <a
              href="https://github.com/al17091/threat_harvester"
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-400 hover:text-cyan-400 transition"
            >
              GitHub: al17091/threat_harvester
            </a>
            <span>&copy; {new Date().getFullYear()} Threat Harvester. MIT License (Code).</span>
          </div>
        </div>
      </footer>

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
                        : selectedIncident.severity === "Low"
                        ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                        : selectedIncident.severity === "Info"
                        ? "bg-slate-800 text-slate-300 border border-slate-700"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {selectedIncident.severity || "Unknown"}
                  </span>
                  {selectedIncident.japan_relevance === "Direct" && (
                    <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      🇯🇵 Japan Direct
                    </span>
                  )}
                  <span className="text-xs text-slate-400 font-mono">{selectedIncident.source_name}</span>
                </div>
                <h2 className="text-lg font-bold text-white leading-snug">
                  {getCleanDisplayTitle(selectedIncident, currentLang)}
                </h2>
                <div className="flex flex-wrap items-center gap-4 mt-2.5 text-xs text-slate-400 font-mono">
                  <div>
                    <span className="text-slate-500 mr-1.5 uppercase font-sans">
                      {currentLang === "ja" ? "情報元公開日時:" : "Source Published:"}
                    </span>
                    <span className="text-cyan-300 font-medium">
                      {selectedIncident.published_at ? formatDate(selectedIncident.published_at) : (currentLang === "ja" ? "不明 / リアルタイム" : "Unknown / Realtime")}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 mr-1.5 uppercase font-sans">
                      {currentLang === "ja" ? "初検知・収集日時:" : "Harvest Ingested:"}
                    </span>
                    <span className="text-slate-300">{formatDate(selectedIncident.harvested_at)}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                {isAdmin && (
                  <button
                    onClick={() => startEditLabels()}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 transition-all shadow-sm"
                    title={currentLang === "ja" ? "自動判定ラベルを管理者が修正" : "Administrator Label Override"}
                  >
                    <Pencil className="w-3.5 h-3.5" />
                    <span>{currentLang === "ja" ? "ラベル修正" : "Edit Labels"}</span>
                  </button>
                )}
                <button
                  onClick={() => {
                    setSelectedIncident(null);
                    setEditingLabels(false);
                  }}
                  className="text-slate-400 hover:text-white p-1 rounded-lg"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4 overflow-y-auto text-sm">
              {/* ADMIN LABEL EDITOR PANEL (Admin Only) */}
              {isAdmin && editingLabels && (
                <div className="p-4 rounded-xl bg-gradient-to-b from-amber-950/40 to-slate-950 border border-amber-500/40 shadow-xl space-y-4">
                  <div className="flex items-center justify-between border-b border-amber-500/20 pb-2.5">
                    <div className="flex items-center space-x-2">
                      <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                      <h4 className="text-xs font-bold text-amber-300 uppercase tracking-wider">
                        {currentLang === "ja" ? "管理者ラベル修正パネル" : "Administrator Label Override"}
                      </h4>
                    </div>
                    <span className="text-[11px] text-amber-400/80 font-mono">
                      {selectedIncident.id}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                    {/* Severity */}
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {currentLang === "ja" ? "重要度 (Severity)" : "Severity"}
                      </label>
                      <select
                        value={editSeverity}
                        onChange={(e) => setEditSeverity(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-amber-400 font-mono"
                      >
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                        <option value="Info">Info</option>
                        <option value="Unknown">Unknown</option>
                      </select>
                    </div>

                    {/* Japan Relevance */}
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {currentLang === "ja" ? "日本関連性 (Japan Relevance)" : "Japan Relevance"}
                      </label>
                      <select
                        value={editJapanRel}
                        onChange={(e) => setEditJapanRel(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-amber-400 font-mono"
                      >
                        <option value="Direct">Direct (日本直接対象)</option>
                        <option value="Indirect">Indirect (間接影響)</option>
                        <option value="None">None (日本無関係)</option>
                        <option value="Unknown">Unknown (不明)</option>
                      </select>
                    </div>

                    {/* Attack Type */}
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {currentLang === "ja" ? "攻撃種別 (Attack Type)" : "Attack Type"}
                      </label>
                      <input
                        type="text"
                        value={editAttackType}
                        onChange={(e) => setEditAttackType(e.target.value)}
                        placeholder="Ransomware, Vulnerability, Data Breach..."
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-amber-400 font-mono"
                      />
                    </div>

                    {/* Target / Victim Org */}
                    <div>
                      <label className="block text-xs font-medium text-slate-400 mb-1">
                        {currentLang === "ja" ? "被害組織 (Victim Organization)" : "Victim Organization"}
                      </label>
                      <input
                        type="text"
                        value={editVictimOrg}
                        onChange={(e) => setEditVictimOrg(e.target.value)}
                        placeholder="Organization name..."
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-amber-400 font-mono"
                      />
                    </div>
                  </div>

                  {/* Threat Actors */}
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <label className="text-xs font-medium text-slate-400">
                        {currentLang === "ja" ? "脅威アクター・攻撃者 (Threat Actors)" : "Threat Actors / Groups"}
                      </label>
                      {editActors.length > 0 && (
                        <button
                          type="button"
                          onClick={() => setEditActors([])}
                          className="text-[11px] text-rose-400 hover:text-rose-300 transition-colors"
                        >
                          {currentLang === "ja" ? "アクター全消去" : "Clear All Actors"}
                        </button>
                      )}
                    </div>

                    {/* Tag list */}
                    <div className="flex flex-wrap gap-1.5 min-h-[36px] p-2 bg-slate-900 border border-slate-800 rounded-lg mb-2">
                      {editActors.length === 0 ? (
                        <span className="text-xs text-slate-600 italic">
                          {currentLang === "ja" ? "アクター未指定 (タグなし)" : "No threat actors set (None identified)"}
                        </span>
                      ) : (
                        editActors.map((actor, idx) => (
                          <span
                            key={idx}
                            className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded text-xs bg-purple-950 text-purple-300 border border-purple-800 font-mono"
                          >
                            <span>{actor}</span>
                            <button
                              type="button"
                              onClick={() => handleRemoveActor(idx)}
                              className="text-purple-400 hover:text-rose-400 p-0.5 rounded transition-colors"
                              title={currentLang === "ja" ? "このアクターを削除" : "Remove actor"}
                            >
                              <X className="w-3 h-3" />
                            </button>
                          </span>
                        ))
                      )}
                    </div>

                    {/* Add new actor input */}
                    <div className="flex items-center space-x-2">
                      <input
                        type="text"
                        value={newActorInput}
                        onChange={(e) => setNewActorInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            handleAddActor();
                          }
                        }}
                        placeholder={currentLang === "ja" ? "アクター名を入力（例: 银狐, APT41, Qilin）" : "Type actor name and press Add..."}
                        className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-amber-400 font-mono"
                      />
                      <button
                        type="button"
                        onClick={handleAddActor}
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                      >
                        {currentLang === "ja" ? "追加" : "Add"}
                      </button>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-end space-x-2.5 pt-2 border-t border-slate-800">
                    <button
                      type="button"
                      onClick={() => setEditingLabels(false)}
                      disabled={savingLabels}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition-colors"
                    >
                      {currentLang === "ja" ? "キャンセル" : "Cancel"}
                    </button>
                    <button
                      type="button"
                      onClick={handleSaveLabels}
                      disabled={savingLabels}
                      className="inline-flex items-center space-x-1.5 px-4 py-1.5 rounded-lg text-xs font-bold bg-amber-500 hover:bg-amber-400 text-slate-950 transition-colors shadow-sm disabled:opacity-50"
                    >
                      {savingLabels ? (
                        <>
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          <span>{currentLang === "ja" ? "保存中..." : "Saving..."}</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle className="w-3.5 h-3.5" />
                          <span>{currentLang === "ja" ? "修正を保存" : "Save Changes"}</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              )}

              <div>
                <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-1">
                  {currentLang === "ja" ? "概要" : "Overview"}
                </h4>
                <p className="text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800 leading-relaxed">
                  {getCleanDisplaySummary(selectedIncident, currentLang)}
                </p>
              </div>

              {/* RAW SOURCE ACCORDION IN MODAL */}
              {(() => {
                const rawText = getRawContentText(selectedIncident);
                return (
                  <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950/70">
                    <button
                      type="button"
                      onClick={() => setShowRawInModal(!showRawInModal)}
                      className="w-full px-3 py-2 flex items-center justify-between text-xs font-semibold text-slate-300 hover:text-white bg-slate-900/80 hover:bg-slate-800/80 transition"
                    >
                      <div className="flex items-center space-x-2">
                        <FileCode className="w-4 h-4 text-cyan-400" />
                        <span>{currentLang === "ja" ? "原文ソースコンテンツ (Raw Source)" : "Raw Source Content"}</span>
                        {rawText ? (
                          <span className="text-[10px] text-slate-500 font-mono">
                            ({rawText.length} {currentLang === "ja" ? "文字" : "chars"})
                          </span>
                        ) : null}
                      </div>
                      <div className="flex items-center space-x-1.5 text-slate-400">
                        <span className="text-[10px]">
                          {showRawInModal ? (currentLang === "ja" ? "非表示" : "Hide") : (currentLang === "ja" ? "表示" : "Show")}
                        </span>
                        <ChevronDown
                          className={`w-3.5 h-3.5 transition-transform duration-200 ${
                            showRawInModal ? "rotate-180" : ""
                          }`}
                        />
                      </div>
                    </button>
                    {showRawInModal && (
                      <div className="p-3 border-t border-slate-800 bg-slate-950 font-mono text-xs text-slate-300 whitespace-pre-wrap break-words max-h-80 overflow-y-auto select-text leading-relaxed">
                        {rawText || (currentLang === "ja" ? "(原文ソースまたはスニペットは記録されていません)" : "(No raw source content or snippet recorded)")}
                      </div>
                    )}
                  </div>
                );
              })()}

              {(selectedIncident.enriched_parsed?.impact_analysis || selectedIncident.impact_analysis || selectedIncident.enriched_parsed?.impact_analysis_ja || selectedIncident.impact_analysis_ja) && (
                <div>
                  <h4 className="text-xs font-semibold text-amber-400 uppercase tracking-wider mb-1">
                    {currentLang === "ja" ? "影響評価・対象スコープ" : "Impact Assessment & Scope"}
                  </h4>
                  <p className="text-slate-300 bg-slate-950 p-3 rounded-lg border border-slate-800 leading-relaxed">
                    {currentLang === "ja"
                      ? (selectedIncident.impact_analysis_ja || selectedIncident.enriched_parsed?.impact_analysis_ja || selectedIncident.impact_analysis || selectedIncident.enriched_parsed?.impact_analysis)
                      : (selectedIncident.impact_analysis || selectedIncident.enriched_parsed?.impact_analysis || selectedIncident.impact_analysis_ja || selectedIncident.enriched_parsed?.impact_analysis_ja)}
                  </p>
                </div>
              )}

              {((selectedIncident.enriched_parsed?.recommended_actions && selectedIncident.enriched_parsed.recommended_actions.length > 0) ||
                (selectedIncident.enriched_parsed?.recommended_actions_ja && selectedIncident.enriched_parsed.recommended_actions_ja.length > 0)) && (
                  <div>
                    <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-1">
                      {currentLang === "ja" ? "推奨アクション・緩和策" : "Recommended Mitigations & Action Items"}
                    </h4>
                    <ul className="list-disc list-inside bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1 text-slate-300">
                      {(currentLang === "ja" && selectedIncident.enriched_parsed?.recommended_actions_ja && selectedIncident.enriched_parsed.recommended_actions_ja.length > 0
                        ? selectedIncident.enriched_parsed.recommended_actions_ja
                        : (selectedIncident.enriched_parsed?.recommended_actions || selectedIncident.enriched_parsed?.recommended_actions_ja || [])).map((action, idx) => (
                        <li key={idx}>{action}</li>
                      ))}
                    </ul>
                  </div>
                )}

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 font-semibold block mb-1">
                    {currentLang === "ja" ? "対象組織 / 被害企業" : "Target Sectors / Victims"}
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {selectedIncident.enriched_parsed?.victim_orgs?.map((v) => (
                      <span key={v} className="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 font-mono">
                        {v}
                      </span>
                    )) ?? <span className="text-xs text-slate-600">{currentLang === "ja" ? "特定なし" : "None specified"}</span>}
                  </div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 font-semibold block mb-1">
                    {currentLang === "ja" ? "脅威アクター / 攻撃グループ" : "Threat Actors / Groups"}
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {(() => {
                      const validModalActors = filterValidThreatActors(
                        selectedIncident.enriched_parsed?.threat_actors || selectedIncident.threat_actors
                      );
                      if (validModalActors.length === 0) {
                        return <span className="text-xs text-slate-600">{currentLang === "ja" ? "特定なし" : "None identified"}</span>;
                      }
                      const reasonsMap =
                        currentLang === "ja"
                          ? selectedIncident.threat_actor_reasons_ja ||
                            selectedIncident.enriched_parsed?.threat_actor_reasons_ja ||
                            selectedIncident.threat_actor_reasons ||
                            selectedIncident.enriched_parsed?.threat_actor_reasons
                          : selectedIncident.threat_actor_reasons ||
                            selectedIncident.enriched_parsed?.threat_actor_reasons;
                      return validModalActors.map((a) => (
                        <span
                          key={a}
                          title={reasonsMap?.[a] || undefined}
                          className="px-2 py-0.5 rounded text-xs bg-purple-950 text-purple-300 border border-purple-800 font-mono"
                        >
                          {a}
                        </span>
                      ));
                    })()}
                  </div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 font-semibold block mb-1">
                    {currentLang === "ja" ? "脆弱性 (CVE)" : "Vulnerabilities (CVE)"}
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {selectedIncident.cves && selectedIncident.cves.length > 0 ? (
                      selectedIncident.cves.map((cve) => (
                        <span
                          key={cve}
                          className="px-2 py-0.5 rounded text-xs bg-amber-950/70 text-amber-300 border border-amber-800/80 font-mono font-medium"
                        >
                          {cve}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-600">{currentLang === "ja" ? "特定なし" : "None specified"}</span>
                    )}
                  </div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-xs text-slate-500 font-semibold block mb-1">
                    {currentLang === "ja" ? "影響製品" : "Affected Product"}
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {selectedIncident.affected_product || selectedIncident.enriched_parsed?.affected_products?.[0] ? (
                      <span className="px-2 py-0.5 rounded text-xs bg-emerald-950/70 text-emerald-300 border border-emerald-800/80 font-mono">
                        {selectedIncident.affected_product || selectedIncident.enriched_parsed?.affected_products?.[0]}
                      </span>
                    ) : (
                      <span className="text-xs text-slate-600">{currentLang === "ja" ? "特定なし" : "None specified"}</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Threat Actor Attribution Basis / Evidence */}
              {(() => {
                const validModalActors = filterValidThreatActors(
                  selectedIncident.enriched_parsed?.threat_actors || selectedIncident.threat_actors
                );
                if (validModalActors.length === 0) return null;

                const resolveReason = (actor: string): string => {
                  const mapJa =
                    selectedIncident.threat_actor_reasons_ja ||
                    selectedIncident.enriched_parsed?.threat_actor_reasons_ja ||
                    {};
                  const mapEn =
                    selectedIncident.threat_actor_reasons ||
                    selectedIncident.enriched_parsed?.threat_actor_reasons ||
                    {};
                  const primaryMap = currentLang === "ja" ? mapJa : mapEn;
                  const fallbackMap = currentLang === "ja" ? mapEn : mapJa;

                  for (const [k, v] of Object.entries(primaryMap)) {
                    if (k.toLowerCase() === actor.toLowerCase() && v) return v;
                  }
                  for (const [k, v] of Object.entries(fallbackMap)) {
                    if (k.toLowerCase() === actor.toLowerCase() && v) return v;
                  }

                  // Client-side snippet fallback if reason map isn't populated yet
                  const extractSnip = (txt?: string | null): string | null => {
                    if (!txt) return null;
                    const idx = txt.toLowerCase().indexOf(actor.toLowerCase());
                    if (idx < 0) return null;
                    const start = Math.max(0, idx - 50);
                    const end = Math.min(txt.length, idx + actor.length + 80);
                    const s = txt.slice(start, end).replace(/\s+/g, " ").trim();
                    return `${start > 0 ? "..." : ""}${s}${end < txt.length ? "..." : ""}`;
                  };

                  const srcLabel =
                    selectedIncident.sources_detail?.[0]?.source_name ||
                    selectedIncident.source_name ||
                    "Report";
                  const titleSnip = extractSnip(selectedIncident.title) || extractSnip(selectedIncident.title_ja);
                  if (titleSnip) {
                    return currentLang === "ja"
                      ? `情報源「${srcLabel}」のタイトルに記載: 「${titleSnip}」`
                      : `Mentioned in [${srcLabel}] title: "${titleSnip}"`;
                  }
                  const rawSnip = extractSnip(selectedIncident.raw_content);
                  if (rawSnip) {
                    return currentLang === "ja"
                      ? `情報源「${srcLabel}」の本文に記載: 「${rawSnip}」`
                      : `Mentioned in [${srcLabel}] article body: "${rawSnip}"`;
                  }
                  const sumSnip = extractSnip(selectedIncident.summary) || extractSnip(selectedIncident.summary_ja);
                  if (sumSnip) {
                    return currentLang === "ja"
                      ? `AI要約・レポート概要に記載: 「${sumSnip}」`
                      : `Mentioned in intelligence summary: "${sumSnip}"`;
                  }
                  return currentLang === "ja"
                    ? `情報源「${srcLabel}」のメタデータまたはAI脅威分析により特定`
                    : `Attributed via [${srcLabel}] feed metadata or AI threat correlation`;
                };

                return (
                  <div className="bg-purple-950/20 border border-purple-900/50 rounded-lg p-3.5 space-y-2">
                    <h4 className="text-xs font-semibold text-purple-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Skull className="w-3.5 h-3.5 text-purple-400" />
                      {currentLang === "ja"
                        ? "脅威アクター特定の根拠・記載箇所"
                        : "Threat Actor Attribution & Source Evidence"}
                    </h4>
                    <div className="space-y-1.5">
                      {validModalActors.map((actor) => (
                        <div
                          key={actor}
                          className="flex flex-col sm:flex-row sm:items-baseline gap-1.5 sm:gap-2.5 text-xs bg-slate-950/70 border border-purple-900/30 rounded px-2.5 py-2"
                        >
                          <span className="px-2 py-0.5 rounded text-[11px] bg-purple-950 text-purple-300 border border-purple-800 font-mono font-semibold shrink-0 self-start">
                            {actor}
                          </span>
                          <span className="text-slate-300 leading-relaxed break-words">
                            {resolveReason(actor)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })()}

              {/* Preserved Sources & Child Reports Timeline */}
              <div className="pt-2 border-t border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider flex items-center">
                    <Radio className="w-3.5 h-3.5 mr-1.5" />
                    {currentLang === "ja" ? "情報ソース・参照元一覧" : "Reference Sources & URLs"} ({selectedIncident.sources_detail?.length || selectedIncident.source_urls?.length || (selectedIncident.url ? 1 : 0)})
                  </h4>
                  {selectedIncident.id.startsWith("incident--") && (
                    <span className="text-[10px] font-mono text-slate-500 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      {selectedIncident.id}
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
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-medium border ${
                              src.source_type === "ransomware_tracker"
                                ? "bg-rose-950/80 text-rose-300 border-rose-800/80"
                                : src.source_type === "darkweb_onion"
                                ? "bg-purple-950/80 text-purple-300 border-purple-800/80"
                                : src.source_type === "vendor_rss"
                                ? "bg-amber-950/80 text-amber-300 border-amber-800/80"
                                : "bg-slate-800 text-cyan-300 border-slate-700"
                            }`}>
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
                              {currentLang === "ja" ? "一次情報リンク" : "Source Link"}
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
                          {currentLang === "ja" ? "開く" : "Open"}
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
                      {currentLang === "ja" ? "一次情報参照URLを開く" : "Open Source Reference URL"} ({selectedIncident.url})
                    </a>
                  </div>
                ) : (
                  <span className="text-xs text-slate-500">
                    {currentLang === "ja" ? "外部ソースURLは記録されていません。" : "No external source URL recorded."}
                  </span>
                )}

                {/* Attached Child Reports Timeline */}
                {selectedIncident.child_items && selectedIncident.child_items.length > 1 && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <h5 className="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-2">
                      {currentLang === "ja" ? "関連レポート時系列" : "Child Reports Timeline"} ({selectedIncident.child_items.length})
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
                {currentLang === "ja" ? "閉じる" : "Close"}
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

              {addModal.type === "ransomware_tracker" && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Tracker / Aggregator Name</label>
                  <input
                    type="text"
                    value={addModal.form.name}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, name: e.target.value } })}
                    placeholder="e.g. Ransomlook Tracker"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">
                    Endpoint URL (API endpoint or RSS feed)
                  </label>
                  <input
                    type="text"
                    value={addModal.form.url}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, url: e.target.value } })}
                    placeholder="https://www.ransomlook.io/api/recent"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">Data Format</label>
                  <select
                    value={addModal.form.type}
                    onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, type: e.target.value } })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  >
                    <option value="api">api (JSON)</option>
                    <option value="rss">rss (XML Feed)</option>
                  </select>
                </div>
              )}

              {addModal.type === "darkweb_onion" && (
                <div className="space-y-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Format / Discovery Type</label>
                    <select
                      value={addModal.form.type}
                      onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, type: e.target.value } })}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                    >
                      <option value="search">Tor Search Engine (Ahmia / SearXNG)</option>
                      <option value="onion">onion (Tor site HTML)</option>
                      <option value="html">html (Tor HTML Scraping)</option>
                      <option value="rss">rss (Tor RSS Feed)</option>
                      <option value="api">api (Tor JSON API)</option>
                    </select>
                  </div>

                  {addModal.form.type === "search" ? (
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
                          <span>AI Directive (Natural Language)</span>
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
                          <span>Static Query</span>
                        </button>
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-400 mb-1">
                          Theme / Source Name (Optional)
                        </label>
                        <input
                          type="text"
                          value={addModal.form.name}
                          onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, name: e.target.value } })}
                          placeholder="e.g. Japan Ransomware & Leak Sites"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600"
                        />
                      </div>

                      {addModal.form.mode === "directive" ? (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <label className="text-xs font-semibold text-slate-400">
                              AI Directive & Threat Hunting Strategy (Sentence)
                            </label>
                            <span className="text-[11px] text-cyan-400 font-mono">Dark Web Hunting</span>
                          </div>
                          <textarea
                            rows={3}
                            value={addModal.form.directive || ""}
                            onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, directive: e.target.value } })}
                            placeholder="e.g. Ransomware leak sites targeting organizations, extortion posts, and database breaches"
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed"
                          />

                          <div className="mt-2 flex items-center justify-between">
                            <button
                              type="button"
                              onClick={() => handlePreviewAIQueries(addModal.form.directive || "", "darkweb_search")}
                              disabled={generatingQueries || !addModal.form.directive?.trim()}
                              className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs border border-slate-700 transition disabled:opacity-50"
                            >
                              {generatingQueries ? (
                                <>
                                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                  <span>Generating AI Keywords...</span>
                                </>
                              ) : (
                                <>
                                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                                  <span>Test Generate Keywords</span>
                                </>
                              )}
                            </button>
                            <span className="text-[11px] text-slate-500">
                              Also automatically generated during harvest cycles
                            </span>
                          </div>

                          {previewQueries.length > 0 && (
                            <div className="mt-2.5 p-2.5 rounded-lg bg-slate-950 border border-cyan-900/60 space-y-1.5">
                              <div className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">
                                AI-generated Tor search queries ({previewQueries.length}):
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
                            Tor Search Keywords (Space-separated)
                          </label>
                          <input
                            type="text"
                            value={addModal.form.query || ""}
                            onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, query: e.target.value } })}
                            placeholder="e.g. japan ransomware leak breach"
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600 font-mono"
                          />
                        </div>
                      )}

                      <div>
                        <label className="block text-xs font-semibold text-slate-400 mb-1">
                          Tor Search Engine Onion URL (Default: official Ahmia onion)
                        </label>
                        <input
                          type="text"
                          value={addModal.form.url}
                          onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, url: e.target.value } })}
                          placeholder="http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600 font-mono text-xs"
                        />
                      </div>
                    </div>
                  ) : (
                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">Hidden Service Name</label>
                      <input
                        type="text"
                        value={addModal.form.name}
                        onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, name: e.target.value } })}
                        placeholder="e.g. LockBit 3.0 Leak Site"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                      />
                      <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">
                        Tor Onion URL (.onion strictly required)
                      </label>
                      <input
                        type="text"
                        value={addModal.form.url}
                        onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, url: e.target.value } })}
                        placeholder="http://exampleleakdomain2345.onion"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                      />
                    </div>
                  )}
                </div>
              )}

              {(addModal.type === "x_monitor" || addModal.type === "web_search") && (
                <div className="space-y-3">
                  {addModal.type === "web_search" && (
                    <div className="space-y-2">
                      <label className="block text-xs font-semibold text-slate-400">
                        Search Provider
                      </label>
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          onClick={() =>
                            setAddModal({
                              ...addModal,
                              form: {
                                ...addModal.form,
                                type: "searxng",
                                url: addModal.form.url || "https://searxng.lab.internal/search",
                                categories: addModal.form.categories || "general,news",
                                compliance_tier: "commercial_ready",
                              },
                            })
                          }
                          className={`py-2 px-3 rounded-lg border text-xs text-left transition ${
                            addModal.form.type !== "gemini"
                              ? "bg-cyan-950/60 border-cyan-500 text-cyan-200"
                              : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                          }`}
                        >
                          <div className="font-semibold flex items-center">
                            <Globe className="w-3.5 h-3.5 mr-1.5 text-cyan-400" />
                            SearXNG Clearnet
                          </div>
                          <div className="text-[10px] text-slate-400 mt-0.5">
                            Zero AI cost, meta search
                          </div>
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            setAddModal({
                              ...addModal,
                              form: {
                                ...addModal.form,
                                type: "gemini",
                                compliance_tier: "commercial_via_official_api",
                              },
                            })
                          }
                          className={`py-2 px-3 rounded-lg border text-xs text-left transition ${
                            addModal.form.type === "gemini"
                              ? "bg-indigo-950/60 border-indigo-500 text-indigo-200"
                              : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                          }`}
                        >
                          <div className="font-semibold flex items-center">
                            <Sparkles className="w-3.5 h-3.5 mr-1.5 text-indigo-400" />
                            Gemini Grounding
                          </div>
                          <div className="text-[10px] text-slate-400 mt-0.5">
                            Google Search (4h throttled)
                          </div>
                        </button>
                      </div>

                      {addModal.form.type !== "gemini" && (
                        <div className="space-y-2 pt-1">
                          <div>
                            <label className="block text-[11px] font-semibold text-slate-400 mb-1">
                              SearXNG API Endpoint
                            </label>
                            <input
                              type="text"
                              value={addModal.form.url}
                              onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, url: e.target.value } })}
                              placeholder="https://searxng.lab.internal/search"
                              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-600"
                            />
                          </div>
                          <div className="grid grid-cols-2 gap-2">
                            <div>
                              <label className="block text-[11px] font-semibold text-slate-400 mb-1">
                                Categories
                              </label>
                              <input
                                type="text"
                                value={addModal.form.categories || ""}
                                onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, categories: e.target.value } })}
                                placeholder="general,news"
                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-600"
                              />
                            </div>
                            <div>
                              <label className="block text-[11px] font-semibold text-slate-400 mb-1">
                                Engines (Optional)
                              </label>
                              <input
                                type="text"
                                value={addModal.form.engines || ""}
                                onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, engines: e.target.value } })}
                                placeholder="google,bing,yahoo"
                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-600"
                              />
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

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
                      <span>AI Directive (Natural Language)</span>
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
                      <span>Static Query</span>
                    </button>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">
                      Theme / Directive Name (Optional)
                    </label>
                    <input
                      type="text"
                      value={addModal.form.name}
                      onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, name: e.target.value } })}
                      placeholder="e.g. Critical Infrastructure & Supply Chain"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600"
                    />
                  </div>

                  {addModal.form.mode === "directive" ? (
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-xs font-semibold text-slate-400">
                          AI Directive & Hunting Scope (Sentence)
                        </label>
                        <span className="text-[11px] text-cyan-400 font-mono">Dynamic Hunting</span>
                      </div>
                      <textarea
                        rows={3}
                        value={addModal.form.directive || ""}
                        onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, directive: e.target.value } })}
                        placeholder="e.g. Focus on ransomware incidents, extortion, and double extortion impacting Japanese healthcare or pharma organizations"
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
                              <span>Generating AI Queries...</span>
                            </>
                          ) : (
                            <>
                              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                              <span>Test Generate Queries</span>
                            </>
                          )}
                        </button>
                        <span className="text-[11px] text-slate-500">
                          Also automatically generated during harvest cycles
                        </span>
                      </div>

                      {previewQueries.length > 0 && (
                        <div className="mt-2.5 p-2.5 rounded-lg bg-slate-950 border border-cyan-900/60 space-y-1.5">
                          <div className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">
                            AI-generated query examples ({previewQueries.length}):
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
                        Static Search Query
                      </label>
                      <input
                        type="text"
                        value={addModal.form.query}
                        onChange={(e) => setAddModal({ ...addModal, form: { ...addModal.form, query: e.target.value } })}
                        placeholder="e.g. (from:piyokango OR from:jpcert) site:x.com"
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

              {editModal.type === "ransomware_tracker" && (
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">Tracker / Aggregator Name</label>
                  <input
                    type="text"
                    value={editModal.form.name}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, name: e.target.value } })}
                    placeholder="e.g. Ransomlook Tracker"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">
                    Endpoint URL (API endpoint or RSS feed)
                  </label>
                  <input
                    type="text"
                    value={editModal.form.url}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, url: e.target.value } })}
                    placeholder="https://www.ransomlook.io/api/recent"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  />
                  <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">Data Format</label>
                  <select
                    value={editModal.form.type}
                    onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, type: e.target.value } })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                  >
                    <option value="api">api (JSON)</option>
                    <option value="rss">rss (XML Feed)</option>
                  </select>
                </div>
              )}

              {editModal.type === "darkweb_onion" && (
                <div className="space-y-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">Format / Discovery Type</label>
                    <select
                      value={editModal.form.type}
                      onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, type: e.target.value } })}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                    >
                      <option value="search">Tor Search Engine (Ahmia / SearXNG)</option>
                      <option value="onion">onion (Tor site HTML)</option>
                      <option value="html">html (Tor HTML Scraping)</option>
                      <option value="rss">rss (Tor RSS Feed)</option>
                      <option value="api">api (Tor JSON API)</option>
                    </select>
                  </div>

                  {editModal.form.type === "search" ? (
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
                          <span>AI Directive (Natural Language)</span>
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
                          <span>Static Query</span>
                        </button>
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-400 mb-1">
                          Theme / Source Name (Optional)
                        </label>
                        <input
                          type="text"
                          value={editModal.form.name}
                          onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, name: e.target.value } })}
                          placeholder="e.g. Japan Ransomware & Leak Sites"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600"
                        />
                      </div>

                      {editModal.form.mode === "directive" ? (
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <label className="text-xs font-semibold text-slate-400">
                              AI Directive & Threat Hunting Strategy (Sentence)
                            </label>
                            <span className="text-[11px] text-cyan-400 font-mono">Dark Web Hunting</span>
                          </div>
                          <textarea
                            rows={3}
                            value={editModal.form.directive || ""}
                            onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, directive: e.target.value } })}
                            placeholder="e.g. Ransomware leak sites targeting organizations, extortion posts, and database breaches"
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed"
                          />

                          <div className="mt-2 flex items-center justify-between">
                            <button
                              type="button"
                              onClick={() => handlePreviewAIQueries(editModal.form.directive || "", "darkweb_search")}
                              disabled={generatingQueries || !editModal.form.directive?.trim()}
                              className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs border border-slate-700 transition disabled:opacity-50"
                            >
                              {generatingQueries ? (
                                <>
                                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                  <span>Generating AI Keywords...</span>
                                </>
                              ) : (
                                <>
                                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                                  <span>Test Generate Keywords</span>
                                </>
                              )}
                            </button>
                            <span className="text-[11px] text-slate-500">
                              Also automatically generated during harvest cycles
                            </span>
                          </div>

                          {previewQueries.length > 0 && (
                            <div className="mt-2.5 p-2.5 rounded-lg bg-slate-950 border border-cyan-900/60 space-y-1.5">
                              <div className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">
                                AI-generated Tor search queries ({previewQueries.length}):
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
                            Tor Search Keywords (Space-separated)
                          </label>
                          <input
                            type="text"
                            value={editModal.form.query || ""}
                            onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, query: e.target.value } })}
                            placeholder="e.g. japan ransomware leak breach"
                            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600 font-mono"
                          />
                        </div>
                      )}

                      <div>
                        <label className="block text-xs font-semibold text-slate-400 mb-1">
                          Tor Search Engine Onion URL (Default: official Ahmia onion)
                        </label>
                        <input
                          type="text"
                          value={editModal.form.url}
                          onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, url: e.target.value } })}
                          placeholder="http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
                          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600 font-mono text-xs"
                        />
                      </div>
                    </div>
                  ) : (
                    <div>
                      <label className="block text-xs font-semibold text-slate-400 mb-1">Hidden Service Name</label>
                      <input
                        type="text"
                        value={editModal.form.name}
                        onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, name: e.target.value } })}
                        placeholder="e.g. LockBit 3.0 Leak Site"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                      />
                      <label className="block text-xs font-semibold text-slate-400 mt-3 mb-1">
                        Tor Onion URL (.onion strictly required)
                      </label>
                      <input
                        type="text"
                        value={editModal.form.url}
                        onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, url: e.target.value } })}
                        placeholder="http://exampleleakdomain2345.onion"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100"
                      />
                    </div>
                  )}
                </div>
              )}

              {(editModal.type === "x_monitor" || editModal.type === "web_search") && (
                <div className="space-y-3">
                  {editModal.type === "web_search" && (
                    <div className="space-y-2">
                      <label className="block text-xs font-semibold text-slate-400">
                        Search Provider
                      </label>
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          onClick={() =>
                            setEditModal({
                              ...editModal,
                              form: {
                                ...editModal.form,
                                type: "searxng",
                                url: editModal.form.url || "https://searxng.lab.internal/search",
                                categories: editModal.form.categories || "general,news",
                                compliance_tier: "commercial_ready",
                              },
                            })
                          }
                          className={`py-2 px-3 rounded-lg border text-xs text-left transition ${
                            editModal.form.type !== "gemini"
                              ? "bg-cyan-950/60 border-cyan-500 text-cyan-200"
                              : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                          }`}
                        >
                          <div className="font-semibold flex items-center">
                            <Globe className="w-3.5 h-3.5 mr-1.5 text-cyan-400" />
                            SearXNG Clearnet
                          </div>
                          <div className="text-[10px] text-slate-400 mt-0.5">
                            Zero AI cost, meta search
                          </div>
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            setEditModal({
                              ...editModal,
                              form: {
                                ...editModal.form,
                                type: "gemini",
                                compliance_tier: "commercial_via_official_api",
                              },
                            })
                          }
                          className={`py-2 px-3 rounded-lg border text-xs text-left transition ${
                            editModal.form.type === "gemini"
                              ? "bg-indigo-950/60 border-indigo-500 text-indigo-200"
                              : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                          }`}
                        >
                          <div className="font-semibold flex items-center">
                            <Sparkles className="w-3.5 h-3.5 mr-1.5 text-indigo-400" />
                            Gemini Grounding
                          </div>
                          <div className="text-[10px] text-slate-400 mt-0.5">
                            Google Search (4h throttled)
                          </div>
                        </button>
                      </div>

                      {editModal.form.type !== "gemini" && (
                        <div className="space-y-2 pt-1">
                          <div>
                            <label className="block text-[11px] font-semibold text-slate-400 mb-1">
                              SearXNG API Endpoint
                            </label>
                            <input
                              type="text"
                              value={editModal.form.url}
                              onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, url: e.target.value } })}
                              placeholder="https://searxng.lab.internal/search"
                              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-600"
                            />
                          </div>
                          <div className="grid grid-cols-2 gap-2">
                            <div>
                              <label className="block text-[11px] font-semibold text-slate-400 mb-1">
                                Categories
                              </label>
                              <input
                                type="text"
                                value={editModal.form.categories || ""}
                                onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, categories: e.target.value } })}
                                placeholder="general,news"
                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-600"
                              />
                            </div>
                            <div>
                              <label className="block text-[11px] font-semibold text-slate-400 mb-1">
                                Engines (Optional)
                              </label>
                              <input
                                type="text"
                                value={editModal.form.engines || ""}
                                onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, engines: e.target.value } })}
                                placeholder="google,bing,yahoo"
                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-100 placeholder-slate-600"
                              />
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

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
                      <span>AI Directive (Natural Language)</span>
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
                      <span>Static Query</span>
                    </button>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-400 mb-1">
                      Theme / Directive Name (Optional)
                    </label>
                    <input
                      type="text"
                      value={editModal.form.name}
                      onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, name: e.target.value } })}
                      placeholder="e.g. Critical Infrastructure & Supply Chain"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-600"
                    />
                  </div>

                  {editModal.form.mode === "directive" ? (
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-xs font-semibold text-slate-400">
                          AI Directive & Hunting Scope (Sentence)
                        </label>
                        <span className="text-[11px] text-cyan-400 font-mono">Dynamic Hunting</span>
                      </div>
                      <textarea
                        rows={3}
                        value={editModal.form.directive || ""}
                        onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, directive: e.target.value } })}
                        placeholder="e.g. Focus on ransomware incidents, extortion, and double extortion impacting Japanese healthcare or pharma organizations"
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
                              <span>Generating AI Queries...</span>
                            </>
                          ) : (
                            <>
                              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                              <span>Test Generate Queries</span>
                            </>
                          )}
                        </button>
                        <span className="text-[11px] text-slate-500">
                          Also automatically generated during harvest cycles
                        </span>
                      </div>

                      {previewQueries.length > 0 && (
                        <div className="mt-2.5 p-2.5 rounded-lg bg-slate-950 border border-cyan-900/60 space-y-1.5">
                          <div className="text-[10px] font-semibold text-cyan-400 uppercase tracking-wider">
                            AI-generated query examples ({previewQueries.length}):
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
                        Static Search Query
                      </label>
                      <input
                        type="text"
                        value={editModal.form.query}
                        onChange={(e) => setEditModal({ ...editModal, form: { ...editModal.form, query: e.target.value } })}
                        placeholder="e.g. (from:piyokango OR from:jpcert) site:x.com"
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

      {/* ALL OBSERVED ENTITIES MODAL */}
      {showAllEntitiesModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl max-w-4xl w-full max-h-[85vh] flex flex-col overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between p-5 border-b border-slate-800 bg-slate-950/40">
              <div className="flex items-center space-x-3">
                <span className="p-2 rounded-xl bg-cyan-950/70 border border-cyan-800/50 text-cyan-400">
                  <Target className="w-5 h-5" />
                </span>
                <div>
                  <h3 className="text-base font-bold text-white tracking-wide">
                    {currentLang === "ja" ? "観測エンティティ一覧" : "Observed Intelligence: All Entities Analysis"}
                  </h3>
                  <p className="text-xs text-slate-400">
                    {currentLang === "ja"
                      ? `プラットフォームで観測された全 ${(allEntityStats || entityStats)?.total_unique_actors || 0} 脅威アクター & 全 ${(allEntityStats || entityStats)?.total_unique_victims || 0} 標的組織`
                      : `Comprehensive aggregate tracking of all ${(allEntityStats || entityStats)?.total_unique_actors || 0} threat actors & ${(allEntityStats || entityStats)?.total_unique_victims || 0} victims`}
                  </p>
                </div>
              </div>
              <button
                onClick={() => {
                  setShowAllEntitiesModal(false);
                  setEntitiesSearch("");
                }}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Sub-Header / Search & Tabs */}
            <div className="p-4 border-b border-slate-800 bg-slate-900 flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="flex space-x-2 w-full sm:w-auto">
                <button
                  onClick={() => setEntitiesModalTab("actors")}
                  className={`flex-1 sm:flex-none px-4 py-2 rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition ${
                    entitiesModalTab === "actors"
                      ? "bg-purple-600 text-white shadow-lg shadow-purple-600/30"
                      : "bg-slate-800 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Skull className="w-3.5 h-3.5" />
                  <span>
                    {currentLang === "ja"
                      ? `脅威アクター (${(allEntityStats || entityStats)?.total_unique_actors || 0})`
                      : `Threat Actors (${(allEntityStats || entityStats)?.total_unique_actors || 0})`}
                  </span>
                </button>

                <button
                  onClick={() => setEntitiesModalTab("victims")}
                  className={`flex-1 sm:flex-none px-4 py-2 rounded-lg text-xs font-semibold flex items-center justify-center space-x-2 transition ${
                    entitiesModalTab === "victims"
                      ? "bg-cyan-600 text-white shadow-lg shadow-cyan-600/30"
                      : "bg-slate-800 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Building2 className="w-3.5 h-3.5" />
                  <span>
                    {currentLang === "ja"
                      ? `標的・被害組織 (${(allEntityStats || entityStats)?.total_unique_victims || 0})`
                      : `Targeted Victims (${(allEntityStats || entityStats)?.total_unique_victims || 0})`}
                  </span>
                </button>
              </div>

              <div className="relative w-full sm:w-72">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={entitiesSearch}
                  onChange={(e) => setEntitiesSearch(e.target.value)}
                  placeholder={
                    entitiesModalTab === "actors"
                      ? (currentLang === "ja" ? "アクター名を検索..." : "Search threat actor...")
                      : (currentLang === "ja" ? "組織名を検索..." : "Search victim org...")
                  }
                  className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>

            {/* Modal Body / Entity List */}
            <div className="p-4 overflow-y-auto flex-1">
              {loadingAllEntities ? (
                <div className="py-20 flex flex-col items-center justify-center space-y-2 text-slate-400">
                  <Loader2 className="w-8 h-8 animate-spin text-cyan-400" />
                  <span className="text-xs">{currentLang === "ja" ? "集計データを読み込み中..." : "Loading aggregated entities..."}</span>
                </div>
              ) : entitiesModalTab === "actors" ? (
                <div className="space-y-1.5">
                  {(() => {
                    const list = (allEntityStats || entityStats)?.top_actors || [];
                    const filtered = list.filter((a) =>
                      !entitiesSearch || a.name.toLowerCase().includes(entitiesSearch.toLowerCase())
                    );
                    if (filtered.length === 0) {
                      return (
                        <div className="py-12 text-center text-slate-500 text-xs">
                          {currentLang === "ja" ? "一致する脅威アクターは見つかりませんでした。" : "No matching threat actors found."}
                        </div>
                      );
                    }
                    return filtered.map((actor, idx) => (
                      <div
                        key={actor.name}
                        className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 hover:bg-slate-800/60 border border-slate-800/80 transition text-xs"
                      >
                        <div className="flex items-center space-x-3">
                          <span className="font-mono text-slate-500 text-[11px] w-6 text-right">
                            #{idx + 1}
                          </span>
                          <span className="font-mono font-bold text-purple-300 text-sm">
                            {actor.name}
                          </span>
                          {actor.japan_count > 0 && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-950/60 text-emerald-300 border border-emerald-800/50 flex items-center space-x-1">
                              <span>🇯🇵</span>
                              <span>Japan ({actor.japan_count})</span>
                            </span>
                          )}
                        </div>

                        <div className="flex items-center space-x-4">
                          {actor.last_seen_at && (
                            <span className="text-slate-500 text-[11px] font-mono hidden sm:inline">
                              Last: {formatDate(actor.last_seen_at)}
                            </span>
                          )}
                          <span className="px-2 py-0.5 rounded-full font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800 text-xs">
                            {actor.count} {currentLang === "ja" ? "件" : "incidents"}
                          </span>
                          <button
                            onClick={() => {
                              setSelectedActorFilter(actor.name);
                              setSelectedVictimFilter("");
                              setSearch(actor.name);
                              setShowAllEntitiesModal(false);
                              setEntitiesSearch("");
                            }}
                            className="px-2.5 py-1 rounded bg-purple-600 hover:bg-purple-500 text-white font-medium text-[11px] transition shadow"
                          >
                            {currentLang === "ja" ? "絞り込み" : "Filter"}
                          </button>
                        </div>
                      </div>
                    ));
                  })()}
                </div>
              ) : (
                <div className="space-y-1.5">
                  {(() => {
                    const list = (allEntityStats || entityStats)?.top_victims || [];
                    const filtered = list.filter((v) => {
                      if (!entitiesSearch) return true;
                      const q = entitiesSearch.toLowerCase();
                      return v.name.toLowerCase().includes(q) || (v.name_en && v.name_en.toLowerCase().includes(q));
                    });
                    if (filtered.length === 0) {
                      return (
                        <div className="py-12 text-center text-slate-500 text-xs">
                          {currentLang === "ja" ? "一致する組織は見つかりませんでした。" : "No matching victim organizations found."}
                        </div>
                      );
                    }
                    return filtered.map((victim, idx) => {
                      const displayName = (currentLang === "en" && victim.name_en) ? victim.name_en : victim.name;
                      return (
                        <div
                          key={victim.name}
                          className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 hover:bg-slate-800/60 border border-slate-800/80 transition text-xs"
                        >
                          <div className="flex items-center space-x-3">
                            <span className="font-mono text-slate-500 text-[11px] w-6 text-right">
                              #{idx + 1}
                            </span>
                            <div>
                              <span className="font-medium text-slate-200 text-sm">
                                {displayName}
                              </span>
                              {victim.name_en && victim.name_en !== displayName && (
                                <span className="ml-2 text-[11px] text-slate-500 font-mono">
                                  ({victim.name_en})
                                </span>
                              )}
                            </div>
                            {victim.japan_count > 0 && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-950/60 text-emerald-300 border border-emerald-800/50 flex items-center space-x-1">
                                <span>🇯🇵</span>
                                <span>Japan</span>
                              </span>
                            )}
                          </div>

                          <div className="flex items-center space-x-4">
                            {victim.last_seen_at && (
                              <span className="text-slate-500 text-[11px] font-mono hidden sm:inline">
                                Last: {formatDate(victim.last_seen_at)}
                              </span>
                            )}
                            <span className="px-2 py-0.5 rounded-full font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 text-xs">
                              {victim.count} {currentLang === "ja" ? "件" : "incidents"}
                            </span>
                            <button
                              onClick={() => {
                                setSelectedVictimFilter(displayName);
                                setSelectedActorFilter("");
                                setSearch(displayName);
                                setShowAllEntitiesModal(false);
                                setEntitiesSearch("");
                              }}
                              className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-[11px] transition shadow"
                            >
                              {currentLang === "ja" ? "絞り込み" : "Filter"}
                            </button>
                          </div>
                        </div>
                      );
                    });
                  })()}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400">
              <span>
                {currentLang === "ja"
                  ? "項目をクリックすると、該当の脅威インシデント一覧へ即座に絞り込まれます。"
                  : "Click any item to filter incidents by that threat actor or organization."}
              </span>
              <button
                onClick={() => {
                  setShowAllEntitiesModal(false);
                  setEntitiesSearch("");
                }}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition font-medium"
              >
                {currentLang === "ja" ? "閉じる" : "Close"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
