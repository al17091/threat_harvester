"use client";

import React, { useEffect, useState, useRef, useMemo } from "react";
import {
  Terminal,
  Maximize2,
  Minimize2,
  Trash2,
  Copy,
  Check,
  Play,
  RotateCw,
  Search,
  X,
  ChevronDown,
  ChevronUp,
  Radio,
  Shield,
  Layers,
  Cpu,
} from "lucide-react";
import { withBasePath } from "./basePath";

export interface LogEntry {
  timestamp: string;
  message: string;
}

interface TerminalConsoleProps {
  isOpen: boolean;
  onClose: () => void;
  isHarvesting: boolean;
  onTriggerHarvest?: () => void;
  onHarvestFinished?: () => void;
  fullTabMode?: boolean;
}

export const TerminalConsole: React.FC<TerminalConsoleProps> = ({
  isOpen,
  onClose,
  isHarvesting,
  onTriggerHarvest,
  onHarvestFinished,
  fullTabMode = false,
}) => {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const [isMinimized, setIsMinimized] = useState(false);
  const [isMaximized, setIsMaximized] = useState(false);
  const [filterText, setFilterText] = useState("");
  const [copied, setCopied] = useState(false);
  const [activePipeline, setActivePipeline] = useState(isHarvesting);

  const terminalBodyRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Sync external harvesting state
  useEffect(() => {
    setActivePipeline(isHarvesting);
  }, [isHarvesting]);

  // Connect SSE or fallback polling
  useEffect(() => {
    if (!isOpen && !fullTabMode && !activePipeline) {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      return;
    }

    let isSubscribed = true;

    // Fetch initial history
    fetch(withBasePath("/api/pipeline/logs?limit=150"))
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && data.logs && isSubscribed) {
          setLogs(data.logs);
          if (typeof data.is_running === "boolean") {
            setActivePipeline(data.is_running);
          }
        }
      })
      .catch((err) => console.error("Initial logs fetch error:", err));

    // Connect Server-Sent Events stream
    try {
      const es = new EventSource(withBasePath("/api/pipeline/stream"));
      eventSourceRef.current = es;

      es.addEventListener("log", (e: MessageEvent) => {
        try {
          const entry: LogEntry = JSON.parse(e.data);
          setLogs((prev) => {
            const next = [...prev, entry];
            if (next.length > 500) {
              return next.slice(next.length - 500);
            }
            return next;
          });
        } catch {
          // ignore parse errors
        }
      });

      es.addEventListener("status", (e: MessageEvent) => {
        try {
          const status = JSON.parse(e.data);
          if (typeof status.is_running === "boolean") {
            setActivePipeline((wasRunning) => {
              if (wasRunning && !status.is_running && onHarvestFinished) {
                onHarvestFinished();
              }
              return status.is_running;
            });
          }
        } catch {
          // ignore
        }
      });

      es.onerror = () => {
        // Fallback: SSE connection dropped, close and rely on polling
        if (es.readyState === EventSource.CLOSED) {
          es.close();
          eventSourceRef.current = null;
        }
      };
    } catch (e) {
      console.warn("EventSource unsupported or failed:", e);
    }

    // Secondary polling interval while active to ensure state synchronization
    const pollInterval = setInterval(() => {
      fetch(withBasePath("/api/pipeline/logs?limit=100"))
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data && isSubscribed) {
            if (typeof data.is_running === "boolean") {
              setActivePipeline((wasRunning) => {
                if (wasRunning && !data.is_running && onHarvestFinished) {
                  onHarvestFinished();
                }
                return data.is_running;
              });
            }
            // If SSE is not delivering, sync logs
            if (!eventSourceRef.current && data.logs) {
              setLogs(data.logs);
            }
          }
        })
        .catch(() => {});
    }, 2500);

    return () => {
      isSubscribed = false;
      clearInterval(pollInterval);
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [isOpen, fullTabMode, activePipeline, onHarvestFinished]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && terminalBodyRef.current) {
      terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const handleClearLogs = async () => {
    setLogs([]);
    try {
      await fetch(withBasePath("/api/pipeline/logs/clear"), { method: "POST" });
    } catch (e) {
      console.error("Clear logs error:", e);
    }
  };

  const handleCopyLogs = () => {
    const text = filteredLogs
      .map((l) => `[${l.timestamp}] ${l.message}`)
      .join("\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredLogs = useMemo(() => {
    if (!filterText) return logs;
    const lower = filterText.toLowerCase();
    return logs.filter(
      (l) =>
        l.message.toLowerCase().includes(lower) ||
        l.timestamp.toLowerCase().includes(lower)
    );
  }, [logs, filterText]);

  // Format log lines with color badges
  const renderLogMessage = (message: string) => {
    // Strip ISO date prefixes if already present in message like "2026/10/04 12:00:00"
    const cleaned = message.replace(/^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\s*/, "");

    // Stage delimiter banners
    if (cleaned.startsWith("=== Starting") || cleaned.startsWith("=== Harvesting")) {
      return (
        <span className="font-bold text-cyan-300 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/80 block my-1">
          {cleaned}
        </span>
      );
    }

    // Alerting notifications
    if (cleaned.includes("[Pipeline] Alerting on threat:")) {
      return (
        <span className="text-rose-300 font-semibold bg-rose-950/60 px-1.5 py-0.5 rounded border border-rose-800/60">
          🚨 {cleaned}
        </span>
      );
    }

    // Suppressed duplicate alerts
    if (cleaned.includes("Suppressing") || cleaned.includes("Skipping seen item")) {
      return <span className="text-slate-500 italic">{cleaned}</span>;
    }

    // Component tags
    const renderWithBadge = (tag: string, badgeClass: string, text: string) => {
      const rest = text.substring(tag.length).trim();
      return (
        <span>
          <span className={`inline-block px-1.5 py-0.2 rounded text-[10px] font-mono mr-1.5 font-semibold ${badgeClass}`}>
            {tag}
          </span>
          <span className="text-slate-200">{rest}</span>
        </span>
      );
    };

    if (cleaned.startsWith("[Pipeline]")) {
      if (cleaned.includes("Analyzing threat with Gemini")) {
        return (
          <span>
            <span className="inline-block px-1.5 py-0.2 rounded text-[10px] font-mono mr-1.5 font-semibold bg-purple-900/60 text-purple-300 border border-purple-700/50">
              [Gemini AI]
            </span>
            <span className="text-purple-200">{cleaned.replace("[Pipeline]", "").trim()}</span>
          </span>
        );
      }
      if (cleaned.includes("Analysis result:")) {
        return (
          <span>
            <span className="inline-block px-1.5 py-0.2 rounded text-[10px] font-mono mr-1.5 font-semibold bg-emerald-900/60 text-emerald-300 border border-emerald-700/50">
              [Enriched]
            </span>
            <span className="text-emerald-200 font-medium">{cleaned.replace("[Pipeline]", "").trim()}</span>
          </span>
        );
      }
      return renderWithBadge("[Pipeline]", "bg-cyan-900/60 text-cyan-300 border border-cyan-700/50", cleaned);
    }

    if (cleaned.startsWith("[RSS]")) {
      return renderWithBadge("[RSS]", "bg-blue-900/60 text-blue-300 border border-blue-700/50", cleaned);
    }

    if (cleaned.startsWith("[Telegram]")) {
      return renderWithBadge("[Telegram]", "bg-violet-900/60 text-violet-300 border border-violet-700/50", cleaned);
    }

    if (cleaned.startsWith("[DarkWeb]")) {
      return renderWithBadge("[DarkWeb]", "bg-amber-900/60 text-amber-300 border border-amber-700/50", cleaned);
    }

    if (cleaned.startsWith("[WebSearch]")) {
      return renderWithBadge("[WebSearch]", "bg-emerald-900/60 text-emerald-300 border border-emerald-700/50", cleaned);
    }

    if (cleaned.startsWith("[XMonitor]")) {
      return renderWithBadge("[XMonitor]", "bg-pink-900/60 text-pink-300 border border-pink-700/50", cleaned);
    }

    if (cleaned.includes("error") || cleaned.includes("Error") || cleaned.includes("Failed")) {
      return <span className="text-rose-400 font-medium">{cleaned}</span>;
    }

    return <span className="text-slate-300">{cleaned}</span>;
  };

  if (!isOpen && !fullTabMode) {
    return null;
  }

  const containerClasses = fullTabMode
    ? "w-full rounded-xl border border-slate-800 bg-slate-950/95 shadow-2xl flex flex-col h-[750px] overflow-hidden"
    : `w-full rounded-xl border border-cyan-900/50 bg-slate-950/95 shadow-2xl shadow-cyan-950/30 flex flex-col mb-6 transition-all duration-200 overflow-hidden ${
        isMaximized ? "h-[620px]" : isMinimized ? "h-14" : "h-[420px]"
      }`;

  return (
    <div className={containerClasses}>
      {/* Terminal Title Bar */}
      <div className="h-11 bg-slate-900/90 border-b border-slate-800 px-3 flex items-center justify-between select-none">
        
        {/* Left: Window Controls & Title */}
        <div className="flex items-center space-x-3">
          {!fullTabMode && (
            <div className="flex items-center space-x-1.5">
              <button
                onClick={onClose}
                className="w-3 h-3 rounded-full bg-rose-500/80 hover:bg-rose-500 transition-colors cursor-pointer"
                title="Close Terminal"
              />
              <button
                onClick={() => {
                  setIsMinimized(!isMinimized);
                  if (isMaximized) setIsMaximized(false);
                }}
                className="w-3 h-3 rounded-full bg-amber-500/80 hover:bg-amber-500 transition-colors cursor-pointer"
                title={isMinimized ? "Expand Height" : "Minimize Height"}
              />
              <button
                onClick={() => {
                  setIsMaximized(!isMaximized);
                  if (isMinimized) setIsMinimized(false);
                }}
                className="w-3 h-3 rounded-full bg-emerald-500/80 hover:bg-emerald-500 transition-colors cursor-pointer"
                title={isMaximized ? "Restore Height" : "Maximize Height"}
              />
            </div>
          )}

          <div className="flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="font-mono text-xs font-semibold text-slate-200 tracking-wide">
              cti-harvester@daemon:~$ <span className="text-cyan-400">tail -f stream.log</span>
            </span>
          </div>

          {/* Running Status Badge */}
          <div className="flex items-center">
            {activePipeline ? (
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-emerald-950/80 text-emerald-300 border border-emerald-800 animate-pulse">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1 animate-ping" />
                HARVESTING LIVE
              </span>
            ) : (
              <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono font-medium bg-slate-800 text-slate-400 border border-slate-700">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 mr-1" />
                STANDBY
              </span>
            )}
          </div>
        </div>

        {/* Right: Actions & Tools */}
        <div className="flex items-center space-x-2">
          {/* Quick Filter Search */}
          {!isMinimized && (
            <div className="relative hidden sm:block">
              <Search className="w-3 h-3 text-slate-500 absolute left-2 top-2" />
              <input
                type="text"
                placeholder="Filter logs..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                className="h-7 w-32 md:w-44 pl-6 pr-6 text-[11px] font-mono bg-slate-950/80 border border-slate-800 rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              {filterText && (
                <button
                  onClick={() => setFilterText("")}
                  className="absolute right-1.5 top-1.5 text-slate-500 hover:text-slate-300"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
          )}

          {/* Trigger Harvest */}
          {onTriggerHarvest && (
            <button
              onClick={onTriggerHarvest}
              disabled={activePipeline}
              className="inline-flex items-center px-2.5 py-1 rounded text-[11px] font-semibold bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white transition cursor-pointer"
              title="Execute threat harvesting now"
            >
              {activePipeline ? (
                <RotateCw className="w-3 h-3 mr-1 animate-spin" />
              ) : (
                <Play className="w-3 h-3 mr-1 text-emerald-300 fill-emerald-300" />
              )}
              <span>Run</span>
            </button>
          )}

          {/* Auto-scroll toggle */}
          {!isMinimized && (
            <button
              onClick={() => setAutoScroll(!autoScroll)}
              className={`px-2 py-1 rounded text-[10px] font-mono transition cursor-pointer border ${
                autoScroll
                  ? "bg-slate-800 text-cyan-300 border-cyan-800/80"
                  : "bg-slate-950 text-slate-500 border-slate-800"
              }`}
              title="Toggle automatic scrolling to bottom"
            >
              Scroll: {autoScroll ? "ON" : "OFF"}
            </button>
          )}

          {/* Copy logs */}
          {!isMinimized && (
            <button
              onClick={handleCopyLogs}
              className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition cursor-pointer"
              title="Copy visible logs to clipboard"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          )}

          {/* Clear logs */}
          {!isMinimized && (
            <button
              onClick={handleClearLogs}
              className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition cursor-pointer"
              title="Clear terminal output"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}

          {!fullTabMode && (
            <button
              onClick={onClose}
              className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition cursor-pointer ml-1"
              title="Close"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Harvester Subsystems Pipeline Status Strip */}
      {!isMinimized && (
        <div className="bg-slate-950 px-3 py-1.5 border-b border-slate-800/80 flex items-center justify-between text-[11px] font-mono overflow-x-auto gap-3 select-none">
          <div className="flex items-center space-x-2 text-slate-400">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span className="font-semibold text-slate-300 uppercase tracking-wider text-[10px]">
              Active Channels:
            </span>
            <span className="px-1.5 py-0.5 rounded bg-blue-950/60 text-blue-300 border border-blue-800/50">
              RSS (16)
            </span>
            <span className="px-1.5 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800/50">
              Telegram (10)
            </span>
            <span className="px-1.5 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800/50">
              DarkWeb (Tor)
            </span>
            <span className="px-1.5 py-0.5 rounded bg-pink-950/60 text-pink-300 border border-pink-800/50">
              X Monitor (6)
            </span>
            <span className="px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/50">
              Web Grounding
            </span>
          </div>

          <div className="flex items-center space-x-3 text-slate-400 shrink-0">
            <span>
              Lines: <strong className="text-slate-200">{filteredLogs.length}</strong>
            </span>
            <span className="text-slate-600">|</span>
            <span className="flex items-center text-slate-400">
              <Cpu className="w-3 h-3 mr-1 text-cyan-400" />
              Gemini 3.7 CTI
            </span>
          </div>
        </div>
      )}

      {/* Terminal Output Body */}
      {!isMinimized && (
        <div
          ref={terminalBodyRef}
          className="flex-1 p-3 bg-slate-950 font-mono text-[11px] leading-relaxed overflow-y-auto selection:bg-cyan-500 selection:text-black space-y-0.5"
        >
          {filteredLogs.length === 0 ? (
            <div className="text-slate-600 italic py-8 text-center">
              No log messages captured yet. Click &quot;Run&quot; above to start threat harvesting.
            </div>
          ) : (
            filteredLogs.map((entry, idx) => (
              <div key={idx} className="flex items-start hover:bg-slate-900/50 px-1 py-0.5 rounded group">
                <span className="text-slate-600 text-[10px] select-none mr-2 shrink-0 pt-0.5">
                  {entry.timestamp ? entry.timestamp.slice(11, 19) : "--:--:--"}
                </span>
                <div className="break-all flex-1">{renderLogMessage(entry.message)}</div>
              </div>
            ))
          )}

          {/* Active Terminal Cursor */}
          <div className="flex items-center text-slate-500 pt-1">
            <span className="text-cyan-400 mr-1.5 font-bold">cti-agent:~$</span>
            <span className="w-2 h-4 bg-cyan-400 inline-block animate-pulse" />
          </div>
        </div>
      )}
    </div>
  );
};
