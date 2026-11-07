# Threat Harvester Caching & Feed Performance Policy

## 1. Overview

Threat Harvester continuously collects and enriches Cyber Threat Intelligence (CTI) feeds at high frequency. As the total volume of incidents and detailed raw content grows, several performance bottlenecks emerged:
- Bloated incident list API payloads caused by PostgreSQL TOAST column decompression, Go memory allocations, and serialization overhead.
- Jarring layout shifts and scroll jumps during pagination caused by dynamic insertion of large loading spinners.
- Redundant network round-trips when flipping between previously visited pages or toggling filters.

This document formalizes the multi-tier caching and rendering optimization architecture established in `v0.2.0-rc.3`. It details the caching lifecycle, invalidation triggers, and core development invariants.

---

## 2. Architecture Overview

```
[ User Interaction (UI) ]
         │
         ├─── 1. Cache Hit ──────> [ In-Memory Page Cache (Tier 1) ]
         │                           (useRef<Map>, 0ms Instant Flip)
         └─── 2. Cache Miss / Invalidation
                  │
                  ▼
         [ Zero Layout-Shift Renderer (Tier 2) ]
         - Top Pulse Line (2px cyan line)
         - Opacity transition (opacity-60)
                  │
                  ▼ HTTP GET /api/incidents
         [ Go API Server (Tier 4) ]
         - Parallelized GetIncidents & GetIncidentsTotal (sync.WaitGroup)
         - Pre-filtered Regex Optimization
                  │
                  ▼ SQL Query (Tier 3)
         [ PostgreSQL Database ]
         - Projection Separation (incidentListSelectCols)
         - TOAST Column Omission (raw_content, sources_detail, source_urls omitted)
```

---

## 3. Detailed Multi-Tier Design

### Tier 1: Client-Side In-Memory Page Cache (`web/app/components/IncidentDashboard.tsx`)

The React dashboard component (`IncidentDashboard`) maintains an in-memory cache using `useRef<Map<string, IncidentsResponse>>`. This enables instantaneous (0ms) page flips between previously loaded pages during an active user session without triggering repeated network round-trips.

#### Composite Cache Key Design
The cache key is a deterministic combination of all query parameters that influence the incident list output:

```typescript
const cacheKey = `${currentLang}:${targetPage}:${targetPageSize}:${search}:${severityFilter}:${japanOnly}:${sourceTypeFilter}:${sortBy}`;
```

#### Cache Lifecycle & Invalidation Triggers
To guarantee data consistency and prevent serving stale threat intelligence, the entire in-memory cache is wiped (`incidentsCacheRef.current.clear()`) under the following triggers:

| Trigger | Event / User Action | Behavior |
|---|---|---|
| **Manual Refresh** | User clicks the "Refresh" button | Clears cache, forces fresh network fetch for the active page |
| **Filter Changes** | User toggles severity, threat level, Japan-only, source type, or sort order | Clears cache, resets to page 1, fetches fresh data |
| **Search Query** | User updates search term (debounced) | Clears cache, resets to page 1, fetches fresh data |
| **Language Toggle** | Switching UI language between `/en` and `/ja` (`currentLang`) | Clears cache, forces fresh fetch for current page |
| **Harvest Completed** | Background harvest completion notification (`handleHarvestFinished`) | Clears cache, triggers background feed refresh |
| **Page Size Change** | User adjusts rows per page | Clears cache, resets to page 1, fetches fresh data |

---

### Tier 2: Zero Layout-Shift UI Policy

Maintaining the user's visual continuity and reading context during pagination and filtering is critical for SOC operational efficiency.

1. **Minimalist Top Indicator**:
   - Replaced full-height loading spinners (which collapsed and re-expanded the 150px+ card container) with a sleek 2px pulsating line (`h-0.5 bg-cyan-400 animate-pulse`) anchored directly beneath the feed header.
2. **Opacity Transition & Event Protection**:
   - During active fetches, the existing incident card stack is retained in place with `opacity-60 pointer-events-none transition-opacity`. This prevents accidental clicks and avoids visual jarring.
3. **Viewport-Aware Scroll Restoration**:
   - When navigating pages, the window smoothly scrolls back to the feed container top **only** if the user has scrolled past the header (`rect.top < 0`).
   - If the feed header is already visible within the viewport, no scroll is dispatched, preserving focus.

---

### Tier 3: Database & API Projection Separation

In PostgreSQL, attributes exceeding threshold sizes (such as large HTML/text in `raw_content`) are stored out-of-line in TOAST tables. Executing `SELECT *` across dozens of rows forces continuous TOAST decompression, massive Go memory allocation, and heavy JSON serialization.

#### Column Projection Separation

- **List Projection (`incidentListSelectCols`)**:
  - Selects only the metadata necessary for summary card rendering (e.g., ID, title, summary, severity, tags, timestamps).
  - Heavy columns are projected as empty constants:
    ```sql
    '' AS raw_content,
    '[]'::jsonb AS source_urls,
    '[]'::jsonb AS sources_detail
    ```
  - **Impact**: Reduces single-page response payload from **485 KB down to 88 KB** (~82% reduction).

- **Detail Projection (`incidentSelectCols`)**:
  - Full attribute retrieval (including TOAST columns) is strictly reserved for the single incident modal endpoint (`/api/incidents/:id`).

#### Memory Allocation & Regex Pre-filtering
In the incident serialization loop (`formatIncidentMap`), dynamic regex compilation overhead in `IsReporterRoleOrAttribution` is mitigated by a fast substring pre-filter (`strings.Contains`), eliminating unnecessary regex compilation overhead by over 99%.

---

### Tier 4: Concurrent DB Execution

The incident list endpoint (`/api/incidents`) requires two independent queries:
1. Fetching the paginated record slice (`GetIncidents`).
2. Counting the total matching records for pagination controls (`GetIncidentsTotal`).

- Both queries are executed concurrently across separate database connections using Go's `sync.WaitGroup`.
- This halves the sequential database wait time from ~300ms down to ~150–200ms.

---

## 4. Development Invariants & Best Practices

1. **Prohibit Heavy Columns in List Projections**:
   - Never add raw web content, full scrape payloads, or unbounded arrays to `incidentListSelectCols`.
   - Any new list attribute must be pre-summarized or bounded in length by the ingestion worker.
2. **Deterministic Cache Key Parity**:
   - When introducing any new filter (e.g., date range, kill chain phase, tag filtering), ensure the filter parameter is incorporated into the `cacheKey` generator in `web/app/components/IncidentDashboard.tsx`.
3. **Mandatory Invalidation Binding**:
   - Any external mutation or ingestion flow that alters incident states must wire into `incidentsCacheRef.current.clear()`.
