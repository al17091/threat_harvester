# Threat Harvester キャッシュ & レンダリング最適化方針 (Caching & Performance Policy)

## 1. 概要 (Overview)

Threat Harvester は CTI (Cyber Threat Intelligence) 情報を高頻度に収集・蓄積するダッシュボードです。インシデント件数および詳細コンテンツの増大に伴い、以下の課題が発生していました：
- 一覧取得 API のペイロード肥大化（PostgreSQL TOAST カラムの展開に伴う Go のメモリ確保・シリアライズ負荷）
- ページネーション時のレイアウトシフト（ローディングスピナー挿入による画面のがたつきとスクロールジャンプ）
- 同一条件や前ページへ戻る際の不要なネットワークラウンドトリップ

本ドキュメントでは、v0.2.0-rc.3 にて確立された多層キャッシュおよびレンダリング最適化アーキテクチャの設計方針、キャッシュライフサイクル、無効化トリガー、および今後の開発規約を規定します。

---

## 2. アーキテクチャ全体像 (Architecture Overview)

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

## 3. レイヤー別詳細設計

### Tier 1: クライアント側インメモリページキャッシュ (`web/app/components/IncidentDashboard.tsx`)

フロントエンドの React コンポーネント (`IncidentDashboard`) 内で `useRef<Map<string, IncidentsResponse>>` を保持し、同一セッション内でのページ間遷移を 0ms（ネットワーク待機なし）で描画します。

#### キャッシュキー設計
キャッシュキーは、取得結果に影響を与える全パラメータを決定論的（Deterministic）に連結した複合文字列です。

```typescript
const cacheKey = `${currentLang}:${targetPage}:${targetPageSize}:${search}:${severityFilter}:${japanOnly}:${sourceTypeFilter}:${sortBy}`;
```

#### キャッシュライフサイクル & 無効化トリガー (Invalidation Triggers)
整合性を保つため、以下のイベント発生時に `incidentsCacheRef.current.clear()` を実行してキャッシュを破棄し、最新データをネットワークから強制再取得します。

| トリガー | 契機 | 動作 |
|---|---|---|
| **手動リフレッシュ** | ユーザーが「更新」ボタンをクリック | キャッシュ全破棄の上、現ページを強制再取得 |
| **フィルタ条件変更** | 深刻度・重要度・国内絞り込み・情報ソース・ソート順の変更 | キャッシュ全破棄の上、1ページ目から再取得 |
| **検索クエリ変更** | 検索入力（デバウンス後） | キャッシュ全破棄の上、1ページ目から再取得 |
| **言語切り替え** | 日本語 / 英語 UI 切替 (`currentLang`) | キャッシュ全破棄の上、現ページを強制再取得 |
| **バックグラウンド収集完了** | `handleHarvestFinished` (ハーベスト実行完了通知) | キャッシュ全破棄の上、バックグラウンド更新 |
| **ページサイズ変更** | 1ページあたり件数の変更 | キャッシュ全破棄の上、1ページ目から再取得 |

---

### Tier 2: ゼロレイアウトシフト (Zero Layout-Shift) UI ポリシー

一覧の再取得やページネーション時に、ユーザーの視線と操作コンテキストを保護します。

1. **インジケータの最小化**:
   - 既存のカード一覧全体を取り払って 150px 超のフルハイトスピナーを挿入する手法を廃止。
   - フィードヘッダー直下に 2px のパルスバー (`h-0.5 bg-cyan-400 animate-pulse`) のみをオーバーレイ表示。
2. **コンテンツ透過と操作保護**:
   - フェッチ中は既存のカードリストを `opacity-60 pointer-events-none transition-opacity` とし、コンテンツの消滅やスクロール飛びを防止。
3. **インテリジェント・スクロール制御**:
   - ページ遷移時、すでにユーザーがフィード上部より下にスクロールしている場合 (`rect.top < 0`) のみフィードトップへスムーズスクロール。
   - フィードヘッダーが見えている状態（画面上部）ではスクロールを実行せず、視線のぶれを防止。

---

### Tier 3: DB / API プロジェクション分離 (Projection Separation)

PostgreSQL では、閾値を超える長文テキスト（`raw_content` 等）は TOAST (The Oversized-Attribute Storage Technique) テーブルへ自動的にオフライン格納されます。一覧取得時にこれらを `SELECT *` すると、ディスクアクセスと伸長（Decompression）処理が大量に発生し、Go 側の JSON シリアライズとネットワーク帯域を圧迫します。

#### プロジェクション設計の分離

- **一覧用プロジェクション (`incidentListSelectCols`)**:
  - カード表示に必要なサマリ（タイトル、要約、深刻度、タグ、日日時等）のみを抽出。
  - TOAST 対象となる巨大カラムは空文字または空 JSON として定数投影：
    ```sql
    '' AS raw_content,
    '[]'::jsonb AS source_urls,
    '[]'::jsonb AS sources_detail
    ```
  - **効果**: 1ページ (20件) のレスポンスペイロードが 485KB → 88KB (約82% 削減)。

- **詳細用プロジェクション (`incidentSelectCols`)**:
  - `/api/incidents/:id`（モーダル詳細表示）でのみ全カラム（TOAST カラム含む）を完全取得。

#### メモリアロケーション & 正規表現の最適化
一覧生成ループ (`formatIncidentMap`) 内での動的正規表現コンパイル負荷を削減するため、`strings.Contains` による事前高速判定を導入し、不要な正規表現コンパイルを 99.9% 排除。

---

### Tier 4: API 並行クエリ実行 (Concurrent Execution)

一覧取得 API (`/api/incidents`) では、一覧レコード取得 (`GetIncidents`) と総件数カウント (`GetIncidentsTotal`) の 2 つの独立した DB クエリが必要です。

- `sync.WaitGroup` を用いて 2 クエリを別 Goroutine で並行実行。
- 逐次実行時の直列待ち時間（約 150ms + 150ms = 300ms）を、並行実行により約 150〜200ms に短縮。

---

## 4. 開発・運用の不変原則 (Invariants & Best Practices)

1. **一覧エンドポイントへの大容量フィールド追加の禁止**:
   - 新規にカラムを追加する際、HTML 全文や生ログなどの大容量テキストを `incidentListSelectCols` に直接含めてはならない。
   - 一覧表示に必要な場合は、Worker 側で要約フィールド（サマリ）を事前に生成して格納すること。
2. **クライアントキャッシュキーの網羅性保持**:
   - ダッシュボードに新しいフィルタ（例: 日付範囲指定、タグ絞り込み）を追加する場合、必ず `web/app/components/IncidentDashboard.tsx` の `cacheKey` 生成式に変数を追加すること。
3. **無効化フックの結合**:
   - 外部イベントやユーザーアクションによってインシデント状態が更新される処理を追加した場合、`incidentsCacheRef.current.clear()` を必ず呼び出すこと。
