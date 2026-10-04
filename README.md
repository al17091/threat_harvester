# Threat Information Harvester (Japan Cyber Threat Intelligence)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Kubernetes / Helm](https://img.shields.io/badge/Kubernetes-Helm_3-326CE5.svg)](charts/information-harvester)

脅威情報（Cyber Threat Intelligence: CTI）の自動収集・AI分析・通知プラットフォームです。  
特に**日本国内を標的・関係先とするサイバー攻撃やインシデント情報**の網羅的かつ低コストな収集に特化しています。


---

## 1. 特徴と収集対象

| 収集ソース | 収集・監視手法 | 費用・リソース特性 |
| :--- | :--- | :--- |
| **一般Web検索 (LLM)** | Gemini API (Google Search Grounding) による日本標的インシデント検索 | 検索エンジンAPI契約不要（Gemini APIクォータ内で実行） |
| **Dark Web (.onion)** | Tor SOCKS5プロキシ経由のランサムウェアDLS（リークサイト）およびトラッカー監視 | 完全無料（クラスタ内Tor Pod経由） |
| **Telegram 監視** | 公開チャンネルWebプレビュー (`t.me/s/<channel>`) のスクレイピング | 完全無料（APIキー・電話番号不要） |
| **X (Twitter) 監視** | Gemini Grounded Search によるX速報・リサーチャー投稿監視 | 高額なX API不要、低コスト |
| **セキュリティベンダー/CERT** | JPCERT/CC, IPA, ScanNetSecurity, Security Next, BleepingComputer, CISA 等のRSS | 完全無料・高精度 |

### Gemini AI による脅威インテリジェンス分析
収集された脅威データは Gemini 2.5 Flash により以下の分析が行われます：
- **日本への関連度判定**: `Direct`（国内組織が直接被害）, `Indirect`（世界規模のゼロデイなど国内波及）, `None`
- **深刻度判定**: `Critical`, `High`, `Medium`, `Low`
- **日本語要約と影響分析**: 3行以内の平易な技術要約と国内への具体的影響
- **推奨対策**: 初動対応や防御アクションの提案

---

## 2. アーキテクチャ

Kubernetes環境（k3s等）上で稼働し、Helmによりワンストップでデプロイ可能です。

- **Harvester CronJob**: 定期実行バッチ（デフォルト毎時実行）。重複排除（SQLite）を行い、条件に合致した脅威をDiscord等へ通知。
- **Tor Proxy Pod**: Alpineベースの軽量Tor SOCKS5デーモン。Onionサイトへの安全な接続を提供。
- **Dev / CLI Container**: 運用・開発コマンドを集約した常駐Pod。クラスタ内外から手動調査やソース別テストを直接実行可能。
- **Persistent Volume Claim**: 過去インシデント履歴および重複排除キャッシュを永続化。

---

## 3. 開発用コンテナと CLI 運用

すべての運用・テスト用コマンドは開発コンテナおよび `harvester` CLI に集約されています。

### 開発コンテナの起動（ローカルDocker）
```bash
# 開発イメージのビルド
docker build -t information_harvester:dev -f Dockerfile.dev .

# 開発コンテナの起動
docker run -it --rm \
  -e GEMINI_API_KEY="your-gemini-api-key" \
  -e DISCORD_WEBHOOK_URL="your-discord-webhook" \
  information_harvester:dev bash
```

### CLI コマンド一覧 (`harvester`)

```bash
# 1. システム・ソース・プロキシの稼働状況ヘルスチェック
harvester status

# 2. 全収集ソースの一括実行 (直近24時間)
harvester run --hours 24

# 3. 日本直接標的のみに絞って通知テスト
harvester run --hours 24 --direct-only

# 4. 各ソース単体の動作テスト (vendor, web, tor, telegram, x)
harvester test --source vendor
harvester test --source telegram
harvester test --source web

# 5. Gemini Search Grounding を使った即時脅威クエリ
harvester search "日本国内 ランサムウェア 被害"

# 6. Tor SOCKS5経由での onion URL / Web 接続テスト
harvester test-onion "http://check.torproject.org"

# 7. 収集済みインシデントの確認 (SQLiteキャッシュ)
harvester history                 # 直近の収集一覧テーブル表示
harvester history --japan-only    # 日本直接標的のみ絞り込み
harvester show <ID>               # 詳細・要約・影響・推奨対策を表示

# 8. 通知・レポート機能の疎通テスト
harvester test-notify             # 設定済みWebhook (Discord/Slack/Generic) にテスト通知
harvester test-notion             # Notionデータベースにテストページ起票
```

### レポート・通知先の連携設定
環境変数または Helm の `values.yaml` で連携先を設定できます：
- **Discord**: `DISCORD_WEBHOOK_URL`
- **Slack**: `SLACK_WEBHOOK_URL`
- **Generic JSON Webhook**: `GENERIC_WEBHOOK_URL` (任意の監視ツールや自動化ワークフローにPOST)
- **Notion データベース**: `NOTION_API_KEY` および `NOTION_DATABASE_ID` (CTI ナレッジベースとして自動起票)

---

## 4. Kubernetes / Helm によるデプロイ

### 1. Helm Chart のインストール
`charts/information-harvester` を使用してクラスタにデプロイします。

```bash
helm upgrade --install information-harvester ./charts/information-harvester \
  --namespace security \
  --create-namespace \
  --set secrets.geminiApiKey="YOUR_GEMINI_API_KEY" \
  --set secrets.discordWebhookUrl="YOUR_DISCORD_WEBHOOK_URL"
```

### 2. クラスタ内 Dev Pod へのアクセス（コマンド集約運用）
Helmデプロイ時、開発・管理用のDev Podが常駐起動します。このコンテナに `exec` してCLIコマンドを実行できます。

```bash
# Dev Pod の名前を確認
kubectl get pods -n security -l app.kubernetes.io/component=dev-cli

# Dev Pod に入ってコマンドを実行
kubectl exec -it deployment/information-harvester-dev -n security -- bash

# コンテナ内で直接ヘルスチェックやテストを実行
harvester status
harvester test --source vendor
```

### 3. 設定のカスタマイズ (`values.yaml`)
`charts/information-harvester/values.yaml` で以下の項目を調整可能です：
- `cronjob.schedule`: 実行間隔（デフォルト: `0 * * * *` 毎時0分）
- `config.notifyDirectOnly`: `true` にすると日本直接標的（Direct）のみ通知
- `tor.enabled`: Tor プロキシ Pod の有効/無効
- `devContainer.enabled`: 開発/運用用 Pod の有効/無効
- `persistence.size`: SQLiteキャッシュ用ボリューム容量（デフォルト: `5Gi`）

---

## 5. 開発規約・コミュニティ

- **開発規約**: コミット規約やエージェント対応方針は [AGENT.md](AGENT.md) に定義されています。
- **コントリビューション**: プルリクエストや機能提案の手順は [CONTRIBUTING.md](CONTRIBUTING.md) をご覧ください。
- **タスク追跡**: 進捗状況および今後のロードマップは [docs/task_tracker.md](docs/task_tracker.md) を参照してください。
- **セキュリティ & 免責事項**: 脆弱性報告や利用上の免責事項は [SECURITY.md](SECURITY.md) をご確認ください。

---

## 6. ライセンス (License)

本プロジェクトは **[MIT License](LICENSE)** の下で公開されているオープンソースソフトウェアです。  
商用・非商用を問わず自由にご利用・改変・再配布いただけます。

