# Threat Information Harvester (Japan Cyber Threat Intelligence)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Kubernetes / Helm](https://img.shields.io/badge/Kubernetes-Helm_3-326CE5.svg)](charts/information-harvester)

脅威情報（Cyber Threat Intelligence: CTI）の自動収集・AI分析・ダッシュボード可視化・通知プラットフォームです。  
特に**日本国内を標的・関係先とするサイバー攻撃やインシデント情報**の網羅的かつ低コストな収集と、直感的なSOC Webダッシュボードを提供します。

---

## 1. 特徴と収集対象

| 収集ソース | 収集・監視手法 | 費用・リソース特性 |
| :--- | :--- | :--- |
| **一般Web検索 (LLM)** | Gemini API (Google Search Grounding) による日本標的インシデント検索 | 検索エンジンAPI契約不要（Gemini APIクォータ内で実行） |
| **Dark Web (.onion)** | Tor SOCKS5プロキシ経由のランサムウェアDLS（リークサイト）およびトラッカー監視 | 完全無料（クラスタ内Tor Pod経由） |
| **Telegram 監視** | 公開チャンネルWebプレビュー (`t.me/s/<channel>`) のスクレイピング | 完全無料（APIキー・電話番号不要） |
| **X (Twitter) 監視** | Gemini Grounded Search によるX速報・リサーチャー投稿監視 | 高額なX API不要、低コスト |
| **セキュリティベンダー/CERT** | JPCERT/CC, IPA, ScanNetSecurity, Security Next, BleepingComputer, CISA 等のRSS | 完全無料・高精度 |

### 高性能 Web ダッシュボード (SOC GUI)
- **タイムライン & インシデント詳細**: 危険度（Critical/High/Medium/Low）、国内標的（Direct/Indirect）、被害組織、攻撃者グループ、推奨対策を瞬時に閲覧。
- **収集ソースGUI管理**: RSSフィード、ダークウェブターゲット、Telegramチャンネル、検索クエリの追加・トグルON/OFF・削除を画面から直感操作。
- **YAML設定ファイル エクスポート**: GUIで更新した収集設定を即座に `config.yaml` としてダウンロード可能。
- **即時収集実行 & 疎通テスト**: 「即時収集実行」ボタンによる非同期パイプライン実行、Discord/Slack/Notion連携テスト。

### 統一 YAML 設定 (`config.yaml`) & データベース
- **統一設定管理**: すべての接続先（DB、Tor、Notion、Webhook、Gemini）と収集ソースを単一の `config.yaml` で管理。`${ENV_VAR}` 展開に対応。
- **CloudNativePG (CNPG) on k3s 対応**: 本番運用では Kubernetes / k3s 上の PostgreSQL (CNPG) を第一級サポート。ローカル開発時は SQLite に自動フォールバック。

---

## 2. クイックスタート (Web ダッシュボード起動)

### ローカル実行
```bash
# 仮想環境の依存関係インストール
pip install -r requirements.txt

# Web ダッシュボードの起動 (デフォルトポート: 8080)
python app.py
# または
harvester serve --port 8080

# ブラウザでアクセス
open http://localhost:8080
```

### Docker による起動
```bash
# イメージのビルド
docker build -t information_harvester:latest .

# コンテナ起動 (Web UI)
docker run -p 8080:8080 \
  -e GEMINI_API_KEY="your-gemini-api-key" \
  -e DISCORD_WEBHOOK_URL="your-discord-webhook" \
  information_harvester:latest
```

---

## 3. CLI 運用 (`harvester`)

コンテナ内またはローカル環境から CLI コマンドによる調査・テストも可能です。

```bash
# 1. Web ダッシュボード起動
harvester serve --port 8080

# 2. システム・ソース・プロキシの稼働状況ヘルスチェック
harvester status

# 3. 全収集ソースの一括実行 (直近24時間)
harvester run --hours 24
harvester run --hours 24 --direct-only    # 日本直接標的のみ通知

# 4. 各ソース単体の動作テスト (vendor, web, tor, telegram, x)
harvester test --source vendor
harvester test --source telegram
harvester test --source web

# 5. Gemini Search Grounding を使った即時脅威クエリ
harvester search "日本国内 ランサムウェア 被害"

# 6. Tor SOCKS5経由での onion URL / Web 接続テスト
harvester test-onion "http://check.torproject.org"

# 7. 収集済みインシデントの確認
harvester history                 # 直近の収集一覧テーブル表示
harvester history --japan-only    # 日本直接標的のみ絞り込み
harvester show <ID>               # 詳細・要約・影響・推奨対策を表示

# 8. 通知・レポート機能の疎通テスト
harvester test-notify             # 設定済みWebhook (Discord/Slack/Generic) にテスト通知
harvester test-notion             # Notionデータベースにテストページ起票
```

---

## 4. Kubernetes / k3s (CloudNativePG) デプロイ

Helm Chart (`charts/information-harvester`) を使用して k3s や Kubernetes クラスタへデプロイします。

### 1. CloudNativePG (PostgreSQL) 連携
k3s クラスタ上に CloudNativePG (CNPG) を配置している場合、CNPG が生成する Secret (`<cluster-name>-app`) の `uri` キーから自動接続できます。

```bash
helm upgrade --install information-harvester ./charts/information-harvester \
  --namespace security \
  --create-namespace \
  --set database.type="postgres" \
  --set database.existingSecret="information-harvester-db-app" \
  --set secrets.geminiApiKey="YOUR_GEMINI_API_KEY" \
  --set secrets.discordWebhookUrl="YOUR_DISCORD_WEBHOOK_URL"
```

※ 本 Chart 内で直接 CNPG Cluster マニフェストを作成する場合は、`--set database.cnpg.enabled=true` を指定します。

### 2. ポートフォワードによるダッシュボード確認
```bash
kubectl port-forward svc/information-harvester 8080:8080 -n security
# ブラウザで http://localhost:8080 にアクセス
```

---

## 5. 開発規約・コミュニティ

- **開発規約**: コミット規約（SSH/GPG署名必須）やエージェント対応方針は [AGENT.md](AGENT.md) に定義されています。
- **コントリビューション**: プルリクエストや機能提案の手順は [CONTRIBUTING.md](CONTRIBUTING.md) をご覧ください。
- **タスク追跡**: 進捗状況および今後のロードマップは [docs/task_tracker.md](docs/task_tracker.md) を参照してください。
- **セキュリティ & 免責事項**: 脆弱性報告や利用上の免責事項は [SECURITY.md](SECURITY.md) をご確認ください。

---

## 6. ライセンス (License)

本プロジェクトは **[MIT License](LICENSE)** の下で公開されているオープンソースソフトウェアです。  
商用・非商用を問わず自由にご利用・改変・再配布いただけます。
