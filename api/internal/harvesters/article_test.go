package harvesters

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtractArticleTextFromHTML(t *testing.T) {
	sampleHTML := `
<!doctype html>
<html>
<head>
  <title>Security Advisory 2026</title>
  <meta name="description" content="Test advisory description">
</head>
<body>
  <header><nav><a href="/">Home</a></nav></header>
  <aside><div class="widget">Popular News</div></aside>
  <article class="article-body">
    <h2>重大な脆弱性についての告知</h2>
    <p>独立行政法人情報処理推進機構（IPA）およびJPCERT/CCは本日、主要製品に影響を与える重大な脆弱性を公表しました。</p>
    <p>攻撃者はこの脆弱性を悪用することで、遠隔から任意のコードを実行できる可能性があります。</p>
    <p>対象となるシステムを利用している管理者は、速やかに最新バージョンへのアップデートを行ってください。</p>
  </article>
  <footer><p>Copyright © 2026 All Rights Reserved.</p></footer>
</body>
</html>
`
	text, err := ExtractArticleTextFromHTML(sampleHTML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(text, "重大な脆弱性についての告知") {
		t.Errorf("expected heading to be extracted, got: %s", text)
	}
	if !strings.Contains(text, "任意のコードを実行できる可能性") {
		t.Errorf("expected paragraph to be extracted, got: %s", text)
	}
	if strings.Contains(text, "Copyright") {
		t.Errorf("footer copyright notice should have been excluded, got: %s", text)
	}
	if strings.Contains(text, "Popular News") {
		t.Errorf("aside text should have been excluded, got: %s", text)
	}
}

func TestFetchArticleContentServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `
<html>
<body>
  <main>
    <h1>緊急セキュリティ情報</h1>
    <p>某大手製造業のサーバーがランサムウェア攻撃を受け、内部ネットワークが一時遮断されました。</p>
    <p>現在フォレンジック調査を実施中であり、復旧作業を進めています。</p>
  </main>
</body>
</html>
`)
	}))
	defer ts.Close()

	ctx := context.Background()
	text, err := FetchArticleContent(ctx, ts.URL)
	if err != nil {
		t.Fatalf("failed to fetch article: %v", err)
	}

	if !strings.Contains(text, "某大手製造業のサーバーがランサムウェア攻撃を受け") {
		t.Errorf("expected extracted text, got: %s", text)
	}
}

func TestFetchArticleContentRejectsOnion(t *testing.T) {
	ctx := context.Background()
	_, err := FetchArticleContent(ctx, "http://somehiddenleakservice.onion/post/123")
	if err == nil {
		t.Error("expected error for onion URL via clearnet article fetcher")
	}
}

func TestExtractURLsFromText(t *testing.T) {
	text := "Breaking news on zero-day: https://example.com/advisory.html! Check also https://t.me/s/mychannel and https://vendor.org/sec."
	urls := ExtractURLsFromText(text)
	if len(urls) != 2 {
		t.Fatalf("expected 2 crawleable URLs (ignoring t.me), got %d: %v", len(urls), urls)
	}
	if urls[0] != "https://example.com/advisory.html" {
		t.Errorf("expected clean URL, got: %s", urls[0])
	}
	if urls[1] != "https://vendor.org/sec" {
		t.Errorf("expected clean URL, got: %s", urls[1])
	}
}

func TestIsCrawleableURL(t *testing.T) {
	valid := []string{
		"https://example.com/article/1",
		"http://news.portal.jp/news/sec",
		"https://t.co/xyz123", // redirector
	}
	for _, u := range valid {
		if !IsCrawleableURL(u) {
			t.Errorf("expected %s to be crawleable", u)
		}
	}

	invalid := []string{
		"https://t.me/s/channel",
		"https://twitter.com/user/status/123",
		"https://x.com/user",
		"http://darkweb.onion/leak",
		"https://example.com/banner.png",
		"https://example.com/archive.zip",
	}
	for _, u := range invalid {
		if IsCrawleableURL(u) {
			t.Errorf("expected %s to NOT be crawleable", u)
		}
	}
}

func TestFollowAndScrapeLinkedArticles(t *testing.T) {
	// Server 2: secondary advisory linked from server 1
	var s2URL string
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `
<html><body><article>
  <h2>ベンダー公式セキュリティ勧告</h2>
  <p>製品バージョン 2.1.0 以前に影響する脆弱性 CVE-2026-99999 に対するパッチを公開しました。</p>
  <p>ただちにアップデートを実施してください。</p>
</article></body></html>`)
	}))
	defer s2.Close()
	s2URL = s2.URL

	// Server 1: blog post linking to server 2
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `
<html><body><article>
  <h2>速報: 新たな脆弱性が発見されました</h2>
  <p>セキュリティ研究者により、広く使われているコンポーネントにゼロデイが確認されました。</p>
  <p>公式勧告はこちらのリンクを参照してください: <a href="%s">公式セキュリティアドバイザリ</a></p>
</article></body></html>`, s2URL)
	}))
	defer s1.Close()

	ctx := context.Background()
	enriched, visited := FollowAndScrapeLinkedArticles(ctx, []string{s1.URL}, 2)

	if len(visited) != 2 {
		t.Fatalf("expected 2 visited URLs across 2 depths, got %d: %v", len(visited), visited)
	}
	if !strings.Contains(enriched, "速報: 新たな脆弱性が発見されました") {
		t.Errorf("expected level 1 text in enriched content, got: %s", enriched)
	}
	if !strings.Contains(enriched, "ベンダー公式セキュリティ勧告") {
		t.Errorf("expected recursively scraped level 2 text in enriched content, got: %s", enriched)
	}
}

func TestFetchOnionArticleContentValidation(t *testing.T) {
	ctx := context.Background()

	// 1. Empty URL
	_, err := FetchOnionArticleContent(ctx, "", "", 10)
	if err == nil {
		t.Errorf("expected error for empty URL")
	}

	// 2. Non-onion URL
	_, err = FetchOnionArticleContent(ctx, "https://example.com/advisory", "", 10)
	if err == nil {
		t.Errorf("expected error for non-onion URL")
	}

	// 3. doFetchHTMLWithTorClient with mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h1>Onion Leak Site</h1><p>Compromised data list</p></body></html>")
	}))
	defer ts.Close()

	html, err := doFetchHTMLWithTorClient(ctx, ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("doFetchHTMLWithTorClient failed: %v", err)
	}
	if !strings.Contains(html, "Onion Leak Site") {
		t.Errorf("expected HTML to contain Onion Leak Site, got: %s", html)
	}

	// Error response
	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer errServer.Close()

	_, err = doFetchHTMLWithTorClient(ctx, errServer.Client(), errServer.URL)
	if err == nil {
		t.Errorf("expected HTTP status error for 403 status")
	}
}


