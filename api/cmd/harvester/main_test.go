package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

func TestCLICommands(t *testing.T) {
	ctx := context.Background()
	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	// 1. Seed item
	now := time.Now().UTC()
	item := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"Test Vendor",
		"CLI Test Threat",
		"https://example.com/cli",
		"CLI Summary",
		"",
		&now,
		nil,
	)
	_ = store.MarkSeen(ctx, item, nil, false)

	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// 2. printUsage
	printUsage()

	// 3. runStatus
	os.Args = []string{"harvester", "status"}
	runStatus(ctx, store)

	// 4. runHistory
	os.Args = []string{"harvester", "history", "-limit=5"}
	runHistory(ctx, store)

	// 5. runShow
	os.Args = []string{"harvester", "show", item.ID}
	runShow(ctx, store)

	// 6. runTestNotify
	runTestNotify(ctx)

	// 7. runTestNotion
	runTestNotion(ctx)

	// 8. runCron with pre-cancelled context
	cronCtx, cancelCron := context.WithCancel(context.Background())
	cancelCron() // cancel immediately
	runCron(cronCtx, store)

	// 9. runWeb with pre-cancelled context
	webCtx, cancelWeb := context.WithCancel(context.Background())
	cancelWeb() // cancel immediately
	os.Args = []string{"harvester", "web", "-port=18080"}
	runWeb(webCtx, store)

	// 10. runHarvest
	os.Args = []string{"harvester", "run", "-lookback=1", "-direct-only=true"}
	runHarvest(ctx, store)
}

