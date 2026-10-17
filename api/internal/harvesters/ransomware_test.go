package harvesters

import (
	"context"
	"testing"

	"github.com/al17091/threat_harvester/api/internal/models"
)

func TestHarvesterSourceTypes(t *testing.T) {
	dw := NewDarkwebOnionHarvester()
	if dw.SourceType() != models.SourceTypeDarkwebOnion {
		t.Fatalf("expected darkweb harvester to have SourceTypeDarkwebOnion, got: %s", dw.SourceType())
	}

	rw := NewRansomwareTrackerHarvester()
	if rw.SourceType() != models.SourceTypeRansomwareTracker {
		t.Fatalf("expected ransomware tracker to have SourceTypeRansomwareTracker, got: %s", rw.SourceType())
	}
}

func TestDarkwebSkipsNonOnion(t *testing.T) {
	dw := NewDarkwebOnionHarvester()
	ctx := context.Background()

	// Should not panic, and will skip any clearnet items
	items, err := dw.Harvest(ctx, nil)
	if err != nil {
		t.Fatalf("Harvest returned error: %v", err)
	}

	for _, item := range items {
		if item.SourceType != models.SourceTypeDarkwebOnion {
			t.Errorf("expected SourceTypeDarkwebOnion, got: %s", item.SourceType)
		}
	}
}
