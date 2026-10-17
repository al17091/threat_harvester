package harvesters

import (
	"context"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
)

type Harvester interface {
	Name() string
	SourceType() models.SourceType
	Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error)
	TestConnection(ctx context.Context) bool
}
