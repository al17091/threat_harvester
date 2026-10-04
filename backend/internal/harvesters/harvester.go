package harvesters

import (
	"context"
	"time"

	"github.com/dapt/information_harvester/backend/internal/models"
)

type Harvester interface {
	Name() string
	SourceType() models.SourceType
	Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error)
	TestConnection(ctx context.Context) bool
}
