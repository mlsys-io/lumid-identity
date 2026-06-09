package models

import "time"

// GpuRental is a per-user record of a GPU rental submitted to FlowMesh.
// Replaces the old client-side localStorage registry so the rentals list +
// detail can be served from the backend (and rendered by a generated
// lumid:table via the me://gpu-rentals source).
type GpuRental struct {
	ID          string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	UserID      string    `gorm:"type:varchar(36);index;not null" json:"-"`
	Name        string    `gorm:"type:varchar(128)" json:"name"`
	TaskID      string    `gorm:"type:varchar(64);index" json:"task_id"`
	WorkflowID  string    `gorm:"type:varchar(64)" json:"workflow_id"`
	GPU         int       `json:"gpu"`
	GPUMemoryGB int       `json:"gpu_memory_gb"`
	CPU         int       `json:"cpu"`
	MemoryGB    int       `json:"memory_gb"`
	Mode        string    `gorm:"type:varchar(16)" json:"mode"`
	TTLSeconds  int       `json:"ttl_seconds"`
	Status      string    `gorm:"type:varchar(24)" json:"status"` // submitted|running|done|cancelled|error
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (GpuRental) TableName() string { return "gpu_rentals" }
