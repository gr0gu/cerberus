package model

import "time"

// Device represents a network host discovered by Cerberus.
type Device struct {
	ID                   int64           `json:"id"`
	IP                   string          `json:"ip"`
	MAC                  string          `json:"mac,omitempty"`
	Hostname             string          `json:"hostname,omitempty"`
	Vendor               string          `json:"vendor,omitempty"`
	Status               string          `json:"status"` // "up" or "down"
	FirstSeen            time.Time       `json:"first_seen"`
	LastSeen             time.Time       `json:"last_seen"`
	ServicesCount        int             `json:"services_count"`
	VulnerabilitiesCount int             `json:"vulnerabilities_count"`
	Services             []Service       `json:"services,omitempty"`
	Vulnerabilities      []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Service represents a network service running on an open port of a device.
type Service struct {
	ID              int64           `json:"id"`
	DeviceID        int64           `json:"device_id"`
	DeviceIP        string          `json:"device_ip,omitempty"`
	Port            int             `json:"port"`
	Protocol        string          `json:"protocol"` // "tcp" or "udp"
	ServiceName     string          `json:"service_name,omitempty"`
	Product         string          `json:"product,omitempty"`
	Version         string          `json:"version,omitempty"`
	State           string          `json:"state"` // "open", "filtered", "closed"
	UpdatedAt       time.Time       `json:"updated_at"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Vulnerability represents an identified CVE or security weakness.
type Vulnerability struct {
	ID           int64     `json:"id"`
	DeviceID     int64     `json:"device_id"`
	DeviceIP     string    `json:"device_ip,omitempty"`
	ServicePort  int       `json:"service_port"`
	CVEID        string    `json:"cve_id"`
	Title        string    `json:"title,omitempty"`
	Severity     string    `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"
	CVSSScore    float64   `json:"cvss_score"`
	Description  string    `json:"description,omitempty"`
	ReferenceURL string    `json:"reference_url,omitempty"`
	DetectedAt   time.Time `json:"detected_at"`
}

// ScanLog records historical scans executed by Cerberus.
type ScanLog struct {
	ID           int64      `json:"id"`
	ScanType     string     `json:"scan_type"` // "discovery", "vulnerability", "immediate"
	Status       string     `json:"status"`    // "running", "completed", "failed"
	TargetSpec   string     `json:"target_spec"`
	HostsFound   int        `json:"hosts_found"`
	VulnsFound   int        `json:"vulns_found"`
	DurationMs   int64      `json:"duration_ms"`
	ErrorMessage string     `json:"error_message,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

// SystemStatus provides a live snapshot of the sentinel.
type SystemStatus struct {
	Uptime               string     `json:"uptime"`
	UptimeSeconds        int64      `json:"uptime_seconds"`
	ActiveDevices        int        `json:"active_devices"`
	TotalDevices         int        `json:"total_devices"`
	TotalServices        int        `json:"total_services"`
	TotalVulnerabilities int        `json:"total_vulnerabilities"`
	DiscoveryNextRun     *time.Time `json:"discovery_next_run,omitempty"`
	VulnNextRun          *time.Time `json:"vuln_next_run,omitempty"`
	IsDiscoveryRunning   bool       `json:"is_discovery_running"`
	IsVulnRunning        bool       `json:"is_vuln_running"`
}

// ExportData represents the complete network sentinel snapshot for JSON export.
type ExportData struct {
	ExportedAt           time.Time `json:"exported_at"`
	NetworkCIDR          string    `json:"network_cidr"`
	TotalDevices         int       `json:"total_devices"`
	TotalVulnerabilities int       `json:"total_vulnerabilities"`
	Devices              []Device  `json:"devices"`
}

// ScanHostResult holds parsed scan results for a single target host.
type ScanHostResult struct {
	IP              string
	MAC             string
	Vendor          string
	Hostname        string
	Status          string
	Services        []Service
	Vulnerabilities []Vulnerability
}
