package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
	_ "modernc.org/sqlite"
)

// Storage handles all persistence logic with SQLite.
type Storage struct {
	db *sql.DB
	mu sync.RWMutex
}

// New initializes the SQLite database, establishes tables, and configures WAL mode.
func New(dbPath string) (*Storage, error) {
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory %s: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for SQLite
	db.SetMaxOpenConns(1) // Single writer safe for SQLite
	db.SetMaxIdleConns(1)

	s := &Storage{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return s, nil
}

func (s *Storage) initSchema() error {
	queries := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA foreign_keys=ON;`,
		`CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL UNIQUE,
			mac TEXT,
			hostname TEXT,
			vendor TEXT,
			status TEXT NOT NULL DEFAULT 'up',
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS services (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			service_name TEXT,
			product TEXT,
			version TEXT,
			state TEXT NOT NULL DEFAULT 'open',
			updated_at DATETIME NOT NULL,
			UNIQUE(device_id, port, protocol)
		);`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			service_port INTEGER NOT NULL,
			cve_id TEXT NOT NULL,
			title TEXT,
			severity TEXT NOT NULL DEFAULT 'UNKNOWN',
			cvss_score REAL DEFAULT 0.0,
			description TEXT,
			reference_url TEXT,
			detected_at DATETIME NOT NULL,
			UNIQUE(device_id, service_port, cve_id)
		);`,
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_type TEXT NOT NULL,
			status TEXT NOT NULL,
			target_spec TEXT NOT NULL,
			hosts_found INTEGER DEFAULT 0,
			vulns_found INTEGER DEFAULT 0,
			duration_ms INTEGER DEFAULT 0,
			error_message TEXT,
			started_at DATETIME NOT NULL,
			completed_at DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS device_scan_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			status TEXT NOT NULL DEFAULT 'up',
			is_vulnerable INTEGER NOT NULL DEFAULT 0,
			vulns_count INTEGER NOT NULL DEFAULT 0,
			max_severity TEXT NOT NULL DEFAULT 'NONE',
			recorded_at DATETIME NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);`,
		`CREATE INDEX IF NOT EXISTS idx_services_device_id ON services(device_id);`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device_id ON vulnerabilities(device_id);`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_device_scan_records_device ON device_scan_records(device_id, recorded_at);`,
		`CREATE INDEX IF NOT EXISTS idx_device_scan_records_scan ON device_scan_records(scan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_device_scan_records_recorded_at ON device_scan_records(recorded_at);`,
	}

	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("executing schema query (%s): %w", query, err)
		}
	}

	return nil
}

// Close closes the underlying database handle.
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// UpsertDevice inserts a new device or updates last_seen/metadata of an existing one.
// Returns the updated device and isNew=true if the device was seen for the first time.
func (s *Storage) UpsertDevice(ctx context.Context, dev *model.Device) (*model.Device, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	var existingID int64
	var firstSeen time.Time
	var existingStatus string

	querySelect := `SELECT id, first_seen, status FROM devices WHERE ip = ?;`
	err := s.db.QueryRowContext(ctx, querySelect, dev.IP).Scan(&existingID, &firstSeen, &existingStatus)

	if err == sql.ErrNoRows {
		// New device
		insertQuery := `INSERT INTO devices (ip, mac, hostname, vendor, status, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?);`
		status := dev.Status
		if status == "" {
			status = "up"
		}
		res, err := s.db.ExecContext(ctx, insertQuery, dev.IP, dev.MAC, dev.Hostname, dev.Vendor, status, now, now)
		if err != nil {
			return nil, false, fmt.Errorf("inserting device: %w", err)
		}

		id, _ := res.LastInsertId()
		dev.ID = id
		dev.FirstSeen = now
		dev.LastSeen = now
		dev.Status = status
		return dev, true, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("querying device: %w", err)
	}

	// Existing device: update last_seen and any newly detected metadata
	updateQuery := `UPDATE devices SET
		last_seen = ?,
		status = ?,
		mac = CASE WHEN ? != '' THEN ? ELSE mac END,
		hostname = CASE WHEN ? != '' THEN ? ELSE hostname END,
		vendor = CASE WHEN ? != '' THEN ? ELSE vendor END
		WHERE id = ?;`

	status := dev.Status
	if status == "" {
		status = "up"
	}

	_, err = s.db.ExecContext(ctx, updateQuery, now, status, dev.MAC, dev.MAC, dev.Hostname, dev.Hostname, dev.Vendor, dev.Vendor, existingID)
	if err != nil {
		return nil, false, fmt.Errorf("updating device: %w", err)
	}

	dev.ID = existingID
	dev.FirstSeen = firstSeen
	dev.LastSeen = now
	dev.Status = status
	return dev, false, nil
}

// GetDevices returns all devices, optionally filtered by status ("up" or "down").
func (s *Storage) GetDevices(ctx context.Context, statusFilter string) ([]model.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT d.id, d.ip, COALESCE(d.mac, ''), COALESCE(d.hostname, ''), COALESCE(d.vendor, ''),
		d.status, d.first_seen, d.last_seen,
		(SELECT COUNT(*) FROM services s WHERE s.device_id = d.id) as services_count,
		(SELECT COUNT(*) FROM vulnerabilities v WHERE v.device_id = d.id) as vulns_count
		FROM devices d`

	var rows *sql.Rows
	var err error

	if statusFilter != "" {
		query += ` WHERE d.status = ? ORDER BY d.last_seen DESC;`
		rows, err = s.db.QueryContext(ctx, query, statusFilter)
	} else {
		query += ` ORDER BY d.last_seen DESC;`
		rows, err = s.db.QueryContext(ctx, query)
	}

	if err != nil {
		return nil, fmt.Errorf("querying devices: %w", err)
	}
	defer rows.Close()

	var devices []model.Device
	for rows.Next() {
		var d model.Device
		if err := rows.Scan(&d.ID, &d.IP, &d.MAC, &d.Hostname, &d.Vendor, &d.Status, &d.FirstSeen, &d.LastSeen, &d.ServicesCount, &d.VulnerabilitiesCount); err != nil {
			return nil, fmt.Errorf("scanning device row: %w", err)
		}
		devices = append(devices, d)
	}

	return devices, nil
}

// GetDeviceByID returns a single device with all associated services and vulnerabilities.
func (s *Storage) GetDeviceByID(ctx context.Context, id int64) (*model.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, ip, COALESCE(mac, ''), COALESCE(hostname, ''), COALESCE(vendor, ''),
		status, first_seen, last_seen
		FROM devices WHERE id = ?;`

	var d model.Device
	err := s.db.QueryRowContext(ctx, query, id).Scan(&d.ID, &d.IP, &d.MAC, &d.Hostname, &d.Vendor, &d.Status, &d.FirstSeen, &d.LastSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("querying device by id: %w", err)
	}

	// Fetch services
	services, err := s.getServicesForDevice(ctx, d.ID, d.IP)
	if err != nil {
		return nil, err
	}
	d.Services = services
	d.ServicesCount = len(services)

	// Fetch vulnerabilities
	vulns, err := s.getVulnerabilitiesForDevice(ctx, d.ID, d.IP)
	if err != nil {
		return nil, err
	}
	d.Vulnerabilities = vulns
	d.VulnerabilitiesCount = len(vulns)

	return &d, nil
}

// GetDeviceByIP retrieves a device record by its IP.
func (s *Storage) GetDeviceByIP(ctx context.Context, ip string) (*model.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, ip, COALESCE(mac, ''), COALESCE(hostname, ''), COALESCE(vendor, ''),
		status, first_seen, last_seen
		FROM devices WHERE ip = ?;`

	var d model.Device
	err := s.db.QueryRowContext(ctx, query, ip).Scan(&d.ID, &d.IP, &d.MAC, &d.Hostname, &d.Vendor, &d.Status, &d.FirstSeen, &d.LastSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("querying device by ip: %w", err)
	}

	return &d, nil
}

// GetActiveDeviceIPs returns IPs of devices marked as 'up'.
func (s *Storage) GetActiveDeviceIPs(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `SELECT ip FROM devices WHERE status = 'up' ORDER BY last_seen DESC;`)
	if err != nil {
		return nil, fmt.Errorf("querying active device IPs: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// UpsertService saves or updates a detected service for a device.
func (s *Storage) UpsertService(ctx context.Context, svc *model.Service) (*model.Service, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	query := `INSERT INTO services (device_id, port, protocol, service_name, product, version, state, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id, port, protocol) DO UPDATE SET
			service_name = excluded.service_name,
			product = excluded.product,
			version = excluded.version,
			state = excluded.state,
			updated_at = excluded.updated_at
		RETURNING id;`

	state := svc.State
	if state == "" {
		state = "open"
	}

	var id int64
	err := s.db.QueryRowContext(ctx, query,
		svc.DeviceID, svc.Port, svc.Protocol, svc.ServiceName, svc.Product, svc.Version, state, now,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("upserting service: %w", err)
	}

	svc.ID = id
	svc.UpdatedAt = now
	return svc, nil
}

// UpsertVulnerability saves a detected vulnerability or updates its details.
// Returns isNew=true if newly inserted.
func (s *Storage) UpsertVulnerability(ctx context.Context, v *model.Vulnerability) (*model.Vulnerability, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	var existingID int64
	checkQuery := `SELECT id FROM vulnerabilities WHERE device_id = ? AND service_port = ? AND cve_id = ?;`
	err := s.db.QueryRowContext(ctx, checkQuery, v.DeviceID, v.ServicePort, v.CVEID).Scan(&existingID)

	if err == sql.ErrNoRows {
		insertQuery := `INSERT INTO vulnerabilities (device_id, service_port, cve_id, title, severity, cvss_score, description, reference_url, detected_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`
		res, err := s.db.ExecContext(ctx, insertQuery,
			v.DeviceID, v.ServicePort, v.CVEID, v.Title, v.Severity, v.CVSSScore, v.Description, v.ReferenceURL, now,
		)
		if err != nil {
			return nil, false, fmt.Errorf("inserting vulnerability: %w", err)
		}
		id, _ := res.LastInsertId()
		v.ID = id
		v.DetectedAt = now
		return v, true, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("checking vulnerability: %w", err)
	}

	// Update existing
	updateQuery := `UPDATE vulnerabilities SET
		title = COALESCE(NULLIF(?, ''), title),
		severity = COALESCE(NULLIF(?, ''), severity),
		cvss_score = CASE WHEN ? > 0 THEN ? ELSE cvss_score END,
		description = COALESCE(NULLIF(?, ''), description),
		reference_url = COALESCE(NULLIF(?, ''), reference_url),
		detected_at = ?
		WHERE id = ?;`

	_, err = s.db.ExecContext(ctx, updateQuery,
		v.Title, v.Severity, v.CVSSScore, v.CVSSScore, v.Description, v.ReferenceURL, now, existingID,
	)
	if err != nil {
		return nil, false, fmt.Errorf("updating vulnerability: %w", err)
	}

	v.ID = existingID
	v.DetectedAt = now
	return v, false, nil
}

func (s *Storage) getServicesForDevice(ctx context.Context, deviceID int64, deviceIP string) ([]model.Service, error) {
	query := `SELECT id, device_id, port, protocol, COALESCE(service_name, ''), COALESCE(product, ''), COALESCE(version, ''), state, updated_at
		FROM services WHERE device_id = ? ORDER BY port ASC;`

	rows, err := s.db.QueryContext(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("querying services for device %d: %w", deviceID, err)
	}
	defer rows.Close()

	var services []model.Service
	for rows.Next() {
		var svc model.Service
		if err := rows.Scan(&svc.ID, &svc.DeviceID, &svc.Port, &svc.Protocol, &svc.ServiceName, &svc.Product, &svc.Version, &svc.State, &svc.UpdatedAt); err != nil {
			return nil, err
		}
		svc.DeviceIP = deviceIP
		services = append(services, svc)
	}
	return services, nil
}

func (s *Storage) getVulnerabilitiesForDevice(ctx context.Context, deviceID int64, deviceIP string) ([]model.Vulnerability, error) {
	query := `SELECT id, device_id, service_port, cve_id, COALESCE(title, ''), severity, cvss_score, COALESCE(description, ''), COALESCE(reference_url, ''), detected_at
		FROM vulnerabilities WHERE device_id = ? ORDER BY cvss_score DESC;`

	rows, err := s.db.QueryContext(ctx, query, deviceID)
	if err != nil {
		return nil, fmt.Errorf("querying vulnerabilities for device %d: %w", deviceID, err)
	}
	defer rows.Close()

	var vulns []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		if err := rows.Scan(&v.ID, &v.DeviceID, &v.ServicePort, &v.CVEID, &v.Title, &v.Severity, &v.CVSSScore, &v.Description, &v.ReferenceURL, &v.DetectedAt); err != nil {
			return nil, err
		}
		v.DeviceIP = deviceIP
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// GetAllServices retrieves all detected services across all devices.
func (s *Storage) GetAllServices(ctx context.Context) ([]model.Service, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT s.id, s.device_id, d.ip, s.port, s.protocol, COALESCE(s.service_name, ''),
		COALESCE(s.product, ''), COALESCE(s.version, ''), s.state, s.updated_at
		FROM services s
		JOIN devices d ON d.id = s.device_id
		ORDER BY d.ip ASC, s.port ASC;`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("querying all services: %w", err)
	}
	defer rows.Close()

	var services []model.Service
	for rows.Next() {
		var svc model.Service
		if err := rows.Scan(&svc.ID, &svc.DeviceID, &svc.DeviceIP, &svc.Port, &svc.Protocol, &svc.ServiceName, &svc.Product, &svc.Version, &svc.State, &svc.UpdatedAt); err != nil {
			return nil, err
		}
		services = append(services, svc)
	}
	return services, nil
}

// GetAllVulnerabilities retrieves all detected CVEs, optionally filtered by severity.
func (s *Storage) GetAllVulnerabilities(ctx context.Context, severity string) ([]model.Vulnerability, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT v.id, v.device_id, d.ip, v.service_port, v.cve_id, COALESCE(v.title, ''),
		v.severity, v.cvss_score, COALESCE(v.description, ''), COALESCE(v.reference_url, ''), v.detected_at
		FROM vulnerabilities v
		JOIN devices d ON d.id = v.device_id`

	var rows *sql.Rows
	var err error

	if severity != "" {
		query += ` WHERE UPPER(v.severity) = UPPER(?) ORDER BY v.cvss_score DESC, v.detected_at DESC;`
		rows, err = s.db.QueryContext(ctx, query, severity)
	} else {
		query += ` ORDER BY v.cvss_score DESC, v.detected_at DESC;`
		rows, err = s.db.QueryContext(ctx, query)
	}

	if err != nil {
		return nil, fmt.Errorf("querying vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulns []model.Vulnerability
	for rows.Next() {
		var v model.Vulnerability
		if err := rows.Scan(&v.ID, &v.DeviceID, &v.DeviceIP, &v.ServicePort, &v.CVEID, &v.Title, &v.Severity, &v.CVSSScore, &v.Description, &v.ReferenceURL, &v.DetectedAt); err != nil {
			return nil, err
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// CreateScanLog creates a new scan log entry.
func (s *Storage) CreateScanLog(ctx context.Context, log *model.ScanLog) (*model.ScanLog, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	startedAt := log.StartedAt.UTC()
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	query := `INSERT INTO scans (scan_type, status, target_spec, hosts_found, vulns_found, duration_ms, error_message, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?);`

	res, err := s.db.ExecContext(ctx, query,
		log.ScanType, log.Status, log.TargetSpec, log.HostsFound, log.VulnsFound, log.DurationMs, log.ErrorMessage, startedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting scan log: %w", err)
	}

	id, _ := res.LastInsertId()
	log.ID = id
	log.StartedAt = startedAt
	return log, nil
}

// UpdateScanLog updates an existing scan log upon completion or failure.
func (s *Storage) UpdateScanLog(ctx context.Context, log *model.ScanLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	query := `UPDATE scans SET
		status = ?,
		hosts_found = ?,
		vulns_found = ?,
		duration_ms = ?,
		error_message = ?,
		completed_at = ?
		WHERE id = ?;`

	_, err := s.db.ExecContext(ctx, query,
		log.Status, log.HostsFound, log.VulnsFound, log.DurationMs, log.ErrorMessage, now, log.ID,
	)
	if err != nil {
		return fmt.Errorf("updating scan log %d: %w", log.ID, err)
	}
	log.CompletedAt = &now
	return nil
}

// GetRecentScans returns the most recent scan logs.
func (s *Storage) GetRecentScans(ctx context.Context, limit int) ([]model.ScanLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, scan_type, status, target_spec, hosts_found, vulns_found, duration_ms,
		COALESCE(error_message, ''), started_at, completed_at
		FROM scans ORDER BY started_at DESC LIMIT ?;`

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("querying scans: %w", err)
	}
	defer rows.Close()

	var logs []model.ScanLog
	for rows.Next() {
		var l model.ScanLog
		if err := rows.Scan(&l.ID, &l.ScanType, &l.Status, &l.TargetSpec, &l.HostsFound, &l.VulnsFound, &l.DurationMs, &l.ErrorMessage, &l.StartedAt, &l.CompletedAt); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// GetCounts returns summary statistics for dashboard status.
func (s *Storage) GetCounts(ctx context.Context) (totalDevs, activeDevs, totalSvcs, totalVulns int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices;`).Scan(&totalDevs)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE status = 'up';`).Scan(&activeDevs)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM services;`).Scan(&totalSvcs)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities;`).Scan(&totalVulns)

	return totalDevs, activeDevs, totalSvcs, totalVulns, nil
}

// ExportAllData produces a full JSON-ready snapshot of devices, services, and vulnerabilities.
func (s *Storage) ExportAllData(ctx context.Context, cidr string) (*model.ExportData, error) {
	devices, err := s.GetDevices(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("exporting devices: %w", err)
	}

	totalVulns := 0
	for i := range devices {
		services, err := s.getServicesForDevice(ctx, devices[i].ID, devices[i].IP)
		if err != nil {
			return nil, err
		}
		devices[i].Services = services
		devices[i].ServicesCount = len(services)

		vulns, err := s.getVulnerabilitiesForDevice(ctx, devices[i].ID, devices[i].IP)
		if err != nil {
			return nil, err
		}
		devices[i].Vulnerabilities = vulns
		devices[i].VulnerabilitiesCount = len(vulns)
		totalVulns += len(vulns)
	}

	return &model.ExportData{
		ExportedAt:           time.Now().UTC(),
		NetworkCIDR:          cidr,
		TotalDevices:         len(devices),
		TotalVulnerabilities: totalVulns,
		Devices:              devices,
	}, nil
}

// RecordDeviceScanObservation writes a point-in-time device observation snapshot.
func (s *Storage) RecordDeviceScanObservation(ctx context.Context, record *model.DeviceScanRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if record.RecordedAt.IsZero() {
		record.RecordedAt = time.Now().UTC()
	}
	if record.Status == "" {
		record.Status = "up"
	}
	if record.MaxSeverity == "" {
		record.MaxSeverity = "NONE"
	}

	isVulnInt := 0
	if record.IsVulnerable {
		isVulnInt = 1
	}

	query := `INSERT INTO device_scan_records (device_id, scan_id, status, is_vulnerable, vulns_count, max_severity, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?);`
	res, err := s.db.ExecContext(ctx, query,
		record.DeviceID, record.ScanID, record.Status, isVulnInt, record.VulnsCount, record.MaxSeverity, record.RecordedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting device scan record: %w", err)
	}
	id, _ := res.LastInsertId()
	record.ID = id
	return nil
}

// GetDeviceSecurityPosture evaluates the current vulnerability count and max severity for a device.
func (s *Storage) GetDeviceSecurityPosture(ctx context.Context, deviceID int64) (bool, int, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getDeviceSecurityPostureInternal(ctx, deviceID)
}

func (s *Storage) getDeviceSecurityPostureInternal(ctx context.Context, deviceID int64) (bool, int, string, error) {
	query := `SELECT COALESCE(severity, 'UNKNOWN') FROM vulnerabilities WHERE device_id = ?;`
	rows, err := s.db.QueryContext(ctx, query, deviceID)
	if err != nil {
		return false, 0, "NONE", fmt.Errorf("querying vulnerabilities for posture: %w", err)
	}
	defer rows.Close()

	vulnsCount := 0
	highestRank := 0
	maxSeverity := "NONE"

	for rows.Next() {
		var sev string
		if err := rows.Scan(&sev); err != nil {
			return false, 0, "NONE", err
		}
		vulnsCount++
		rank := severityRank(sev)
		if rank > highestRank {
			highestRank = rank
			maxSeverity = strings.ToUpper(sev)
		}
	}

	return vulnsCount > 0, vulnsCount, maxSeverity, nil
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "UNKNOWN":
		return 1
	default:
		return 0
	}
}

// MarkMissingDevicesDown marks devices absent from a discovery sweep as 'down' and writes 'down' scan records.
func (s *Storage) MarkMissingDevicesDown(ctx context.Context, scanID int64, observedIPs []string, scanTime time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if scanTime.IsZero() {
		scanTime = time.Now().UTC()
	}

	observedMap := make(map[string]struct{}, len(observedIPs))
	for _, ip := range observedIPs {
		observedMap[ip] = struct{}{}
	}

	rows, err := s.db.QueryContext(ctx, `SELECT id, ip, status FROM devices;`)
	if err != nil {
		return fmt.Errorf("querying devices for missing check: %w", err)
	}
	defer rows.Close()

	type missingDev struct {
		id    int64
		wasUp bool
	}
	var missing []missingDev

	for rows.Next() {
		var id int64
		var ip, status string
		if err := rows.Scan(&id, &ip, &status); err != nil {
			return fmt.Errorf("scanning device: %w", err)
		}
		if _, observed := observedMap[ip]; !observed {
			missing = append(missing, missingDev{id: id, wasUp: status == "up"})
		}
	}
	rows.Close()

	for _, dev := range missing {
		if dev.wasUp {
			if _, err := s.db.ExecContext(ctx, `UPDATE devices SET status = 'down' WHERE id = ?;`, dev.id); err != nil {
				return fmt.Errorf("updating device %d to down: %w", dev.id, err)
			}
		}

		insertRecord := `INSERT INTO device_scan_records (device_id, scan_id, status, is_vulnerable, vulns_count, max_severity, recorded_at)
			VALUES (?, ?, 'down', 0, 0, 'NONE', ?);`
		if _, err := s.db.ExecContext(ctx, insertRecord, dev.id, scanID, scanTime); err != nil {
			return fmt.Errorf("inserting down record for device %d: %w", dev.id, err)
		}
	}

	return nil
}

// GetTimeline returns scan ticks and continuous device activity periods across a time window.
func (s *Storage) GetTimeline(ctx context.Context, from, to time.Time, statusFilter string, vulnerableOnly bool) (*model.TimelineResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if to.IsZero() {
		to = time.Now().UTC()
	}
	if from.IsZero() {
		from = to.Add(-24 * time.Hour)
	}

	// 1. Fetch scan ticks in time window
	scanQuery := `SELECT id, started_at, scan_type, status, target_spec, hosts_found, duration_ms
		FROM scans WHERE started_at >= ? AND started_at <= ? ORDER BY started_at ASC;`
	scanRows, err := s.db.QueryContext(ctx, scanQuery, from, to)
	if err != nil {
		return nil, fmt.Errorf("querying scans for timeline: %w", err)
	}
	defer scanRows.Close()

	var scanTicks []model.ScanTick
	for scanRows.Next() {
		var tick model.ScanTick
		if err := scanRows.Scan(&tick.ScanID, &tick.Timestamp, &tick.ScanType, &tick.Status, &tick.TargetSpec, &tick.HostsFound, &tick.DurationMs); err != nil {
			return nil, fmt.Errorf("scanning scan tick: %w", err)
		}
		scanTicks = append(scanTicks, tick)
	}
	scanRows.Close()
	if scanTicks == nil {
		scanTicks = []model.ScanTick{}
	}

	// 2. Fetch devices (with optional status filter)
	devQuery := `SELECT id, ip, COALESCE(mac, ''), COALESCE(hostname, ''), COALESCE(vendor, ''), status, first_seen, last_seen FROM devices`
	var devRows *sql.Rows
	if statusFilter != "" {
		devQuery += ` WHERE status = ? ORDER BY ip ASC;`
		devRows, err = s.db.QueryContext(ctx, devQuery, statusFilter)
	} else {
		devQuery += ` ORDER BY ip ASC;`
		devRows, err = s.db.QueryContext(ctx, devQuery)
	}
	if err != nil {
		return nil, fmt.Errorf("querying devices for timeline: %w", err)
	}
	defer devRows.Close()

	type devMeta struct {
		id        int64
		ip        string
		mac       string
		hostname  string
		vendor    string
		status    string
		firstSeen time.Time
		lastSeen  time.Time
	}
	var devList []devMeta
	for devRows.Next() {
		var d devMeta
		if err := devRows.Scan(&d.id, &d.ip, &d.mac, &d.hostname, &d.vendor, &d.status, &d.firstSeen, &d.lastSeen); err != nil {
			return nil, fmt.Errorf("scanning device: %w", err)
		}
		devList = append(devList, d)
	}
	devRows.Close()

	// 3. Fetch scan records for these devices in time window
	recordQuery := `SELECT device_id, status, is_vulnerable, vulns_count, max_severity, recorded_at
		FROM device_scan_records
		WHERE recorded_at >= ? AND recorded_at <= ?
		ORDER BY device_id ASC, recorded_at ASC;`
	recRows, err := s.db.QueryContext(ctx, recordQuery, from, to)
	if err != nil {
		return nil, fmt.Errorf("querying device scan records: %w", err)
	}
	defer recRows.Close()

	recordsByDev := make(map[int64][]model.DeviceScanRecord)
	for recRows.Next() {
		var rec model.DeviceScanRecord
		var isVulnInt int
		if err := recRows.Scan(&rec.DeviceID, &rec.Status, &isVulnInt, &rec.VulnsCount, &rec.MaxSeverity, &rec.RecordedAt); err != nil {
			return nil, fmt.Errorf("scanning record: %w", err)
		}
		rec.IsVulnerable = isVulnInt == 1
		recordsByDev[rec.DeviceID] = append(recordsByDev[rec.DeviceID], rec)
	}
	recRows.Close()

	// 4. Build timeline periods for each device
	var timelineDevices []model.TimelineDevice
	for _, dev := range devList {
		records := recordsByDev[dev.id]
		var periods []model.TimelinePeriod

		if len(records) > 0 {
			var currentPeriod *model.TimelinePeriod

			for _, rec := range records {
				if currentPeriod == nil {
					currentPeriod = &model.TimelinePeriod{
						StartedAt:    rec.RecordedAt,
						EndedAt:      rec.RecordedAt,
						Status:       rec.Status,
						IsVulnerable: rec.IsVulnerable,
						VulnsCount:   rec.VulnsCount,
						MaxSeverity:  rec.MaxSeverity,
						IsOngoing:    false,
					}
					continue
				}

				// Check for state shift: status change, vulnerability change, or max severity change
				stateChanged := (currentPeriod.Status != rec.Status) ||
					(currentPeriod.IsVulnerable != rec.IsVulnerable) ||
					(currentPeriod.MaxSeverity != rec.MaxSeverity)

				if stateChanged {
					// Close previous period
					periods = append(periods, *currentPeriod)
					// Start new period
					currentPeriod = &model.TimelinePeriod{
						StartedAt:    rec.RecordedAt,
						EndedAt:      rec.RecordedAt,
						Status:       rec.Status,
						IsVulnerable: rec.IsVulnerable,
						VulnsCount:   rec.VulnsCount,
						MaxSeverity:  rec.MaxSeverity,
						IsOngoing:    false,
					}
				} else {
					// Extend current period
					currentPeriod.EndedAt = rec.RecordedAt
					if rec.VulnsCount > currentPeriod.VulnsCount {
						currentPeriod.VulnsCount = rec.VulnsCount
					}
				}
			}

			if currentPeriod != nil {
				// If device is up and the period is active up to the latest known records, mark ongoing
				if dev.status == currentPeriod.Status {
					currentPeriod.IsOngoing = true
					if to.After(currentPeriod.EndedAt) {
						currentPeriod.EndedAt = to
					}
				}
				periods = append(periods, *currentPeriod)
			}
		} else {
			// Fallback: If no granular scan records yet (e.g. before first scan recorded),
			// synthesize period if first_seen/last_seen intersects window
			if !dev.lastSeen.Before(from) && !dev.firstSeen.After(to) {
				start := dev.firstSeen
				if start.Before(from) {
					start = from
				}
				end := dev.lastSeen
				if end.After(to) {
					end = to
				}

				// Check current vulnerability posture
				isVuln, vulnsCount, maxSev, _ := s.getDeviceSecurityPostureInternal(ctx, dev.id)

				periods = append(periods, model.TimelinePeriod{
					StartedAt:    start,
					EndedAt:      end,
					Status:       dev.status,
					IsVulnerable: isVuln,
					VulnsCount:   vulnsCount,
					MaxSeverity:  maxSev,
					IsOngoing:    dev.status == "up",
				})
			}
		}

		if periods == nil {
			periods = []model.TimelinePeriod{}
		}

		// If vulnerableOnly is set, check if any period has vulnerabilities
		if vulnerableOnly {
			hasVulnPeriod := false
			for _, p := range periods {
				if p.IsVulnerable {
					hasVulnPeriod = true
					break
				}
			}
			if !hasVulnPeriod {
				continue
			}
		}

		timelineDevices = append(timelineDevices, model.TimelineDevice{
			DeviceID:      dev.id,
			IP:            dev.ip,
			MAC:           dev.mac,
			Hostname:      dev.hostname,
			Vendor:        dev.vendor,
			CurrentStatus: dev.status,
			Periods:       periods,
		})
	}

	if timelineDevices == nil {
		timelineDevices = []model.TimelineDevice{}
	}

	return &model.TimelineResponse{
		TimeWindow: model.TimelineTimeWindow{
			From:         from,
			To:           to,
			TotalScans:   len(scanTicks),
			TotalDevices: len(timelineDevices),
		},
		ScanTicks: scanTicks,
		Devices:   timelineDevices,
	}, nil
}
