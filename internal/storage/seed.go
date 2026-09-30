package storage

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/gr0gu/cerberus/internal/model"
)

// SeedMockData populates the database with realistic devices, services, vulnerabilities,
// scans, and point-in-time observation records across a 24-hour timeline.
func (s *Storage) SeedMockData(ctx context.Context) error {
	now := time.Now().UTC()

	log.Println("[Storage Seed] Populating mock timeline data...")

	// 1. Devices
	devs := []struct {
		device *model.Device
		svcs   []model.Service
		vulns  []model.Vulnerability
	}{
		{
			device: &model.Device{
				IP:        "172.28.0.1",
				MAC:       "02:42:AC:1C:00:01",
				Hostname:  "gateway-router",
				Vendor:    "Cisco Systems",
				Status:    "up",
				FirstSeen: now.Add(-24 * time.Hour),
				LastSeen:  now,
			},
			svcs: []model.Service{
				{Port: 53, Protocol: "udp", ServiceName: "dns", Product: "dnsmasq", Version: "2.85", State: "open"},
				{Port: 443, Protocol: "tcp", ServiceName: "https", Product: "cisco-ios-http", Version: "15.2", State: "open"},
			},
		},
		{
			device: &model.Device{
				IP:        "172.28.0.10",
				MAC:       "02:42:AC:1C:00:0A",
				Hostname:  "target-nginx",
				Vendor:    "Docker Inc.",
				Status:    "up",
				FirstSeen: now.Add(-24 * time.Hour),
				LastSeen:  now,
			},
			svcs: []model.Service{
				{Port: 80, Protocol: "tcp", ServiceName: "http", Product: "nginx", Version: "1.21.6", State: "open"},
			},
			vulns: []model.Vulnerability{
				{
					ServicePort:  80,
					CVEID:        "CVE-2021-23017",
					Title:        "1-byte memory overwrite in resolver",
					Severity:     "HIGH",
					CVSSScore:    7.5,
					Description:  "A security issue in nginx 0.6.18-1.20.0 allows an attacker to cause 1-byte memory overwrite via DNS response.",
					ReferenceURL: "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
				},
			},
		},
		{
			device: &model.Device{
				IP:        "172.28.0.20",
				MAC:       "02:42:AC:1C:00:14",
				Hostname:  "target-redis",
				Vendor:    "Docker Inc.",
				Status:    "up",
				FirstSeen: now.Add(-24 * time.Hour),
				LastSeen:  now,
			},
			svcs: []model.Service{
				{Port: 6379, Protocol: "tcp", ServiceName: "redis", Product: "redis-server", Version: "6.2.6", State: "open"},
			},
		},
		{
			device: &model.Device{
				IP:        "172.28.0.30",
				MAC:       "02:42:AC:1C:00:1E",
				Hostname:  "target-dvwa",
				Vendor:    "Linux Foundation",
				Status:    "up",
				FirstSeen: now.Add(-24 * time.Hour),
				LastSeen:  now,
			},
			svcs: []model.Service{
				{Port: 80, Protocol: "tcp", ServiceName: "http", Product: "apache", Version: "2.4.25", State: "open"},
				{Port: 3306, Protocol: "tcp", ServiceName: "mysql", Product: "mysql-server", Version: "5.7.35", State: "open"},
			},
			vulns: []model.Vulnerability{
				{
					ServicePort:  80,
					CVEID:        "CVE-2018-1234",
					Title:        "Arbitrary Code Execution in File Upload",
					Severity:     "CRITICAL",
					CVSSScore:    9.8,
					Description:  "Unauthenticated remote code execution vulnerability in file upload module.",
					ReferenceURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1234",
				},
				{
					ServicePort:  80,
					CVEID:        "CVE-2019-9999",
					Title:        "SQL Injection via Login Authentication",
					Severity:     "HIGH",
					CVSSScore:    8.2,
					Description:  "Blind and error-based SQL injection allows database dump.",
					ReferenceURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9999",
				},
				{
					ServicePort:  80,
					CVEID:        "CVE-2020-5555",
					Title:        "Stored Cross-Site Scripting (XSS)",
					Severity:     "MEDIUM",
					CVSSScore:    5.4,
					Description:  "Stored script execution in guestbook comments.",
					ReferenceURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5555",
				},
			},
		},
		{
			device: &model.Device{
				IP:        "172.28.0.50",
				MAC:       "B8:27:EB:AA:11:99",
				Hostname:  "rogue-iot-cam",
				Vendor:    "Raspberry Pi Foundation",
				Status:    "down",
				FirstSeen: now.Add(-12 * time.Hour),
				LastSeen:  now.Add(-4 * time.Hour),
			},
			svcs: []model.Service{
				{Port: 554, Protocol: "tcp", ServiceName: "rtsp", Product: "live555", Version: "1.0", State: "open"},
				{Port: 8081, Protocol: "tcp", ServiceName: "http", Product: "motion-httpd", Version: "4.3.2", State: "open"},
			},
			vulns: []model.Vulnerability{
				{
					ServicePort:  554,
					CVEID:        "CVE-2022-2900",
					Title:        "Unauthenticated RTSP Stream Disclosure",
					Severity:     "MEDIUM",
					CVSSScore:    6.5,
					Description:  "Flaw in RTSP server allows video stream capture without authentication.",
					ReferenceURL: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2900",
				},
			},
		},
	}

	savedDevMap := make(map[string]*model.Device)
	for _, entry := range devs {
		dev, _, err := s.UpsertDevice(ctx, entry.device)
		if err != nil {
			return fmt.Errorf("seeding device %s: %w", entry.device.IP, err)
		}
		savedDevMap[dev.IP] = dev

		for _, svc := range entry.svcs {
			svc.DeviceID = dev.ID
			if _, err := s.UpsertService(ctx, &svc); err != nil {
				return fmt.Errorf("seeding service %d on %s: %w", svc.Port, dev.IP, err)
			}
		}

		for _, vuln := range entry.vulns {
			vuln.DeviceID = dev.ID
			if _, _, err := s.UpsertVulnerability(ctx, &vuln); err != nil {
				return fmt.Errorf("seeding vuln %s on %s: %w", vuln.CVEID, dev.IP, err)
			}
		}
	}

	// 2. Scans across 24h
	scanSpecs := []struct {
		scanType   string
		startedAt  time.Time
		durationMs int64
		hostsFound int
		vulnsFound int
		targetSpec string
	}{
		{scanType: "discovery", startedAt: now.Add(-20 * time.Hour), durationMs: 1420, hostsFound: 4, targetSpec: "172.28.0.0/24"},
		{scanType: "discovery", startedAt: now.Add(-16 * time.Hour), durationMs: 1390, hostsFound: 4, targetSpec: "172.28.0.0/24"},
		{scanType: "discovery", startedAt: now.Add(-12 * time.Hour), durationMs: 1580, hostsFound: 5, targetSpec: "172.28.0.0/24"},
		{scanType: "immediate", startedAt: now.Add(-11*time.Hour - 45*time.Minute), durationMs: 3820, hostsFound: 1, vulnsFound: 1, targetSpec: "172.28.0.50"},
		{scanType: "vulnerability", startedAt: now.Add(-8 * time.Hour), durationMs: 12450, hostsFound: 5, vulnsFound: 5, targetSpec: "[172.28.0.1 172.28.0.10 172.28.0.20 172.28.0.30 172.28.0.50]"},
		{scanType: "discovery", startedAt: now.Add(-4 * time.Hour), durationMs: 1460, hostsFound: 3, targetSpec: "172.28.0.0/24"},
		{scanType: "discovery", startedAt: now.Add(-1 * time.Hour), durationMs: 1410, hostsFound: 4, targetSpec: "172.28.0.0/24"},
		{scanType: "vulnerability", startedAt: now.Add(-30 * time.Minute), durationMs: 9800, hostsFound: 4, vulnsFound: 4, targetSpec: "[172.28.0.1 172.28.0.10 172.28.0.20 172.28.0.30]"},
	}

	type obsRecord struct {
		ip     string
		status string
		isVuln bool
		vulns  int
		maxSev string
	}

	// Map of scan index -> list of observations
	obsMatrix := [][]obsRecord{
		// Scan 0 (-20h, discovery): 4 hosts alive, clean
		{
			{ip: "172.28.0.1", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.10", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.20", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.30", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
		},
		// Scan 1 (-16h, discovery): 4 hosts alive, clean
		{
			{ip: "172.28.0.1", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.10", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.20", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.30", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
		},
		// Scan 2 (-12h, discovery): rogue-iot-cam (172.28.0.50) appears
		{
			{ip: "172.28.0.1", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.10", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.20", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.30", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.50", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
		},
		// Scan 3 (-11h45m, immediate vuln scan on 172.28.0.50): MEDIUM vuln found
		{
			{ip: "172.28.0.50", status: "up", isVuln: true, vulns: 1, maxSev: "MEDIUM"},
		},
		// Scan 4 (-8h, full vulnerability scan): 172.28.0.10 HIGH, 172.28.0.30 CRITICAL, 172.28.0.50 MEDIUM
		{
			{ip: "172.28.0.1", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.10", status: "up", isVuln: true, vulns: 1, maxSev: "HIGH"},
			{ip: "172.28.0.20", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.30", status: "up", isVuln: true, vulns: 3, maxSev: "CRITICAL"},
			{ip: "172.28.0.50", status: "up", isVuln: true, vulns: 1, maxSev: "MEDIUM"},
		},
		// Scan 5 (-4h, discovery): 172.28.0.20 and 172.28.0.50 drop offline
		{
			{ip: "172.28.0.1", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.10", status: "up", isVuln: true, vulns: 1, maxSev: "HIGH"},
			{ip: "172.28.0.20", status: "down", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.30", status: "up", isVuln: true, vulns: 3, maxSev: "CRITICAL"},
			{ip: "172.28.0.50", status: "down", isVuln: false, vulns: 0, maxSev: "NONE"},
		},
		// Scan 6 (-1h, discovery): 172.28.0.20 recovers up, 172.28.0.50 still down
		{
			{ip: "172.28.0.1", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.10", status: "up", isVuln: true, vulns: 1, maxSev: "HIGH"},
			{ip: "172.28.0.20", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.30", status: "up", isVuln: true, vulns: 3, maxSev: "CRITICAL"},
			{ip: "172.28.0.50", status: "down", isVuln: false, vulns: 0, maxSev: "NONE"},
		},
		// Scan 7 (-30m, vulnerability audit on active hosts)
		{
			{ip: "172.28.0.1", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.10", status: "up", isVuln: true, vulns: 1, maxSev: "HIGH"},
			{ip: "172.28.0.20", status: "up", isVuln: false, vulns: 0, maxSev: "NONE"},
			{ip: "172.28.0.30", status: "up", isVuln: true, vulns: 3, maxSev: "CRITICAL"},
		},
	}

	for i, spec := range scanSpecs {
		scanLog, err := s.CreateScanLog(ctx, &model.ScanLog{
			ScanType:   spec.scanType,
			Status:     "completed",
			TargetSpec: spec.targetSpec,
			HostsFound: spec.hostsFound,
			VulnsFound: spec.vulnsFound,
			DurationMs: spec.durationMs,
			StartedAt:  spec.startedAt,
		})
		if err != nil {
			return fmt.Errorf("seeding scan %d: %w", i, err)
		}

		if i < len(obsMatrix) {
			for _, obs := range obsMatrix[i] {
				dev := savedDevMap[obs.ip]
				if dev == nil {
					continue
				}
				err := s.RecordDeviceScanObservation(ctx, &model.DeviceScanRecord{
					DeviceID:     dev.ID,
					ScanID:       scanLog.ID,
					Status:       obs.status,
					IsVulnerable: obs.isVuln,
					VulnsCount:   obs.vulns,
					MaxSeverity:  obs.maxSev,
					RecordedAt:   spec.startedAt,
				})
				if err != nil {
					return fmt.Errorf("seeding observation for %s in scan %d: %w", obs.ip, i, err)
				}
			}
		}
	}

	log.Println("[Storage Seed] Successfully seeded 5 mock devices, services, CVEs, 8 scans, and 29 observations.")
	return nil
}
