package scanner

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/gr0gu/cerberus/internal/model"
)

var (
	cveRegex  = regexp.MustCompile(`\bCVE-\d{4}-\d{4,7}\b`)
	cvssRegex = regexp.MustCompile(`\b(10(?:\.0)?|[0-9]\.[0-9])\b`)
)

// ParseNmapXML unmarshals raw XML bytes into NmapRun.
func ParseNmapXML(data []byte) (*NmapRun, error) {
	var run NmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap xml: %w", err)
	}
	return &run, nil
}

// ExtractDevices parses active hosts from an Nmap discovery scan.
func ExtractDevices(run *NmapRun) []model.Device {
	var devices []model.Device

	for _, host := range run.Hosts {
		if host.Status.State != "up" {
			continue
		}

		var ip, mac, vendor, hostname string

		for _, addr := range host.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				if ip == "" {
					ip = addr.Addr
				}
			case "mac":
				mac = addr.Addr
				if addr.Vendor != "" {
					vendor = addr.Vendor
				}
			}
		}

		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0].Name
		}

		if ip == "" {
			continue
		}

		devices = append(devices, model.Device{
			IP:       ip,
			MAC:      mac,
			Hostname: hostname,
			Vendor:   vendor,
			Status:   "up",
		})
	}

	return devices
}

// ExtractHostResults parses ports, services, and vulnerabilities for all hosts.
func ExtractHostResults(run *NmapRun) []model.ScanHostResult {
	var results []model.ScanHostResult

	for _, host := range run.Hosts {
		var ip, mac, vendor, hostname string

		for _, addr := range host.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				if ip == "" {
					ip = addr.Addr
				}
			case "mac":
				mac = addr.Addr
				if addr.Vendor != "" {
					vendor = addr.Vendor
				}
			}
		}

		if len(host.Hostnames) > 0 {
			hostname = host.Hostnames[0].Name
		}

		if ip == "" {
			continue
		}

		var services []model.Service
		var vulns []model.Vulnerability

		for _, p := range host.Ports {
			svcState := p.State.State
			if svcState == "" {
				svcState = "open"
			}

			svc := model.Service{
				DeviceIP:    ip,
				Port:        p.PortID,
				Protocol:    p.Protocol,
				ServiceName: p.Service.Name,
				Product:     p.Service.Product,
				Version:     p.Service.Version,
				State:       svcState,
			}
			services = append(services, svc)

			// Parse vulnerabilities from scripts
			extractedVulns := extractVulnerabilitiesFromScripts(ip, p.PortID, p.Scripts)
			vulns = append(vulns, extractedVulns...)
		}

		results = append(results, model.ScanHostResult{
			IP:              ip,
			MAC:             mac,
			Vendor:          vendor,
			Hostname:        hostname,
			Status:          host.Status.State,
			Services:        services,
			Vulnerabilities: vulns,
		})
	}

	return results
}

func extractVulnerabilitiesFromScripts(ip string, port int, scripts []NmapScript) []model.Vulnerability {
	var vulns []model.Vulnerability
	seenCVEs := make(map[string]bool)

	for _, script := range scripts {
		// 1. Structured table parsing (vulners.nse format)
		structuredVulns := parseStructuredScriptTables(ip, port, script)
		for _, v := range structuredVulns {
			if !seenCVEs[v.CVEID] {
				seenCVEs[v.CVEID] = true
				vulns = append(vulns, v)
			}
		}

		// 2. Fallback text output regex parsing
		if script.Output != "" {
			lines := strings.Split(script.Output, "\n")
			for _, line := range lines {
				cveMatch := cveRegex.FindString(line)
				if cveMatch != "" && !seenCVEs[cveMatch] {
					seenCVEs[cveMatch] = true

					var cvssScore float64
					cvssMatch := cvssRegex.FindString(line)
					if cvssMatch != "" {
						cvssScore, _ = strconv.ParseFloat(cvssMatch, 64)
					}

					vulns = append(vulns, model.Vulnerability{
						DeviceIP:     ip,
						ServicePort:  port,
						CVEID:        cveMatch,
						Title:        fmt.Sprintf("Vulnerability in port %d (%s)", port, script.ID),
						Severity:     SeverityFromCVSS(cvssScore),
						CVSSScore:    cvssScore,
						Description:  strings.TrimSpace(line),
						ReferenceURL: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveMatch),
					})
				}
			}
		}
	}

	return vulns
}

func parseStructuredScriptTables(ip string, port int, script NmapScript) []model.Vulnerability {
	var vulns []model.Vulnerability

	// Recursively inspect tables for CVE items
	var traverseTable func(tbl NmapTable)
	traverseTable = func(tbl NmapTable) {
		// Check if this table is a CVE entry
		isCVE := strings.HasPrefix(strings.ToUpper(tbl.Key), "CVE-")
		var cveID, elemType string
		var cvssScore float64

		for _, elem := range tbl.Elems {
			switch elem.Key {
			case "id":
				cveID = elem.Value
			case "type":
				elemType = elem.Value
			case "cvss":
				cvssScore, _ = strconv.ParseFloat(elem.Value, 64)
			}
		}

		if isCVE || (cveID != "" && (elemType == "cve" || strings.HasPrefix(strings.ToUpper(cveID), "CVE-"))) {
			targetCVE := cveID
			if targetCVE == "" {
				targetCVE = tbl.Key
			}

			vulns = append(vulns, model.Vulnerability{
				DeviceIP:     ip,
				ServicePort:  port,
				CVEID:        targetCVE,
				Title:        fmt.Sprintf("Vulnerability %s on port %d", targetCVE, port),
				Severity:     SeverityFromCVSS(cvssScore),
				CVSSScore:    cvssScore,
				Description:  fmt.Sprintf("Identified via %s script", script.ID),
				ReferenceURL: fmt.Sprintf("https://vulners.com/cve/%s", targetCVE),
			})
		}

		for _, subTbl := range tbl.Tables {
			traverseTable(subTbl)
		}
	}

	for _, tbl := range script.Tables {
		traverseTable(tbl)
	}

	return vulns
}

// SeverityFromCVSS converts CVSS numeric score to severity tier.
func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
