package models

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/runZeroInc/runZeroHound/pkg/runzero"
	"github.com/runZeroInc/runZeroHound/pkg/runzero/sanitize"
)

// Asset is used work with exported assets from the runZero console
type Asset struct {
	ID                   uuid.UUID                    `json:"id,omitempty"`
	CreatedAt            int64                        `json:"created_at,omitempty"`
	UpdatedAt            int64                        `json:"updated_at,omitempty"`
	OrganizationID       uuid.UUID                    `json:"organization_id,omitempty"`
	SiteID               uuid.UUID                    `json:"site_id,omitempty"`
	Alive                bool                         `json:"alive,omitempty"`
	LastSeen             int64                        `json:"last_seen,omitempty"`
	FirstSeen            int64                        `json:"first_seen,omitempty"`
	DetectedBy           string                       `json:"detected_by,omitempty"`
	Type                 string                       `json:"type,omitempty"`
	Category             string                       `json:"category,omitempty"`
	Functions            []string                     `json:"functions,omitempty"`
	OSVendor             string                       `json:"os_vendor,omitempty"`
	OSProduct            string                       `json:"os_product,omitempty"`
	OS                   string                       `json:"os,omitempty"`
	OSVersion            string                       `json:"os_version,omitempty"`
	HWVendor             string                       `json:"hw_vendor,omitempty"`
	HWProduct            string                       `json:"hw_product,omitempty"`
	HWVersion            string                       `json:"hw_version,omitempty"`
	HW                   string                       `json:"hw,omitempty"`
	Addresses            []string                     `json:"addresses,omitempty"`
	AddressesExtra       []string                     `json:"addresses_extra,omitempty"`
	MACs                 []string                     `json:"macs,omitempty"`
	MACVendors           []string                     `json:"mac_vendors,omitempty"`
	Names                []string                     `json:"names,omitempty"`
	Domains              []string                     `json:"domains,omitempty"`
	Tags                 map[string]string            `json:"tags,omitempty"`
	Services             map[string]map[string]string `json:"services,omitempty"`
	Credentials          map[string]string            `json:"credentials,omitempty"`
	RTTs                 map[string][]uint64          `json:"rtts,omitempty"`
	Attributes           map[string]string            `json:"attributes,omitempty"`
	ServiceCount         int64                        `json:"service_count,omitempty"`
	ServiceCountTCP      int64                        `json:"service_count_tcp,omitempty"`
	ServiceCountUDP      int64                        `json:"service_count_udp,omitempty"`
	ServiceCountARP      int64                        `json:"service_count_arp,omitempty"`
	ServiceCountICMP     int64                        `json:"service_count_icmp,omitempty"`
	SoftwareCount        int64                        `json:"software_count,omitempty"`
	VulnerabilityCount   int64                        `json:"vulnerability_count,omitempty"`
	LowestTTL            int64                        `json:"lowest_ttl,omitempty"`
	LowestRTT            int64                        `json:"lowest_rtt,omitempty"`
	LastAgentID          uuid.UUID                    `json:"last_agent_id,omitempty"`
	LastTaskID           uuid.UUID                    `json:"last_task_id,omitempty"`
	FirstTaskID          uuid.UUID                    `json:"first_task_id,omitempty"`
	NewestMAC            string                       `json:"newest_mac,omitempty"`
	NewestMACVendor      string                       `json:"newest_mac_vendor,omitempty"`
	NewestMACAge         int64                        `json:"newest_mac_age,omitempty"`
	Comments             string                       `json:"comments,omitempty"`
	ServicePortsTCP      []string                     `json:"service_ports_tcp,omitempty"`
	ServicePortsUDP      []string                     `json:"service_ports_udp,omitempty"`
	ServiceProtocols     []string                     `json:"service_protocols,omitempty"`
	ServiceProducts      []string                     `json:"service_products,omitempty"`
	Scanned              bool                         `json:"scanned,omitempty"`
	SourceIDs            []int                        `json:"source_ids,omitempty"`
	CustomIntegrationIDs []uuid.UUID                  `json:"custom_integration_ids,omitempty"`
	EndOfLifeOS          int64                        `json:"eol_os,omitempty"`
	EndOfLifeOSExtended  int64                        `json:"eol_os_ext,omitempty"`
	OutlierScore         int64                        `json:"outlier_score,omitempty"`
	OutlierRaw           int64                        `json:"outlier_raw,omitempty"`
	RiskRank             int64                        `json:"risk_rank,omitempty"`
	ModifiedRiskRank     int64                        `json:"modified_risk_rank,omitempty"`
	CriticalityRank      int64                        `json:"criticality_rank,omitempty"`
	OrganizationName     string                       `json:"org_name,omitempty"`
	SiteName             string                       `json:"site_name,omitempty"`
	AgentName            string                       `json:"agent_name,omitempty"`
	AgentExternalIP      string                       `json:"agent_external_ip,omitempty"`
	HostedZoneName       string                       `json:"hosted_zone_name,omitempty"`
	Subnets              map[string]any               `json:"subnets,omitempty"`

	// Ownership maps ownership types to asset owners
	Ownership any `json:"ownership,omitempty"`
	Owners    any `json:"owners,omitempty"`

	// ForeignAttributes includes non-runZero data source attributes
	ForeignAttributes map[string][]map[string]string `json:"foreign_attributes,omitempty"`
}

const MaxReadErrors = 10

func LoadFromReader(logr *slog.Logger, fd io.Reader) ([]*Asset, error) {
	var lastErr error
	ecnt := atomic.Int64{}
	wg := sync.WaitGroup{}
	fdc := make(chan string, 1)
	assets := make([]*Asset, 0)

	lock := sync.Mutex{}
	acnt := atomic.Int64{}
	stime := time.Now()

	assetLineWorker := func() {
		defer wg.Done()
		for line := range fdc {

			if ecnt.Load() >= MaxReadErrors {
				logr.Error("maximum read errors reached, aborting load")
				return
			}

			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			ima := &Asset{}

			err := json.Unmarshal([]byte(line), ima)
			if err != nil {
				tline := sanitize.Truncate(line, 64)
				logr.Warn("failed to deserialize asset", "error", err, "line", tline)
				ecnt.Add(1)
				lock.Lock()
				lastErr = err
				lock.Unlock()
				continue
			}

			lock.Lock()
			acnt.Add(1)
			if acnt.Load()%1000 == 0 {
				logr.Info(fmt.Sprintf("loaded %d assets in %s", acnt.Load(), time.Since(stime).Truncate(time.Second)))
			}
			assets = append(assets, ima)
			lock.Unlock()
		}
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go assetLineWorker()
	}

	if err := runzero.ReadLines(fd, fdc); err != nil {
		return nil, err
	}
	wg.Wait()

	logr.Info(fmt.Sprintf("loaded %d assets in %s", acnt.Load(), time.Since(stime).Truncate(time.Second)))

	return assets, lastErr
}
