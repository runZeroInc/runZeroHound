package nextnet

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ScanResult holds the findings for a single scanned host.
// The JSON representation is the .nxt file format.
type ScanResult struct {
	Host  string            `json:"host"`
	Port  string            `json:"port,omitempty"`
	Proto string            `json:"proto,omitempty"`
	Probe string            `json:"probe,omitempty"`
	Name  string            `json:"name,omitempty"`
	Nets  []string          `json:"nets,omitempty"`
	Info  map[string]string `json:"info"`
}

// Prober is the interface implemented by every scan probe.
type Prober interface {
	Setup()
	Initialize()
	Wait()
	AddTarget(string)
	CloseInput()
	SetOutput(chan<- ScanResult)
	CheckRateLimit()
	SetLimiter(Limiter)
}

// Limiter is a minimal interface for token-bucket rate limiters.
type Limiter interface {
	Allow() bool
}

// Probe is the base type embedded by all probes.
type Probe struct {
	name    string
	waiter  sync.WaitGroup
	input   chan string
	output  chan<- ScanResult
	limiter Limiter
}

func (p *Probe) String() string { return p.name }

func (p *Probe) Wait() { p.waiter.Wait() }

func (p *Probe) Setup() {
	p.name = "generic"
	p.input = make(chan string)
}

func (p *Probe) Initialize() {
	p.Setup()
	p.name = "generic"
}

func (p *Probe) SetOutput(c chan<- ScanResult) { p.output = c }

func (p *Probe) AddTarget(t string) { p.input <- t }

func (p *Probe) CloseInput() { close(p.input) }

func (p *Probe) SetLimiter(l Limiter) { p.limiter = l }

func (p *Probe) CheckRateLimit() {
	for !p.limiter.Allow() {
		time.Sleep(10 * time.Millisecond)
	}
}

// probes holds the set of registered probe implementations.
// Probes register themselves in their init() function.
var probes []Prober

// Scanner runs a nextnet scan against the given CIDRs and writes JSONL
// results to output (which may be a file or os.Stdout).
//
// ppsRate controls the maximum packets per second.
func Scanner(cidrs []string, ppsRate int, output *os.File) error {
	limiter := newTokenBucketLimiter(ppsRate)

	cAddr := make(chan string)
	cOut := make(chan ScanResult)

	// Reset and initialize probes for this scan
	probes = nil
	probes = append(probes, new(ProbeNetbios))
	probes = append(probes, new(ProbeSNMP))
	for _, probe := range probes {
		probe.Initialize()
		probe.SetOutput(cOut)
		probe.SetLimiter(limiter)
	}

	var wi, wo sync.WaitGroup

	wi.Add(1)
	go func() {
		for addr := range cAddr {
			for _, probe := range probes {
				probe.AddTarget(addr)
			}
		}
		for _, probe := range probes {
			probe.CloseInput()
		}
		wi.Done()
	}()

	wo.Add(1)
	go func() {
		for found := range cOut {
			j, err := json.Marshal(found)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error marshaling result: %v: %s\n", found, err)
				continue
			}
			if _, werr := output.Write(j); werr != nil {
				fmt.Fprintf(os.Stderr, "error writing result: %s\n", werr)
				continue
			}
			if _, werr := output.Write([]byte("\n")); werr != nil {
				fmt.Fprintf(os.Stderr, "error writing newline: %s\n", werr)
			}
		}
		wo.Done()
	}()

	for _, cidr := range cidrs {
		AddressesFromCIDR(cidr, cAddr)
	}
	close(cAddr)

	wi.Wait()
	for _, probe := range probes {
		probe.Wait()
	}
	close(cOut)
	wo.Wait()

	return nil
}

// tokenBucketLimiter is a simple token-bucket rate limiter that does not
// require any external dependencies.
type tokenBucketLimiter struct {
	rate     int
	tokens   int
	lastTick time.Time
	mu       sync.Mutex
}

func newTokenBucketLimiter(rate int) *tokenBucketLimiter {
	return &tokenBucketLimiter{rate: rate, tokens: rate, lastTick: time.Now()}
}

func (l *tokenBucketLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(l.lastTick).Seconds()
	add := int(elapsed * float64(l.rate))
	if add > 0 {
		l.tokens += add
		if l.tokens > l.rate {
			l.tokens = l.rate
		}
		l.lastTick = now
	}
	if l.tokens > 0 {
		l.tokens--
		return true
	}
	return false
}
