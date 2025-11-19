//go:build windows
// +build windows

package core

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Check interface - setiap pemeriksaan harus implement ini
type Check interface {
	ID() string
	Name() string
	Category() string
	Run(ctx context.Context) Finding
}

// Scanner adalah orchestrator utama
type Scanner struct {
	checks   []Check
	config   Config
	progress *ProgressReporter
	mu       sync.Mutex
}

// Config untuk scanner
type Config struct {
	Timeout        time.Duration
	ParallelChecks bool
	MaxWorkers     int
	Verbose        bool
}

// NewScanner membuat instance scanner baru
func NewScanner(cfg Config) *Scanner {
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}

	return &Scanner{
		checks:   make([]Check, 0),
		config:   cfg,
		progress: NewProgressReporter(),
	}
}

// RegisterCheck menambahkan check ke scanner
func (s *Scanner) RegisterCheck(check Check) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks = append(s.checks, check)
}

// Run menjalankan semua checks yang terdaftar
func (s *Scanner) Run(ctx context.Context, filterIDs []string) []CheckResult {
	// Filter checks jika ada
	checksToRun := s.filterChecks(filterIDs)
	if len(checksToRun) == 0 {
		return []CheckResult{}
	}

	// Setup progress reporter
	s.progress.SetTotal(len(checksToRun))
	s.progress.Start()
	defer s.progress.Stop()

	// Context dengan timeout
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	results := make([]CheckResult, 0, len(checksToRun))
	resultsCh := make(chan CheckResult, len(checksToRun))

	// Batasi concurrency
	semaphore := make(chan struct{}, s.config.MaxWorkers)
	var wg sync.WaitGroup

	for _, check := range checksToRun {
		wg.Add(1)
		go func(c Check) {
			defer wg.Done()
			semaphore <- struct{}{}        // acquire
			defer func() { <-semaphore }() // release

			result := s.runSingleCheck(ctx, c)
			resultsCh <- result
		}(check)
	}

	// Wait and close
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results
	for result := range resultsCh {
		results = append(results, result)
		s.progress.Increment(result.CheckID, result.Status)
	}

	return results
}

// runSingleCheck menjalankan satu check dengan error handling
func (s *Scanner) runSingleCheck(ctx context.Context, check Check) CheckResult {
	result := CheckResult{
		CheckID:   check.ID(),
		CheckName: check.Name(),
		Category:  check.Category(),
		StartTime: time.Now(),
		Status:    "running",
	}

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			result.Status = "error"
			result.Error = fmt.Sprintf("panic: %v", r)
			result.Duration = time.Since(result.StartTime)
		}
	}()

	// Check context cancellation
	select {
	case <-ctx.Done():
		result.Status = "timeout"
		result.Error = "context cancelled or timeout"
		result.Duration = time.Since(result.StartTime)
		return result
	default:
	}

	// Run the actual check
	finding := check.Run(ctx)
	result.Finding = finding
	result.Duration = time.Since(result.StartTime)

	// Determine status
	if finding.Status == "vulnerable" {
		result.Status = "vulnerable"
	} else if finding.Status == "not_applicable" {
		result.Status = "skipped"
	} else {
		result.Status = "ok"
	}

	return result
}

// filterChecks memfilter checks berdasarkan ID
func (s *Scanner) filterChecks(ids []string) []Check {
	if len(ids) == 0 {
		return s.checks
	}

	// Buat map untuk lookup cepat
	idMap := make(map[string]bool)
	for _, id := range ids {
		idMap[id] = true
	}

	filtered := make([]Check, 0)
	for _, check := range s.checks {
		if idMap[check.ID()] {
			filtered = append(filtered, check)
		}
	}

	return filtered
}

// CheckResult adalah hasil dari satu check
type CheckResult struct {
	CheckID   string        `json:"check_id"`
	CheckName string        `json:"check_name"`
	Category  string        `json:"category"`
	Status    string        `json:"status"` // ok, vulnerable, error, timeout, skipped
	Finding   Finding       `json:"finding,omitempty"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	StartTime time.Time     `json:"-"`
}
