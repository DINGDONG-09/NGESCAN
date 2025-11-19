//go:build windows
// +build windows

package core

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// ProgressReporter menampilkan progress scan
type ProgressReporter struct {
	total     int
	completed int
	mu        sync.Mutex
	ticker    *time.Ticker
	done      chan bool
	current   string
	status    string
	startTime time.Time
}

// NewProgressReporter membuat progress reporter baru
func NewProgressReporter() *ProgressReporter {
	return &ProgressReporter{
		done: make(chan bool),
	}
}

// SetTotal set total checks
func (p *ProgressReporter) SetTotal(total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total = total
}

// Start memulai progress bar
func (p *ProgressReporter) Start() {
	p.startTime = time.Now()
	p.ticker = time.NewTicker(200 * time.Millisecond)

	go func() {
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		frameIdx := 0

		for {
			select {
			case <-p.ticker.C:
				p.mu.Lock()
				frame := frames[frameIdx%len(frames)]
				frameIdx++

				percentage := 0
				if p.total > 0 {
					percentage = (p.completed * 100) / p.total
				}

				elapsed := time.Since(p.startTime).Round(time.Second)

				// Clear line and print progress
				fmt.Fprintf(os.Stderr, "\r\033[K%s [%d/%d] (%d%%) | %s | %s | Elapsed: %s",
					Colorize(frame, ColorCyan),
					p.completed,
					p.total,
					percentage,
					p.current,
					p.getStatusColor(p.status),
					elapsed,
				)
				p.mu.Unlock()

			case <-p.done:
				return
			}
		}
	}()
}

// Increment increment progress
func (p *ProgressReporter) Increment(checkID, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.completed++
	p.current = checkID
	p.status = status
}

// Stop menghentikan progress bar
func (p *ProgressReporter) Stop() {
	if p.ticker != nil {
		p.ticker.Stop()
		close(p.done)

		// Clear progress line
		fmt.Fprintf(os.Stderr, "\r\033[K")

		// Print completion
		elapsed := time.Since(p.startTime).Round(time.Second)
		fmt.Fprintf(os.Stderr, "✓ Scan completed: %d checks in %s\n\n",
			p.completed, elapsed)
	}
}

// getStatusColor returns colored status
func (p *ProgressReporter) getStatusColor(status string) string {
	switch status {
	case "vulnerable":
		return Colorize("VULN", ColorRed)
	case "ok":
		return Colorize("OK", ColorGreen)
	case "error":
		return Colorize("ERROR", ColorYellow)
	case "timeout":
		return Colorize("TIMEOUT", ColorYellow)
	case "skipped":
		return Colorize("SKIP", ColorGray)
	default:
		return Colorize("RUN", ColorCyan)
	}
}

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
)

// Colorize wraps text with color
func Colorize(text, color string) string {
	return color + text + ColorReset
}
