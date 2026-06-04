package metrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Snapshot is a point-in-time set of unsigned counter values.
type Snapshot map[string]uint64

// String implements expvar.Var, returning the snapshot as JSON.
func (s Snapshot) String() string {
	b, _ := json.Marshal(map[string]uint64(s))
	return string(b)
}

// Source returns a point-in-time metrics snapshot.
type Source interface {
	Snapshot() Snapshot
}

// Registry collects named metric sources.
type Registry struct {
	mu      sync.Mutex
	sources map[string]Source
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{sources: make(map[string]Source)}
}

// Register adds source under prefix. Prefix must be non-empty and unique.
func (r *Registry) Register(prefix string, source Source) error {
	if r == nil {
		return errors.New("metrics: nil registry")
	}
	if prefix == "" {
		return errors.New("metrics: empty prefix")
	}
	if source == nil {
		return errors.New("metrics: nil source")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sources == nil {
		r.sources = make(map[string]Source)
	}
	if _, ok := r.sources[prefix]; ok {
		return fmt.Errorf("metrics: duplicate prefix %q", prefix)
	}
	r.sources[prefix] = source
	return nil
}

// WriteOpenMetrics writes all registered counter snapshots in OpenMetrics text
// format.
func (r *Registry) WriteOpenMetrics(w io.Writer) error {
	if r == nil {
		return errors.New("metrics: nil registry")
	}
	r.mu.Lock()
	sources := make(map[string]Source, len(r.sources))
	for prefix, source := range r.sources {
		sources[prefix] = source
	}
	r.mu.Unlock()

	prefixes := make([]string, 0, len(sources))
	for prefix := range sources {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)

	for _, prefix := range prefixes {
		snap := sources[prefix].Snapshot()
		names := make([]string, 0, len(snap))
		for name := range snap {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			metricName := cleanName(prefix + "_" + name)
			if _, err := fmt.Fprintf(w, "# TYPE %s counter\n%s_total %d\n", metricName, metricName, snap[name]); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(w, "# EOF\n"); err != nil {
		return err
	}
	return nil
}

func cleanName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}
