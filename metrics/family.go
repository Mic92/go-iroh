package metrics

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Family is a metric vector keyed by a fixed label set.
type Family struct {
	mu         sync.Mutex
	name       string
	typ        MetricType
	labelNames []string
	children   map[string]*FamilyMetric
}

// FamilyMetric is one labeled metric in a [Family].
type FamilyMetric struct {
	mu      sync.Mutex
	labels  []Label
	counter uint64
	gauge   float64
}

// NewFamily returns a metric family with labelNames in output order.
func NewFamily(name string, typ MetricType, labelNames ...string) *Family {
	return &Family{
		name:       name,
		typ:        typ,
		labelNames: append([]string(nil), labelNames...),
		children:   make(map[string]*FamilyMetric),
	}
}

// With returns the child metric for labelValues.
func (f *Family) With(labelValues ...string) (*FamilyMetric, error) {
	if f == nil {
		return nil, errors.New("metrics: nil family")
	}
	if len(labelValues) != len(f.labelNames) {
		return nil, fmt.Errorf("metrics: got %d label values, want %d", len(labelValues), len(f.labelNames))
	}
	labels := make([]Label, len(labelValues))
	for i := range labelValues {
		labels[i] = Label{Name: f.labelNames[i], Value: labelValues[i]}
	}
	key := familyKey(labelValues)

	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.children[key]
	if m == nil {
		m = &FamilyMetric{labels: labels}
		f.children[key] = m
	}
	return m, nil
}

// Add adds delta to m. Use it for counter families.
func (m *FamilyMetric) Add(delta uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.counter += delta
	m.mu.Unlock()
}

// Set sets m to value. Use it for gauge families.
func (m *FamilyMetric) Set(value float64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.gauge = value
	m.mu.Unlock()
}

// StructuredSnapshot returns all children in f.
func (f *Family) StructuredSnapshot() StructuredSnapshot {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	children := make(map[string]*FamilyMetric, len(f.children))
	for key, child := range f.children {
		children[key] = child
	}
	f.mu.Unlock()

	out := make(StructuredSnapshot, len(children))
	for key, child := range children {
		child.mu.Lock()
		value := MetricValue{
			Name:    f.name,
			Type:    f.typ,
			Labels:  append([]Label(nil), child.labels...),
			Counter: child.counter,
			Gauge:   child.gauge,
		}
		child.mu.Unlock()
		out[f.name+"\x00"+key] = value
	}
	return out
}

func familyKey(values []string) string {
	return strings.Join(values, "\x00")
}
