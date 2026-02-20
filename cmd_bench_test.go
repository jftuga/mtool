package main

import (
	"github.com/jftuga/mtool/v2/internal/bench"
	"testing"
)

func TestPercentile(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if got := bench.Percentile(nil, 50); got != 0 {
			t.Errorf("Percentile(nil, 50) = %f, want 0", got)
		}
	})

	t.Run("single element", func(t *testing.T) {
		if got := bench.Percentile([]float64{42.0}, 99); got != 42.0 {
			t.Errorf("Percentile([42], 99) = %f, want 42", got)
		}
	})

	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	t.Run("p50", func(t *testing.T) {
		got := bench.Percentile(sorted, 50)
		if got != 5.0 {
			t.Errorf("p50 = %f, want 5", got)
		}
	})

	t.Run("p100", func(t *testing.T) {
		got := bench.Percentile(sorted, 100)
		if got != 10.0 {
			t.Errorf("p100 = %f, want 10", got)
		}
	})

	t.Run("p10", func(t *testing.T) {
		got := bench.Percentile(sorted, 10)
		if got != 1.0 {
			t.Errorf("p10 = %f, want 1", got)
		}
	})
}
