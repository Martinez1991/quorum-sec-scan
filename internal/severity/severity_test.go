package severity

import (
	"testing"

	"github.com/quorum-sec/quorum/internal/model"
)

func TestFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  model.Severity
	}{
		{9.8, model.SevCritical},
		{9.0, model.SevCritical},
		{7.5, model.SevHigh},
		{4.0, model.SevMedium},
		{0.1, model.SevLow},
		{0, model.SevUnknown},
	}
	for _, c := range cases {
		if got := FromCVSS(c.score); got != c.want {
			t.Errorf("FromCVSS(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestFromDockle(t *testing.T) {
	if FromDockle("FATAL") != model.SevHigh {
		t.Error("FATAL should map to HIGH")
	}
	if FromDockle("WARN") != model.SevMedium {
		t.Error("WARN should map to MEDIUM")
	}
	if FromDockle("INFO") != model.SevLow {
		t.Error("INFO should map to LOW")
	}
}

func TestMaxAndAtLeast(t *testing.T) {
	if Max(model.SevLow, model.SevCritical, model.SevMedium) != model.SevCritical {
		t.Error("Max wrong")
	}
	if !AtLeast(model.SevHigh, model.SevMedium) {
		t.Error("HIGH should be >= MEDIUM")
	}
	if AtLeast(model.SevLow, model.SevHigh) {
		t.Error("LOW should not be >= HIGH")
	}
}

func TestParse(t *testing.T) {
	if s, ok := Parse("high"); !ok || s != model.SevHigh {
		t.Errorf("Parse(high) = %q,%v", s, ok)
	}
	if _, ok := Parse("bogus"); ok {
		t.Error("bogus should not parse")
	}
}
