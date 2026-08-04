package backend

import (
	"strings"
	"testing"
)

func avail(container, vm bool) []Availability {
	return []Availability{
		{Name: "container", Tier: TierContainer, Available: container, Reason: "no runtime", Runtime: "docker"},
		{Name: "vm", Tier: TierVM, Available: vm, Reason: "no kvm", Runtime: "kata"},
	}
}

func TestFloorRefusal(t *testing.T) {
	_, err := Select(SelectionInput{Floor: TierVM, Availabilities: avail(true, false)})
	nb, ok := err.(*ErrNoBackend)
	if !ok {
		t.Fatalf("want ErrNoBackend, got %v", err)
	}
	// The diagnostic names what is missing.
	if !strings.Contains(nb.Error(), "no kvm") {
		t.Errorf("diagnostic must name what is missing: %v", nb)
	}
}

func TestRequestedBackendBelowFloor(t *testing.T) {
	_, err := Select(SelectionInput{
		Floor:          TierVM,
		RequestedName:  "container",
		Availabilities: avail(true, true),
	})
	if err == nil {
		t.Fatal("requesting a backend below the floor must fail, not downgrade")
	}
}

func TestHighestTierDefault(t *testing.T) {
	av, err := Select(SelectionInput{Floor: TierContainer, Availabilities: avail(true, true)})
	if err != nil {
		t.Fatal(err)
	}
	if av.Name != "vm" {
		t.Errorf("want vm (highest tier), got %s", av.Name)
	}
}

func TestRequestedBackendHonored(t *testing.T) {
	av, err := Select(SelectionInput{
		Floor: TierContainer, RequestedName: "container",
		Availabilities: avail(true, true),
	})
	if err != nil {
		t.Fatal(err)
	}
	if av.Name != "container" {
		t.Errorf("want container, got %s", av.Name)
	}
}

func TestForceIsolationLowersFloor(t *testing.T) {
	av, err := Select(SelectionInput{
		Floor: TierVM, ForcedTier: TierContainer,
		Availabilities: avail(true, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if av.Name != "container" {
		t.Errorf("forced selection: got %s", av.Name)
	}
}

func TestMeets(t *testing.T) {
	if !Meets(TierVM, TierContainer) || Meets(TierContainer, TierVM) {
		t.Error("tier ordering wrong")
	}
}
