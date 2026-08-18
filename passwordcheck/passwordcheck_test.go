package passwordcheck

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type recordingChecker struct {
	name   string
	err    error
	calls  *[]string
	gotCtx context.Context
}

func (c *recordingChecker) Check(ctx context.Context, _ string) error {
	c.gotCtx = ctx
	*c.calls = append(*c.calls, c.name)
	return c.err
}

func TestAllRunsEveryCheckerUntilOneRejects(t *testing.T) {
	var calls []string
	all := All(
		&recordingChecker{name: "first", calls: &calls},
		&recordingChecker{name: "second", calls: &calls},
		&recordingChecker{name: "third", calls: &calls},
	)
	if err := all.Check(context.Background(), "correct-battery-staple"); err != nil {
		t.Fatalf("All.Check = %v, want nil", err)
	}
	if len(calls) != 3 {
		t.Fatalf("checkers run = %v, want all three", calls)
	}
}

func TestAllStopsAtTheFirstRejection(t *testing.T) {
	var calls []string
	all := All(
		&recordingChecker{name: "first", calls: &calls},
		&recordingChecker{name: "second", calls: &calls, err: ErrCompromised},
		&recordingChecker{name: "third", calls: &calls},
	)
	err := all.Check(context.Background(), "password")
	if !errors.Is(err, ErrCompromised) {
		t.Fatalf("All.Check = %v, want ErrCompromised", err)
	}
	if len(calls) != 2 || calls[1] != "second" {
		t.Fatalf("checkers run = %v, want the run to stop after \"second\"", calls)
	}
}

func TestAllPropagatesANonRejectionError(t *testing.T) {
	sentinel := errors.New("lookup unavailable")
	all := All(&recordingChecker{name: "only", calls: new([]string), err: fmt.Errorf("wrapped: %w", sentinel)})
	err := all.Check(context.Background(), "correct-battery-staple")
	if !errors.Is(err, sentinel) {
		t.Fatalf("All.Check = %v, want the underlying error", err)
	}
	if errors.Is(err, ErrCompromised) {
		t.Fatal("an operational failure must not be reported as a breach hit")
	}
}

func TestAllOfNothingAcceptsEverything(t *testing.T) {
	if err := All().Check(context.Background(), "password"); err != nil {
		t.Fatalf("All().Check = %v, want nil", err)
	}
}

// TestCheckersSatisfyTheInterface is a compile-time assertion that both
// shipped checkers really are Checkers; a signature drift here would only
// show up at a caller's WithPasswordChecker call otherwise.
func TestCheckersSatisfyTheInterface(t *testing.T) {
	var _ Checker = NewBlocklist()
	var _ Checker = NewHIBP()
	var _ Checker = All()
}

func TestErrCompromisedCarriesTheRatifiedMessage(t *testing.T) {
	if got, want := ErrCompromised.Error(), "sulis: password appears in a breach corpus"; got != want {
		t.Fatalf("ErrCompromised.Error() = %q, want %q", got, want)
	}
}
