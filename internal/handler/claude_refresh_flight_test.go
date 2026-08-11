package handler

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A burst of 401s on one account used to produce a rotation per caller: they
// serialised on a per-email mutex, and each one that arrived after the collapse
// window had closed performed its own full exchange. Every extra rotation
// invalidates the access tokens already handed out (making the burst worse) and
// is another draw at the lost-response window that quarantines the family.
// These tests pin the coalescing that replaced it.

func TestBeginRefreshElectsOneLeaderPerEmail(t *testing.T) {
	const email = "burst@example.com"
	const callers = 32

	var leaders int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	flights := make([]*refreshFlight, callers)

	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			f, leader := beginRefresh(email)
			flights[i] = f
			if leader {
				atomic.AddInt32(&leaders, 1)
				// Hold the slot long enough that every follower has to find it.
				time.Sleep(20 * time.Millisecond)
				f.finish(email, "rotated-token", nil)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&leaders); got != 1 {
		t.Fatalf("want exactly 1 leader for %d concurrent callers, got %d", callers, got)
	}
	for i, f := range flights {
		if f == nil {
			t.Fatalf("caller %d got no flight", i)
		}
	}
}

func TestFollowersReceiveLeaderResult(t *testing.T) {
	const email = "shared@example.com"

	f, leader := beginRefresh(email)
	if !leader {
		t.Fatal("first caller must be the leader")
	}

	// Followers arriving while the exchange is in flight must join it rather
	// than start a second rotation.
	const followers = 8
	got := make(chan string, followers)
	for i := 0; i < followers; i++ {
		go func() {
			ff, leader := beginRefresh(email)
			if leader {
				got <- "UNEXPECTED-LEADER"
				return
			}
			<-ff.done
			got <- ff.token
		}()
	}

	time.Sleep(10 * time.Millisecond)
	f.finish(email, "rotated-token", nil)

	for i := 0; i < followers; i++ {
		select {
		case v := <-got:
			if v != "rotated-token" {
				t.Fatalf("follower %d got %q, want the leader's rotated token", i, v)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("follower %d never woke", i)
		}
	}
}

func TestFollowersReceiveLeaderError(t *testing.T) {
	const email = "failing@example.com"
	wantErr := errors.New("invalid_grant")

	f, leader := beginRefresh(email)
	if !leader {
		t.Fatal("first caller must be the leader")
	}

	done := make(chan error, 1)
	go func() {
		ff, leader := beginRefresh(email)
		if leader {
			done <- errors.New("unexpected leader")
			return
		}
		<-ff.done
		done <- ff.err
	}()

	time.Sleep(10 * time.Millisecond)
	f.finish(email, "", wantErr)

	select {
	case err := <-done:
		if !errors.Is(err, wantErr) {
			t.Fatalf("follower got %v, want the leader's error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower never woke")
	}
}

// A finished flight must not be adopted by the next burst — otherwise an
// account would rotate once and then serve that one result forever.
func TestFlightIsReleasedAfterFinish(t *testing.T) {
	const email = "sequential@example.com"

	f1, leader := beginRefresh(email)
	if !leader {
		t.Fatal("first caller must be the leader")
	}
	f1.finish(email, "first", nil)

	f2, leader := beginRefresh(email)
	if !leader {
		t.Fatal("a caller after the previous flight finished must lead a new one")
	}
	if f2 == f1 {
		t.Fatal("second flight must be a fresh flight, not the completed one")
	}
	f2.finish(email, "second", nil)
}

// Coalescing is per account: one account's in-flight refresh must never block
// or answer for another.
func TestFlightsAreScopedPerEmail(t *testing.T) {
	fa, leaderA := beginRefresh("a@example.com")
	fb, leaderB := beginRefresh("b@example.com")

	if !leaderA || !leaderB {
		t.Fatal("distinct accounts must each elect their own leader")
	}
	if fa == fb {
		t.Fatal("distinct accounts must not share a flight")
	}
	fa.finish("a@example.com", "tok-a", nil)
	fb.finish("b@example.com", "tok-b", nil)

	if fa.token != "tok-a" || fb.token != "tok-b" {
		t.Fatalf("results crossed accounts: a=%q b=%q", fa.token, fb.token)
	}
}
