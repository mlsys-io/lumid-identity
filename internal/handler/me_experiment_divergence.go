package handler

// What this install declares, against what the published app declares.
//
// THE PLAN ASKED FOR THE WRONG COMPARISON. The divergence measured on the
// scheduler volume was across TENANTS — three mbb-consultant installs carrying
// three different experiment sets and two different UI surfaces. That is real,
// and it is not a comparison this endpoint may make: one user's installs are
// not another's business, and identity scopes every read to the caller for
// exactly that reason.
//
// The comparison a user CAN act on is against upstream. An app is installed
// once per tenant and then drifts as the published version moves — a new
// experiment lands upstream and the installed copy never gains it, or a local
// definition is edited and diverges. Both are invisible: the Experiments tab
// lists what the local bundle declares and has no way to say "there is another
// one you do not have".
//
// Cheap and best-effort. fetchRepoSpecYAML is already how MeAppConfig and the
// UI surface read the published tree, and a failure here must never fail the
// listing — an app that was never published simply has nothing to compare to.

import (
	"gopkg.in/yaml.v3"
)

type experimentDivergence struct {
	// Declared upstream, absent from this install — `app_update` would bring it.
	MissingHere []string `json:"missing_here,omitempty"`
	// Declared here, absent upstream — a local definition, or one removed
	// upstream. Not a problem by itself: define_experiment writes to the
	// caller's own tenant deliberately, and publishing for everyone is a
	// separate operator act.
	LocalOnly []string `json:"local_only,omitempty"`
	// Upstream could not be read (never published, private, offline). Stated so
	// an empty result is not mistaken for agreement.
	Unavailable bool `json:"unavailable,omitempty"`
}

// experimentIDsFromSpec pulls just the experiment ids out of a spec blob.
func experimentIDsFromSpec(blob []byte) ([]string, bool) {
	var doc struct {
		Experiments []struct {
			ID string `yaml:"id"`
		} `yaml:"experiments"`
	}
	if yaml.Unmarshal(blob, &doc) != nil {
		return nil, false
	}
	out := make([]string, 0, len(doc.Experiments))
	for _, e := range doc.Experiments {
		if e.ID != "" {
			out = append(out, e.ID)
		}
	}
	return out, true
}

// compareExperimentIDs is the set difference, both ways. Split out so the rule
// is testable without a network or a tenant.
func compareExperimentIDs(local, upstream []string) experimentDivergence {
	up := make(map[string]bool, len(upstream))
	for _, id := range upstream {
		up[id] = true
	}
	here := make(map[string]bool, len(local))
	for _, id := range local {
		here[id] = true
	}
	var d experimentDivergence
	for _, id := range upstream {
		if !here[id] {
			d.MissingHere = append(d.MissingHere, id)
		}
	}
	for _, id := range local {
		if !up[id] {
			d.LocalOnly = append(d.LocalOnly, id)
		}
	}
	return d
}

// experimentDivergenceFor compares the caller's install against the published
// app. Returns nil when there is nothing to say.
func experimentDivergenceFor(userID, app string, localIDs []string) *experimentDivergence {
	blob, ok := fetchRepoSpecYAML(userID, app)
	if !ok {
		return &experimentDivergence{Unavailable: true}
	}
	upstream, parsed := experimentIDsFromSpec(blob)
	if !parsed {
		return &experimentDivergence{Unavailable: true}
	}
	d := compareExperimentIDs(localIDs, upstream)
	if len(d.MissingHere) == 0 && len(d.LocalOnly) == 0 {
		return nil
	}
	return &d
}
