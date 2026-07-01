// Minimal, dependency-free poller for the Claude Compliance Activity Feed.
//
// Pages through GET /v1/compliance/activities using the documented cursor
// contract (after_id / last_id / has_more) with only the Go standard library,
// invoking a handler for each raw Activity record. Pair with
// ClaudeComplianceMapper to normalize the records to OCSF.
//
// Docs: https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed
//
// This mirrors the Python iter_activities poller in
// integrations/anthropic/compliance/client.py.
package ocsf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// claudeComplianceBaseURL is the default Activity Feed endpoint.
const claudeComplianceBaseURL = "https://api.anthropic.com/v1/compliance/activities"

// claudeComplianceMaxLimit is the maximum page size accepted by the feed.
const claudeComplianceMaxLimit = 5000

// ActivityFeedOptions configures the Claude Compliance Activity Feed poller.
//
// Repeatable filters (ActivityTypes, OrganizationIDs, ActorIDs) are encoded
// with array-bracket query keys (e.g. activity_types[]). AfterID lets a caller
// resume from a previously persisted cursor.
type ActivityFeedOptions struct {
	ActivityTypes   []string
	OrganizationIDs []string
	ActorIDs        []string
	CreatedAtGte    string
	CreatedAtLt     string
	AfterID         string
	Limit           int          // default 100; valid 1..5000
	BaseURL         string       // default https://api.anthropic.com/v1/compliance/activities
	HTTPClient      *http.Client // optional; default http.DefaultClient
}

// activityFeedPage is the decoded JSON envelope for a single feed page.
type activityFeedPage struct {
	Data    []map[string]interface{} `json:"data"`
	HasMore bool                     `json:"has_more"`
	LastID  string                   `json:"last_id"`
}

// IterActivities pages the feed, invoking handler for each Activity. It stops
// when has_more is false, the handler returns an error, or ctx is cancelled.
func IterActivities(ctx context.Context, apiKey string, opts ActivityFeedOptions,
	handler func(activity map[string]interface{}) error) error {
	limit := opts.Limit
	if limit == 0 {
		limit = 100
	}
	if limit < 1 || limit > claudeComplianceMaxLimit {
		return fmt.Errorf("limit must be between 1 and %d", claudeComplianceMaxLimit)
	}

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = claudeComplianceBaseURL
	}
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	baseParams := url.Values{}
	baseParams.Set("limit", strconv.Itoa(limit))
	for _, v := range opts.ActivityTypes {
		baseParams.Add("activity_types[]", v)
	}
	for _, v := range opts.OrganizationIDs {
		baseParams.Add("organization_ids[]", v)
	}
	for _, v := range opts.ActorIDs {
		baseParams.Add("actor_ids[]", v)
	}
	if opts.CreatedAtGte != "" {
		baseParams.Set("created_at.gte", opts.CreatedAtGte)
	}
	if opts.CreatedAtLt != "" {
		baseParams.Set("created_at.lt", opts.CreatedAtLt)
	}

	cursor := opts.AfterID
	for {
		params := cloneValues(baseParams)
		if cursor != "" {
			params.Set("after_id", cursor)
		}

		reqURL := baseURL + "?" + params.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("x-api-key", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("compliance activities request failed: status %d: %s", resp.StatusCode, string(body))
		}

		var page activityFeedPage
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}

		for _, activity := range page.Data {
			if err := handler(activity); err != nil {
				return err
			}
		}

		if !page.HasMore {
			break
		}
		cursor = page.LastID
		if cursor == "" {
			break
		}
	}
	return nil
}

// cloneValues returns a shallow copy of v so per-page mutation (after_id) does
// not leak into the shared base params.
func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}
