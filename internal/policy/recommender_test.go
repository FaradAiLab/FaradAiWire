package policy

import (
	"testing"
)

func TestRecommender(t *testing.T) {
	recommender := NewRecommender()

	t.Run("database tools trigger db sanitization pack", func(t *testing.T) {
		req := RecommendationRequest{
			ProtocolTypes: []string{"stdio"},
			ProtocolNames: []string{"PostgreSQL Bridge"},
			ToolNames:     []string{"query", "list_tables"},
			AttachedPacks: []string{},
		}
		recs := recommender.Recommend(req)
		if len(recs) != 1 {
			t.Fatalf("expected 1 recommendation, got %d", len(recs))
		}
		if recs[0].PackID != "pack:db-sanitization" {
			t.Errorf("expected pack:db-sanitization, got %s", recs[0].PackID)
		}
		if len(recs[0].MatchedTools) == 0 {
			t.Errorf("expected matched tools list to be non-empty")
		}
	})

	t.Run("cloud tools trigger cloud infra pack", func(t *testing.T) {
		req := RecommendationRequest{
			ProtocolTypes: []string{"sse"},
			ProtocolNames: []string{"AWS Connector"},
			ToolNames:     []string{"s3_put_blob", "describe_instances"},
			AttachedPacks: []string{},
		}
		recs := recommender.Recommend(req)
		if len(recs) != 1 {
			t.Fatalf("expected 1 recommendation, got %d", len(recs))
		}
		if recs[0].PackID != "pack:cloud-infra" {
			t.Errorf("expected pack:cloud-infra, got %s", recs[0].PackID)
		}
	})

	t.Run("command execution tools trigger command injection pack", func(t *testing.T) {
		req := RecommendationRequest{
			ToolNames: []string{"execute_bash", "run_terminal_command"},
		}
		recs := recommender.Recommend(req)
		if len(recs) != 1 {
			t.Fatalf("expected 1 recommendation, got %d", len(recs))
		}
		if recs[0].PackID != "pack:command-injection" {
			t.Errorf("expected pack:command-injection, got %s", recs[0].PackID)
		}
	})

	t.Run("filesystem tools trigger path traversal pack", func(t *testing.T) {
		req := RecommendationRequest{
			ToolNames: []string{"read_file", "write_file", "list_dir"},
		}
		recs := recommender.Recommend(req)
		if len(recs) != 1 {
			t.Fatalf("expected 1 recommendation, got %d", len(recs))
		}
		if recs[0].PackID != "pack:path-traversal" {
			t.Errorf("expected pack:path-traversal, got %s", recs[0].PackID)
		}
	})

	t.Run("networking and scraping tools trigger ssrf defense pack", func(t *testing.T) {
		req := RecommendationRequest{
			ToolNames: []string{"curl_request", "fetch_url", "browser_scrape"},
		}
		recs := recommender.Recommend(req)
		if len(recs) != 1 {
			t.Fatalf("expected 1 recommendation, got %d", len(recs))
		}
		if recs[0].PackID != "pack:ssrf-defense" {
			t.Errorf("expected pack:ssrf-defense, got %s", recs[0].PackID)
		}
	})

	t.Run("saas api tools trigger saas tokens pack", func(t *testing.T) {
		req := RecommendationRequest{
			ToolNames: []string{"github_create_issue", "openai_chat_completion", "stripe_charge"},
		}
		recs := recommender.Recommend(req)
		if len(recs) != 1 {
			t.Fatalf("expected 1 recommendation, got %d", len(recs))
		}
		if recs[0].PackID != "pack:saas-tokens" {
			t.Errorf("expected pack:saas-tokens, got %s", recs[0].PackID)
		}
	})

	t.Run("multi-domain tools trigger multiple packs", func(t *testing.T) {
		req := RecommendationRequest{
			ToolNames: []string{"sql_query", "s3_sync", "execute_bash", "read_file", "fetch_url", "github_push"},
		}
		recs := recommender.Recommend(req)
		if len(recs) != 6 {
			t.Fatalf("expected 6 recommendations, got %d", len(recs))
		}
	})

	t.Run("already attached packs are excluded", func(t *testing.T) {
		req := RecommendationRequest{
			ToolNames:     []string{"query", "s3_upload", "execute_bash"},
			AttachedPacks: []string{"pack:db-sanitization", "pack:command-injection"},
		}
		recs := recommender.Recommend(req)
		if len(recs) != 1 {
			t.Fatalf("expected 1 recommendation (cloud only), got %d", len(recs))
		}
		if recs[0].PackID != "pack:cloud-infra" {
			t.Errorf("expected pack:cloud-infra, got %s", recs[0].PackID)
		}
	})

	t.Run("harmless tools trigger zero recommendations", func(t *testing.T) {
		req := RecommendationRequest{
			ProtocolNames: []string{"Math Utility"},
			ToolNames:     []string{"add", "subtract", "get_current_time"},
		}
		recs := recommender.Recommend(req)
		if len(recs) != 0 {
			t.Errorf("expected 0 recommendations, got %d", len(recs))
		}
	})
}
