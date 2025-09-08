package httpx

import (
	"os"
	"testing"
)

func TestParseJSONL(t *testing.T) {
	data, err := os.ReadFile("testdata/httpx.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ParseJSONL(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res))
	}
	if res[0].StatusCode != 200 || res[0].Title != "Lab" {
		t.Fatalf("unexpected first result %+v", res[0])
	}
	if len(res[0].Tech) != 2 {
		t.Fatalf("expected tech list, got %+v", res[0])
	}
}
