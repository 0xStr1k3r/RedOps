package dnsx

import (
	"os"
	"testing"
)

func TestParseJSONL(t *testing.T) {
	data, err := os.ReadFile("testdata/dnsx.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ParseJSONL(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || len(res[0].A) != 1 {
		t.Fatalf("unexpected results %+v", res)
	}
}
