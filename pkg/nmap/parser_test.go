package nmap

import (
	"os"
	"testing"
)

func TestParseXML(t *testing.T) {
	data, err := os.ReadFile("testdata/scan.xml")
	if err != nil {
		t.Skip("no testdata")
	}
	hosts, err := ParseXML(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].IP != "10.10.10.10" {
		t.Fatalf("unexpected hosts %+v", hosts)
	}
	if len(hosts[0].Services) != 2 {
		t.Fatalf("expected 2 services, got %+v", hosts[0].Services)
	}
}
