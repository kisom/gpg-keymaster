package pgputil

import "testing"

func TestKeyGen(t *testing.T) {
	identities := map[string]bool{
		"John Q. Public (test key) <jqp@example.org>":         true,
		"John Q. Public (test key) <john.public@example.com>": true,
	}
	rsaBits = 1024

	k := &Key{
		Name:    "John Q. Public",
		Comment: "test key",
		UIDs: []string{
			"jqp@example.org",
			"john.public@example.com",
		},
	}

	ent, err := k.Generate()
	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(ent.Identities) != len(identities) {
		t.Fatalf("Expected %d identities, but have %d", len(identities),
			len(ent.Identities))
	}
	for id := range ent.Identities {
		if !identities[id] {
			t.Fatal("Unknown identity", id)
		}
	}
}
