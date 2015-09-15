package pgputil

import "testing"

func TestKeyGen(t *testing.T) {
	rsaBits = 1024

	k := &Key{
		Name:    "John Q. Public",
		Comment: "test key",
		UIDs: []string{
			"jqp@example.org",
			"john.public@example.com",
		},
	}

	_, err := k.Generate()
	if err != nil {
		t.Fatalf("%v", err)
	}
}
