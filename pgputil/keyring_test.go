package pgputil

import (
	"os"
	"testing"
)

//    ./pubring.gpg
//    -------------
//    pub   1024R/0x65F5F3A0C40946B8 2015-09-17
//    uid                 [ultimate] John Q. Public <jqp@example.org>
//    sub   1024R/0x88A66033E3451855 2015-09-17
//
//    pub   1024R/0xB5C298D20E11F977 2015-09-17
//    uid                 [ultimate] Test Key <null@127.0.0.1>
//    sub   1024R/0x68E839A9AEB8644C 2015-09-17
//
//    ./secring.gpg
//    -------------
//    sec   1024R/0x65F5F3A0C40946B8 2015-09-17
//    uid                            John Q. Public <jqp@example.org>
//    ssb   1024R/0x88A66033E3451855 2015-09-17
//
//    sec   1024R/0xB5C298D20E11F977 2015-09-17
//    uid                            Test Key <null@127.0.0.1>
//    ssb   1024R/0x68E839A9AEB8644C 2015-09-17

var (
	testPublicRing = "testdata/pubring.gpg"
	testSecretRing = "testdata/secring.gpg"
	testPassword   = []byte("passord")
)

func TestLoadKeyRing(t *testing.T) {
	const searchName = "John Q. Public <jqp@example.org>"
	ent, err := LoadKey(testSecretRing, 0x65F5F3A0C40946B8, testPassword)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var found bool
	var names []string

	for name := range ent.Identities {
		if name == searchName {
			found = true
			break
		}
		names = append(names, name)
	}

	if !found {
		t.Fatalf("Couldn't find the identity %s, only %v", searchName, names)
	}
}

func TestWriteKeyRing(t *testing.T) {
	const testPubRing = "testdata/testpub.gpg"
	const testSecRing = "testdata/testsec.gpg"

	pubRing, err := os.Create(testPubRing)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer pubRing.Close()

	secRing, err := os.Create(testSecRing)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer secRing.Close()

	keys := []*Key{
		&Key{
			Name:    "John Q. Public",
			Comment: "test key",
			UIDs: []string{
				"jqp@example.org",
				"john.public@example.com",
			},
		},
		&Key{
			Name: "J. Random Hacker",
			UIDs: []string{
				"jrhp@example.org",
				"jrhacker@example.com",
			},
		},
	}

	for _, k := range keys {
		ent, err := k.Generate()
		if err != nil {
			t.Fatalf("%v", err)
		}

		err = ent.Serialize(pubRing)
		if err != nil {
			t.Fatalf("%v", err)
		}

		err = ent.SerializePrivate(secRing, PGPConfig())
		if err != nil {
			t.Fatalf("%v", err)
		}
	}
}
