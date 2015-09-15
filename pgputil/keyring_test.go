package pgputil

import "testing"

//    testdata/pubring.gpg
//    --------------------
//    pub   1024R/0x80A3F4356BA114E7 2015-09-17
//    uid                 [ultimate] Test Key <null@127.0.0.1>
//    sub   1024R/0x8BE96E98813001B5 2015-09-17
//
//    pub   1024R/0xD8677565650A8F35 2015-09-17
//    uid                 [ultimate] John Q. Public <jqp@example.org>
//    sub   1024R/0xFFB79C070EE41DE1 2015-09-17
//
//    testdata/secring.gpg
//    --------------------
//    sec   1024R/0x80A3F4356BA114E7 2015-09-17
//    uid                            Test Key <null@127.0.0.1>
//    ssb   1024R/0x8BE96E98813001B5 2015-09-17
//
//    sec   1024R/0xD8677565650A8F35 2015-09-17
//    uid                            John Q. Public <jqp@example.org>
//    ssb   1024R/0xFFB79C070EE41DE1 2015-09-17

var (
	testPublicRing = "testdata/pubring.gpg"
	testSecretRing = "testdata/secring.gpg"
	testPassword   = []byte("passord")
)

func TestLoadKeyRing(t *testing.T) {
	_, err := LoadKey(testPublicRing, 0xD8677565650A8F35, testPassword)
	if err != nil {
		t.Fatal("%v", err)
	}
}
