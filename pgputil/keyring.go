package pgputil

import (
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
)

func LoadKey(kr string, id uint64, pass []byte) (*openpgp.Entity, error) {
	krf, err := os.Open(kr)
	if err != nil {
		return nil, err
	}
	defer krf.Close()

	el, err := openpgp.ReadKeyRing(krf)
	if err != nil {
		el, err = openpgp.ReadArmoredKeyRing(krf)
		if err != nil {
			return nil, err
		}
	}

	found := el.KeysById(id)
	if len(found) == 0 {
		return nil, fmt.Errorf("no keys found with id %d", id)
	}

	return found[0].Entity, nil
}
