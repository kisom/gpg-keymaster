package pgputil

import (
	"errors"
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

	var ent *openpgp.Entity

	for i := range found {
		if found[i].Entity.PrivateKey != nil {
			ent = found[i].Entity
			break
		}
	}

	if ent == nil {
		return nil, errors.New("no valid identity could be found")
	} else if ent.PrivateKey == nil {
		return nil, errors.New("no valid private key found")
	}

	if ent.PrivateKey.Encrypted {
		err = ent.PrivateKey.Decrypt(pass)
		if err != nil {
			return nil, err
		}
	}

	return ent, nil
}
