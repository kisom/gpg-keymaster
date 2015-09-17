// Package pgputil contains functions that are useful for generating
// OpenPGP keys where a name and comment should be applied to a number
// of email addresses. This is useful for generating a personal key
// that should be applied to a number of email address identities.
package pgputil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var (
	rsaBits = 4096
	hash    = crypto.SHA512
)

// PGPConfig returns a sane set of defaults: zlib compression, SHA512,
// and 4096-bit RSA keys.
func PGPConfig() *packet.Config {
	return &packet.Config{
		DefaultCompressionAlgo: packet.CompressionZLIB,
		DefaultHash:            hash,
		RSABits:                rsaBits,
	}
}

func newSignature() *packet.Signature {
	return &packet.Signature{
		Hash: hash,
	}
}

// A Key stores metadata that is used to generate keys.
type Key struct {
	Name    string   `json:"name"`
	Comment string   `json:"comment"`
	UIDs    []string `json:"uids"`
}

// A Keypair stores serialised keys for export.
type Keypair struct {
	Comment string
	Private *bytes.Buffer
	Public  *bytes.Buffer
}

// PGPID returns an OpenPGP identity (e.g. UID) for the email. The
// email must be one of the emails present in the UIDs field.
func (k *Key) PGPID(email string) *openpgp.Identity {
	var found bool
	for i := range k.UIDs {
		if k.UIDs[i] == email {
			found = true
			break
		}
	}

	if !found {
		return nil
	}

	uid := packet.NewUserId(k.Name, k.Comment, email)
	if uid == nil {
		return nil
	}

	comment := k.Comment
	if comment != "" {
		comment = "(" + comment + ") "
	}

	name := fmt.Sprintf("%s %s<%s>", k.Name, comment, email)
	return &openpgp.Identity{
		Name:          name,
		UserId:        uid,
		SelfSignature: newSignature(),
	}
}

func generateSubkey() (*openpgp.Subkey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	when := time.Now()
	spriv := packet.NewRSAPrivateKey(when, priv)
	return &openpgp.Subkey{
		PrivateKey: spriv,
		PublicKey:  &spriv.PublicKey,
		Sig:        newSignature(),
	}, nil
}

// Generate creates a new OpenPGP key from metadata. Due to
// limitations in the OpenPGP library, these keys are unprotected and
// must have a password applied using the GPG tool.
func (k *Key) Generate() (*openpgp.Entity, error) {
	primaryID := k.UIDs[0]
	subIDs := k.UIDs[1:]

	log.Println("generating primary key")
	ent, err := openpgp.NewEntity(k.Name, k.Comment, primaryID, PGPConfig())
	if err != nil {
		return nil, err
	}

	log.Println("generating subkey")
	cryptkey, err := generateSubkey()
	if err != nil {
		return nil, err
	}

	for _, id := range subIDs {
		uid := k.PGPID(id)
		if nil == uid {
			return nil, errors.New("invalid identity")
		}
		ent.Identities[uid.Name] = uid
	}

	for name := range ent.Identities {
		log.Println("self-signing identity", name)
		err = ent.SignIdentity(name, ent, PGPConfig())
		if err != nil {
			return nil, err
		}
	}

	log.Println("signing subkey")
	err = cryptkey.Sig.SignKey(cryptkey.PublicKey, ent.PrivateKey, PGPConfig())
	if err != nil {
		return nil, err
	}
	ent.Subkeys = []openpgp.Subkey{*cryptkey}
	return ent, nil
}

// New generates a new key with the supplied metadata, and signs it
// with the provided identity key. If the predecessor key is not nil,
// it will also be used to sign the key to provide continuity.
