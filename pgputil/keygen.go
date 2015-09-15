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

type Key struct {
	Name    string   `json:"name"`
	Comment string   `json:"comment"`
	UIDs    []string `json:"uids"`
}

type Keypair struct {
	Comment string
	Private *bytes.Buffer
	Public  *bytes.Buffer
}

func (k *Key) PGPID(email string) *openpgp.Identity {
	uid := packet.NewUserId(k.Name, k.Comment, email)
	if uid == nil {
		return nil
	}

	comment := k.Comment
	if comment != "" {
		comment = "(" + comment + ") "
	}
	name := fmt.Sprintf("%s %s<%s>", k.Name, email, comment)
	fmt.Println("comment:", comment)
	fmt.Println("email:", email)

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
		log.Println(id)
		uid := k.PGPID(id)
		if nil == uid {
			return nil, errors.New("invalid identity")
		}
		log.Printf("%#v", uid)
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
