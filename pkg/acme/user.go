package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
)

func (a *Acme) getContact() []string {
	return []string{
		fmt.Sprintf("mailto:%s", a.kubelego.LegoEmail()),
	}
}

func (a *Acme) acceptTos(tos string) bool {
	a.Log().Infof("If you don't accept the TOS (%s) please exit the program now", tos)
	return true
}

func (a *Acme) createUser() error {
	privateKeyPem, privateKey, err := a.generatePrivateKey()
	if err != nil {
		return err
	}

	a.acmeClient = &acme.Client{
		Key:          privateKey,
		DirectoryURL: a.kubelego.LegoURL(),
	}

	account := &acme.Account{
		Contact: a.getContact(),
	}

	account, err = a.acmeClient.Register(
		context.Background(),
		account,
		a.acceptTos,
	)
	if err != nil {
		return err
	}
	a.Log().Infof("Created an ACME account (registration url: %s)", account.URI)

	a.acmeAccountURI = account.URI
	a.acmeAccount = account

	return a.kubelego.SaveAcmeUser(
		map[string][]byte{
			kubelego.AcmePrivateKey:      privateKeyPem,
			kubelego.AcmeRegistrationUrl: []byte(account.URI),
		},
	)
}

func (a *Acme) getUser() error {

	userData, err := a.kubelego.AcmeUser()
	if err != nil {
		return err
	}

	privateKeyData, ok := userData[kubelego.AcmePrivateKey]
	if !ok {
		return fmt.Errorf("Could not find acme private key with key '%s'", kubelego.AcmePrivateKey)
	}
	block, _ := pem.Decode(privateKeyData)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	a.acmeClient = &acme.Client{
		Key:          privateKey,
		DirectoryURL: a.kubelego.LegoURL(),
	}

	acmeAccountURIBytes, ok := userData[kubelego.AcmeRegistrationUrl]
	if ok {
		return nil
	}
	a.acmeAccountURI = string(acmeAccountURIBytes)

	regData, ok := userData[kubelego.AcmeRegistration]
	if !ok {
		return fmt.Errorf("Could not find an ACME account URI in the account secret")
	}
	reg := acmeAccountRegistration{}
	err = json.Unmarshal(regData, &reg)
	if err != nil {
		return err
	}
	a.acmeAccountURI = reg.URI

	return nil
}

func (a *Acme) validateUser() error {
	return nil
}

func (a *Acme) generatePrivateKey() ([]byte, *rsa.PrivateKey, error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, kubelego.RsaKeySize)
	if err != nil {
		return []byte{}, nil, err
	}

	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}

	return pem.EncodeToMemory(block), privateKey, nil

}
