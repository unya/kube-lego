package acme

import (
	"errors"
	"fmt"
	"github.com/jetstack/kube-lego/pkg/kubelego_const"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/jetstack/kube-lego/pkg/kubelego_const"

	"github.com/cenk/backoff"
	"github.com/xenolf/lego/acme"
	"time"
)

func (a *Acme) newAcmeClient() (*acme.Client, error) {

	// get existing user or create new one
	err := a.getUser()
	if err != nil {
		err := a.createUser()
		if err != nil {
			return nil, err
		}
	} else {
		// validate if account URL and private Key is valid
		err := a.validateUser()
		if err != nil {
			a.Log().Fatalf("Error verifying existing user: %s", err)
		}
	}

	return nil, nil
}

func (a *Acme) testReachabliltyHost(host string) error {
	url := &url.URL{}
	url.Scheme = "http"
	url.Host = host
	url.Path = kubelego.AcmeHttpSelfTest

	a.Log().WithField("host", host).Debugf("testing reachablity of %s", url.String())
	response, err := http.Get(url.String())
	if err != nil {
		return err
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("wrong status code '%d'", response.StatusCode)
	}

	defer response.Body.Close()
	idReceived, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return errors.New("unable to read body")
	}

	if string(idReceived) != a.id {
		if err != nil {
			return fmt.Errorf("received id (%s) did not match expected (%s)", idReceived, a.id)
		}
	}
	return nil

}

func (a *Acme) TestReachability(hosts []string) (errs []error) {
	for _, host := range hosts {
		err := a.testReachabliltyHost(host)
		if err != nil {
			a.Log().WithField("host", host).Warn(err)
			errs = append(errs, err)
		}
	}
	return errs
}

func (a *Acme) ObtainCertificate(domains []string) (data map[string][]byte, err error) {

	op := func() error {
		data, err = a.obtainCertificate(domains)

		if err != nil {
			a.Log().Warn("Error while obtaining certificate: ", err)
		}

		return err
	}

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = time.Duration(time.Second * 30)

	err = backoff.Retry(op, b)
	return
}

func (a *Acme) obtainCertificate(domains []string) (data map[string][]byte, err error) {

	errs := a.TestReachability(domains)
	if len(errs) > 0 {
		err = errors.New("reachabily test failed for this cert")
		return
	}

	client, err := a.client()
	if err != nil {
		return
	}

	certificates, failures := client.ObtainCertificate(
		domains,
		true, // always get bundle
		nil,
	)
	if len(failures) > 0 {
		err = fmt.Errorf("Errors while obtaining cert: %s", failures)
		return
	}

	a.Log().Printf("Got certs=%s", certificates)

	data = map[string][]byte{
		kubelego.TLSCertKey:       certificates.Certificate,
		kubelego.TLSPrivateKeyKey: certificates.PrivateKey,
	}

	return
}

func (a *Acme) CleanUp(host, token, _ string) error {
	a.challengesMutex.Lock()
	if _, ok := a.challengesTokenToKey[token]; ok {
		delete(a.challengesTokenToKey, token)
	}
	if _, ok := a.challengesHostToToken[host]; ok {
		delete(a.challengesHostToToken, host)
	}
	a.challengesMutex.Unlock()
	return nil
}

func (a *Acme) Present(host, token, key string) error {
	a.challengesMutex.Lock()
	a.challengesHostToToken[host] = token
	a.challengesTokenToKey[token] = key
	a.challengesMutex.Unlock()
	return nil
}
