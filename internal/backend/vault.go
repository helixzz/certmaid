package backend

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	certmaid "github.com/helixzz/certmaid"
)

// VaultBackend issues certificates from a Vault PKI ACME endpoint.
type VaultBackend struct {
	directoryURL string
	eabKid       string
	eabHMACKey   string
}

// NewVaultBackend creates a new VaultBackend with the given configuration.
func NewVaultBackend(directoryURL, eabKid, eabHMACKey string) *VaultBackend {
	return &VaultBackend{
		directoryURL: directoryURL,
		eabKid:       eabKid,
		eabHMACKey:   eabHMACKey,
	}
}

// acmeUser implements the registration.User interface for lego.
type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// Issue obtains a certificate from the Vault PKI ACME endpoint.
func (v *VaultBackend) Issue(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled before issuing certificate %q: %w", spec.Name, err)
	}

	if len(spec.Domains) == 0 {
		return nil, fmt.Errorf("certificate spec %q has no domains", spec.Name)
	}

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ACME account key: %w", err)
	}

	user := &acmeUser{
		email: "",
		key:   accountKey,
	}

	config := lego.NewConfig(user)
	config.CADirURL = v.directoryURL

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("creating lego client: %w", err)
	}

	httpProvider := http01.NewProviderServer("", "80")
	if err := client.Challenge.SetHTTP01Provider(httpProvider); err != nil {
		return nil, fmt.Errorf("setting HTTP-01 provider: %w", err)
	}

	if v.eabKid != "" && v.eabHMACKey != "" {
		reg, regErr := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  v.eabKid,
			HmacEncoded:          v.eabHMACKey,
		})
		if regErr != nil {
			return nil, fmt.Errorf("registering ACME account with EAB: %w", regErr)
		}
		user.registration = reg
	} else {
		reg, regErr := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if regErr != nil {
			return nil, fmt.Errorf("registering ACME account: %w", regErr)
		}
		user.registration = reg
	}

	certKeyType := mapKeyType(spec.KeyType)
	privateKey, err := certcrypto.GeneratePrivateKey(certKeyType)
	if err != nil {
		return nil, fmt.Errorf("generating certificate private key: %w", err)
	}

	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    spec.Domains,
		Bundle:     true,
		PrivateKey: privateKey,
	})
	if err != nil {
		return nil, fmt.Errorf("obtaining certificate for %q: %w", spec.Name, err)
	}

	leafPEM, chainPEMs, err := splitCertChain(resource.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate chain for %q: %w", spec.Name, err)
	}

	notAfter, err := extractNotAfter(leafPEM)
	if err != nil {
		return nil, fmt.Errorf("extracting expiration for %q: %w", spec.Name, err)
	}

	return &certmaid.CertificateBundle{
		Certificate: leafPEM,
		PrivateKey:  resource.PrivateKey,
		IssuingCA:   resource.IssuerCertificate,
		CAChain:     chainPEMs,
		Domains:     spec.Domains,
		NotAfter:    notAfter,
	}, nil
}

func mapKeyType(kt string) certcrypto.KeyType {
	switch kt {
	case "RSA2048":
		return certcrypto.RSA2048
	case "ECDSA256":
		return certcrypto.EC256
	case "ECDSA384":
		return certcrypto.EC384
	default:
		return certcrypto.RSA2048
	}
}

func splitCertChain(bundle []byte) (leaf []byte, chain [][]byte, err error) {
	var blocks []*pem.Block
	rest := bundle
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
		rest = remaining
	}

	if len(blocks) == 0 {
		return nil, nil, fmt.Errorf("no PEM blocks found in certificate bundle")
	}

	leaf = pem.EncodeToMemory(blocks[0])
	for i := 1; i < len(blocks); i++ {
		chain = append(chain, pem.EncodeToMemory(blocks[i]))
	}

	return leaf, chain, nil
}

func extractNotAfter(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing certificate: %w", err)
	}

	return cert.NotAfter, nil
}