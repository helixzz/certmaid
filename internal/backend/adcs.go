package backend

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	certmaid "github.com/helixzz/certmaid"
)

// PKCS#9 challengePassword attribute OID (1.2.840.113549.1.9.7).
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// PKCS#7 content type OIDs.
var (
	oidPKCS7Data       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// pkcs7ContentInfo is the top-level PKCS#7 structure.
type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// pkcs7SignedData is the PKCS#7 signed-data content.
type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      pkcs7ContentInfo
	Certificates     asn1.RawValue `asn1:"tag:0,optional,explicit"`
	CRLs             asn1.RawValue `asn1:"tag:1,optional,explicit"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

// certRepAttribute is a single attribute in a CSR (type + values).
type certRepAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// certificationRequestInfo is the to-be-signed portion of a PKCS#10 CSR.
type certificationRequestInfo struct {
	Version       int
	Subject       asn1.RawValue
	SubjectPKInfo asn1.RawValue
	Attributes    []certRepAttribute `asn1:"tag:0,set,optional"`
}

// certificationRequest is a full PKCS#10 CSR.
type certificationRequest struct {
	TBSCSR           certificationRequestInfo
	SignatureAlgo    pkix.AlgorithmIdentifier
	SignatureValue   asn1.BitString
}

// ADCSBackend issues certificates from an Active Directory Certificate Services
// NDES server using the SCEP protocol.
type ADCSBackend struct {
	serverURL     string
	challengePass string
	caFingerprint string
	pollInterval  time.Duration
	pollTimeout   time.Duration

	mu         sync.Mutex
	httpClient *http.Client
}

// NewADCSBackend creates a new ADCSBackend with the given configuration.
func NewADCSBackend(serverURL, challengePassword, caFingerprint string, pollInterval, pollTimeout time.Duration) *ADCSBackend {
	return &ADCSBackend{
		serverURL:     serverURL,
		challengePass: challengePassword,
		caFingerprint: caFingerprint,
		pollInterval:  pollInterval,
		pollTimeout:   pollTimeout,
	}
}

// getHTTPClient returns the lazily-initialized HTTP client.
func (a *ADCSBackend) getHTTPClient() *http.Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.httpClient == nil {
		a.httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	return a.httpClient
}

// Issue obtains a certificate from the AD CS NDES server via SCEP.
func (a *ADCSBackend) Issue(ctx context.Context, spec certmaid.CertificateSpec) (*certmaid.CertificateBundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled before issuing certificate %q: %w", spec.Name, err)
	}

	if len(spec.Domains) == 0 {
		return nil, fmt.Errorf("certificate spec %q has no domains", spec.Name)
	}

	switch spec.KeyType {
	case "ECDSA256", "ECDSA384":
		return nil, fmt.Errorf("AD CS SCEP backend only supports RSA keys; use RSA2048 or RSA4096")
	}

	httpClient := a.getHTTPClient()

	// 1. Fetch the CA certificate(s).
	caCerts, err := getCACert(ctx, httpClient, a.serverURL)
	if err != nil {
		return nil, fmt.Errorf("getting CA certificate for %q: %w", spec.Name, err)
	}

	caCert, err := selectCACert(caCerts, a.caFingerprint)
	if err != nil {
		return nil, fmt.Errorf("selecting CA certificate for %q: %w", spec.Name, err)
	}

	// 2. Generate RSA private key.
	keyBits := 2048
	if spec.KeyType == "RSA4096" {
		keyBits = 4096
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA private key for %q: %w", spec.Name, err)
	}

	// 3. Build CSR with challengePassword attribute.
	csrDER, err := buildCSR(spec.Domains, privateKey, a.challengePass)
	if err != nil {
		return nil, fmt.Errorf("building CSR for %q: %w", spec.Name, err)
	}

	// 4. Submit PKIOperation.
	respData, status, err := submitPKIOperation(ctx, httpClient, a.serverURL, csrDER)
	if err != nil {
		return nil, fmt.Errorf("submitting PKIOperation for %q: %w", spec.Name, err)
	}

	// 5. Handle PENDING with polling.
	if status == "PENDING" {
		respData, err = pollForCert(ctx, httpClient, a.serverURL, a.pollInterval, a.pollTimeout)
		if err != nil {
			return nil, fmt.Errorf("polling for certificate %q: %w", spec.Name, err)
		}
	}

	// 6. Extract the issued certificate from the response.
	cert, err := extractCertificate(respData)
	if err != nil {
		return nil, fmt.Errorf("extracting certificate for %q: %w", spec.Name, err)
	}

	// 7. Build the CertificateBundle.
	leafPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	issuingCAPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	var caChain [][]byte
	for _, c := range caCerts {
		caChain = append(caChain, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))
	}

	return &certmaid.CertificateBundle{
		Certificate: leafPEM,
		PrivateKey:  keyPEM,
		IssuingCA:   issuingCAPEM,
		CAChain:     caChain,
		Domains:     spec.Domains,
		NotAfter:    cert.NotAfter,
	}, nil
}

// getCACert fetches the CA certificate(s) from the NDES server.
func getCACert(ctx context.Context, httpClient *http.Client, serverURL string) ([]*x509.Certificate, error) {
	reqURL := strings.TrimRight(serverURL, "/") + "?operation=GetCACert"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating GetCACert request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GetCACert request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GetCACert returned status %d: %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("reading GetCACert response: %w", err)
	}

	// Try PKCS#7 degenerate "certs-only" bundle first.
	certs, err := parseCertificatesFromPKCS7(data)
	if err == nil && len(certs) > 0 {
		return certs, nil
	}

	// Try raw DER certificate.
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return []*x509.Certificate{cert}, nil
	}

	// Try PEM.
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return []*x509.Certificate{cert}, nil
		}
	}

	return nil, fmt.Errorf("parsing GetCACert response: not a valid PKCS#7 degenerate bundle, DER, or PEM certificate")
}

// submitPKIOperation sends the CSR to the NDES PKIOperation endpoint.
// Returns the raw response body and the pkiStatus string.
func submitPKIOperation(ctx context.Context, httpClient *http.Client, serverURL string, csrDER []byte) ([]byte, string, error) {
	reqURL := strings.TrimRight(serverURL, "/") + "?operation=PKIOperation"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(csrDER))
	if err != nil {
		return nil, "", fmt.Errorf("creating PKIOperation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-pki-message")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("PKIOperation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("PKIOperation returned status %d: %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, "", fmt.Errorf("reading PKIOperation response: %w", err)
	}

	// Try to parse as PKCS#7 CertRep to extract status.
	status := extractPKIStatus(data)
	return data, status, nil
}

// pollForCert polls the NDES server until a certificate is issued or timeout.
func pollForCert(ctx context.Context, httpClient *http.Client, serverURL string, pollInterval, pollTimeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(pollTimeout)

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("polling timed out after %v", pollTimeout)
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled during poll: %w", ctx.Err())
		case <-time.After(pollInterval):
		}

		reqURL := strings.TrimRight(serverURL, "/") + "?operation=PKIOperation"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating poll request: %w", err)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("poll request failed: %w", err)
		}

		data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading poll response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("poll returned status %d: %s", resp.StatusCode, string(data))
		}

		status := extractPKIStatus(data)
		switch status {
		case "SUCCESS":
			return data, nil
		case "FAILURE":
			return nil, fmt.Errorf("certificate request failed")
		case "PENDING":
			continue
		default:
			// If we can't determine status, try to extract a certificate directly.
			if _, err := extractCertificate(data); err == nil {
				return data, nil
			}
			continue
		}
	}
}

// extractPKIStatus attempts to extract the pkiStatus from a PKCS#7 CertRep response.
// Returns "PENDING" if status cannot be determined (conservative default).
func extractPKIStatus(data []byte) string {
	ci := pkcs7ContentInfo{}
	if _, err := asn1.Unmarshal(data, &ci); err != nil {
		return ""
	}
	if !ci.ContentType.Equal(oidPKCS7SignedData) {
		return ""
	}

	sd := pkcs7SignedData{}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return ""
	}

	// The inner content is the CertRep. Try to parse pkiStatus from it.
	// CertRep ::= SEQUENCE { response SEQUENCE OF CertResponse, ... }
	// CertResponse ::= SEQUENCE { certReqId INTEGER, certStatus PKIStatusInfo, ... }
	// PKIStatusInfo ::= SEQUENCE { status PKIStatus, ... }
	// PKIStatus ::= INTEGER { granted(0), grantedWithMods(1), rejection(2), waiting(3), ... }

	// For simplicity, we check if the response contains a certificate.
	// If it does, we assume SUCCESS; otherwise PENDING.
	if sd.Certificates.Bytes != nil && len(sd.Certificates.Bytes) > 0 {
		return "SUCCESS"
	}
	return "PENDING"
}

// extractCertificate extracts an x509 certificate from a PKCS#7 response or raw DER/PEM.
func extractCertificate(data []byte) (*x509.Certificate, error) {
	// Try PKCS#7 first.
	certs, err := parseCertificatesFromPKCS7(data)
	if err == nil && len(certs) > 0 {
		return certs[0], nil
	}

	// Try raw DER.
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}

	// Try PEM.
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("could not extract certificate from response")
}

// parseCertificatesFromPKCS7 extracts certificates from a PKCS#7 signedData or
// degenerate certs-only bundle.
func parseCertificatesFromPKCS7(data []byte) ([]*x509.Certificate, error) {
	ci := pkcs7ContentInfo{}
	if _, err := asn1.Unmarshal(data, &ci); err != nil {
		return nil, fmt.Errorf("unmarshaling PKCS#7 ContentInfo: %w", err)
	}

	if !ci.ContentType.Equal(oidPKCS7SignedData) {
		return nil, fmt.Errorf("not a signedData content type")
	}

	sd := pkcs7SignedData{}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("unmarshaling PKCS#7 SignedData: %w", err)
	}

	if sd.Certificates.Bytes == nil || len(sd.Certificates.Bytes) == 0 {
		return nil, fmt.Errorf("no certificates in PKCS#7")
	}

	// The certificates field is [0] IMPLICIT SET OF Certificate.
	// Each certificate is a raw DER-encoded x509 certificate.
	var rawCerts []asn1.RawValue
	if _, err := asn1.Unmarshal(sd.Certificates.Bytes, &rawCerts); err != nil {
		return nil, fmt.Errorf("unmarshaling PKCS#7 certificates: %w", err)
	}

	var certs []*x509.Certificate
	for _, rc := range rawCerts {
		cert, err := x509.ParseCertificate(rc.FullBytes)
		if err != nil {
			// Skip unparseable certificates.
			continue
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no parseable certificates in PKCS#7")
	}

	return certs, nil
}

// buildCSR constructs a PKCS#10 CSR with the challengePassword attribute embedded.
func buildCSR(domains []string, key *rsa.PrivateKey, challengePassword string) ([]byte, error) {
	// 1. Build the subject.
	subject := pkix.Name{CommonName: domains[0]}
	subjectDER, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshaling subject: %w", err)
	}

	// 2. Build SubjectPublicKeyInfo.
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}

	// 3. Build the challengePassword attribute value (DirectoryString as PrintableString).
	challengeValue, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagPrintableString,
		Bytes: []byte(challengePassword),
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling challenge password: %w", err)
	}

	challengeAttr := certRepAttribute{
		Type: oidChallengePassword,
		Value: asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagSet,
			Bytes: challengeValue,
		},
	}

	// 4. Build the extensionRequest attribute for SANs.
	sanExt, err := buildSANExtension(domains)
	if err != nil {
		return nil, fmt.Errorf("building SAN extension: %w", err)
	}

	extReqValue, err := asn1.Marshal([]pkix.Extension{sanExt})
	if err != nil {
		return nil, fmt.Errorf("marshaling extension request: %w", err)
	}

	extReqAttr := certRepAttribute{
		Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}, // extensionRequest
		Value: asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagSet,
			Bytes: extReqValue,
		},
	}

	// 5. Build CertificationRequestInfo.
	cri := certificationRequestInfo{
		Version: 0,
		Subject: asn1.RawValue{FullBytes: subjectDER},
		SubjectPKInfo: asn1.RawValue{FullBytes: pubKeyDER},
		Attributes:    []certRepAttribute{challengeAttr, extReqAttr},
	}

	criDER, err := asn1.Marshal(cri)
	if err != nil {
		return nil, fmt.Errorf("marshaling CertificationRequestInfo: %w", err)
	}

	// 6. Sign the CertificationRequestInfo.
	hash := sha256.Sum256(criDER)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing CSR: %w", err)
	}

	// 7. Build the full CertificationRequest.
	csr := certificationRequest{
		TBSCSR: cri,
		SignatureAlgo: pkix.AlgorithmIdentifier{
			Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSAEncryption
			Parameters: asn1.NullRawValue,
		},
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}

	csrDER, err := asn1.Marshal(csr)
	if err != nil {
		return nil, fmt.Errorf("marshaling CertificationRequest: %w", err)
	}

	return csrDER, nil
}

// buildSANExtension creates a Subject Alternative Name extension for the given domains.
func buildSANExtension(domains []string) (pkix.Extension, error) {
	var rawValues []asn1.RawValue
	for _, d := range domains {
		rawValues = append(rawValues, asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   2, // dNSName
			Bytes: []byte(d),
		})
	}

	sanDER, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling SAN: %w", err)
	}

	return pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // subjectAltName
		Value: sanDER,
	}, nil
}

// selectCACert picks the appropriate CA certificate from the list.
// If a fingerprint is provided, the matching certificate is returned.
// Otherwise, the first certificate with key encipherment usage is preferred.
func selectCACert(certs []*x509.Certificate, caFingerprint string) (*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CA certificates available")
	}

	if caFingerprint != "" {
		fp := strings.ReplaceAll(caFingerprint, ":", "")
		fp = strings.ReplaceAll(fp, " ", "")
		fp = strings.ToLower(fp)
		fpBytes, err := hex.DecodeString(fp)
		if err != nil {
			return nil, fmt.Errorf("invalid CA fingerprint %q: %w", caFingerprint, err)
		}

		for _, cert := range certs {
			hash := sha256.Sum256(cert.Raw)
			if bytes.Equal(hash[:], fpBytes) {
				return cert, nil
			}
		}
		return nil, fmt.Errorf("no CA certificate matches fingerprint %q", caFingerprint)
	}

	enciphermentKeyUsages := x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment
	for _, cert := range certs {
		if cert.KeyUsage&enciphermentKeyUsages != 0 {
			return cert, nil
		}
	}

	return certs[0], nil
}

// serialNumber generates a random serial number for self-signed certificates.
func serialNumber() *big.Int {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return new(big.Int).SetBytes(b)
}
