// Package backend provides CA backend implementations for certificate issuance.
package backend

import certmaid "github.com/helixzz/certmaid"

// Backend is the interface for CA backends that issue certificates.
// This is a re-export of the root package's Backend interface.
type Backend = certmaid.Backend