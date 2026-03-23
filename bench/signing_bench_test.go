package bench

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// algConfig holds the parameters for each algorithm under test.
type algConfig struct {
	dnsAlg  uint8
	oqsName string // empty for traditional algorithms
	name    string
}

var algorithms = []algConfig{
	{dns.RSASHA256, "", "RSA-SHA256"},
	{dns.ECDSAP256SHA256, "", "ECDSA-P256"},
	{dns.ED25519, "", "Ed25519"},
	{dns.FALCON512, "Falcon-512", "Falcon-512"},
	{dns.FALCON1024, "Falcon-1024", "Falcon-1024"},
	{dns.ML_DSA_44, "ML-DSA-44", "ML-DSA-44"},
	{dns.ML_DSA_65, "ML-DSA-65", "ML-DSA-65"},
	{dns.ML_DSA_87, "ML-DSA-87", "ML-DSA-87"},
	{dns.MAYO1, "MAYO-1", "MAYO-1"},
	{dns.MAYO3, "MAYO-3", "MAYO-3"},
	{dns.SNOVA, "SNOVA_24_5_4", "SNOVA"},
	{dns.SPHINCS_SHA2, "SPHINCS+-SHA2-128s-simple", "SLH-DSA-SHA2-128s"},
}

// benchKey holds the material needed for one signing operation.
type benchKey struct {
	dnskey  *dns.DNSKEY
	signer  crypto.Signer // non-nil for traditional, nil for PQC
	privRaw []byte        // raw secret key for PQC, nil for traditional
	tag     uint16
}

func generateKey(alg algConfig) (*benchKey, error) {
	dk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "bench.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: alg.dnsAlg,
	}

	if alg.oqsName != "" {
		return generatePQCKey(alg, dk)
	}
	return generateTraditionalKey(alg, dk)
}

func generatePQCKey(alg algConfig, dk *dns.DNSKEY) (*benchKey, error) {
	sig := oqs.Signature{}
	if err := sig.Init(alg.oqsName, nil); err != nil {
		return nil, fmt.Errorf("oqs init %s: %w", alg.oqsName, err)
	}

	pubKey, err := sig.GenerateKeyPair()
	if err != nil {
		sig.Clean()
		return nil, fmt.Errorf("oqs keygen %s: %w", alg.oqsName, err)
	}

	exported := sig.ExportSecretKey()
	secretKey := make([]byte, len(exported))
	copy(secretKey, exported)
	sig.Clean()

	dk.PublicKey = base64.StdEncoding.EncodeToString(pubKey)
	return &benchKey{dnskey: dk, privRaw: secretKey, tag: dk.KeyTag()}, nil
}

func generateTraditionalKey(alg algConfig, dk *dns.DNSKEY) (*benchKey, error) {
	switch alg.dnsAlg {
	case dns.RSASHA256:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		// RFC 3110 format: 1-byte exponent length + exponent + modulus
		e := big.NewInt(int64(key.PublicKey.E))
		eBytes := e.Bytes()
		nBytes := key.PublicKey.N.Bytes()
		pub := make([]byte, 0, 1+len(eBytes)+len(nBytes))
		if len(eBytes) <= 255 {
			pub = append(pub, byte(len(eBytes)))
		} else {
			pub = append(pub, 0)
			buf := make([]byte, 2)
			binary.BigEndian.PutUint16(buf, uint16(len(eBytes)))
			pub = append(pub, buf...)
		}
		pub = append(pub, eBytes...)
		pub = append(pub, nBytes...)
		dk.PublicKey = base64.StdEncoding.EncodeToString(pub)
		return &benchKey{dnskey: dk, signer: key, tag: dk.KeyTag()}, nil

	case dns.ECDSAP256SHA256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		xBytes := key.PublicKey.X.Bytes()
		yBytes := key.PublicKey.Y.Bytes()
		// Pad to 32 bytes each for P-256
		pub := make([]byte, 64)
		copy(pub[32-len(xBytes):32], xBytes)
		copy(pub[64-len(yBytes):64], yBytes)
		dk.PublicKey = base64.StdEncoding.EncodeToString(pub)
		return &benchKey{dnskey: dk, signer: key, tag: dk.KeyTag()}, nil

	case dns.ED25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		dk.PublicKey = base64.StdEncoding.EncodeToString(pub)
		return &benchKey{dnskey: dk, signer: priv, tag: dk.KeyTag()}, nil
	}
	return nil, fmt.Errorf("unsupported traditional algorithm: %d", alg.dnsAlg)
}

func makeRRset() []dns.RR {
	rr, _ := dns.NewRR("bench.example. 3600 IN A 192.0.2.1")
	return []dns.RR{rr}
}

func newRRSIG(alg uint8, tag uint16) *dns.RRSIG {
	now := time.Now().UTC()
	return &dns.RRSIG{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeRRSIG},
		Algorithm:  alg,
		KeyTag:     tag,
		SignerName: "bench.example.",
		Inception:  uint32(now.Add(-time.Hour).Unix()),
		Expiration: uint32(now.Add(8 * 24 * time.Hour).Unix()),
		OrigTtl:    3600,
	}
}

// BenchmarkSign measures raw signing time for each algorithm.
func BenchmarkSign(b *testing.B) {
	rrset := makeRRset()

	for _, alg := range algorithms {
		key, err := generateKey(alg)
		if err != nil {
			b.Fatalf("keygen %s: %v", alg.name, err)
		}

		b.Run(alg.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sig := newRRSIG(alg.dnsAlg, key.tag)
				if err := sig.SignWithPQC(key.signer, rrset, key.privRaw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
