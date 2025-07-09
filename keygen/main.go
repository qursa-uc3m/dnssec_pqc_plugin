package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
	// Define flags
	domain := flag.String("domain", "mydomain.org", "Domain name for key generation")
	algName := flag.String("algorithm", "", "PQC algorithm name (required)")
	algorithmNumber := flag.String("number", "", "Algorithm number/ID (required)")
	help := flag.Bool("help", false, "Show help and available algorithms")

	flag.Parse()

	// Show help if requested or if required parameters are missing
	if *help || *algName == "" || *algorithmNumber == "" {
		if *help {
			fmt.Println("PQC DNSSEC Key Generator")
			fmt.Println("========================")
		}

		flag.Usage()

		// Show available algorithms
		sigs := oqs.SupportedSigs()
		fmt.Println("\nSupported signature algorithms:")
		for _, sig := range sigs {
			fmt.Println(" -", sig)
		}

		enabled := oqs.EnabledSigs()
		fmt.Println("\nEnabled signature algorithms:")
		for _, alg := range enabled {
			fmt.Println(" -", alg)
		}

		fmt.Println("\nExamples:")
		fmt.Println("  ./keygen -algorithm SNOVA_24_5_4_SHAKE -number 31")
		fmt.Println("  ./keygen -domain example.com -algorithm FALCON512 -number 17")
		fmt.Println("  ./keygen -algorithm DILITHIUM2 -number 18 -domain test.org")

		if *algName == "" || *algorithmNumber == "" {
			os.Exit(1)
		}
		return
	}

	var sig oqs.Signature
	err := sig.Init(*algName, nil)
	if err != nil {
		fmt.Println("Error initializing signature mechanism:", err)
		return
	}
	defer sig.Clean()

	// Generate key pair
	publicKey, err := sig.GenerateKeyPair()
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}
	secretKey := sig.ExportSecretKey()

	// Calculate Key ID from public key
	keyID := generateKeyID(publicKey)

	// Convert public key to Base64 for DNSKEY record
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)

	// Format DNSKEY record (for .key file)
	publicKeyContent := fmt.Sprintf("; This is a DNSKEY record\n%s. IN DNSKEY 257 3 %s %s\n",
		*domain, *algorithmNumber, publicKeyBase64)

	// Generate creation, publication and activation timestamps in YYYYMMDDhhmmss format
	now := time.Now().UTC().Format("20060102150405")

	// Convert private key to Base64
	privateKeyBase64 := base64.StdEncoding.EncodeToString(secretKey)

	// Format private key file in BIND-like format
	privateKeyContent := fmt.Sprintf(`Private-key-format: v1.3
Algorithm: %s
Created: %s
Publish: %s
Activate: %s
PrivateKey: %s
`, *algorithmNumber, now, now, now, privateKeyBase64)

	// Format file names following convention:
	// K<domain>+<algorithm_number>+<keyID>.key and .private
	publicFileName := fmt.Sprintf("K%s+%s+%d.key", *domain, *algorithmNumber, keyID)
	privateFileName := fmt.Sprintf("K%s+%s+%d.private", *domain, *algorithmNumber, keyID)

	// Save public key (text) to .key file
	err = os.WriteFile(publicFileName, []byte(publicKeyContent), 0644)
	if err != nil {
		fmt.Println("Error saving public key:", err)
		return
	}

	// Save private key in textual format (BIND-like)
	err = os.WriteFile(privateFileName, []byte(privateKeyContent), 0600)
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return
	}

	fmt.Println("Keys generated successfully:")
	fmt.Println("Domain:", *domain)
	fmt.Println("Algorithm:", *algName)
	fmt.Println("Algorithm Number:", *algorithmNumber)
	fmt.Println("Public key:", publicFileName)
	fmt.Println("Private key:", privateFileName)
}

// generateKeyID calculates the Key ID by taking the first 2 bytes of the SHA-256 hash of the public key
func generateKeyID(publicKey []byte) uint16 {
	hash := sha256.Sum256(publicKey)
	return binary.BigEndian.Uint16(hash[:2])
}
