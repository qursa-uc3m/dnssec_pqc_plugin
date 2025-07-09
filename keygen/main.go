package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
	sigs := oqs.SupportedSigs()
	fmt.Println("Algoritmos de firma soportados por liboqs:")
	for _, sig := range sigs {
		fmt.Println(" -", sig)
	}

	enabled := oqs.EnabledSigs()
	fmt.Println("Algoritmos de firma habilitados en esta instalación:")
	for _, alg := range enabled {
		fmt.Println(" -", alg)
	}

	// Dominio para el que se generan las claves
	domain := "mydomain.org"
	// Código de algoritmo que CoreDNS espera
	algorithmNumber := "031"
	// Nombre del algoritmo en OQS
	algName := "SNOVA_24_5_4_SHAKE"

	var sig oqs.Signature
	err := sig.Init(algName, nil)
	if err != nil {
		fmt.Println("Error al inicializar el mecanismo de firma:", err)
		return
	}
	defer sig.Clean()

	// Genera el par de claves
	publicKey, err := sig.GenerateKeyPair()
	if err != nil {
		fmt.Println("Error al generar el par de claves:", err)
		return
	}
	secretKey := sig.ExportSecretKey()

	// Calcular el Key ID a partir de la clave pública
	keyID := generateKeyID(publicKey)

	// Convertir la clave pública a Base64 para incluirla en el registro DNSKEY
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)

	// Formatear el registro DNSKEY (para el archivo .key)
	publicKeyContent := fmt.Sprintf("; This is a DNSKEY record\n%s. IN DNSKEY 257 3 %s %s\n",
		domain, algorithmNumber, publicKeyBase64)

	// Generar las fechas de creación, publicación y activación en formato YYYYMMDDhhmmss
	now := time.Now().UTC().Format("20060102150405")

	// Convertir la clave privada a Base64
	privateKeyBase64 := base64.StdEncoding.EncodeToString(secretKey)

	// Formatear el fichero privado en formato similar al que genera BIND
	privateKeyContent := fmt.Sprintf(`Private-key-format: v1.3
Algorithm: %s
Created: %s
Publish: %s
Activate: %s
PrivateKey: %s
`, algorithmNumber, now, now, now, privateKeyBase64)

	// Formatear los nombres de los ficheros siguiendo la convención:
	// K<dominio>+<número de algoritmo>+<keyID>.key y .private
	publicFileName := fmt.Sprintf("K%s+%s+%d.key", domain, algorithmNumber, keyID)
	privateFileName := fmt.Sprintf("K%s+%s+%d.private", domain, algorithmNumber, keyID)

	// Guardar la clave pública (texto) en el archivo .key
	err = os.WriteFile(publicFileName, []byte(publicKeyContent), 0644)
	if err != nil {
		fmt.Println("Error al guardar la clave pública:", err)
		return
	}

	// Guardar la clave privada en formato textual (BIND-like)
	err = os.WriteFile(privateFileName, []byte(privateKeyContent), 0600)
	if err != nil {
		fmt.Println("Error al guardar la clave privada:", err)
		return
	}

	fmt.Println("Claves generadas correctamente:")
	fmt.Println("Clave pública:", publicFileName)
	fmt.Println("Clave privada:", privateFileName)
}

// generateKeyID calcula el Key ID tomando los primeros 2 bytes del hash SHA-256 de la clave pública
func generateKeyID(publicKey []byte) uint16 {
	hash := sha256.Sum256(publicKey)
	return binary.BigEndian.Uint16(hash[:2])
}
