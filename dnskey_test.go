package dnssec_pqc

import (
	"fmt"
	"testing"
)

func TestParseKey(t *testing.T) {
	pubFile := "path_to_public_key_file"   // Reemplaza con tu archivo de clave pública
	privFile := "path_to_private_key_file" // Reemplaza con tu archivo de clave privada

	dnskey, err := ParseKeyFile(pubFile, privFile)
	if err != nil {
		fmt.Println("Error al parsear las claves:", err)
		return
	}

	fmt.Println("Clave pública:", dnskey.K)
	fmt.Println("Clave privada (raw bytes):", dnskey.privRaw)

}
