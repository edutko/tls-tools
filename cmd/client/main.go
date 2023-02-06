package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"tls-cert-tools/internal/client"
	"tls-cert-tools/internal/config"
	"tls-cert-tools/internal/util"
)

func main() {
	configFile := flag.String("config", "server.conf", "configuration file")
	flag.Parse()

	cfgBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalln(err)
	}

	var cfg config.Config
	err = json.Unmarshal(cfgBytes, &cfg)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Generating keys and certificates...")
	c, err := client.NewClientFromConfig(cfg)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("Host: %s\n", c.Addr)
	conn, err := tls.Dial("tcp", c.Addr, c.TLSConfig)
	if err != nil {
		log.Fatalln(err)
	}
	defer func() {
		err = conn.Close()
		if err != nil {
			log.Println(err)
		}
	}()

	err = conn.Handshake()
	if err != nil {
		log.Println(err)
	}

	cs := conn.ConnectionState()
	fmt.Printf("  TLS Version: %s\n", util.TLSVersionString(cs.Version))
	fmt.Printf("  Cipher suite: %s\n", tls.CipherSuiteName(cs.CipherSuite))
	for _, crt := range cs.PeerCertificates {
		fmt.Printf("  Certificate: %s\n", crt.Subject.CommonName)
		fmt.Printf("    Signature algorithm: %s\n", crt.SignatureAlgorithm.String())
	}
}
