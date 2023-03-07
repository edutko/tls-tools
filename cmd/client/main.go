package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"tls-tools/internal/client"
	"tls-tools/internal/config"
	"tls-tools/internal/pki"
	"tls-tools/internal/tlsutil"
)

func main() {
	configFile := flag.String("config", "client.conf", "configuration file")
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
	certStore, err := pki.NewStoreFromConfig(cfg.Certs)
	if err != nil {
		log.Fatalln(err)
	}

	cs, err := client.NewClientsFromConfig(cfg.Clients, certStore)
	if err != nil {
		log.Fatalln(err)
	}

	for _, c := range cs {
		info, err := c.GatherListenerInfo()
		if err != nil {
			log.Printf("error: %s: %v", c.Addr, err)
		}

		fmt.Printf("Host: %s\n", info.Addr)
		fmt.Printf("  TLS Version: %s\n", tlsutil.TLSVersionString(info.TLSVersion))
		fmt.Printf("  Cipher suite: %s\n", tls.CipherSuiteName(info.CipherSuite))
		for _, crt := range info.PeerCerts {
			fmt.Printf("  Certificate: %s\n", crt.Subject.CommonName)
			fmt.Printf("    Signature algorithm: %s\n", crt.SignatureAlgorithm.String())
		}
	}
}
