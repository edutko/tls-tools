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
	p, err := client.NewClientPoolFromConfig(cfg)
	if err != nil {
		log.Fatalln(err)
	}

	for _, c := range p.Clients {
		info, err := c.GatherListenerInfo()
		if err != nil {
			log.Printf("error: %s: %v", c.Addr, err)
		}

		fmt.Printf("Host: %s\n", info.Addr)
		fmt.Printf("  TLS Version: %s\n", util.TLSVersionString(info.TLSVersion))
		fmt.Printf("  Cipher suite: %s\n", tls.CipherSuiteName(info.CipherSuite))
		for _, crt := range info.PeerCerts {
			fmt.Printf("  Certificate: %s\n", crt.Subject.CommonName)
			fmt.Printf("    Signature algorithm: %s\n", crt.SignatureAlgorithm.String())
		}
	}
}
