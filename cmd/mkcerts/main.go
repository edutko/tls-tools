package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"tls-tools/internal/config"
	"tls-tools/internal/pki"
)

func main() {
	configFile := flag.String("config", "certs.conf", "configuration file")
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
	store, err := pki.NewStoreFromConfig(cfg.Certs)
	if err != nil {
		log.Fatalln(err)
	}

	for name, entry := range store {
		err = os.WriteFile(name+".key", entry.GetKeyPEM(), 0600)
		if err != nil {
			log.Fatalln(err)
		}
		err = os.WriteFile(name+".crt", entry.GetCertPEM(), 0644)
		if err != nil {
			log.Fatalln(err)
		}
	}
}
