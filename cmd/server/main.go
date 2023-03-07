package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"

	"tls-tools/internal/config"
	"tls-tools/internal/pki"
	"tls-tools/internal/server"
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
	certStore, err := pki.NewStoreFromConfig(cfg.Certs)
	if err != nil {
		log.Fatalln(err)
	}

	srv, err := server.NewServerFromConfig(cfg.Listeners, certStore)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		log.Println("Received Ctrl-C. Shutting down...")
		cancel()
	}()

	log.Println("Listening for connections...")
	srv.Start(ctx)
}
