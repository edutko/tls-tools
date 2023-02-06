all: client server mkcerts
clean:
	rm -rf out

client: out/client
server: out/server
mkcerts: out/mkcerts

out/client: cmd/client internal/*
	[ -d out ] || mkdir out
	go build -o out/client ./cmd/client

out/server: cmd/server internal/*
	[ -d out ] || mkdir out
	go build -o out/server ./cmd/server

out/mkcerts: cmd/mkcerts internal/*
	[ -d out ] || mkdir out
	go build -o out/mkcerts ./cmd/mkcerts
