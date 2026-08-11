// Command trivy-ls is a Language Server Protocol server that reports Trivy
// findings as editor diagnostics.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/owenrumney/go-lsp/server"
	"github.com/owenrumney/trivy-ls/internal/handler"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("trivy-ls: %v", err)
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "print the server version and exit")
	debugUI := flag.String("debug-ui", "", "serve the LSP traffic inspector on this address (e.g. localhost:9000)")
	flag.Parse()

	if *showVersion {
		fmt.Println("trivy-ls", handler.Version)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := handler.Options()
	if *debugUI != "" {
		opts = append(opts, server.WithDebugUI(*debugUI))
	}

	srv := server.NewServer(handler.New(), opts...)
	return srv.Run(ctx, server.RunStdio())
}
