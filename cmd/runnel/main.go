package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/ArshyaAI/runnel/internal/app"
	"github.com/ArshyaAI/runnel/internal/cli"
)

func main() {
	cmd := cli.NewRoot(productionOptions())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cmd.ExecuteContext(ctx); err != nil {
		var exitErr *cli.ExitError
		code := cli.ExitUsage
		if errors.As(err, &exitErr) {
			code = exitErr.Code
		}
		if err.Error() != "" {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), err)
		}
		os.Exit(code)
	}
}

func productionOptions() cli.Options {
	archive := app.Archive{}
	scanner := cli.NewLocalScanner()
	evidence, evidenceErr := app.NewProductionEvidence(scanner)
	recoveryService, recoveryErr := app.NewProductionRecovery(scanner)
	options := cli.Options{Scan: scanner, History: archive, Receipt: archive}
	if evidenceErr == nil {
		options.Explain = evidence
	}
	if recoveryErr == nil {
		options.Recovery = recoveryService
	}
	return options
}
