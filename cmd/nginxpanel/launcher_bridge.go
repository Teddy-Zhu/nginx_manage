package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"nginxpanel/internal/launcher"
)

func runLauncherBridge(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("launcher-bridge", flag.ContinueOnError)
	data := f.String("data-dir", "", "installed data directory")
	describe := f.Bool("describe", false, "describe the immutable launcher bridge contract")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *describe && *data != "" || !*describe && *data == "" {
		return errors.New("launcher 桥接参数无效")
	}
	if *describe {
		return launcher.DescribeBridge(os.Stdout)
	}
	return launcher.RunBridge(ctx, *data, os.Stdin, os.Stdout)
}
