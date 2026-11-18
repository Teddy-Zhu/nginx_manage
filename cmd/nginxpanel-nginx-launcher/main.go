// nginxpanel-nginx-launcher is the entry point of the published Nginx image.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"nginxpanel/internal/nginxcontainer"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] != "nginx-container-launch" && args[0] != "nginx-container-test" {
		return errors.New("expected nginx-container-launch or nginx-container-test")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	defaultData := os.Getenv("NGINXPANEL_DATA_DIR")
	if defaultData == "" {
		defaultData = "/srv/nginxpanel"
	}
	data := flags.String("data-dir", defaultData, "installed node data directory")
	var revision string
	if command == "nginx-container-test" {
		flags.StringVar(&revision, "nginx-test-revision", "", "candidate configuration revision")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("Nginx launcher does not accept positional arguments")
	}
	dir, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	if command == "nginx-container-test" {
		return nginxcontainer.LaunchTest(dir, revision)
	}
	return nginxcontainer.Launch(dir)
}
