// nginxpanel-release runs only in the publisher's build environment.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"nginxpanel/internal/releases"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 || os.Args[1] != "spec" && os.Args[1] != "bundle" {
		return errors.New("usage: nginxpanel-release <spec|bundle>")
	}
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	repo := f.String("repository", "", "approved owner/repository")
	version := f.String("version", "", "SemVer version without v prefix")
	commit := f.String("commit", "", "approved full source commit")
	component := f.String("component", "panel", "publication component: panel or nginx (spec)")
	output := f.String("output", "", "new output file (spec) or directory (bundle)")
	specFile := f.String("spec", "", "publication specification (bundle)")
	inputRoot := f.String("input-root", "", "prepared package input tree (bundle)")
	images := f.String("images", "", "optional OCI image publication input (bundle)")
	keyFile := f.String("key-file", "", "private 0600 Ed25519 seed file outside input/output (bundle)")
	keyID := f.String("key-id", "", "approved signing key ID (bundle)")
	public := f.String("public-key", "", "independently approved Base64 public key (bundle)")
	notesFile := f.String("notes-file", "", "approved UTF-8 release notes, at most 8 KiB (spec)")
	policyFile := f.String("policy-file", "", "independently approved version-specific release policy (spec and bundle)")
	if err := f.Parse(os.Args[2:]); err != nil {
		return err
	}
	if f.NArg() != 0 || *output == "" {
		return errors.New("须提供输出路径，不能使用额外位置参数")
	}
	if *policyFile == "" {
		return errors.New("须提供 --policy-file，不能从构建产物推导回滚授权")
	}
	if os.Args[1] == "spec" {
		if *notesFile == "" {
			return errors.New("spec 须提供 --notes-file")
		}
		notes, err := releases.ReadPublicationNotes(*notesFile)
		if err != nil {
			return err
		}
		automaticRollback, err := releases.ReadPublicationPolicy(*policyFile, *version)
		if err != nil {
			return err
		}
		var spec releases.PublicationSpec
		switch *component {
		case "panel":
			spec, err = releases.NewPublication(*repo, *version, *commit, notes, automaticRollback)
		case "nginx":
			spec, err = releases.NewImagePublication(*repo, *version, *commit, notes, automaticRollback)
		default:
			return errors.New("发布组件须为 panel 或 nginx")
		}
		if err != nil {
			return err
		}
		raw, err := json.MarshalIndent(spec, "", "  ")
		if err != nil {
			return err
		}
		out, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		err = out.Chmod(0644)
		if err == nil {
			_, err = out.Write(append(raw, '\n'))
		}
		if err == nil {
			err = out.Sync()
		}
		closeErr := out.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	if *notesFile != "" {
		return errors.New("bundle 使用 spec 中的已批准说明，不能提供 --notes-file")
	}
	if *specFile == "" || *inputRoot == "" || *keyFile == "" {
		return errors.New("bundle 须提供 --spec、--input-root 和 --key-file")
	}
	paths := []*string{output, specFile, inputRoot, keyFile, policyFile}
	if *images != "" {
		paths = append(paths, images)
	}
	for _, value := range paths {
		abs, err := filepath.Abs(*value)
		if err != nil {
			return err
		}
		*value = abs
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	result, err := releases.Publish(ctx, releases.PublishInput{InputRoot: *inputRoot, SpecPath: *specFile, Output: *output, KeyPath: *keyFile, KeyID: *keyID, PublicKey: *public, Repository: *repo, Version: *version, Commit: *commit, ImagesPath: *images, PolicyPath: *policyFile})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
