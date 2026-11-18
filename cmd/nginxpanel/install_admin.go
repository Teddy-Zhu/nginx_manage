package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"nginxpanel/internal/app"
	"nginxpanel/internal/auth"
)

func runInitialAdminPrepare(args []string) error {
	flags := flag.NewFlagSet("installation-admin-prepare", flag.ContinueOnError)
	username := flags.String("username", "", "initial administrator username")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("管理员密码通过标准输入读取")
	}
	const maxInput = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxInput+1))
	if err != nil {
		return err
	}
	if len(raw) > maxInput {
		return errors.New("密码输入过长")
	}
	password := string(raw)
	if strings.HasSuffix(password, "\n") {
		password = strings.TrimSuffix(strings.TrimSuffix(password, "\n"), "\r")
	}
	if strings.ContainsAny(password, "\r\n\x00") {
		return errors.New("密码输入须为一行")
	}
	record, err := auth.PrepareInitialAdmin(*username, password)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(record)
}

func initPanel(ctx context.Context, dataDir string, development, adminStdin bool) (string, error) {
	if !adminStdin {
		return app.Init(ctx, dataDir, development)
	}
	const maxRecord = 4096
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxRecord+1))
	if err != nil {
		return "", err
	}
	var admin auth.InitialAdmin
	if len(raw) > maxRecord || json.Unmarshal(raw, &admin) != nil {
		return "", errors.New("管理员安装记录无效")
	}
	return app.InitWithAdmin(ctx, dataDir, admin)
}
