package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"nginxpanel/internal/agent"
	"nginxpanel/internal/components"
	"nginxpanel/internal/panelruntime"
	"nginxpanel/internal/releases"
	"nginxpanel/internal/secure"
	"nginxpanel/internal/software"
)

func runUpgradeCLI(parent context.Context, args []string) error {
	flags := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	data := flags.String("data-dir", "/srv/nginxpanel", "安装数据目录")
	trust := flags.String("release-trust", "/etc/nginxpanel/release-trust.json", "本机信任的发行公钥配置")
	token := flags.String("release-token", "", "私有发行的本机令牌文件")
	tag := flags.String("version", "", "指定 GitHub 发行标签，例如 v1.2.3")
	beta := flags.Bool("dev", false, "使用 Beta 更新通道")
	check := flags.Bool("check", false, "仅检查可用版本")
	yes := flags.Bool("yes", false, "确认下载、安装并重启")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || os.Geteuid() != 0 {
		return errors.New("请在安装主机使用 root 运行 nginxpanel upgrade")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	current, err := panelruntime.Read(*data)
	if err != nil {
		return err
	}
	plan, err := components.CheckCoreUpgrade(ctx, *trust, *token, *tag, *beta)
	if err != nil {
		return fmt.Errorf("检查更新失败：%w", err)
	}
	target := plan.Manifest.Version
	fmt.Printf("当前版本 %s\n发行版本 %s\n", current.Release.Version, target)
	comparison, err := releases.CompareVersions(current.Release.Version, target)
	if err != nil {
		return err
	}
	if comparison >= 0 {
		fmt.Println("当前没有可用更新")
		return nil
	}
	if *check {
		return nil
	}
	if !*yes {
		fmt.Print("下载安装并重启面板？[y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			fmt.Println("已取消更新")
			return nil
		}
	}
	request := software.Request{Action: "update-panel", PlanID: plan.ID, Prerelease: *beta}
	input := components.Input{Action: "software", Software: &request, Tag: releases.ManifestTag(plan.Manifest),
		Assets: plan.Selected, ManifestSHA256: plan.ManifestSHA256, TrustSHA256: plan.TrustSHA256}
	progress := func(message string) { fmt.Println(message) }
	if err = components.PrepareCoreUpgrade(ctx, *data, *trust, *token, input, progress); err != nil {
		return err
	}
	id := secure.ID()
	fmt.Println("更新任务 " + id)
	result, err := agent.ApplyCoreUpgrade(ctx, *data, *trust, id, request, progress)
	if err != nil {
		return fmt.Errorf("更新任务 %s：%w", id, err)
	}
	fmt.Println(result.Message)
	return nil
}

func runInstallUpgradeCLI(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("install-upgrade", flag.ContinueOnError)
	data := flags.String("data-dir", "", "已安装的数据目录")
	trust := flags.String("package-trust", "", "安装包随附的发行公钥")
	yes := flags.Bool("yes", false, "确认安装并重启")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *data == "" {
		return errors.New("须指定已安装的数据目录")
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	return agent.InstallCorePackage(ctx, *data, binary, *trust, func(current, target string, upgrade bool) bool {
		action := "覆盖安装"
		if upgrade {
			action = "升级"
		}
		fmt.Printf("当前版本 %s\n安装包版本 %s\n操作 %s，面板将重启，配置和数据将保留。\n", current, target, action)
		if *yes {
			return true
		}
		fmt.Printf("确认%s？[y/N] ", action)
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			fmt.Println("已取消安装")
			return false
		}
		return true
	}, func(message string) { fmt.Println(message) })
}
