package releases

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Installed reauthenticates a root-approved installation against current local
// keys. Expiry controls new admissions; it does not expire installed executables.
// approvedAt and trustSHA must come from an immutable, root-owned binding, never
// from a business request. No file, lock or cache is created by this function.
func Installed(ctx context.Context, in Input, id string, approvedAt int64, trustSHA string) (Result, error) {
	if approvedAt <= 0 || approvedAt > time.Now().Unix()+300 || !validHash(trustSHA) {
		return Result{}, errors.New("本机安装批准记录无效")
	}
	return inspectPrepared(ctx, in, id, approvedAt, trustSHA)
}
func inspectPrepared(ctx context.Context, in Input, id string, at int64, historicalTrust string) (Result, error) {
	if !validHash(id) {
		return Result{}, errors.New("准备计划标识无效")
	}
	dir := filepath.Join(Store, id)
	if err := rootParents(filepath.Join(dir, ".inspection")); err != nil {
		return Result{}, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return Result{}, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0755 {
		return Result{}, errors.New("已准备目录权限无效")
	}
	in.ManifestPath, in.SignaturePath = filepath.Join(dir, "release-manifest.json"), filepath.Join(dir, "release-manifest.sig")
	v, err := verifyAt(in, at)
	if err != nil {
		return Result{}, err
	}
	currentTrustSHA := v.plan.TrustSHA256
	if historicalTrust != "" {
		// Rebuild the original receipt identity while authenticating with current
		// policy. Adding an unrelated key must not invalidate a valid installation.
		v.plan.ID = ""
		v.plan.TrustSHA256 = historicalTrust
		raw, e := json.Marshal(v.plan)
		if e != nil {
			return Result{}, e
		}
		v.plan.ID = hash(raw)
	}
	if v.plan.ID != id {
		return Result{}, ErrReleaseChanged
	}
	raw, err := json.Marshal(v.plan)
	if err != nil {
		return Result{}, err
	}
	v.seal = hash(raw)
	if err = verifyPrepared(ctx, dir, v, raw); err != nil {
		return Result{}, err
	}
	if err = checkRuntime(ctx, v.plan.Assets); err != nil {
		return Result{}, err
	}
	current, err := readTrust(in.TrustPath)
	if err != nil {
		return Result{}, err
	}
	if hash(current.raw) != currentTrustSHA || historicalTrust == "" && time.Now().Unix() >= v.plan.Manifest.ExpiresAt {
		return Result{}, ErrReleaseChanged
	}
	if err = ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{State: "prepared", Directory: dir, Reused: true, Plan: v.Plan()}, nil
}
