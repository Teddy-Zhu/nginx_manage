package releases

import (
	"errors"
	"regexp"
	"strings"

	modsemver "golang.org/x/mod/semver"
)

var developmentBuild = regexp.MustCompile(`^(v[0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)\.([0-9]+)-dev$`)

// CompareVersions compares embedded release versions, ignoring build metadata.
func CompareVersions(current, target string) (int, error) {
	if !validVersion(current) || !validVersion(target) {
		return 0, errors.New("当前程序或目标发行的版本号无效")
	}
	comparable := func(version string) string {
		version, _, _ = strings.Cut("v"+version, "+")
		if parts := developmentBuild.FindStringSubmatch(version); parts != nil {
			// Keep the required -dev release suffix while comparing both CI
			// build and attempt numbers numerically, including attempts >= 10.
			version = parts[1] + "-dev." + parts[2] + "." + parts[3]
		}
		return version
	}
	left, right := comparable(current), comparable(target)
	if !modsemver.IsValid(left) || !modsemver.IsValid(right) {
		return 0, errors.New("开发版本的构建编号无效")
	}
	return modsemver.Compare(left, right), nil
}
