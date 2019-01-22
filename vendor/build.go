// Copyright (C) 2014 The DappBox Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

// +build ignore

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"
)

var (
	versionRe = regexp.MustCompile(`-[0-9]{1,3}-g[0-9a-f]{5,10}`)
	goarch    string
	goos      string
	noupgrade bool
	version   string
	goVersion float64
	race      bool
	debug     = os.Getenv("BUILDDEBUG") != ""
)

type target struct {
	name              string
	debname           string
	debdeps           []string
	debpost           string
	description       string
	buildPkg          string
	binaryName        string
	archiveFiles      []archiveFile
	installationFiles []archiveFile
	tags              []string
}

type archiveFile struct {
	src  string
	dst  string
	perm os.FileMode
}

var targets = map[string]target{
	"all": {
		// Only valid for the "build" and "install" commands as it lacks all
		// the archive creation stuff.
		buildPkg: "./cmd/...",
		tags:     []string{"purego"},
	},
	"dappbox": {
		// The default target for "build", "install", "tar", "zip", "deb", etc.
		name:        "dappbox",
		debname:     "dappbox",
		debdeps:     []string{"libc6", "procps"},
		debpost:     "script/post-upgrade",
		description: "Open Source Continuous File Synchronization",
		buildPkg:    "./cmd/dappbox",
		binaryName:  "dappbox", // .exe will be added automatically for Windows builds
		archiveFiles: []archiveFile{
			{src: "{{binary}}", dst: "{{binary}}", perm: 0755},
			{src: "README.md", dst: "README.txt", perm: 0644},
			{src: "LICENSE", dst: "LICENSE.txt", perm: 0644},
			{src: "AUTHORS", dst: "AUTHORS.txt", perm: 0644},
			// All files from etc/ and extra/ added automatically in init().
		},
		installationFiles: []archiveFile{
			{src: "{{binary}}", dst: "deb/usr/bin/{{binary}}", perm: 0755},
			{src: "README.md", dst: "deb/usr/share/doc/dappbox/README.txt", perm: 0644},
			{src: "LICENSE", dst: "deb/usr/share/doc/dappbox/LICENSE.txt", perm: 0644},
			{src: "AUTHORS", dst: "deb/usr/share/doc/dappbox/AUTHORS.txt", perm: 0644},
			{src: "man/dappbox.1", dst: "deb/usr/share/man/man1/dappbox.1", perm: 0644},
			{src: "man/dappbox-config.5", dst: "deb/usr/share/man/man5/dappbox-config.5", perm: 0644},
			{src: "man/dappbox-stignore.5", dst: "deb/usr/share/man/man5/dappbox-stignore.5", perm: 0644},
			{src: "man/dappbox-device-ids.7", dst: "deb/usr/share/man/man7/dappbox-device-ids.7", perm: 0644},
			{src: "man/dappbox-event-api.7", dst: "deb/usr/share/man/man7/dappbox-event-api.7", perm: 0644},
			{src: "man/dappbox-faq.7", dst: "deb/usr/share/man/man7/dappbox-faq.7", perm: 0644},
			{src: "man/dappbox-networking.7", dst: "deb/usr/share/man/man7/dappbox-networking.7", perm: 0644},
			{src: "man/dappbox-rest-api.7", dst: "deb/usr/share/man/man7/dappbox-rest-api.7", perm: 0644},
			{src: "man/dappbox-security.7", dst: "deb/usr/share/man/man7/dappbox-security.7", perm: 0644},
			{src: "man/dappbox-versioning.7", dst: "deb/usr/share/man/man7/dappbox-versioning.7", perm: 0644},
			{src: "etc/linux-systemd/system/dappbox@.service", dst: "deb/lib/systemd/system/dappbox@.service", perm: 0644},
			{src: "etc/linux-systemd/system/dappbox-resume.service", dst: "deb/lib/systemd/system/dappbox-resume.service", perm: 0644},
			{src: "etc/linux-systemd/user/dappbox.service", dst: "deb/usr/lib/systemd/user/dappbox.service", perm: 0644},
			{src: "etc/firewall-ufw/dappbox", dst: "deb/etc/ufw/applications.d/dappbox", perm: 0644},
		},
	},
	"stdiscosrv": {
		name:        "stdiscosrv",
		debname:     "dappbox-discosrv",
		debdeps:     []string{"libc6"},
		description: "DappBox Discovery Server",
		buildPkg:    "./cmd/stdiscosrv",
		binaryName:  "stdiscosrv", // .exe will be added automatically for Windows builds
		archiveFiles: []archiveFile{
			{src: "{{binary}}", dst: "{{binary}}", perm: 0755},
			{src: "cmd/stdiscosrv/README.md", dst: "README.txt", perm: 0644},
			{src: "cmd/stdiscosrv/LICENSE", dst: "LICENSE.txt", perm: 0644},
			{src: "AUTHORS", dst: "AUTHORS.txt", perm: 0644},
		},
		installationFiles: []archiveFile{
			{src: "{{binary}}", dst: "deb/usr/bin/{{binary}}", perm: 0755},
			{src: "cmd/stdiscosrv/README.md", dst: "deb/usr/share/doc/dappbox-discosrv/README.txt", perm: 0644},
			{src: "cmd/stdiscosrv/LICENSE", dst: "deb/usr/share/doc/dappbox-discosrv/LICENSE.txt", perm: 0644},
			{src: "AUTHORS", dst: "deb/usr/share/doc/dappbox-discosrv/AUTHORS.txt", perm: 0644},
			{src: "man/stdiscosrv.1", dst: "deb/usr/share/man/man1/stdiscosrv.1", perm: 0644},
		},
		tags: []string{"purego"},
	},
	"strelaysrv": {
		name:        "strelaysrv",
		debname:     "dappbox-relaysrv",
		debdeps:     []string{"libc6"},
		description: "DappBox Relay Server",
		buildPkg:    "./cmd/strelaysrv",
		binaryName:  "strelaysrv", // .exe will be added automatically for Windows builds
		archiveFiles: []archiveFile{
			{src: "{{binary}}", dst: "{{binary}}", perm: 0755},
			{src: "cmd/strelaysrv/README.md", dst: "README.txt", perm: 0644},
			{src: "cmd/strelaysrv/LICENSE", dst: "LICENSE.txt", perm: 0644},
			{src: "AUTHORS", dst: "AUTHORS.txt", perm: 0644},
		},
		installationFiles: []archiveFile{
			{src: "{{binary}}", dst: "deb/usr/bin/{{binary}}", perm: 0755},
			{src: "cmd/strelaysrv/README.md", dst: "deb/usr/share/doc/dappbox-relaysrv/README.txt", perm: 0644},
			{src: "cmd/strelaysrv/LICENSE", dst: "deb/usr/share/doc/dappbox-relaysrv/LICENSE.txt", perm: 0644},
			{src: "AUTHORS", dst: "deb/usr/share/doc/dappbox-relaysrv/AUTHORS.txt", perm: 0644},
			{src: "man/strelaysrv.1", dst: "deb/usr/share/man/man1/strelaysrv.1", perm: 0644},
		},
	},
	"strelaypoolsrv": {
		name:        "strelaypoolsrv",
		debname:     "dappbox-relaypoolsrv",
		debdeps:     []string{"libc6"},
		description: "DappBox Relay Pool Server",
		buildPkg:    "./cmd/strelaypoolsrv",
		binaryName:  "strelaypoolsrv", // .exe will be added automatically for Windows builds
		archiveFiles: []archiveFile{
			{src: "{{binary}}", dst: "{{binary}}", perm: 0755},
			{src: "cmd/strelaypoolsrv/README.md", dst: "README.txt", perm: 0644},
			{src: "cmd/strelaypoolsrv/LICENSE", dst: "LICENSE.txt", perm: 0644},
			{src: "AUTHORS", dst: "AUTHORS.txt", perm: 0644},
		},
		installationFiles: []archiveFile{
			{src: "{{binary}}", dst: "deb/usr/bin/{{binary}}", perm: 0755},
			{src: "cmd/strelaypoolsrv/README.md", dst: "deb/usr/share/doc/dappbox-relaypoolsrv/README.txt", perm: 0644},
			{src: "cmd/strelaypoolsrv/LICENSE", dst: "deb/usr/share/doc/dappbox-relaypoolsrv/LICENSE.txt", perm: 0644},
			{src: "AUTHORS", dst: "deb/usr/share/doc/dappbox-relaypoolsrv/AUTHORS.txt", perm: 0644},
		},
	},
}

var (
	// fast linters complete in a fraction of a second and might as well be
	// run always as part of the build
	fastLinters = []string{
		"deadcode",
		"golint",
		"ineffassign",
		"vet",
	}

	// slow linters take several seconds and are run only as part of the
	// "metalint" command.
	slowLinters = []string{
		"gosimple",
		"staticcheck",
		"structcheck",
		"unused",
		"varcheck",
	}

	// Which parts of the tree to lint
	lintDirs = []string{".", "./lib/...", "./cmd/..."}

	// Messages to ignore
	lintExcludes = []string{
		".pb.go",
		"should have comment",
		"protocol.Vector composite literal uses unkeyed fields",
		"cli.Requires composite literal uses unkeyed fields",
		"Use DialContext instead",   // Go 1.7
		"os.SEEK_SET is deprecated", // Go 1.7
		"SA4017",                    // staticcheck "is a pure function but its return value is ignored"
	}
)

func init() {
	// The "dappbox" target includes a few more files found in the "etc"
	// and "extra" dirs.
	dappboxPkg := targets["dappbox"]
	for _, file := range listFiles("etc") {
		dappboxPkg.archiveFiles = append(dappboxPkg.archiveFiles, archiveFile{src: file, dst: file, perm: 0644})
	}
	for _, file := range listFiles("extra") {
		dappboxPkg.archiveFiles = append(dappboxPkg.archiveFiles, archiveFile{src: file, dst: file, perm: 0644})
	}
	for _, file := range listFiles("extra") {
		dappboxPkg.installationFiles = append(dappboxPkg.installationFiles, archiveFile{src: file, dst: "deb/usr/share/doc/dappbox/" + filepath.Base(file), perm: 0644})
	}
	targets["dappbox"] = dappboxPkg
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)

	if debug {
		t0 := time.Now()
		defer func() {
			log.Println("... build completed in", time.Since(t0))
		}()
	}

	if os.Getenv("GOPATH") == "" {
		setGoPath()
	}

	// Set path to $GOPATH/bin:$PATH so that we can for sure find tools we
	// might have installed during "build.go setup".
	os.Setenv("PATH", fmt.Sprintf("%s%cbin%c%s", os.Getenv("GOPATH"), os.PathSeparator, os.PathListSeparator, os.Getenv("PATH")))

	parseFlags()

	checkArchitecture()

	// Invoking build.go with no parameters at all builds everything (incrementally),
	// which is what you want for maximum error checking during development.
	if flag.NArg() == 0 {
		runCommand("install", targets["all"])
	} else {
		// with any command given but not a target, the target is
		// "dappbox". So "go run build.go install" is "go run build.go install
		// dappbox" etc.
		targetName := "dappbox"
		if flag.NArg() > 1 {
			targetName = flag.Arg(1)
		}
		target, ok := targets[targetName]
		if !ok {
			log.Fatalln("Unknown target", target)
		}

		runCommand(flag.Arg(0), target)
	}
}

func checkArchitecture() {
	switch goarch {
	case "386", "amd64", "arm", "arm64", "ppc64", "ppc64le", "mips", "mipsle":
		break
	default:
		log.Printf("Unknown goarch %q; proceed with caution!", goarch)
	}
}

func runCommand(cmd string, target target) {
	switch cmd {
	case "setup":
		setup()

	case "install":
		var tags []string
		if noupgrade {
			tags = []string{"noupgrade"}
		}
		install(target, tags)
		metalint(fastLinters, lintDirs)

	case "build":
		var tags []string
		if noupgrade {
			tags = []string{"noupgrade"}
		}
		build(target, tags)
		metalint(fastLinters, lintDirs)

	case "test":
		test("./lib/...", "./cmd/...")

	case "bench":
		bench("./lib/...", "./cmd/...")

	case "assets":
		rebuildAssets()

	case "proto":
		proto()

	case "contracts":
		contracts()

	case "translate":
		translate()

	case "transifex":
		transifex()

	case "tar":
		buildTar(target)

	case "zip":
		buildZip(target)

	case "deb":
		buildDeb(target)

	case "snap":
		buildSnap(target)

	case "clean":
		clean()

	case "vet":
		metalint(fastLinters, lintDirs)

	case "lint":
		metalint(fastLinters, lintDirs)

	case "metalint":
		metalint(fastLinters, lintDirs)
		metalint(slowLinters, lintDirs)

	case "version":
		fmt.Println(getVersion())

	default:
		log.Fatalf("Unknown command %q", cmd)
	}
}

// setGoPath sets GOPATH correctly with the assumption that we are
// in $GOPATH/src/github.com/dappbox/dappbox.
func setGoPath() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	gopath := filepath.Clean(filepath.Join(cwd, "../../../../"))
	log.Println("GOPATH is", gopath)
	os.Setenv("GOPATH", gopath)
}

func parseFlags() {
	flag.StringVar(&goarch, "goarch", runtime.GOARCH, "GOARCH")
	flag.StringVar(&goos, "goos", runtime.GOOS, "GOOS")
	flag.BoolVar(&noupgrade, "no-upgrade", noupgrade, "Disable upgrade functionality")
	flag.StringVar(&version, "version", getVersion(), "Set compiled in version string")
	flag.BoolVar(&race, "race", race, "Use race detector")
	flag.Parse()
}

func setup() {
	packages := []string{
		"github.com/alecthomas/gometalinter",
		"github.com/AlekSi/gocov-xml",
		"github.com/axw/gocov/gocov",
		"github.com/FiloSottile/gvt",
		"github.com/golang/lint/golint",
		"github.com/gordonklaus/ineffassign",
		"github.com/mdempsky/unconvert",
		"github.com/mitchellh/go-wordwrap",
		"github.com/opennota/check/cmd/...",
		"github.com/tsenart/deadcode",
		"golang.org/x/net/html",
		"golang.org/x/tools/cmd/cover",
		"honnef.co/go/simple/cmd/gosimple",
		"honnef.co/go/staticcheck/cmd/staticcheck",
		"honnef.co/go/unused/cmd/unused",
        "github.com/shirou/gopsutil/disk",
	}
	for _, pkg := range packages {
		fmt.Println(pkg)
		runPrint("go", "get", "-u", pkg)
	}

	runPrint("go", "install", "-v", "./vendor/github.com/gogo/protobuf/protoc-gen-gogofast")
}

func test(pkgs ...string) {
	lazyRebuildAssets()

	useRace := runtime.GOARCH == "amd64"
	switch runtime.GOOS {
	case "darwin", "linux", "freebsd", "windows":
	default:
		useRace = false
	}

	if useRace {
		runPrint("go", append([]string{"test", "-short", "-race", "-timeout", "60s", "-tags", "purego"}, pkgs...)...)
	} else {
		runPrint("go", append([]string{"test", "-short", "-timeout", "60s", "-tags", "purego"}, pkgs...)...)
	}
}

func bench(pkgs ...string) {
	lazyRebuildAssets()
	runPrint("go", append([]string{"test", "-run", "NONE", "-bench", "."}, pkgs...)...)
}

func install(target target, tags []string) {
	lazyRebuildAssets()

	tags = append(target.tags, tags...)

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	os.Setenv("GOBIN", filepath.Join(cwd, "bin"))
	args := []string{"install", "-v", "-ldflags", ldflags()}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, " "))
	}
	if race {
		args = append(args, "-race")
	}
	args = append(args, target.buildPkg)

	os.Setenv("GOOS", goos)
	os.Setenv("GOARCH", goarch)
	runPrint("go", args...)
}

func build(target target, tags []string) {
	lazyRebuildAssets()

	tags = append(target.tags, tags...)

	rmr(target.binaryName)
	args := []string{"build", "-i", "-v", "-ldflags", ldflags()}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, " "))
	}
	if race {
		args = append(args, "-race")
	}
	args = append(args, target.buildPkg)

	os.Setenv("GOOS", goos)
	os.Setenv("GOARCH", goarch)
	runPrint("go", args...)
}

func buildTar(target target) {
	name := archiveName(target)
	filename := name + ".tar.gz"

	var tags []string
	if noupgrade {
		tags = []string{"noupgrade"}
		name += "-noupgrade"
	}

	build(target, tags)

	if goos == "darwin" {
		macosCodesign(target.binaryName)
	}

	for i := range target.archiveFiles {
		target.archiveFiles[i].src = strings.Replace(target.archiveFiles[i].src, "{{binary}}", target.binaryName, 1)
		target.archiveFiles[i].dst = strings.Replace(target.archiveFiles[i].dst, "{{binary}}", target.binaryName, 1)
		target.archiveFiles[i].dst = name + "/" + target.archiveFiles[i].dst
	}

	tarGz(filename, target.archiveFiles)
	log.Println(filename)
}

func buildZip(target target) {
	target.binaryName += ".exe"

	name := archiveName(target)
	filename := name + ".zip"

	var tags []string
	if noupgrade {
		tags = []string{"noupgrade"}
		name += "-noupgrade"
	}

	build(target, tags)

	for i := range target.archiveFiles {
		target.archiveFiles[i].src = strings.Replace(target.archiveFiles[i].src, "{{binary}}", target.binaryName, 1)
		target.archiveFiles[i].dst = strings.Replace(target.archiveFiles[i].dst, "{{binary}}", target.binaryName, 1)
		target.archiveFiles[i].dst = name + "/" + target.archiveFiles[i].dst
	}

	zipFile(filename, target.archiveFiles)
	log.Println(filename)
}

func buildDeb(target target) {
	os.RemoveAll("deb")

	// "goarch" here is set to whatever the Debian packages expect. We correct
	// it to what we actually know how to build and keep the Debian variant
	// name in "debarch".
	debarch := goarch
	switch goarch {
	case "i386":
		goarch = "386"
	case "armel", "armhf":
		goarch = "arm"
	}

	build(target, []string{"noupgrade"})

	for i := range target.installationFiles {
		target.installationFiles[i].src = strings.Replace(target.installationFiles[i].src, "{{binary}}", target.binaryName, 1)
		target.installationFiles[i].dst = strings.Replace(target.installationFiles[i].dst, "{{binary}}", target.binaryName, 1)
	}

	for _, af := range target.installationFiles {
		if err := copyFile(af.src, af.dst, af.perm); err != nil {
			log.Fatal(err)
		}
	}

	maintainer := "DappBox Release Management <release@dappbox.net>"
	debver := version
	if strings.HasPrefix(debver, "v") {
		debver = debver[1:]
		// Debian interprets dashes as separator between main version and
		// Debian package version, and thus thinks 0.14.26-rc.1 is better
		// than just 0.14.26. This rectifies that.
		debver = strings.Replace(debver, "-", "~", -1)
	}
	args := []string{
		"-t", "deb",
		"-s", "dir",
		"-C", "deb",
		"-n", target.debname,
		"-v", debver,
		"-a", debarch,
		"-m", maintainer,
		"--vendor", maintainer,
		"--description", target.description,
		"--url", "https://dappbox.net/",
		"--license", "MPL-2",
	}
	for _, dep := range target.debdeps {
		args = append(args, "-d", dep)
	}
	if target.debpost != "" {
		args = append(args, "--after-upgrade", target.debpost)
	}
	runPrint("fpm", args...)
}

func buildSnap(target target) {
	os.RemoveAll("snap")

	tmpl, err := template.ParseFiles("snapcraft.yaml.template")
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create("snapcraft.yaml")
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}

	snaparch := goarch
	if snaparch == "armhf" {
		goarch = "arm"
	}
	snapver := version
	if strings.HasPrefix(snapver, "v") {
		snapver = snapver[1:]
	}
	snapgrade := "devel"
	if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+(-rc.\d+)?$`, snapver); matched {
		snapgrade = "stable"
	}
	err = tmpl.Execute(f, map[string]string{
		"Version":      snapver,
		"Architecture": snaparch,
		"Grade":        snapgrade,
	})
	if err != nil {
		log.Fatal(err)
	}
	runPrint("snapcraft", "clean")
	build(target, []string{"noupgrade"})
	runPrint("snapcraft")
}

func copyFile(src, dst string, perm os.FileMode) error {
	dstDir := filepath.Dir(dst)
	os.MkdirAll(dstDir, 0755) // ignore error
	srcFd, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFd.Close()
	dstFd, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer dstFd.Close()
	_, err = io.Copy(dstFd, srcFd)
	return err
}

func listFiles(dir string) []string {
	var res []string
	filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			res = append(res, path)
		}
		return nil
	})
	return res
}

func rebuildAssets() {
	runPipe("lib/auto/gui.files.go", "go", "run", "script/genassets.go", "gui")
	runPipe("cmd/strelaypoolsrv/auto/gui.go", "go", "run", "script/genassets.go", "cmd/strelaypoolsrv/gui")
}

func lazyRebuildAssets() {
	if shouldRebuildAssets("lib/auto/gui.files.go", "gui") || shouldRebuildAssets("cmd/strelaypoolsrv/auto/gui.go", "cmd/strelaypoolsrv/auto/gui") {
		rebuildAssets()
	}
}

func shouldRebuildAssets(target, srcdir string) bool {
	info, err := os.Stat(target)
	if err != nil {
		// If the file doesn't exist, we must rebuild it
		return true
	}

	// Check if any of the files in gui/ are newer than the asset file. If
	// so we should rebuild it.
	currentBuild := info.ModTime()
	assetsAreNewer := false
	stop := errors.New("no need to iterate further")
	filepath.Walk(srcdir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.ModTime().After(currentBuild) {
			assetsAreNewer = true
			return stop
		}
		return nil
	})

	return assetsAreNewer
}

func proto() {
	runPrint("go", "generate", "./lib/...")
}

func contracts() {
	runPrint("go", "generate", "./contracts/...")
}

func translate() {
	os.Chdir("gui/default/assets/lang")
	runPipe("lang-en-new.json", "go", "run", "../../../../script/translate.go", "lang-en.json", "../../../")
	os.Remove("lang-en.json")
	err := os.Rename("lang-en-new.json", "lang-en.json")
	if err != nil {
		log.Fatal(err)
	}
	os.Chdir("../../../..")
}

func transifex() {
	os.Chdir("gui/default/assets/lang")
	runPrint("go", "run", "../../../../script/transifexdl.go")
}

func clean() {
	rmr("bin")
	rmr(filepath.Join(os.Getenv("GOPATH"), fmt.Sprintf("pkg/%s_%s/github.com/dappbox", goos, goarch)))
}

func ldflags() string {
	sep := '='
	if goVersion > 0 && goVersion < 1.5 {
		sep = ' '
	}

	b := new(bytes.Buffer)
	b.WriteString("-w")
	fmt.Fprintf(b, " -X main.Version%c%s", sep, version)
	fmt.Fprintf(b, " -X main.BuildStamp%c%d", sep, buildStamp())
	fmt.Fprintf(b, " -X main.BuildUser%c%s", sep, buildUser())
	fmt.Fprintf(b, " -X main.BuildHost%c%s", sep, buildHost())
	return b.String()
}

func rmr(paths ...string) {
	for _, path := range paths {
		if debug {
			log.Println("rm -r", path)
		}
		os.RemoveAll(path)
	}
}

func getReleaseVersion() (string, error) {
	fd, err := os.Open("RELEASE")
	if err != nil {
		return "", err
	}
	defer fd.Close()

	bs, err := ioutil.ReadAll(fd)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(bs)), nil
}

func getGitVersion() (string, error) {
	v, err := runError("git", "describe", "--always", "--dirty")
	if err != nil {
		return "", err
	}
	v = versionRe.ReplaceAllFunc(v, func(s []byte) []byte {
		s[0] = '+'
		return s
	})
	return string(v), nil
}

func getVersion() string {
	// First try for a RELEASE file,
	if ver, err := getReleaseVersion(); err == nil {
		return ver
	}
	// ... then see if we have a Git tag.
	if ver, err := getGitVersion(); err == nil {
		if strings.Contains(ver, "-") {
			// The version already contains a hash and stuff. See if we can
			// find a current branch name to tack onto it as well.
			return ver + getBranchSuffix()
		}
		return ver
	}
	// This seems to be a dev build.
	return "unknown-dev"
}

func getBranchSuffix() string {
	bs, err := runError("git", "branch", "-a", "--contains")
	if err != nil {
		return ""
	}

	branches := strings.Split(string(bs), "\n")
	if len(branches) == 0 {
		return ""
	}

	branch := ""
	for i, candidate := range branches {
		if strings.HasPrefix(candidate, "*") {
			// This is the current branch. Select it!
			branch = strings.TrimLeft(candidate, " \t*")
			break
		} else if i == 0 {
			// Otherwise the first branch in the list will do.
			branch = strings.TrimSpace(branch)
		}
	}

	if branch == "" {
		return ""
	}

	// The branch name may be on the form "remotes/origin/foo" from which we
	// just want "foo".
	parts := strings.Split(branch, "/")
	if len(parts) == 0 || len(parts[len(parts)-1]) == 0 {
		return ""
	}

	branch = parts[len(parts)-1]
	if branch == "master" {
		// master builds are the default.
		return ""
	}

	validBranchRe := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	if !validBranchRe.MatchString(branch) {
		// There's some odd stuff in the branch name. Better skip it.
		return ""
	}

	return "-" + branch
}

func buildStamp() int64 {
	// If SOURCE_DATE_EPOCH is set, use that.
	if s, _ := strconv.ParseInt(os.Getenv("SOURCE_DATE_EPOCH"), 10, 64); s > 0 {
		return s
	}

	// Try to get the timestamp of the latest commit.
	bs, err := runError("git", "show", "-s", "--format=%ct")
	if err != nil {
		// Fall back to "now".
		return time.Now().Unix()
	}

	s, _ := strconv.ParseInt(string(bs), 10, 64)
	return s
}

func buildUser() string {
	if v := os.Getenv("BUILD_USER"); v != "" {
		return v
	}

	u, err := user.Current()
	if err != nil {
		return "unknown-user"
	}
	return strings.Replace(u.Username, " ", "-", -1)
}

func buildHost() string {
	if v := os.Getenv("BUILD_HOST"); v != "" {
		return v
	}

	h, err := os.Hostname()
	if err != nil {
		return "unknown-host"
	}
	return h
}

func buildArch() string {
	os := goos
	if os == "darwin" {
		os = "macosx"
	}
	return fmt.Sprintf("%s-%s", os, goarch)
}

func archiveName(target target) string {
	return fmt.Sprintf("%s-%s-%s", target.name, buildArch(), version)
}

func runError(cmd string, args ...string) ([]byte, error) {
	if debug {
		t0 := time.Now()
		log.Println("runError:", cmd, strings.Join(args, " "))
		defer func() {
			log.Println("... in", time.Since(t0))
		}()
	}
	ecmd := exec.Command(cmd, args...)
	bs, err := ecmd.CombinedOutput()
	return bytes.TrimSpace(bs), err
}

func runPrint(cmd string, args ...string) {
	if debug {
		t0 := time.Now()
		log.Println("runPrint:", cmd, strings.Join(args, " "))
		defer func() {
			log.Println("... in", time.Since(t0))
		}()
	}
	ecmd := exec.Command(cmd, args...)
	ecmd.Stdout = os.Stdout
	ecmd.Stderr = os.Stderr
	err := ecmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}

func runPipe(file, cmd string, args ...string) {
	if debug {
		t0 := time.Now()
		log.Println("runPipe:", cmd, strings.Join(args, " "))
		defer func() {
			log.Println("... in", time.Since(t0))
		}()
	}
	fd, err := os.Create(file)
	if err != nil {
		log.Fatal(err)
	}
	ecmd := exec.Command(cmd, args...)
	ecmd.Stdout = fd
	ecmd.Stderr = os.Stderr
	err = ecmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	fd.Close()
}

func tarGz(out string, files []archiveFile) {
	fd, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}

	gw := gzip.NewWriter(fd)
	tw := tar.NewWriter(gw)

	for _, f := range files {
		sf, err := os.Open(f.src)
		if err != nil {
			log.Fatal(err)
		}

		info, err := sf.Stat()
		if err != nil {
			log.Fatal(err)
		}
		h := &tar.Header{
			Name:    f.dst,
			Size:    info.Size(),
			Mode:    int64(info.Mode()),
			ModTime: info.ModTime(),
		}

		err = tw.WriteHeader(h)
		if err != nil {
			log.Fatal(err)
		}
		_, err = io.Copy(tw, sf)
		if err != nil {
			log.Fatal(err)
		}
		sf.Close()
	}

	err = tw.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = gw.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = fd.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func zipFile(out string, files []archiveFile) {
	fd, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}

	zw := zip.NewWriter(fd)

	for _, f := range files {
		sf, err := os.Open(f.src)
		if err != nil {
			log.Fatal(err)
		}

		info, err := sf.Stat()
		if err != nil {
			log.Fatal(err)
		}

		fh, err := zip.FileInfoHeader(info)
		if err != nil {
			log.Fatal(err)
		}
		fh.Name = filepath.ToSlash(f.dst)
		fh.Method = zip.Deflate

		if strings.HasSuffix(f.dst, ".txt") {
			// Text file. Read it and convert line endings.
			bs, err := ioutil.ReadAll(sf)
			if err != nil {
				log.Fatal(err)
			}
			bs = bytes.Replace(bs, []byte{'\n'}, []byte{'\n', '\r'}, -1)
			fh.UncompressedSize = uint32(len(bs))
			fh.UncompressedSize64 = uint64(len(bs))

			of, err := zw.CreateHeader(fh)
			if err != nil {
				log.Fatal(err)
			}
			of.Write(bs)
		} else {
			// Binary file. Copy verbatim.
			of, err := zw.CreateHeader(fh)
			if err != nil {
				log.Fatal(err)
			}
			_, err = io.Copy(of, sf)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	err = zw.Close()
	if err != nil {
		log.Fatal(err)
	}
	err = fd.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func macosCodesign(file string) {
	if pass := os.Getenv("CODESIGN_KEYCHAIN_PASS"); pass != "" {
		bs, err := runError("security", "unlock-keychain", "-p", pass)
		if err != nil {
			log.Println("Codesign: unlocking keychain failed:", string(bs))
			return
		}
	}

	if id := os.Getenv("CODESIGN_IDENTITY"); id != "" {
		bs, err := runError("codesign", "-s", id, file)
		if err != nil {
			log.Println("Codesign: signing failed:", string(bs))
			return
		}
		log.Println("Codesign: successfully signed", file)
	}
}

func metalint(linters []string, dirs []string) {
	ok := true
	if isGometalinterInstalled() {
		if !gometalinter(linters, dirs, lintExcludes...) {
			ok = false
		}
	}
	if !ok {
		log.Fatal("Build succeeded, but there were lint warnings")
	}
}

func isGometalinterInstalled() bool {
	if _, err := runError("gometalinter", "--disable-all"); err != nil {
		log.Println("gometalinter is not installed")
		return false
	}
	return true
}

func gometalinter(linters []string, dirs []string, excludes ...string) bool {
	params := []string{"--disable-all", "--concurrency=2", "--deadline=300s"}

	for _, linter := range linters {
		params = append(params, "--enable="+linter)
	}

	for _, exclude := range excludes {
		params = append(params, "--exclude="+exclude)
	}

	for _, dir := range dirs {
		params = append(params, dir)
	}

	bs, _ := runError("gometalinter", params...)

	nerr := 0
	lines := make(map[string]struct{})
	for _, line := range strings.Split(string(bs), "\n") {
		if line == "" {
			continue
		}
		if _, ok := lines[line]; ok {
			continue
		}
		log.Println(line)
		if strings.Contains(line, "executable file not found") {
			log.Println(` - Try "go run build.go setup" to install missing tools`)
		}
		lines[line] = struct{}{}
		nerr++
	}

	return nerr == 0
}
