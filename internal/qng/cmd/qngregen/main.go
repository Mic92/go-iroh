// Command qngregen regenerates internal/qng from the quic-go module pinned in
// go.mod.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	modulePath = "github.com/quic-go/quic-go"
	destDir    = "internal/qng"
)

var keepPaths = []string{
	"README.md",
	"rawkey_quic_test.go",
	"anchor.go",
	"regenerate.sh",
	"n0ext",
	"cmd/qngregen",
}

var importRewrites = []struct {
	old string
	new string
}{
	{modulePath + "/internal/", "github.com/tmc/go-iroh/internal/qng/internal/"},
	{modulePath + "/qlogwriter/", "github.com/tmc/go-iroh/internal/qng/qlogwriter/"},
	{modulePath + "/qlogwriter", "github.com/tmc/go-iroh/internal/qng/qlogwriter"},
	{modulePath + "/qlog", "github.com/tmc/go-iroh/internal/qng/qlog"},
	{modulePath + "/quicvarint", "github.com/tmc/go-iroh/internal/qng/quicvarint"},
	{modulePath, "github.com/tmc/go-iroh/internal/qng"},
	{"crypto/tls", "github.com/tmc/go-iroh/internal/itls/tls"},
}

func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "usage: go run ./internal/qng/cmd/qngregen\n")
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "qngregen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := moduleRoot()
	if err != nil {
		return err
	}
	if err := os.Chdir(root); err != nil {
		return err
	}
	modDir, err := moduleDir(modulePath)
	if err != nil {
		return err
	}
	pkgs, err := quicGoPackages()
	if err != nil {
		return err
	}
	fmt.Printf("forking quic-go from: %s\n", modDir)

	tmp, err := os.MkdirTemp("", "qngregen-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := preserveOverlays(tmp); err != nil {
		return err
	}

	if err := os.RemoveAll(destDir); err != nil {
		return err
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}

	count := 0
	for _, pkg := range pkgs {
		rel := strings.TrimPrefix(pkg, modulePath)
		rel = strings.TrimPrefix(rel, "/")
		src := filepath.Join(modDir, rel)
		dst := filepath.Join(destDir, rel)
		if rel == "" {
			src = modDir
			dst = destDir
		}
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
		files, err := filepath.Glob(filepath.Join(src, "*.go"))
		if err != nil {
			return err
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			if err := copyFile(file, filepath.Join(dst, filepath.Base(file))); err != nil {
				return err
			}
			count++
		}
	}
	fmt.Printf("copied %d files\n", count)

	if err := rewriteGoFiles(destDir); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(modDir, "LICENSE"), filepath.Join(destDir, "LICENSE")); err != nil {
		return err
	}
	if err := restoreOverlays(tmp); err != nil {
		return err
	}
	if err := gofmt(destDir); err != nil {
		return err
	}
	fmt.Println("done; now run: go build ./... && go test ./internal/qng/")
	return nil
}

func moduleRoot() (string, error) {
	cmd := exec.Command("go", "env", "GOMOD")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		return "", fmt.Errorf("not in a Go module")
	}
	return filepath.Dir(gomod), nil
}

func moduleDir(path string) (string, error) {
	cmd := exec.Command("go", "list", "-m", "-json", path)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list -m %s: %w", path, err)
	}
	var m struct {
		Dir string
	}
	if err := json.Unmarshal(out, &m); err != nil {
		return "", err
	}
	if m.Dir == "" {
		return "", fmt.Errorf("module %s has no local directory; run go mod download %s", path, path)
	}
	return m.Dir, nil
}

func quicGoPackages() ([]string, error) {
	cmd := exec.Command("go", "list", "-deps", modulePath)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -deps %s: %w", modulePath, err)
	}
	var pkgs []string
	for _, line := range strings.Split(string(out), "\n") {
		if line == modulePath || strings.HasPrefix(line, modulePath+"/") {
			pkgs = append(pkgs, line)
		}
	}
	sort.Strings(pkgs)
	return pkgs, nil
}

func preserveOverlays(tmp string) error {
	for _, rel := range keepPaths {
		src := filepath.Join(destDir, rel)
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := copyTree(src, filepath.Join(tmp, rel)); err != nil {
			return err
		}
	}
	return nil
}

func restoreOverlays(tmp string) error {
	return filepath.WalkDir(tmp, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(tmp, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dst := filepath.Join(destDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		return copyFile(path, dst)
	})
}

func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return copyFile(src, dst)
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		return copyFile(path, out)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func rewriteGoFiles(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		return rewriteImports(path)
	})
}

func rewriteImports(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return err
	}
	changed := false
	for _, spec := range file.Imports {
		old, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return err
		}
		newPath, ok := rewriteImportPath(old)
		if !ok {
			continue
		}
		if old == "crypto/tls" && spec.Name == nil {
			spec.Name = ast.NewIdent("tls")
		}
		spec.Path.Value = strconv.Quote(newPath)
		changed = true
	}
	if !changed {
		return nil
	}
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, file); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func rewriteImportPath(path string) (string, bool) {
	for _, r := range importRewrites {
		if path == r.old {
			return r.new, true
		}
		if strings.HasSuffix(r.old, "/") && strings.HasPrefix(path, r.old) {
			return r.new + strings.TrimPrefix(path, r.old), true
		}
	}
	return path, false
}

func gofmt(path string) error {
	cmd := exec.Command("gofmt", "-w", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gofmt %s: %w", path, err)
	}
	return nil
}
