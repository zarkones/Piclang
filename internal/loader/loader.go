// Package loader resolves Piclang packages (directory = package) and imports.
package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/piclang/piclang/internal/ast"
	"github.com/piclang/piclang/internal/lexer"
	"github.com/piclang/piclang/internal/parser"
)

// Package is one compiled package (all .pic files in a directory, or a single file).
type Package struct {
	Name       string
	ImportPath string
	Dir        string
	Files      []*ast.File
}

// Program is a full import graph ready for type-checking.
type Program struct {
	ModRoot  string
	Main     *Package
	Packages map[string]*Package
	Order    []*Package
	Errors   []string
	// IncludePaths are extra roots searched for import paths (e.g. repo root for "std/...").
	IncludePaths []string
}

// Options for LoadEntry.
type Options struct {
	// IncludePaths are searched (in order) for import "a/b" as <path>/a/b.
	// ModRoot is always tried first.
	IncludePaths []string
}

// LoadEntry loads a .pic file or package directory and all imports.
func LoadEntry(entry string) (*Program, error) {
	return LoadEntryWith(entry, Options{})
}

// LoadEntryWith loads entry with extra include paths.
func LoadEntryWith(entry string, opts Options) (*Program, error) {
	abs, err := filepath.Abs(entry)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}

	prog := &Program{
		Packages:     make(map[string]*Package),
		IncludePaths: append([]string{}, opts.IncludePaths...),
	}

	var mainDir string
	var mainFiles []string
	if info.IsDir() {
		mainDir = abs
		prog.ModRoot = filepath.Dir(abs)
		mainFiles, err = listPicFiles(abs)
		if err != nil {
			return nil, err
		}
		if len(mainFiles) == 0 {
			return nil, fmt.Errorf("no .pic files in %s", abs)
		}
	} else {
		if !strings.HasSuffix(strings.ToLower(abs), ".pic") {
			return nil, fmt.Errorf("entry must be a .pic file or directory: %s", abs)
		}
		mainDir = filepath.Dir(abs)
		prog.ModRoot = mainDir
		mainFiles = []string{abs}
	}

	// Always search modroot; then user -I; then env / default std roots.
	roots := []string{prog.ModRoot}
	roots = append(roots, prog.IncludePaths...)
	roots = append(roots, defaultIncludePaths()...)
	prog.IncludePaths = uniqAbs(roots)

	mainPkg, err := prog.loadPackage(".", mainDir, mainFiles)
	if err != nil {
		return nil, err
	}
	prog.Main = mainPkg
	prog.Packages["."] = mainPkg

	queue := []string{"."}
	seen := map[string]bool{".": true}
	for len(queue) > 0 {
		curPath := queue[0]
		queue = queue[1:]
		cur := prog.Packages[curPath]
		for _, f := range cur.Files {
			for _, imp := range f.Imports {
				ip := cleanImportPath(imp.Path)
				if ip == "" || ip == "." {
					prog.Errors = append(prog.Errors, fmt.Sprintf("%s: invalid import path %q", f.Path, imp.Path))
					continue
				}
				if seen[ip] {
					continue
				}
				seen[ip] = true
				dir, files, err := prog.findPackage(ip)
				if err != nil {
					prog.Errors = append(prog.Errors, fmt.Sprintf("%s: import %q: %v", f.Path, ip, err))
					continue
				}
				pkg, err := prog.loadPackage(ip, dir, files)
				if err != nil {
					prog.Errors = append(prog.Errors, fmt.Sprintf("%s: import %q: %v", f.Path, ip, err))
					continue
				}
				prog.Packages[ip] = pkg
				queue = append(queue, ip)
			}
		}
	}

	if len(prog.Errors) > 0 {
		return prog, fmt.Errorf("%d load error(s)", len(prog.Errors))
	}
	prog.Order = topoOrder(prog)
	return prog, nil
}

func defaultIncludePaths() []string {
	var out []string
	if v := os.Getenv("PICLANG_ROOT"); v != "" {
		out = append(out, v)
	}
	// Walk up from cwd looking for a directory that contains std/
	if cwd, err := os.Getwd(); err == nil {
		dir := cwd
		for i := 0; i < 8; i++ {
			if st, err := os.Stat(filepath.Join(dir, "std")); err == nil && st.IsDir() {
				out = append(out, dir)
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return out
}

func uniqAbs(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
	}
	return out
}

func (prog *Program) findPackage(importPath string) (dir string, files []string, err error) {
	rel := filepath.FromSlash(importPath)
	var tried []string
	for _, root := range prog.IncludePaths {
		cand := filepath.Join(root, rel)
		tried = append(tried, cand)
		files, e := resolvePackageFiles(cand)
		if e == nil {
			// directory or single-file package
			if st, err := os.Stat(cand); err == nil && st.IsDir() {
				return cand, files, nil
			}
			// single file package: cand.pic
			return filepath.Dir(files[0]), files, nil
		}
	}
	return "", nil, fmt.Errorf("package not found (searched: %s)", strings.Join(tried, ", "))
}

func (prog *Program) loadPackage(importPath, dir string, files []string) (*Package, error) {
	pkg := &Package{
		ImportPath: importPath,
		Dir:        dir,
	}
	var pkgName string
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		lex := lexer.New(string(src))
		p := parser.New(lex)
		f := p.ParseFile(path)
		if errs := p.Errors(); len(errs) > 0 {
			return nil, fmt.Errorf("%s:\n  %s", path, strings.Join(errs, "\n  "))
		}
		if pkgName == "" {
			pkgName = f.Package
		} else if f.Package != pkgName {
			return nil, fmt.Errorf("package name mismatch in %s: got %q, want %q", path, f.Package, pkgName)
		}
		pkg.Files = append(pkg.Files, f)
	}
	pkg.Name = pkgName
	if pkg.Name == "" {
		pkg.Name = "main"
	}
	return pkg, nil
}

func listPicFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(strings.ToLower(name), ".pic") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	sort.Strings(files)
	return files, nil
}

func resolvePackageFiles(dir string) ([]string, error) {
	info, err := os.Stat(dir)
	if err == nil && info.IsDir() {
		files, err := listPicFiles(dir)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("no .pic files in %s", dir)
		}
		return files, nil
	}
	single := dir + ".pic"
	if st, err := os.Stat(single); err == nil && !st.IsDir() {
		return []string{single}, nil
	}
	return nil, fmt.Errorf("not found: %s", dir)
}

// CleanPath normalizes an import path.
func CleanPath(p string) string {
	return cleanImportPath(p)
}

func cleanImportPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.Trim(p, "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if strings.Contains(p, "..") {
		return ""
	}
	return p
}

func topoOrder(prog *Program) []*Package {
	deps := map[string][]string{}
	for ip, pkg := range prog.Packages {
		var d []string
		seen := map[string]bool{}
		for _, f := range pkg.Files {
			for _, imp := range f.Imports {
				p := cleanImportPath(imp.Path)
				if p == "" || p == ip || seen[p] {
					continue
				}
				if _, ok := prog.Packages[p]; ok {
					seen[p] = true
					d = append(d, p)
				}
			}
		}
		deps[ip] = d
	}
	var order []*Package
	visited := map[string]bool{}
	var visit func(string)
	visit = func(ip string) {
		if visited[ip] {
			return
		}
		visited[ip] = true
		for _, d := range deps[ip] {
			visit(d)
		}
		if pkg := prog.Packages[ip]; pkg != nil {
			order = append(order, pkg)
		}
	}
	var keys []string
	for k := range prog.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		visit(k)
	}
	return order
}

// Mangle returns the link-time symbol for a package-level name.
func Mangle(pkgName, name string, isMain bool) string {
	if isMain || pkgName == "main" {
		return name
	}
	safe := strings.ReplaceAll(pkgName, "/", "_")
	safe = strings.ReplaceAll(safe, ".", "_")
	return safe + "_" + name
}

// IsExported reports Go-style export: leading uppercase letter.
func IsExported(name string) bool {
	if name == "" {
		return false
	}
	r := rune(name[0])
	return r >= 'A' && r <= 'Z'
}
