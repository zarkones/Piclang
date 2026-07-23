package sema

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/piclang/piclang/internal/ast"
	"github.com/piclang/piclang/internal/loader"
	"github.com/piclang/piclang/internal/parser"
	"github.com/piclang/piclang/internal/token"
	"github.com/piclang/piclang/internal/types"
)

// Object is a named symbol.
type Object struct {
	Name      string
	LinkName  string // codegen / linker name
	Type      types.Type
	IsConst   bool
	IsFunc    bool
	IsGlobal  bool
	IsBuiltin bool
	IsPackage bool // import binding
	Exported  bool
	PkgName   string // defining package name
	ImpPath   string // if IsPackage, import path of target
	ConstVal  uint64
	HasConst  bool
	Offset    int64
	Node      ast.Node
}

// Scope is a lexical scope.
type Scope struct {
	Parent *Scope
	Objs   map[string]*Object
}

func newScope(parent *Scope) *Scope {
	return &Scope{Parent: parent, Objs: make(map[string]*Object)}
}

func (s *Scope) define(obj *Object) error {
	if _, ok := s.Objs[obj.Name]; ok {
		return fmt.Errorf("redefinition of %s", obj.Name)
	}
	s.Objs[obj.Name] = obj
	return nil
}

func (s *Scope) lookup(name string) *Object {
	for sc := s; sc != nil; sc = sc.Parent {
		if o, ok := sc.Objs[name]; ok {
			return o
		}
	}
	return nil
}

// pkgState holds per-package type/symbol tables.
type pkgState struct {
	Path     string
	Name     string
	IsMain   bool
	Pkg      *loader.Package
	Scope    *Scope
	Types    map[string]types.Type
	Structs  map[string]*types.StructType
	Exports  map[string]*Object // exported names only
	AllNames map[string]*Object // all package-level objects by short name
}

// FuncUnit is a function ready for codegen.
type FuncUnit struct {
	Decl *ast.FuncDecl
	Obj  *Object
	Pkg  *pkgState
}

// Checker performs type checking and builds symbol info for a whole program.
type Checker struct {
	errors   []string
	universe *Scope

	// by import path
	pkgs map[string]*pkgState
	// current context while checking
	curPkg    *pkgState
	curFile   *ast.File
	fileScope *Scope // package scope + this file's imports

	ExprType map[ast.Expr]types.Type
	Uses     map[*ast.Ident]*Object
	// package selector: resolve.Foo
	SelObj map[*ast.SelectorExpr]*Object

	// codegen view (link names)
	Funcs   map[string]*Object // LinkName → obj
	Globals []*Object
	Strings []StringLit
	// emission order
	FuncUnits []*FuncUnit

	curFunc   *Object
	curScope  *Scope
	loopDepth int
}

// StringLit is a collected string constant.
type StringLit struct {
	Data   []byte
	Label  string
	Offset int64
}

// New creates a checker for a single file (package main, no imports).
func New(file *ast.File) *Checker {
	if file.Package == "" {
		file.Package = "main"
	}
	prog := &loader.Program{
		ModRoot:  ".",
		Packages: map[string]*loader.Package{},
	}
	pkg := &loader.Package{
		Name:       file.Package,
		ImportPath: ".",
		Files:      []*ast.File{file},
	}
	prog.Main = pkg
	prog.Packages["."] = pkg
	prog.Order = []*loader.Package{pkg}
	return NewProgram(prog)
}

// NewProgram creates a checker for a full loaded program.
func NewProgram(prog *loader.Program) *Checker {
	c := &Checker{
		universe: newScope(nil),
		pkgs:     make(map[string]*pkgState),
		ExprType: make(map[ast.Expr]types.Type),
		Uses:     make(map[*ast.Ident]*Object),
		SelObj:   make(map[*ast.SelectorExpr]*Object),
		Funcs:    make(map[string]*Object),
	}
	c.installBuiltins()
	for _, lp := range prog.Order {
		isMain := lp == prog.Main || lp.ImportPath == "."
		ps := &pkgState{
			Path:     lp.ImportPath,
			Name:     lp.Name,
			IsMain:   isMain,
			Pkg:      lp,
			Scope:    newScope(c.universe),
			Types:    types.BuiltinMap(), // each pkg gets builtins for local resolve
			Structs:  make(map[string]*types.StructType),
			Exports:  make(map[string]*Object),
			AllNames: make(map[string]*Object),
		}
		// Builtins are in universe; package types map starts with builtins copy
		c.pkgs[lp.ImportPath] = ps
	}
	return c
}

func (c *Checker) installBuiltins() {
	builtins := []struct {
		name string
		ft   *types.FuncType
	}{
		{"__readgs", &types.FuncType{Params: []types.Type{types.TyU64}, Ret: types.TyU64}},
		{"__writegs", &types.FuncType{Params: []types.Type{types.TyU64, types.TyU64}, Ret: types.TyVoid}},
		{"__base", &types.FuncType{Params: nil, Ret: types.TyU64}},
		{"__end", &types.FuncType{Params: nil, Ret: types.TyU64}},
		{"__hash", &types.FuncType{Params: []types.Type{types.TyPU8}, Ret: types.TyU32}},
		{"__breakpoint", &types.FuncType{Params: nil, Ret: types.TyVoid}},
		{"__syscall", &types.FuncType{
			Params: []types.Type{types.TyU64, types.TyU64, types.TyU64, types.TyU64, types.TyU64, types.TyU64, types.TyU64},
			Ret:    types.TyU64,
		}},
		{"__sysv_call", &types.FuncType{
			Params: []types.Type{types.TyPVoid, types.TyU64, types.TyU64, types.TyU64, types.TyU64, types.TyU64, types.TyU64},
			Ret:    types.TyU64,
		}},
		{"__memcpy", &types.FuncType{Params: []types.Type{types.TyPVoid, types.TyPVoid, types.TyU64}, Ret: types.TyPVoid}},
		{"__memset", &types.FuncType{Params: []types.Type{types.TyPVoid, types.TyU64, types.TyU64}, Ret: types.TyPVoid}},
		{"__memcmp", &types.FuncType{Params: []types.Type{types.TyPVoid, types.TyPVoid, types.TyU64}, Ret: types.TyI64}},
		{"__strlen", &types.FuncType{Params: []types.Type{types.TyPU8}, Ret: types.TyU64}},
		{"__load8", &types.FuncType{Params: []types.Type{types.TyPVoid}, Ret: types.TyU8}},
		{"__load16", &types.FuncType{Params: []types.Type{types.TyPVoid}, Ret: types.TyU16}},
		{"__load32", &types.FuncType{Params: []types.Type{types.TyPVoid}, Ret: types.TyU32}},
		{"__load64", &types.FuncType{Params: []types.Type{types.TyPVoid}, Ret: types.TyU64}},
		{"__store8", &types.FuncType{Params: []types.Type{types.TyPVoid, types.TyU64}, Ret: types.TyVoid}},
		{"__store16", &types.FuncType{Params: []types.Type{types.TyPVoid, types.TyU64}, Ret: types.TyVoid}},
		{"__store32", &types.FuncType{Params: []types.Type{types.TyPVoid, types.TyU64}, Ret: types.TyVoid}},
		{"__store64", &types.FuncType{Params: []types.Type{types.TyPVoid, types.TyU64}, Ret: types.TyVoid}},
		{"__rdtsc", &types.FuncType{Params: nil, Ret: types.TyU64}},
	}
	for _, b := range builtins {
		_ = c.universe.define(&Object{
			Name: b.name, LinkName: b.name, Type: b.ft, IsFunc: true, IsBuiltin: true,
		})
	}
}

// Errors returns check errors.
func (c *Checker) Errors() []string { return c.errors }

func (c *Checker) errorf(n ast.Node, format string, args ...any) {
	line, col := 0, 0
	path := ""
	if c.curFile != nil {
		path = c.curFile.Path + ":"
	}
	if n != nil {
		line, col = n.Pos()
	}
	msg := fmt.Sprintf("%s%d:%d: "+format, append([]any{path, line, col}, args...)...)
	c.errors = append(c.errors, msg)
}

// Check runs semantic analysis on the program constructed via New/NewProgram.
func (c *Checker) Check() error {
	// Collect import paths from packages that were loaded
	var order []*pkgState
	// Prefer stable order: non-main first is whatever map iteration gives; fix by sorting paths
	paths := make([]string, 0, len(c.pkgs))
	for p := range c.pkgs {
		paths = append(paths, p)
	}
	// simple sort
	for i := 0; i < len(paths); i++ {
		for j := i + 1; j < len(paths); j++ {
			if paths[j] < paths[i] {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}
	// main package "." last for body checking is fine; declare all first
	for _, p := range paths {
		order = append(order, c.pkgs[p])
	}

	// Pass 1: declare structs in every package (forward)
	for _, ps := range order {
		c.curPkg = ps
		for _, f := range ps.Pkg.Files {
			c.curFile = f
			for _, d := range f.Decls {
				if sd, ok := d.(*ast.StructDecl); ok {
					st := &types.StructType{Name: sd.Name}
					// qualify display name for non-main
					if !ps.IsMain {
						st.Name = ps.Name + "." + sd.Name
					}
					ps.Structs[sd.Name] = st
					ps.Types[sd.Name] = st
				}
			}
		}
	}

	// Pass 2: type aliases + struct layout (may reference same-package types)
	for _, ps := range order {
		c.curPkg = ps
		for _, f := range ps.Pkg.Files {
			c.curFile = f
			c.fileScope = ps.Scope // types don't need imports yet for same-pkg
			for _, d := range f.Decls {
				if td, ok := d.(*ast.TypeAliasDecl); ok {
					t := c.resolveType(td.Type)
					ps.Types[td.Name] = t
				}
			}
		}
		for _, f := range ps.Pkg.Files {
			c.curFile = f
			for _, d := range f.Decls {
				if sd, ok := d.(*ast.StructDecl); ok {
					st := ps.Structs[sd.Name]
					for _, field := range sd.Fields {
						ft := c.resolveType(field.Type)
						st.Fields = append(st.Fields, types.StructField{Name: field.Name, Type: ft})
					}
					st.Layout()
				}
			}
		}
	}

	// Pass 3: declare functions and globals (need import types for signatures - resolve with file imports)
	for _, ps := range order {
		c.curPkg = ps
		for _, f := range ps.Pkg.Files {
			c.curFile = f
			c.fileScope = c.makeFileScope(ps, f)
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					ft := &types.FuncType{}
					for _, p := range d.Params {
						ft.Params = append(ft.Params, c.resolveType(p.Type))
					}
					var rs []types.Type
					if len(d.Results) > 0 {
						for _, r := range d.Results {
							rs = append(rs, c.resolveType(r))
						}
					} else if d.Ret != nil {
						rs = []types.Type{c.resolveType(d.Ret)}
					}
					// ABI limit: total cells <= 4
					if types.TotalABICells(rs) > 4 {
						c.errorf(d, "too many return values for ABI (max 4 register cells; []T uses 3)")
					}
					// structs in multi-return forbidden in v1
					if len(rs) > 1 {
						for _, r := range rs {
							if r.Kind() == types.Struct {
								c.errorf(d, "struct multi-return not supported; use pointer")
							}
						}
					}
					ft.SetResults(rs)
					link := loader.Mangle(ps.Name, d.Name, ps.IsMain)
					obj := &Object{
						Name: d.Name, LinkName: link, Type: ft, IsFunc: true,
						Exported: IsExported(d.Name), PkgName: ps.Name, Node: d,
					}
					if err := ps.Scope.define(obj); err != nil {
						c.errorf(d, "%s", err)
					}
					ps.AllNames[d.Name] = obj
					if obj.Exported {
						ps.Exports[d.Name] = obj
					}
					c.Funcs[link] = obj
					c.FuncUnits = append(c.FuncUnits, &FuncUnit{Decl: d, Obj: obj, Pkg: ps})
				case *ast.VarDecl:
					t := c.resolveType(d.Type)
					if t == nil || (d.Type == nil && d.Value == nil) {
						if d.Value != nil {
							t = types.TyU64
						} else {
							c.errorf(d, "variable %s needs a type", d.Name)
							t = types.TyU64
						}
					}
					link := loader.Mangle(ps.Name, d.Name, ps.IsMain)
					obj := &Object{
						Name: d.Name, LinkName: link, Type: t, IsGlobal: true, IsConst: d.IsConst,
						Exported: IsExported(d.Name), PkgName: ps.Name, Node: d,
					}
					if d.IsConst && d.Value != nil {
						if v, ok := c.constInt(d.Value); ok {
							obj.ConstVal = v
							obj.HasConst = true
						}
					}
					// skip storage for pure integer consts in non-addressed case - keep all non-const
					if err := ps.Scope.define(obj); err != nil {
						c.errorf(d, "%s", err)
					}
					ps.AllNames[d.Name] = obj
					if obj.Exported {
						ps.Exports[d.Name] = obj
					}
					if !(obj.IsConst && obj.HasConst) {
						c.Globals = append(c.Globals, obj)
					}
				}
			}
		}
	}

	// Pass 4: check bodies
	for _, ps := range order {
		c.curPkg = ps
		for _, f := range ps.Pkg.Files {
			c.curFile = f
			c.fileScope = c.makeFileScope(ps, f)
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					c.checkFunc(d, ps)
				case *ast.VarDecl:
					if d.Value != nil {
						c.curScope = c.fileScope
						vt := c.checkExpr(d.Value)
						obj := ps.AllNames[d.Name]
						if obj != nil && d.Type == nil {
							obj.Type = vt
						}
						if obj != nil && !types.Assignable(obj.Type, vt) {
							c.errorf(d, "cannot assign %s to %s", vt, obj.Type)
						}
					}
				}
			}
		}
	}

	// main() must exist in main package
	mainPkg := c.pkgs["."]
	if mainPkg == nil {
		// single-file might use path ""
		for _, ps := range c.pkgs {
			if ps.IsMain {
				mainPkg = ps
				break
			}
		}
	}
	if mainPkg == nil || mainPkg.AllNames["main"] == nil {
		c.errorf(nil, "missing entry function main() in package main")
	} else if !mainPkg.AllNames["main"].IsFunc {
		c.errorf(nil, "main is not a function")
	}

	if len(c.errors) > 0 {
		return fmt.Errorf("%d error(s)", len(c.errors))
	}
	return nil
}

func (c *Checker) makeFileScope(ps *pkgState, f *ast.File) *Scope {
	sc := newScope(ps.Scope)
	for _, imp := range f.Imports {
		path := loader.CleanPath(imp.Path)
		target := c.pkgs[path]
		if target == nil {
			// try cleaned path
			for p, pk := range c.pkgs {
				if p == path || pk.Name == imp.Alias {
					target = pk
					path = p
					break
				}
			}
		}
		if target == nil {
			c.errorf(imp, "imported package %q not loaded", imp.Path)
			continue
		}
		obj := &Object{
			Name: imp.Alias, IsPackage: true, ImpPath: path, PkgName: target.Name,
		}
		if err := sc.define(obj); err != nil {
			c.errorf(imp, "%s", err)
		}
	}
	return sc
}

func (c *Checker) resolveType(te ast.TypeExpr) types.Type {
	if te == nil {
		return types.TyVoid
	}
	switch t := te.(type) {
	case *ast.IdentType:
		if c.curPkg != nil {
			if ty, ok := c.curPkg.Types[t.Name]; ok {
				return ty
			}
		}
		// builtins
		if ty, ok := types.BuiltinMap()[t.Name]; ok {
			return ty
		}
		c.errorf(t, "unknown type %s", t.Name)
		return types.TyU64
	case *ast.QualType:
		// pkg.Type
		pkgObj := c.lookupName(t.Pkg)
		if pkgObj == nil || !pkgObj.IsPackage {
			c.errorf(t, "unknown package %s in type", t.Pkg)
			return types.TyU64
		}
		ps := c.pkgs[pkgObj.ImpPath]
		if ps == nil {
			c.errorf(t, "package %s not loaded", t.Pkg)
			return types.TyU64
		}
		ty, ok := ps.Types[t.Name]
		if !ok {
			c.errorf(t, "package %s has no type %s", t.Pkg, t.Name)
			return types.TyU64
		}
		if !IsExported(t.Name) && (c.curPkg == nil || c.curPkg.Path != ps.Path) {
			c.errorf(t, "type %s.%s is not exported", t.Pkg, t.Name)
		}
		return ty
	case *ast.PtrType:
		return &types.Pointer{Elem: c.resolveType(t.Elem)}
	case *ast.SliceTypeExpr:
		return &types.SliceType{Elem: c.resolveType(t.Elem)}
	case *ast.ArrayType:
		var n int64
		if t.Len != nil {
			if v, ok := c.constInt(t.Len); ok {
				n = int64(v)
			}
		}
		return &types.ArrayType{Elem: c.resolveType(t.Elem), Len: n}
	case *ast.FuncType:
		ft := &types.FuncType{}
		for _, p := range t.Params {
			ft.Params = append(ft.Params, c.resolveType(p))
		}
		if t.Ret != nil {
			ft.SetResults([]types.Type{c.resolveType(t.Ret)})
		} else {
			ft.SetResults(nil)
		}
		return ft
	}
	return types.TyU64
}

func (c *Checker) lookupName(name string) *Object {
	if c.curScope != nil {
		if o := c.curScope.lookup(name); o != nil {
			return o
		}
	}
	if c.fileScope != nil {
		if o := c.fileScope.lookup(name); o != nil {
			return o
		}
	}
	if c.curPkg != nil {
		if o := c.curPkg.Scope.lookup(name); o != nil {
			return o
		}
	}
	return c.universe.lookup(name)
}

func (c *Checker) checkFunc(d *ast.FuncDecl, ps *pkgState) {
	obj := ps.AllNames[d.Name]
	c.curFunc = obj
	sc := newScope(c.fileScope)
	c.curScope = sc
	ft := obj.Type.(*types.FuncType)
	for i, p := range d.Params {
		po := &Object{Name: p.Name, LinkName: p.Name, Type: ft.Params[i], Node: p}
		if err := sc.define(po); err != nil {
			c.errorf(p, "%s", err)
		}
	}
	c.checkBlock(d.Body)
	c.curFunc = nil
	c.curScope = c.fileScope
}

func (c *Checker) checkBlock(b *ast.BlockStmt) {
	if b == nil {
		return
	}
	prev := c.curScope
	c.curScope = newScope(prev)
	for _, s := range b.Stmts {
		c.checkStmt(s)
	}
	c.curScope = prev
}

func (c *Checker) checkStmt(s ast.Stmt) {
	switch s := s.(type) {
	case *ast.BlockStmt:
		c.checkBlock(s)
	case *ast.VarDecl:
		var t types.Type
		if s.Type != nil {
			t = c.resolveType(s.Type)
		}
		if s.Value != nil {
			vt := c.checkExpr(s.Value)
			if t == nil || s.Type == nil {
				t = vt
			} else if !types.Assignable(t, vt) {
				c.errorf(s, "cannot assign %s to %s", vt, t)
			}
		}
		if t == nil {
			t = types.TyU64
		}
		obj := &Object{Name: s.Name, LinkName: s.Name, Type: t, IsConst: s.IsConst, Node: s}
		if s.IsConst && s.Value != nil {
			if v, ok := c.constInt(s.Value); ok {
				obj.ConstVal = v
				obj.HasConst = true
			}
		}
		if err := c.curScope.define(obj); err != nil {
			c.errorf(s, "%s", err)
		}
	case *ast.ReturnStmt:
		ft := c.curFunc.Type.(*types.FuncType)
		want := ft.ResultTypes()
		// normalize Results from Value
		results := s.Results
		if len(results) == 0 && s.Value != nil {
			results = []ast.Expr{s.Value}
		}
		if len(want) == 0 {
			if len(results) > 0 {
				c.errorf(s, "too many return values")
			}
			return
		}
		// Go-style passthrough: return f() when f's multi-results match.
		if len(results) == 1 && len(want) > 1 {
			vt := c.checkExpr(results[0])
			if tup, ok := vt.(*types.Tuple); ok {
				if len(tup.Elems) != len(want) {
					c.errorf(s, "wrong number of return values: have %d, want %d", len(tup.Elems), len(want))
					return
				}
				for i := range want {
					if !types.Assignable(want[i], tup.Elems[i]) {
						c.errorf(results[0], "cannot return %s as %s", tup.Elems[i], want[i])
					}
				}
				return
			}
			c.errorf(s, "wrong number of return values: have 1, want %d", len(want))
			return
		}
		if len(results) == 1 && len(want) == 1 {
			vt := c.checkExpr(results[0])
			if tup, ok := vt.(*types.Tuple); ok && len(tup.Elems) != 1 {
				c.errorf(s, "multi-value in single-value context: have %d values", len(tup.Elems))
				return
			}
			if !types.Assignable(want[0], vt) {
				c.errorf(results[0], "cannot return %s as %s", vt, want[0])
			}
			return
		}
		if len(results) != len(want) {
			c.errorf(s, "wrong number of return values: have %d, want %d", len(results), len(want))
			// still typecheck what we can
		}
		n := len(results)
		if n > len(want) {
			n = len(want)
		}
		for i := 0; i < n; i++ {
			vt := c.checkExpr(results[i])
			if tup, ok := vt.(*types.Tuple); ok {
				c.errorf(results[i], "multi-value %s in multi-return list (use return f() passthrough)", tup)
				continue
			}
			if !types.Assignable(want[i], vt) {
				c.errorf(results[i], "cannot return %s as %s", vt, want[i])
			}
		}
	case *ast.DeferStmt:
		if s.Free != nil {
			c.checkExpr(s.Free)
			return
		}
		if s.Call == nil {
			c.errorf(s, "defer requires a function call or free(...)")
			return
		}
		if len(s.Call.Args) > 4 {
			c.errorf(s, "defer supports at most 4 arguments")
		}
		// Type-check like a normal call; args are evaluated at defer time (Go).
		c.checkExpr(s.Call)
	case *ast.IfStmt:
		ct := c.checkExpr(s.Cond)
		if !types.IsInteger(ct) && !types.IsPointer(ct) {
			c.errorf(s.Cond, "condition must be scalar")
		}
		c.checkBlock(s.Then)
		if s.Else != nil {
			c.checkStmt(s.Else)
		}
	case *ast.WhileStmt:
		ct := c.checkExpr(s.Cond)
		if !types.IsInteger(ct) && !types.IsPointer(ct) {
			c.errorf(s.Cond, "condition must be scalar")
		}
		c.loopDepth++
		c.checkBlock(s.Body)
		c.loopDepth--
	case *ast.ForStmt:
		prev := c.curScope
		c.curScope = newScope(prev)
		if s.Init != nil {
			c.checkStmt(s.Init)
		}
		if s.Cond != nil {
			c.checkExpr(s.Cond)
		}
		if s.Post != nil {
			c.checkExpr(s.Post)
		}
		c.loopDepth++
		c.checkBlock(s.Body)
		c.loopDepth--
		c.curScope = prev
	case *ast.BreakStmt, *ast.ContinueStmt:
		if c.loopDepth == 0 {
			c.errorf(s, "break/continue outside loop")
		}
	case *ast.AssignStmt:
		c.checkAssign(s)
	case *ast.ExprStmt:
		c.checkExpr(s.X)
	}
}

func (c *Checker) checkAssign(s *ast.AssignStmt) {
	lhss := s.Lhss
	if len(lhss) == 0 && s.Lhs != nil {
		lhss = []ast.Expr{s.Lhs}
	}
	if len(lhss) == 0 {
		c.errorf(s, "assignment missing left-hand side")
		return
	}

	// Multi-assign / := from call
	if len(lhss) > 1 || s.Define {
		rt := c.checkExpr(s.Rhs)
		var results []types.Type
		if tup, ok := rt.(*types.Tuple); ok {
			results = tup.Elems
		} else if len(lhss) == 1 {
			results = []types.Type{rt}
		} else {
			c.errorf(s, "multi-assign requires multi-return call on RHS, got %s", rt)
			return
		}
		if len(results) != len(lhss) {
			c.errorf(s, "assignment mismatch: %d LHS, %d values", len(lhss), len(results))
			return
		}
		for i, lhs := range lhss {
			if id, ok := lhs.(*ast.Ident); ok && id.Name == "_" {
				continue
			}
			if s.Define {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					c.errorf(lhs, ":= left side must be identifier")
					continue
				}
				obj := &Object{Name: id.Name, LinkName: id.Name, Type: results[i], Node: id}
				if err := c.curScope.define(obj); err != nil {
					c.errorf(lhs, "%s", err)
				}
				c.Uses[id] = obj
				continue
			}
			lt := c.checkExpr(lhs)
			if !types.Assignable(lt, results[i]) && s.Op == token.Assign {
				c.errorf(lhs, "cannot assign %s to %s", results[i], lt)
			}
		}
		return
	}

	// Single LHS
	if s.Define {
		id, ok := lhss[0].(*ast.Ident)
		if !ok {
			c.errorf(s, ":= left side must be identifier")
			return
		}
		rt := c.checkExpr(s.Rhs)
		if tup, ok := rt.(*types.Tuple); ok {
			c.errorf(s, "multi-value in single := ; use a, b := ...")
			_ = tup
			return
		}
		obj := &Object{Name: id.Name, LinkName: id.Name, Type: rt, Node: id}
		if err := c.curScope.define(obj); err != nil {
			c.errorf(s, "%s", err)
		}
		c.Uses[id] = obj
		return
	}

	lt := c.checkExpr(lhss[0])
	rt := c.checkExpr(s.Rhs)
	if tup, ok := rt.(*types.Tuple); ok {
		c.errorf(s, "multi-value in single assignment; use a, b = f()")
		_ = tup
		return
	}
	if !types.Assignable(lt, rt) && s.Op == token.Assign {
		c.errorf(s, "cannot assign %s to %s", rt, lt)
	}
}

func (c *Checker) checkExpr(e ast.Expr) types.Type {
	if e == nil {
		return types.TyVoid
	}
	var t types.Type
	switch e := e.(type) {
	case *ast.Ident:
		if e.Name == "_" {
			// blank identifier only valid on assign LHS (checked there)
			t = types.TyU64
			break
		}
		obj := c.lookupName(e.Name)
		if obj == nil {
			c.errorf(e, "undefined: %s", e.Name)
			t = types.TyU64
		} else {
			c.Uses[e] = obj
			if obj.IsPackage {
				// package name as value is not a first-class type; use void-ish
				t = types.TyU64
			} else {
				t = obj.Type
			}
		}
	case *ast.BasicLit:
		switch e.Kind {
		case token.Int:
			t = types.TyU64
		case token.String:
			// Always record in this checker's string table. StrIndex is relative
			// to the current Checker (re-check of the same AST must reassign).
			e.StrIndex = len(c.Strings)
			data := append([]byte(e.Value), 0)
			c.Strings = append(c.Strings, StringLit{
				Data:  data,
				Label: fmt.Sprintf("str_%d", e.StrIndex),
			})
			t = types.TyPU8
		case token.Char:
			t = types.TyU8
		case token.True, token.False:
			t = types.TyBool
		case token.Null:
			t = types.TyPVoid
		default:
			t = types.TyU64
		}
	case *ast.UnaryExpr:
		xt := c.checkExpr(e.X)
		switch e.Op {
		case token.Star:
			if !types.IsPointer(xt) {
				c.errorf(e, "cannot dereference %s", xt)
				t = types.TyU64
			} else {
				t = xt.(*types.Pointer).Elem
			}
		case token.Bang, token.Minus, token.Tilde, token.Plus:
			t = xt
		default:
			t = xt
		}
	case *ast.AddrOf:
		xt := c.checkExpr(e.X)
		t = &types.Pointer{Elem: xt}
	case *ast.BinaryExpr:
		lt := c.checkExpr(e.X)
		rt := c.checkExpr(e.Y)
		switch e.Op {
		case token.Eq, token.Neq, token.Lt, token.Gt, token.Le, token.Ge, token.AndAnd, token.OrOr:
			t = types.TyBool
		case token.Plus:
			if types.IsPointer(lt) && types.IsInteger(rt) {
				t = lt
			} else if types.IsInteger(lt) && types.IsPointer(rt) {
				t = rt
			} else {
				t = lt
			}
		case token.Minus:
			if types.IsPointer(lt) && types.IsPointer(rt) {
				t = types.TyI64
			} else if types.IsPointer(lt) && types.IsInteger(rt) {
				t = lt
			} else {
				t = lt
			}
		default:
			_ = rt
			t = lt
		}
	case *ast.CallExpr:
		// package.Func(...)
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok {
				pkgObj := c.lookupName(id.Name)
				if pkgObj != nil && pkgObj.IsPackage {
					c.Uses[id] = pkgObj
					ps := c.pkgs[pkgObj.ImpPath]
					if ps == nil {
						c.errorf(e, "package %s not loaded", id.Name)
						t = types.TyU64
						break
					}
					mem, ok := ps.Exports[sel.Sel]
					if !ok {
						// allow same-package? imports are other packages
						c.errorf(e, "%s.%s undefined or not exported", id.Name, sel.Sel)
						t = types.TyU64
						break
					}
					c.SelObj[sel] = mem
					for _, a := range e.Args {
						c.checkExpr(a)
					}
					if ft, ok := mem.Type.(*types.FuncType); ok {
						rs := ft.ResultTypes()
						if len(rs) == 0 {
							t = types.TyVoid
						} else if len(rs) == 1 {
							t = rs[0]
						} else {
							t = &types.Tuple{Elems: rs}
						}
					} else {
						t = types.TyU64
					}
					c.ExprType[e] = t
					return t
				}
			}
		}
		ft := c.checkExpr(e.Fun)
		if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "__hash" {
			if len(e.Args) == 1 {
				if lit, ok := e.Args[0].(*ast.BasicLit); ok && lit.Kind == token.String {
					_ = HashStringA(lit.Value)
					t = types.TyU32
					c.ExprType[e] = t
					return t
				}
			}
		}
		if id, ok := e.Fun.(*ast.Ident); ok && (id.Name == "__syscall" || id.Name == "__sysv_call") {
			for _, a := range e.Args {
				c.checkExpr(a)
			}
			t = types.TyU64
			c.ExprType[e] = t
			return t
		}
		var fty *types.FuncType
		switch ft := ft.(type) {
		case *types.FuncType:
			fty = ft
		case *types.Pointer:
			if f2, ok := ft.Elem.(*types.FuncType); ok {
				fty = f2
			}
		}
		if fty == nil {
			if types.IsInteger(ft) || types.IsPointer(ft) {
				for _, a := range e.Args {
					c.checkExpr(a)
				}
				t = types.TyU64
				c.ExprType[e] = t
				return t
			}
			c.errorf(e, "cannot call %s", ft)
			t = types.TyU64
		} else {
			for _, a := range e.Args {
				c.checkExpr(a)
			}
			rs := fty.ResultTypes()
			if len(rs) == 0 {
				t = types.TyVoid
			} else if len(rs) == 1 {
				t = rs[0]
			} else {
				t = &types.Tuple{Elems: rs}
			}
		}
	case *ast.IndexExpr:
		xt := c.checkExpr(e.X)
		c.checkExpr(e.Index)
		switch xt := xt.(type) {
		case *types.Pointer:
			t = xt.Elem
		case *types.ArrayType:
			t = xt.Elem
		case *types.SliceType:
			t = xt.Elem
		default:
			c.errorf(e, "cannot index %s", xt)
			t = types.TyU64
		}
	case *ast.SliceExpr:
		xt := c.checkExpr(e.X)
		if e.Low != nil {
			c.checkExpr(e.Low)
		}
		if e.High != nil {
			c.checkExpr(e.High)
		}
		switch xt := xt.(type) {
		case *types.SliceType:
			t = xt
		case *types.ArrayType:
			t = &types.SliceType{Elem: xt.Elem}
		case *types.Pointer:
			// allow p[i:j] as []elem view? skip for v1
			c.errorf(e, "slice expression requires slice or array type, got %s", xt)
			t = &types.SliceType{Elem: types.TyU8}
		default:
			c.errorf(e, "cannot slice %s", xt)
			t = &types.SliceType{Elem: types.TyU8}
		}
	case *ast.MakeExpr:
		ty := c.resolveType(e.Type)
		if !types.IsSlice(ty) {
			c.errorf(e, "make requires slice type, got %s", ty)
			t = &types.SliceType{Elem: types.TyU8}
		} else {
			t = ty
		}
		c.checkExpr(e.Len)
		if e.Cap != nil {
			c.checkExpr(e.Cap)
		}
	case *ast.AppendExpr:
		st := c.checkExpr(e.Slice)
		if !types.IsSlice(st) {
			c.errorf(e, "append requires slice, got %s", st)
			t = &types.SliceType{Elem: types.TyU8}
		} else {
			t = st
			elem := types.SliceElem(st)
			for _, el := range e.Elems {
				et := c.checkExpr(el)
				if !types.Assignable(elem, et) {
					c.errorf(el, "cannot append %s to %s", et, st)
				}
			}
		}
	case *ast.LenExpr:
		xt := c.checkExpr(e.X)
		if types.IsSlice(xt) || xt.Kind() == types.Array || types.IsPointer(xt) {
			// pointer: not Go; we only allow slice/array for len
		}
		if !types.IsSlice(xt) && xt.Kind() != types.Array {
			// allow *u8 as strlen? No - use strings.Len. Only slice/array.
			if types.IsPointer(xt) {
				c.errorf(e, "len() on pointer unsupported; use strings.Len for *u8")
			} else if !types.IsSlice(xt) {
				c.errorf(e, "len() requires slice or array")
			}
		}
		t = types.TyU64
	case *ast.CapExpr:
		xt := c.checkExpr(e.X)
		if !types.IsSlice(xt) {
			c.errorf(e, "cap() requires slice")
		}
		t = types.TyU64
	case *ast.CopyExpr:
		dt := c.checkExpr(e.Dst)
		st := c.checkExpr(e.Src)
		if !types.IsSlice(dt) || !types.IsSlice(st) {
			c.errorf(e, "copy requires two slices")
		} else if !types.SliceElem(dt).Equals(types.SliceElem(st)) {
			c.errorf(e, "copy element types differ")
		}
		t = types.TyU64
	case *ast.FreeExpr:
		xt := c.checkExpr(e.X)
		if !types.IsSlice(xt) {
			c.errorf(e, "free() requires a slice")
		}
		t = types.TyVoid
	case *ast.SelectorExpr:
		// package.Member or struct.field
		if id, ok := e.X.(*ast.Ident); ok {
			pkgObj := c.lookupName(id.Name)
			if pkgObj != nil && pkgObj.IsPackage {
				c.Uses[id] = pkgObj
				ps := c.pkgs[pkgObj.ImpPath]
				if ps == nil {
					c.errorf(e, "package %s not loaded", id.Name)
					t = types.TyU64
					break
				}
				mem, ok := ps.Exports[e.Sel]
				if !ok {
					c.errorf(e, "%s.%s undefined or not exported", id.Name, e.Sel)
					t = types.TyU64
					break
				}
				c.SelObj[e] = mem
				t = mem.Type
				c.ExprType[e] = t
				return t
			}
		}
		xt := c.checkExpr(e.X)
		var st *types.StructType
		switch xt := xt.(type) {
		case *types.StructType:
			st = xt
		case *types.Pointer:
			if s, ok := xt.Elem.(*types.StructType); ok {
				st = s
			}
		}
		if st == nil {
			c.errorf(e, "cannot select field on %s", xt)
			t = types.TyU64
		} else {
			f, ok := st.Field(e.Sel)
			if !ok {
				c.errorf(e, "no field %s on %s", e.Sel, st.Name)
				t = types.TyU64
			} else {
				t = f.Type
			}
		}
	case *ast.CastExpr:
		c.checkExpr(e.X)
		t = c.resolveType(e.Type)
	case *ast.SizeofExpr:
		_ = c.resolveType(e.Type)
		t = types.TyU64
	case *ast.ParenExpr:
		t = c.checkExpr(e.X)
	default:
		t = types.TyU64
	}
	c.ExprType[e] = t
	return t
}

func (c *Checker) constInt(e ast.Expr) (uint64, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind == token.Int {
			v, err := parser.ParseInt(e.Value)
			return v, err == nil
		}
		if e.Kind == token.Char && len(e.Value) > 0 {
			return uint64(e.Value[0]), true
		}
		if e.Kind == token.True {
			return 1, true
		}
		if e.Kind == token.False || e.Kind == token.Null {
			return 0, true
		}
	case *ast.UnaryExpr:
		v, ok := c.constInt(e.X)
		if !ok {
			return 0, false
		}
		switch e.Op {
		case token.Minus:
			return uint64(-int64(v)), true
		case token.Tilde:
			return ^v, true
		case token.Bang:
			if v == 0 {
				return 1, true
			}
			return 0, true
		}
	case *ast.BinaryExpr:
		l, ok1 := c.constInt(e.X)
		r, ok2 := c.constInt(e.Y)
		if !ok1 || !ok2 {
			return 0, false
		}
		switch e.Op {
		case token.Plus:
			return l + r, true
		case token.Minus:
			return l - r, true
		case token.Star:
			return l * r, true
		case token.Slash:
			if r == 0 {
				return 0, false
			}
			return l / r, true
		case token.Percent:
			if r == 0 {
				return 0, false
			}
			return l % r, true
		case token.Amp:
			return l & r, true
		case token.Pipe:
			return l | r, true
		case token.Caret:
			return l ^ r, true
		case token.Shl:
			return l << r, true
		case token.Shr:
			return l >> r, true
		}
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "__hash" {
			if len(e.Args) == 1 {
				if lit, ok := e.Args[0].(*ast.BasicLit); ok && lit.Kind == token.String {
					return uint64(HashStringA(lit.Value)), true
				}
			}
		}
	case *ast.SizeofExpr:
		ty := c.resolveType(e.Type)
		return uint64(ty.Size()), true
	case *ast.CastExpr:
		return c.constInt(e.X)
	case *ast.ParenExpr:
		return c.constInt(e.X)
	case *ast.Ident:
		obj := c.lookupName(e.Name)
		if obj != nil && obj.HasConst {
			return obj.ConstVal, true
		}
	case *ast.SelectorExpr:
		if obj := c.SelObj[e]; obj != nil && obj.HasConst {
			return obj.ConstVal, true
		}
	}
	return 0, false
}

// HashStringA is the Stardust-style djb2 uppercase hash.
func HashStringA(s string) uint32 {
	const magicKey uint32 = 5381
	const magicSeed uint32 = 5
	hash := magicKey
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' {
			ch -= 0x20
		}
		hash = ((hash << magicSeed) + hash) + uint32(ch)
	}
	return hash
}

// TypeOf returns the type of an expression.
func (c *Checker) TypeOf(e ast.Expr) types.Type {
	if t, ok := c.ExprType[e]; ok {
		return t
	}
	return types.TyU64
}

// LookupType resolves a type name in the main/current package builtins+structs.
func (c *Checker) LookupType(name string) types.Type {
	if c.curPkg != nil {
		if t, ok := c.curPkg.Types[name]; ok {
			return t
		}
	}
	// search all packages' structs by short name for sizeof fallback
	for _, ps := range c.pkgs {
		if t, ok := ps.Types[name]; ok {
			return t
		}
	}
	return types.BuiltinMap()[name]
}

// IsExported reports Go-style export (leading uppercase letter).
func IsExported(name string) bool {
	if name == "" {
		return false
	}
	r, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(r)
}

// LinkNameOf returns the codegen name for an object (or bare name).
func LinkNameOf(obj *Object) string {
	if obj == nil {
		return ""
	}
	if obj.LinkName != "" {
		return obj.LinkName
	}
	return obj.Name
}
