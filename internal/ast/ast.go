package ast

import "github.com/piclang/piclang/internal/token"

// Node is the base AST interface.
type Node interface {
	Pos() (line, col int)
}

// File is a compilation unit (.pic source file).
type File struct {
	Path    string
	Package string // package clause; default "main" if omitted
	Imports []*ImportSpec
	Decls   []Decl
}

func (f *File) Pos() (int, int) { return 1, 1 }

// ImportSpec is a single import: import "path" or import alias "path".
type ImportSpec struct {
	Alias     string // empty → last path element
	Path      string // import path, e.g. "resolve" or "lib/pe"
	Line, Col int
}

func (s *ImportSpec) Pos() (int, int) { return s.Line, s.Col }

// Decl is a top-level declaration.
type Decl interface {
	Node
	declNode()
}

// FuncDecl is a function declaration.
type FuncDecl struct {
	Name    string
	Params  []*Field
	Results []TypeExpr // empty = void; one = single; many = multi-return
	// Ret is the first result if len(Results)==1; kept for older code paths.
	Ret       TypeExpr
	Body      *BlockStmt
	IsEntry   bool // main
	Line, Col int
}

func (d *FuncDecl) Pos() (int, int) { return d.Line, d.Col }
func (d *FuncDecl) declNode()       {}

// VarDecl is a global or local variable declaration.
type VarDecl struct {
	Name      string
	Type      TypeExpr
	Value     Expr
	IsGlobal  bool
	IsConst   bool
	Line, Col int
}

func (d *VarDecl) Pos() (int, int) { return d.Line, d.Col }
func (d *VarDecl) declNode()       {}
func (d *VarDecl) stmtNode()       {}

// TypeAliasDecl: type Name = Type
type TypeAliasDecl struct {
	Name      string
	Type      TypeExpr
	Line, Col int
}

func (d *TypeAliasDecl) Pos() (int, int) { return d.Line, d.Col }
func (d *TypeAliasDecl) declNode()       {}

// StructDecl: struct Name { fields }
type StructDecl struct {
	Name      string
	Fields    []*Field
	Line, Col int
}

func (d *StructDecl) Pos() (int, int) { return d.Line, d.Col }
func (d *StructDecl) declNode()       {}

// Field is a named typed parameter or struct field.
type Field struct {
	Name      string
	Type      TypeExpr
	Line, Col int
}

func (f *Field) Pos() (int, int) { return f.Line, f.Col }

// ---- Type expressions ----

// TypeExpr describes a type in source.
type TypeExpr interface {
	Node
	typeExprNode()
}

// IdentType is a named type (u64, MyStruct, ...).
type IdentType struct {
	Name      string
	Line, Col int
}

func (t *IdentType) Pos() (int, int) { return t.Line, t.Col }
func (t *IdentType) typeExprNode()   {}

// QualType is a package-qualified type: pkg.TypeName
type QualType struct {
	Pkg       string
	Name      string
	Line, Col int
}

func (t *QualType) Pos() (int, int) { return t.Line, t.Col }
func (t *QualType) typeExprNode()   {}

// PtrType is *T.
type PtrType struct {
	Elem      TypeExpr
	Line, Col int
}

func (t *PtrType) Pos() (int, int) { return t.Line, t.Col }
func (t *PtrType) typeExprNode()   {}

// ArrayType is [N]T.
type ArrayType struct {
	Len       Expr
	Elem      TypeExpr
	Line, Col int
}

func (t *ArrayType) Pos() (int, int) { return t.Line, t.Col }
func (t *ArrayType) typeExprNode()   {}

// SliceTypeExpr is []T.
type SliceTypeExpr struct {
	Elem      TypeExpr
	Line, Col int
}

func (t *SliceTypeExpr) Pos() (int, int) { return t.Line, t.Col }
func (t *SliceTypeExpr) typeExprNode()   {}

// FuncType is fn(args) -> ret (for function pointers).
type FuncType struct {
	Params    []TypeExpr
	Ret       TypeExpr
	Line, Col int
}

func (t *FuncType) Pos() (int, int) { return t.Line, t.Col }
func (t *FuncType) typeExprNode()   {}

// ---- Statements ----

type Stmt interface {
	Node
	stmtNode()
}

type BlockStmt struct {
	Stmts     []Stmt
	Line, Col int
}

func (s *BlockStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *BlockStmt) stmtNode()       {}

type ExprStmt struct {
	X         Expr
	Line, Col int
}

func (s *ExprStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *ExprStmt) stmtNode()       {}

type ReturnStmt struct {
	Results []Expr // empty = bare return; one or more values
	// Value is Results[0] when len==1 (compat helpers may set both)
	Value     Expr
	Line, Col int
}

func (s *ReturnStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *ReturnStmt) stmtNode()       {}

// DeferStmt is Go-style defer: defer f(args...) or defer free(s).
// Args / slice evaluated now; action runs on function return (LIFO).
type DeferStmt struct {
	Call      *CallExpr // function call form
	Free      *FreeExpr // free(slice) form
	Line, Col int
}

func (s *DeferStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *DeferStmt) stmtNode()       {}

type IfStmt struct {
	Cond      Expr
	Then      *BlockStmt
	Else      Stmt // *BlockStmt or *IfStmt or nil
	Line, Col int
}

func (s *IfStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *IfStmt) stmtNode()       {}

type WhileStmt struct {
	Cond      Expr
	Body      *BlockStmt
	Line, Col int
}

func (s *WhileStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *WhileStmt) stmtNode()       {}

type ForStmt struct {
	Init      Stmt // VarDecl or ExprStmt or nil
	Cond      Expr
	Post      Expr
	Body      *BlockStmt
	Line, Col int
}

func (s *ForStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *ForStmt) stmtNode()       {}

type BreakStmt struct{ Line, Col int }

func (s *BreakStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *BreakStmt) stmtNode()       {}

type ContinueStmt struct{ Line, Col int }

func (s *ContinueStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *ContinueStmt) stmtNode()       {}

type AssignStmt struct {
	// Lhss holds one or more left-hand sides (multi-assign from multi-return call).
	Lhss []Expr
	// Lhs is Lhss[0] when single (compat)
	Lhs       Expr
	Op        token.Kind // Assign, PlusEq, Define (:=)
	Rhs       Expr
	Define    bool // true for :=
	Line, Col int
}

func (s *AssignStmt) Pos() (int, int) { return s.Line, s.Col }
func (s *AssignStmt) stmtNode()       {}

// ---- Expressions ----

type Expr interface {
	Node
	exprNode()
}

type Ident struct {
	Name      string
	Line, Col int
}

func (e *Ident) Pos() (int, int) { return e.Line, e.Col }
func (e *Ident) exprNode()       {}

type BasicLit struct {
	Kind  token.Kind // Int, String, Char, True, False, Null
	Value string
	// StrIndex is the index into Checker.Strings for string lits (−1 if unset).
	// Assigned once during typecheck; codegen uses it so emit order need not match.
	StrIndex  int
	Line, Col int
}

func (e *BasicLit) Pos() (int, int) { return e.Line, e.Col }
func (e *BasicLit) exprNode()       {}

type UnaryExpr struct {
	Op        token.Kind
	X         Expr
	Line, Col int
}

func (e *UnaryExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *UnaryExpr) exprNode()       {}

type BinaryExpr struct {
	Op        token.Kind
	X, Y      Expr
	Line, Col int
}

func (e *BinaryExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *BinaryExpr) exprNode()       {}

type CallExpr struct {
	Fun       Expr
	Args      []Expr
	Line, Col int
}

func (e *CallExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *CallExpr) exprNode()       {}

type IndexExpr struct {
	X         Expr
	Index     Expr
	Line, Col int
}

func (e *IndexExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *IndexExpr) exprNode()       {}

// SliceExpr is s[low:high] (either bound optional; missing = 0 or len).
type SliceExpr struct {
	X         Expr
	Low       Expr // may be nil
	High      Expr // may be nil
	Line, Col int
}

func (e *SliceExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *SliceExpr) exprNode()       {}

// MakeExpr is make([]T, len) or make([]T, len, cap).
type MakeExpr struct {
	Type      TypeExpr
	Len       Expr
	Cap       Expr // nil → cap = len
	Line, Col int
}

func (e *MakeExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *MakeExpr) exprNode()       {}

// AppendExpr is append(slice, elems...).
type AppendExpr struct {
	Slice     Expr
	Elems     []Expr
	Line, Col int
}

func (e *AppendExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *AppendExpr) exprNode()       {}

// LenExpr is len(x).
type LenExpr struct {
	X         Expr
	Line, Col int
}

func (e *LenExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *LenExpr) exprNode()       {}

// CapExpr is cap(x).
type CapExpr struct {
	X         Expr
	Line, Col int
}

func (e *CapExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *CapExpr) exprNode()       {}

// CopyExpr is copy(dst, src) -> u64.
type CopyExpr struct {
	Dst, Src  Expr
	Line, Col int
}

func (e *CopyExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *CopyExpr) exprNode()       {}

// FreeExpr is free(x) for owning slices (statement-like expression).
type FreeExpr struct {
	X         Expr
	Line, Col int
}

func (e *FreeExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *FreeExpr) exprNode()       {}

type SelectorExpr struct {
	X         Expr
	Sel       string
	Line, Col int
}

func (e *SelectorExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *SelectorExpr) exprNode()       {}

type CastExpr struct {
	Type      TypeExpr
	X         Expr
	Line, Col int
}

func (e *CastExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *CastExpr) exprNode()       {}

type SizeofExpr struct {
	Type      TypeExpr
	Line, Col int
}

func (e *SizeofExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *SizeofExpr) exprNode()       {}

type ParenExpr struct {
	X         Expr
	Line, Col int
}

func (e *ParenExpr) Pos() (int, int) { return e.Line, e.Col }
func (e *ParenExpr) exprNode()       {}

// AddrOf: &expr
type AddrOf struct {
	X         Expr
	Line, Col int
}

func (e *AddrOf) Pos() (int, int) { return e.Line, e.Col }
func (e *AddrOf) exprNode()       {}

// StarExpr: *expr (dereference) - also used as type, but as expr it's unary *
// We use UnaryExpr with Star for deref.

// CompositeLit for struct/array: Type { a, b } or { .field = v }
type CompositeLit struct {
	Type      TypeExpr // optional
	Elts      []Expr
	Line, Col int
}

func (e *CompositeLit) Pos() (int, int) { return e.Line, e.Col }
func (e *CompositeLit) exprNode()       {}
