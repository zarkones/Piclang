package parser

import (
	"fmt"
	"strconv"

	"github.com/piclang/piclang/internal/ast"
	"github.com/piclang/piclang/internal/lexer"
	"github.com/piclang/piclang/internal/token"
)

// Parser builds an AST from tokens.
type Parser struct {
	l      *lexer.Lexer
	tok    token.Token
	peek   token.Token
	errors []string
}

// New creates a parser.
func New(l *lexer.Lexer) *Parser {
	p := &Parser{l: l}
	p.next()
	p.next()
	return p
}

// Errors returns parse errors.
func (p *Parser) Errors() []string {
	errs := append([]string{}, p.l.Errors()...)
	return append(errs, p.errors...)
}

func (p *Parser) next() {
	p.tok = p.peek
	p.peek = p.l.Next()
}

func (p *Parser) errorf(format string, args ...any) {
	msg := fmt.Sprintf("%d:%d: "+format, append([]any{p.tok.Line, p.tok.Column}, args...)...)
	p.errors = append(p.errors, msg)
}

func (p *Parser) expect(k token.Kind) token.Token {
	if p.tok.Kind != k {
		p.errorf("expected %s, got %s", k, p.tok.Kind)
	}
	t := p.tok
	p.next()
	return t
}

// ParseFile parses a full compilation unit.
func (p *Parser) ParseFile(path string) *ast.File {
	f := &ast.File{Path: path, Package: "main"}

	// package name  (optional; defaults to main)
	if p.tok.Kind == token.Package {
		p.next()
		name := p.expect(token.Ident)
		f.Package = name.Lit
		if p.tok.Kind == token.Semicolon {
			p.next()
		}
	}

	// import blocks (must precede other decls, like Go)
	for p.tok.Kind == token.Import {
		f.Imports = append(f.Imports, p.parseImport()...)
	}

	for p.tok.Kind != token.EOF {
		// ASI may insert bare ';' between top-level decls
		if p.tok.Kind == token.Semicolon {
			p.next()
			continue
		}
		if p.tok.Kind == token.Import {
			p.errorf("import must appear before other declarations")
			p.next()
			continue
		}
		if p.tok.Kind == token.Package {
			p.errorf("package clause must be first")
			p.next()
			continue
		}
		d := p.parseDecl()
		if d != nil {
			f.Decls = append(f.Decls, d)
		}
		if len(p.errors) > 50 {
			break
		}
	}
	return f
}

// parseImport handles:
//
//	import "path"
//	import alias "path"
//	import ( "a"; "b" )  or  import ( alias "a" \n "b" )
func (p *Parser) parseImport() []*ast.ImportSpec {
	p.expect(token.Import)
	var specs []*ast.ImportSpec
	if p.tok.Kind == token.LParen {
		p.next()
		for p.tok.Kind != token.RParen && p.tok.Kind != token.EOF {
			if p.tok.Kind == token.Semicolon {
				p.next()
				continue
			}
			specs = append(specs, p.parseImportSpec())
			if p.tok.Kind == token.Semicolon {
				p.next()
			}
		}
		p.expect(token.RParen)
		if p.tok.Kind == token.Semicolon {
			p.next()
		}
		return specs
	}
	specs = append(specs, p.parseImportSpec())
	if p.tok.Kind == token.Semicolon {
		p.next()
	}
	return specs
}

func (p *Parser) parseImportSpec() *ast.ImportSpec {
	line, col := p.tok.Line, p.tok.Column
	alias := ""
	// optional alias identifier before string
	if p.tok.Kind == token.Ident && p.peek.Kind == token.String {
		alias = p.tok.Lit
		p.next()
	}
	pathTok := p.expect(token.String)
	path := pathTok.Lit
	if alias == "" {
		alias = importDefaultAlias(path)
	}
	return &ast.ImportSpec{Alias: alias, Path: path, Line: line, Col: col}
}

func importDefaultAlias(path string) string {
	// last path element: "lib/pe" → "pe"
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

func (p *Parser) parseDecl() ast.Decl {
	switch p.tok.Kind {
	case token.Fn:
		return p.parseFunc()
	case token.Var, token.Const:
		return p.parseVarDecl(true)
	case token.Type:
		return p.parseTypeAlias()
	case token.Struct:
		return p.parseStruct()
	default:
		p.errorf("expected declaration, got %s", p.tok.Kind)
		p.next()
		return nil
	}
}

func (p *Parser) parseFunc() *ast.FuncDecl {
	line, col := p.tok.Line, p.tok.Column
	p.expect(token.Fn)
	name := p.expect(token.Ident)
	p.expect(token.LParen)
	var params []*ast.Field
	if p.tok.Kind != token.RParen {
		for {
			params = append(params, p.parseField())
			if p.tok.Kind != token.Comma {
				break
			}
			p.next()
		}
	}
	p.expect(token.RParen)
	var results []ast.TypeExpr
	var ret ast.TypeExpr
	if p.tok.Kind == token.Arrow {
		p.next()
		if p.tok.Kind == token.LParen {
			p.next()
			for p.tok.Kind != token.RParen && p.tok.Kind != token.EOF {
				results = append(results, p.parseType())
				if p.tok.Kind != token.Comma {
					break
				}
				p.next()
			}
			p.expect(token.RParen)
		} else {
			ret = p.parseType()
			results = []ast.TypeExpr{ret}
		}
	}
	if len(results) == 1 {
		ret = results[0]
	}
	body := p.parseBlock()
	return &ast.FuncDecl{
		Name: name.Lit, Params: params, Results: results, Ret: ret, Body: body,
		IsEntry: name.Lit == "main", Line: line, Col: col,
	}
}

func (p *Parser) parseField() *ast.Field {
	line, col := p.tok.Line, p.tok.Column
	name := p.expect(token.Ident)
	// allow name: Type or just Type for anon (we require name: Type)
	var typ ast.TypeExpr
	if p.tok.Kind == token.Colon {
		p.next()
		typ = p.parseType()
	} else {
		// bare type as param name? treat ident as type with empty name - disallow
		p.errorf("expected ':' after parameter name")
		typ = &ast.IdentType{Name: "u64", Line: line, Col: col}
	}
	return &ast.Field{Name: name.Lit, Type: typ, Line: line, Col: col}
}

func (p *Parser) parseVarDecl(global bool) *ast.VarDecl {
	line, col := p.tok.Line, p.tok.Column
	isConst := p.tok.Kind == token.Const
	p.next()
	name := p.expect(token.Ident)
	var typ ast.TypeExpr
	if p.tok.Kind == token.Colon {
		p.next()
		typ = p.parseType()
	}
	var val ast.Expr
	if p.tok.Kind == token.Assign {
		p.next()
		val = p.parseExpr()
	}
	if p.tok.Kind == token.Semicolon {
		p.next()
	}
	return &ast.VarDecl{
		Name: name.Lit, Type: typ, Value: val,
		IsGlobal: global, IsConst: isConst, Line: line, Col: col,
	}
}

func (p *Parser) parseTypeAlias() *ast.TypeAliasDecl {
	line, col := p.tok.Line, p.tok.Column
	p.expect(token.Type)
	name := p.expect(token.Ident)
	p.expect(token.Assign)
	typ := p.parseType()
	if p.tok.Kind == token.Semicolon {
		p.next()
	}
	return &ast.TypeAliasDecl{Name: name.Lit, Type: typ, Line: line, Col: col}
}

func (p *Parser) parseStruct() *ast.StructDecl {
	line, col := p.tok.Line, p.tok.Column
	p.expect(token.Struct)
	name := p.expect(token.Ident)
	p.expect(token.LBrace)
	var fields []*ast.Field
	for p.tok.Kind != token.RBrace && p.tok.Kind != token.EOF {
		fl, fc := p.tok.Line, p.tok.Column
		fname := p.expect(token.Ident)
		p.expect(token.Colon)
		ftyp := p.parseType()
		fields = append(fields, &ast.Field{Name: fname.Lit, Type: ftyp, Line: fl, Col: fc})
		if p.tok.Kind == token.Comma || p.tok.Kind == token.Semicolon {
			p.next()
		}
	}
	p.expect(token.RBrace)
	return &ast.StructDecl{Name: name.Lit, Fields: fields, Line: line, Col: col}
}

func (p *Parser) parseType() ast.TypeExpr {
	line, col := p.tok.Line, p.tok.Column
	// pointer: *T
	if p.tok.Kind == token.Star {
		p.next()
		return &ast.PtrType{Elem: p.parseType(), Line: line, Col: col}
	}
	// slice []T or array [N]T
	if p.tok.Kind == token.LBracket {
		p.next()
		if p.tok.Kind == token.RBracket {
			p.next()
			return &ast.SliceTypeExpr{Elem: p.parseType(), Line: line, Col: col}
		}
		n := p.parseExpr()
		p.expect(token.RBracket)
		return &ast.ArrayType{Len: n, Elem: p.parseType(), Line: line, Col: col}
	}
	// function type: fn(T, U) -> V  or  fn(name: T, U) -> V
	if p.tok.Kind == token.Fn {
		p.next()
		p.expect(token.LParen)
		var params []ast.TypeExpr
		if p.tok.Kind != token.RParen {
			for {
				// optional name:
				if p.tok.Kind == token.Ident && p.peek.Kind == token.Colon {
					p.next()
					p.next()
				}
				params = append(params, p.parseType())
				if p.tok.Kind != token.Comma {
					break
				}
				p.next()
			}
		}
		p.expect(token.RParen)
		var ret ast.TypeExpr
		if p.tok.Kind == token.Arrow {
			p.next()
			if p.tok.Kind == token.LParen {
				// fn(...) -> (T, U) - encode as first only in FuncType AST for now;
				// full multi on func types of variables is rare; parse into Ret via first
				// and store remaining via... skip: use single Tuple not in TypeExpr.
				// Parse all as sequential Qual - actually use IdentType wrapper.
				// Simpler: disallow multi-result on function pointer types in v1;
				// only allow on func decls. For pointer types keep single ret.
				p.next()
				ret = p.parseType()
				for p.tok.Kind == token.Comma {
					p.next()
					_ = p.parseType() // ignore extra for type literals in v1
				}
				p.expect(token.RParen)
			} else {
				ret = p.parseType()
			}
		}
		return &ast.FuncType{Params: params, Ret: ret, Line: line, Col: col}
	}
	// named or package.Type
	if p.tok.Kind == token.Ident {
		name := p.tok.Lit
		p.next()
		if p.tok.Kind == token.Dot {
			p.next()
			sel := p.expect(token.Ident)
			return &ast.QualType{Pkg: name, Name: sel.Lit, Line: line, Col: col}
		}
		return &ast.IdentType{Name: name, Line: line, Col: col}
	}
	p.errorf("expected type, got %s", p.tok.Kind)
	p.next()
	return &ast.IdentType{Name: "void", Line: line, Col: col}
}

func (p *Parser) parseBlock() *ast.BlockStmt {
	line, col := p.tok.Line, p.tok.Column
	p.expect(token.LBrace)
	var stmts []ast.Stmt
	for p.tok.Kind != token.RBrace && p.tok.Kind != token.EOF {
		if p.tok.Kind == token.Semicolon {
			p.next()
			continue
		}
		stmts = append(stmts, p.parseStmt())
	}
	p.expect(token.RBrace)
	return &ast.BlockStmt{Stmts: stmts, Line: line, Col: col}
}

func (p *Parser) parseStmt() ast.Stmt {
	switch p.tok.Kind {
	case token.Var, token.Const:
		return p.parseVarDecl(false)
	case token.Return:
		return p.parseReturn()
	case token.Defer:
		return p.parseDefer()
	case token.If:
		return p.parseIf()
	case token.While:
		return p.parseWhile()
	case token.For:
		return p.parseFor()
	case token.Break:
		s := &ast.BreakStmt{Line: p.tok.Line, Col: p.tok.Column}
		p.next()
		if p.tok.Kind == token.Semicolon {
			p.next()
		}
		return s
	case token.Continue:
		s := &ast.ContinueStmt{Line: p.tok.Line, Col: p.tok.Column}
		p.next()
		if p.tok.Kind == token.Semicolon {
			p.next()
		}
		return s
	case token.LBrace:
		return p.parseBlock()
	default:
		return p.parseSimpleStmt()
	}
}

func (p *Parser) parseReturn() *ast.ReturnStmt {
	line, col := p.tok.Line, p.tok.Column
	p.next()
	var results []ast.Expr
	if p.tok.Kind != token.Semicolon && p.tok.Kind != token.RBrace {
		results = append(results, p.parseExpr())
		for p.tok.Kind == token.Comma {
			p.next()
			results = append(results, p.parseExpr())
		}
	}
	if p.tok.Kind == token.Semicolon {
		p.next()
	}
	var val ast.Expr
	if len(results) == 1 {
		val = results[0]
	}
	return &ast.ReturnStmt{Results: results, Value: val, Line: line, Col: col}
}

func (p *Parser) parseDefer() *ast.DeferStmt {
	line, col := p.tok.Line, p.tok.Column
	p.expect(token.Defer)
	// Go: defer f(...); also allow defer free(s) for slices
	x := p.parseExpr()
	if fr, ok := x.(*ast.FreeExpr); ok {
		if p.tok.Kind == token.Semicolon {
			p.next()
		}
		return &ast.DeferStmt{Free: fr, Line: line, Col: col}
	}
	call, ok := x.(*ast.CallExpr)
	if !ok {
		if par, ok := x.(*ast.ParenExpr); ok {
			if fr, ok := par.X.(*ast.FreeExpr); ok {
				if p.tok.Kind == token.Semicolon {
					p.next()
				}
				return &ast.DeferStmt{Free: fr, Line: line, Col: col}
			}
			call, ok = par.X.(*ast.CallExpr)
		}
		if !ok {
			p.errorf("defer requires a function call or free(...)")
			call = &ast.CallExpr{Fun: x, Line: line, Col: col}
		}
	}
	if p.tok.Kind == token.Semicolon {
		p.next()
	}
	return &ast.DeferStmt{Call: call, Line: line, Col: col}
}

func (p *Parser) parseIf() *ast.IfStmt {
	line, col := p.tok.Line, p.tok.Column
	p.expect(token.If)
	cond := p.parseExpr()
	then := p.parseBlock()
	var els ast.Stmt
	if p.tok.Kind == token.Else {
		p.next()
		if p.tok.Kind == token.If {
			els = p.parseIf()
		} else {
			els = p.parseBlock()
		}
	}
	return &ast.IfStmt{Cond: cond, Then: then, Else: els, Line: line, Col: col}
}

func (p *Parser) parseWhile() *ast.WhileStmt {
	line, col := p.tok.Line, p.tok.Column
	p.expect(token.While)
	cond := p.parseExpr()
	body := p.parseBlock()
	return &ast.WhileStmt{Cond: cond, Body: body, Line: line, Col: col}
}

func (p *Parser) parseFor() *ast.ForStmt {
	line, col := p.tok.Line, p.tok.Column
	p.expect(token.For)
	// for init; cond; post { }  or  for cond { } (while-like)
	var init ast.Stmt
	var cond, post ast.Expr

	// Peek: if starts with var/const or looks like assignment chain with ;
	if p.tok.Kind == token.LBrace {
		// infinite for { }
		return &ast.ForStmt{Body: p.parseBlock(), Line: line, Col: col}
	}

	// Try parse init part
	if p.tok.Kind == token.Var || p.tok.Kind == token.Const {
		init = p.parseVarDecl(false)
		// parseVarDecl already ate optional ;
		if p.tok.Kind != token.Semicolon && p.tok.Kind != token.LBrace {
			// cond
			cond = p.parseExpr()
		}
		if p.tok.Kind == token.Semicolon {
			p.next()
			if p.tok.Kind != token.LBrace {
				post = p.parseExpr()
			}
		}
	} else {
		// expression or empty
		// Lookahead for classic for: expr; expr; expr
		e := p.parseExpr()
		if p.tok.Kind == token.Semicolon {
			// for e; cond; post
			init = &ast.ExprStmt{X: e, Line: line, Col: col}
			p.next()
			if p.tok.Kind != token.Semicolon && p.tok.Kind != token.LBrace {
				cond = p.parseExpr()
			}
			if p.tok.Kind == token.Semicolon {
				p.next()
				if p.tok.Kind != token.LBrace {
					post = p.parseExpr()
				}
			}
		} else if p.tok.Kind == token.Assign || p.tok.Kind == token.Define || p.tok.Kind == token.PlusEq ||
			p.tok.Kind == token.MinusEq || p.tok.Kind == token.StarEq || p.tok.Kind == token.SlashEq {
			op := p.tok.Kind
			p.next()
			rhs := p.parseExpr()
			as := &ast.AssignStmt{Lhs: e, Lhss: []ast.Expr{e}, Op: op, Rhs: rhs, Define: op == token.Define, Line: line, Col: col}
			if p.tok.Kind == token.Semicolon {
				init = as
				p.next()
				if p.tok.Kind != token.Semicolon && p.tok.Kind != token.LBrace {
					cond = p.parseExpr()
				}
				if p.tok.Kind == token.Semicolon {
					p.next()
					if p.tok.Kind != token.LBrace {
						post = p.parseExpr()
					}
				}
			} else {
				// treat as assign stmt before block - shouldn't happen in for header
				init = as
			}
		} else {
			// while-style: for cond {
			cond = e
		}
	}
	body := p.parseBlock()
	return &ast.ForStmt{Init: init, Cond: cond, Post: post, Body: body, Line: line, Col: col}
}

func (p *Parser) parseSimpleStmt() ast.Stmt {
	line, col := p.tok.Line, p.tok.Column
	// blank ident for multi-assign discard
	e := p.parseExprOrBlank()
	// multi-assign: a, b, c = f()  or  a, b := f()
	var lhss []ast.Expr
	lhss = append(lhss, e)
	for p.tok.Kind == token.Comma {
		p.next()
		lhss = append(lhss, p.parseExprOrBlank())
	}
	switch p.tok.Kind {
	case token.Assign, token.Define, token.PlusEq, token.MinusEq, token.StarEq, token.SlashEq:
		op := p.tok.Kind
		if (op == token.PlusEq || op == token.MinusEq || op == token.StarEq || op == token.SlashEq) && len(lhss) > 1 {
			p.errorf("compound assignment with multiple LHS not allowed")
		}
		p.next()
		rhs := p.parseExpr()
		if p.tok.Kind == token.Semicolon {
			p.next()
		}
		return &ast.AssignStmt{
			Lhss: lhss, Lhs: lhss[0], Op: op, Rhs: rhs,
			Define: op == token.Define, Line: line, Col: col,
		}
	default:
		if len(lhss) > 1 {
			p.errorf("expected assignment after multi-name list")
		}
		if p.tok.Kind == token.Semicolon {
			p.next()
		}
		return &ast.ExprStmt{X: e, Line: line, Col: col}
	}
}

// parseExprOrBlank parses an expression or the blank identifier _.
func (p *Parser) parseExprOrBlank() ast.Expr {
	if p.tok.Kind == token.Ident && p.tok.Lit == "_" {
		line, col := p.tok.Line, p.tok.Column
		p.next()
		return &ast.Ident{Name: "_", Line: line, Col: col}
	}
	return p.parseExpr()
}

// ---- Expressions (Pratt) ----

const (
	precLowest = iota
	precOr
	precAnd
	precBitOr
	precBitXor
	precBitAnd
	precEquality
	precCompare
	precShift
	precSum
	precProduct
	precUnary
	precCall
)

func precOf(k token.Kind) int {
	switch k {
	case token.OrOr:
		return precOr
	case token.AndAnd:
		return precAnd
	case token.Pipe:
		return precBitOr
	case token.Caret:
		return precBitXor
	case token.Amp:
		return precBitAnd
	case token.Eq, token.Neq:
		return precEquality
	case token.Lt, token.Gt, token.Le, token.Ge:
		return precCompare
	case token.Shl, token.Shr:
		return precShift
	case token.Plus, token.Minus:
		return precSum
	case token.Star, token.Slash, token.Percent:
		return precProduct
	case token.LParen, token.LBracket, token.Dot:
		return precCall
	}
	return precLowest
}

func (p *Parser) parseExpr() ast.Expr {
	return p.parseBinary(precLowest)
}

func (p *Parser) parseBinary(prec int) ast.Expr {
	left := p.parseUnary()
	for {
		pr := precOf(p.tok.Kind)
		if pr <= prec {
			break
		}
		// postfix handled separately
		if p.tok.Kind == token.LParen || p.tok.Kind == token.LBracket || p.tok.Kind == token.Dot {
			left = p.parsePostfix(left)
			continue
		}
		op := p.tok.Kind
		line, col := p.tok.Line, p.tok.Column
		p.next()
		right := p.parseBinary(pr)
		left = &ast.BinaryExpr{Op: op, X: left, Y: right, Line: line, Col: col}
	}
	// drain postfix after binary at same level
	for p.tok.Kind == token.LParen || p.tok.Kind == token.LBracket || p.tok.Kind == token.Dot {
		left = p.parsePostfix(left)
	}
	return left
}

func (p *Parser) parseUnary() ast.Expr {
	switch p.tok.Kind {
	case token.Bang, token.Minus, token.Tilde, token.Star, token.Amp, token.Plus:
		op := p.tok.Kind
		line, col := p.tok.Line, p.tok.Column
		p.next()
		x := p.parseUnary()
		if op == token.Amp {
			return &ast.AddrOf{X: x, Line: line, Col: col}
		}
		return &ast.UnaryExpr{Op: op, X: x, Line: line, Col: col}
	}
	return p.parsePrimary()
}

func (p *Parser) parsePostfix(left ast.Expr) ast.Expr {
	line, col := p.tok.Line, p.tok.Column
	switch p.tok.Kind {
	case token.LParen:
		p.next()
		var args []ast.Expr
		if p.tok.Kind != token.RParen {
			for {
				args = append(args, p.parseExpr())
				if p.tok.Kind != token.Comma {
					break
				}
				p.next()
			}
		}
		p.expect(token.RParen)
		return &ast.CallExpr{Fun: left, Args: args, Line: line, Col: col}
	case token.LBracket:
		p.next()
		// s[i], s[i:j], s[i:], s[:j], s[:]
		var low, high ast.Expr
		if p.tok.Kind != token.Colon && p.tok.Kind != token.RBracket {
			low = p.parseExpr()
		}
		if p.tok.Kind == token.Colon {
			p.next()
			if p.tok.Kind != token.RBracket {
				high = p.parseExpr()
			}
			p.expect(token.RBracket)
			return &ast.SliceExpr{X: left, Low: low, High: high, Line: line, Col: col}
		}
		if low == nil {
			p.errorf("missing index expression")
			low = &ast.BasicLit{Kind: token.Int, Value: "0", Line: line, Col: col}
		}
		p.expect(token.RBracket)
		return &ast.IndexExpr{X: left, Index: low, Line: line, Col: col}
	case token.Dot:
		p.next()
		sel := p.expect(token.Ident)
		return &ast.SelectorExpr{X: left, Sel: sel.Lit, Line: line, Col: col}
	}
	return left
}

func (p *Parser) parsePrimary() ast.Expr {
	line, col := p.tok.Line, p.tok.Column
	switch p.tok.Kind {
	case token.Ident:
		name := p.tok.Lit
		p.next()
		// cast[T](x) form (cast is also a keyword, but allow bare-ident form)
		if name == "cast" && p.tok.Kind == token.LBracket {
			p.next()
			typ := p.parseType()
			p.expect(token.RBracket)
			p.expect(token.LParen)
			x := p.parseExpr()
			p.expect(token.RParen)
			return &ast.CastExpr{Type: typ, X: x, Line: line, Col: col}
		}
		var e ast.Expr = &ast.Ident{Name: name, Line: line, Col: col}
		for p.tok.Kind == token.LParen || p.tok.Kind == token.LBracket || p.tok.Kind == token.Dot {
			e = p.parsePostfix(e)
		}
		return e
	case token.Int, token.String, token.Char:
		lit := &ast.BasicLit{Kind: p.tok.Kind, Value: p.tok.Lit, StrIndex: -1, Line: line, Col: col}
		p.next()
		return lit
	case token.True, token.False, token.Null:
		lit := &ast.BasicLit{Kind: p.tok.Kind, Value: p.tok.Lit, StrIndex: -1, Line: line, Col: col}
		p.next()
		return lit
	case token.Cast:
		p.next()
		// cast(T, expr) or cast[T](expr)
		if p.tok.Kind == token.LBracket {
			p.next()
			typ := p.parseType()
			p.expect(token.RBracket)
			p.expect(token.LParen)
			x := p.parseExpr()
			p.expect(token.RParen)
			return &ast.CastExpr{Type: typ, X: x, Line: line, Col: col}
		}
		p.expect(token.LParen)
		typ := p.parseType()
		p.expect(token.Comma)
		x := p.parseExpr()
		p.expect(token.RParen)
		return &ast.CastExpr{Type: typ, X: x, Line: line, Col: col}
	case token.Sizeof:
		p.next()
		p.expect(token.LParen)
		typ := p.parseType()
		p.expect(token.RParen)
		return &ast.SizeofExpr{Type: typ, Line: line, Col: col}
	case token.Make:
		p.next()
		p.expect(token.LParen)
		typ := p.parseType()
		p.expect(token.Comma)
		ln := p.parseExpr()
		var cp ast.Expr
		if p.tok.Kind == token.Comma {
			p.next()
			cp = p.parseExpr()
		}
		p.expect(token.RParen)
		return &ast.MakeExpr{Type: typ, Len: ln, Cap: cp, Line: line, Col: col}
	case token.Append:
		p.next()
		p.expect(token.LParen)
		sl := p.parseExpr()
		var elems []ast.Expr
		for p.tok.Kind == token.Comma {
			p.next()
			elems = append(elems, p.parseExpr())
		}
		p.expect(token.RParen)
		return &ast.AppendExpr{Slice: sl, Elems: elems, Line: line, Col: col}
	case token.Len:
		p.next()
		p.expect(token.LParen)
		x := p.parseExpr()
		p.expect(token.RParen)
		return &ast.LenExpr{X: x, Line: line, Col: col}
	case token.Cap:
		p.next()
		p.expect(token.LParen)
		x := p.parseExpr()
		p.expect(token.RParen)
		return &ast.CapExpr{X: x, Line: line, Col: col}
	case token.Copy:
		p.next()
		p.expect(token.LParen)
		dst := p.parseExpr()
		p.expect(token.Comma)
		src := p.parseExpr()
		p.expect(token.RParen)
		return &ast.CopyExpr{Dst: dst, Src: src, Line: line, Col: col}
	case token.Free:
		p.next()
		p.expect(token.LParen)
		x := p.parseExpr()
		p.expect(token.RParen)
		return &ast.FreeExpr{X: x, Line: line, Col: col}
	case token.LParen:
		p.next()
		// could be cast (T)(x) - we use cast keyword instead
		x := p.parseExpr()
		p.expect(token.RParen)
		e := &ast.ParenExpr{X: x, Line: line, Col: col}
		var out ast.Expr = e
		for p.tok.Kind == token.LParen || p.tok.Kind == token.LBracket || p.tok.Kind == token.Dot {
			out = p.parsePostfix(out)
		}
		return out
	default:
		p.errorf("unexpected token in expression: %s", p.tok.Kind)
		p.next()
		return &ast.BasicLit{Kind: token.Int, Value: "0", Line: line, Col: col}
	}
}

// ParseInt is a helper for integer literals.
func ParseInt(s string) (uint64, error) {
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}
