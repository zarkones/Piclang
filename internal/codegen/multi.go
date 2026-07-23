package codegen

import (
	"github.com/piclang/piclang/internal/ast"
	"github.com/piclang/piclang/internal/encode"
	"github.com/piclang/piclang/internal/sema"
	"github.com/piclang/piclang/internal/token"
	"github.com/piclang/piclang/internal/types"
)

// Multi-return ABI: up to 4 cells in RAX, RDX, R8, R9 (same order as slice return).
var multiRegs = []int{encode.RAX, encode.RDX, encode.R8, encode.R9}

func (g *Gen) pushResultCells(t types.Type) {
	if types.IsSlice(t) {
		g.buf.Push(encode.RAX)
		g.buf.Push(encode.RDX)
		g.buf.Push(encode.R8)
		return
	}
	g.buf.Push(encode.RAX)
}

// emitMultiReturn places return values into ABI regs then leaves.
func (g *Gen) emitMultiReturn(s *ast.ReturnStmt, ft *types.FuncType) {
	want := ft.ResultTypes()
	results := s.Results
	if len(results) == 0 && s.Value != nil {
		results = []ast.Expr{s.Value}
	}
	if len(want) == 0 {
		g.buf.XorRR(encode.RAX, encode.RAX)
		g.emitFuncLeave()
		return
	}
	if len(results) == 1 && !types.IsSlice(want[0]) && len(want) == 1 {
		g.emitExpr(results[0])
		g.emitFuncLeave()
		return
	}
	// Evaluate LTR, push cells, then load into regs
	var cellTypes []types.Type
	for i, r := range results {
		if i >= len(want) {
			break
		}
		g.emitExpr(r)
		// if result is slice type, emitExpr left rax,rdx,r8
		g.pushResultCells(want[i])
		n := types.ABICells(want[i])
		for c := 0; c < n; c++ {
			cellTypes = append(cellTypes, want[i]) // placeholder count
		}
	}
	total := types.TotalABICells(want)
	if total > 4 {
		total = 4
	}
	// stack has `total` cells, last on top; first result's first cell at bottom
	for i := 0; i < total; i++ {
		off := int32(8 * (total - 1 - i))
		g.buf.MovRMDisp(multiRegs[i], encode.RSP, off)
	}
	if total > 0 {
		g.buf.AddRI(encode.RSP, int32(8*total))
	}
	_ = cellTypes
	g.emitFuncLeave()
}

// emitMultiAssign stores multi-return results from ABI regs into LHS list.
func (g *Gen) emitMultiAssign(s *ast.AssignStmt) {
	lhss := s.Lhss
	if len(lhss) == 0 && s.Lhs != nil {
		lhss = []ast.Expr{s.Lhs}
	}
	g.emitExpr(s.Rhs)
	rt := g.chk.TypeOf(s.Rhs)
	var results []types.Type
	if tup, ok := rt.(*types.Tuple); ok {
		results = tup.Elems
	} else {
		results = []types.Type{rt}
	}

	total := types.TotalABICells(results)
	if total > 4 {
		total = 4
	}
	// Push RAX.. in order so cell 0 is at rsp+0 after reverse push
	for i := total - 1; i >= 0; i-- {
		g.buf.Push(multiRegs[i])
	}
	// After pushing R9..RAX reverse: top is RAX (first cell). Good: cell i at rsp+8*i

	cell := 0
	for i, lhs := range lhss {
		if i >= len(results) {
			break
		}
		n := types.ABICells(results[i])
		if id, ok := lhs.(*ast.Ident); ok && id.Name == "_" {
			cell += n
			continue
		}
		if n == 3 {
			g.buf.MovRMDisp(encode.RAX, encode.RSP, int32(8*cell))
			g.buf.MovRMDisp(encode.RDX, encode.RSP, int32(8*(cell+1)))
			g.buf.MovRMDisp(encode.R8, encode.RSP, int32(8*(cell+2)))
			if id, ok := lhs.(*ast.Ident); ok {
				if off, ok := g.locals[id.Name]; ok {
					g.storeSliceLocal(off)
				} else {
					g.storeTo(lhs)
				}
			} else {
				g.storeTo(lhs)
			}
		} else {
			g.buf.MovRMDisp(encode.RAX, encode.RSP, int32(8*cell))
			if id, ok := lhs.(*ast.Ident); ok {
				if off, ok := g.locals[id.Name]; ok {
					g.buf.MovMRDisp(encode.RBP, off, encode.RAX)
				} else {
					g.storeTo(lhs)
				}
			} else {
				g.storeTo(lhs)
			}
		}
		cell += n
	}
	if total > 0 {
		g.buf.AddRI(encode.RSP, int32(8*total))
	}
}

// fix emitFuncLeave to save multi regs
func (g *Gen) saveResultRegs() {
	// 4 slots starting at retSaveOff
	g.buf.MovMRDisp(encode.RBP, g.retSaveOff, encode.RAX)
	g.buf.MovMRDisp(encode.RBP, g.retSaveOff+8, encode.RDX)
	g.buf.MovMRDisp(encode.RBP, g.retSaveOff+16, encode.R8)
	g.buf.MovMRDisp(encode.RBP, g.retSaveOff+24, encode.R9)
}

func (g *Gen) restoreResultRegs() {
	g.buf.MovRMDisp(encode.RAX, encode.RBP, g.retSaveOff)
	g.buf.MovRMDisp(encode.RDX, encode.RBP, g.retSaveOff+8)
	g.buf.MovRMDisp(encode.R8, encode.RBP, g.retSaveOff+16)
	g.buf.MovRMDisp(encode.R9, encode.RBP, g.retSaveOff+24)
}

func (g *Gen) emitReturn(s *ast.ReturnStmt) {
	// determine expected results from current function
	// We don't have curFunc on Gen - use single-value path if one result expr
	results := s.Results
	if len(results) == 0 && s.Value != nil {
		results = []ast.Expr{s.Value}
	}
	if len(results) == 0 {
		g.buf.XorRR(encode.RAX, encode.RAX)
		g.emitFuncLeave()
		return
	}
	if len(results) == 1 {
		// Single expr: scalar, slice header, or multi-return passthrough (regs already set).
		g.emitExpr(results[0])
		g.emitFuncLeave()
		return
	}
	// multi: need types from expressions
	var want []types.Type
	for _, r := range results {
		want = append(want, g.chk.TypeOf(r))
	}
	// evaluate LTR and pack into ABI
	total := 0
	for _, t := range want {
		total += types.ABICells(t)
	}
	if total > 4 {
		total = 4
	}
	for i, r := range results {
		g.emitExpr(r)
		if i < len(want) {
			g.pushResultCells(want[i])
		}
	}
	for i := 0; i < total; i++ {
		off := int32(8 * (total - 1 - i))
		g.buf.MovRMDisp(multiRegs[i], encode.RSP, off)
	}
	if total > 0 {
		g.buf.AddRI(encode.RSP, int32(8*total))
	}
	g.emitFuncLeave()
}

func (g *Gen) ensureLocal(name string, t types.Type) {
	if _, ok := g.locals[name]; ok {
		return
	}
	sz := int64(8)
	if types.IsSlice(t) {
		sz = 24
	} else if t != nil && t.Size() > 0 {
		sz = t.Size()
		if sz < 8 {
			sz = 8
		}
		sz = alignUp(sz, 8)
	}
	g.localSize += int32(sz)
	// WARNING: frame already allocated - late locals use negative offsets further down
	// which may be outside the allocated frame. For := we need pre-scan.
	// Temporary: still record offset; may clobber. Better pre-scan := in allocLocals.
	g.locals[name] = -g.localSize
}

// pre-scan := declarations into locals before frame size fixed - call from allocLocals
func allocDefineLocals(g *Gen, s ast.Stmt) {
	switch s := s.(type) {
	case *ast.AssignStmt:
		if !s.Define {
			return
		}
		lhss := s.Lhss
		if len(lhss) == 0 && s.Lhs != nil {
			lhss = []ast.Expr{s.Lhs}
		}
		rt := g.chk.TypeOf(s.Rhs)
		var results []types.Type
		if tup, ok := rt.(*types.Tuple); ok {
			results = tup.Elems
		} else {
			results = []types.Type{rt}
		}
		for i, lhs := range lhss {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			var t types.Type = types.TyU64
			if i < len(results) {
				t = results[i]
			}
			if _, exists := g.locals[id.Name]; !exists {
				sz := int64(8)
				if types.IsSlice(t) {
					sz = 24
				}
				g.localSize += int32(sz)
				g.locals[id.Name] = -g.localSize
			}
		}
	case *ast.BlockStmt:
		for _, st := range s.Stmts {
			allocDefineLocals(g, st)
		}
	case *ast.IfStmt:
		allocDefineLocals(g, s.Then)
		if s.Else != nil {
			allocDefineLocals(g, s.Else)
		}
	case *ast.WhileStmt:
		allocDefineLocals(g, s.Body)
	case *ast.ForStmt:
		if s.Init != nil {
			allocDefineLocals(g, s.Init)
		}
		allocDefineLocals(g, s.Body)
	}
}

var _ = token.Assign
var _ = sema.LinkNameOf
