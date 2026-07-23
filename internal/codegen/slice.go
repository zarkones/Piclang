package codegen

import (
	"github.com/piclang/piclang/internal/ast"
	"github.com/piclang/piclang/internal/encode"
	"github.com/piclang/piclang/internal/types"
)

// Slice value convention after emitExpr / returns:
//
//	RAX = ptr
//	RDX = len
//	R8  = cap_field (capacity | OWN bit in high bit)

func (g *Gen) sliceElemSize(t types.Type) int64 {
	if el := types.SliceElem(t); el != nil {
		if sz := el.Size(); sz > 0 {
			return sz
		}
	}
	return 1
}

func (g *Gen) storeSliceLocal(off int32) {
	g.buf.MovMRDisp(encode.RBP, off, encode.RAX)
	g.buf.MovMRDisp(encode.RBP, off+8, encode.RDX)
	g.buf.MovMRDisp(encode.RBP, off+16, encode.R8)
}

func (g *Gen) loadSliceLocal(off int32) {
	g.buf.MovRMDisp(encode.RAX, encode.RBP, off)
	g.buf.MovRMDisp(encode.RDX, encode.RBP, off+8)
	g.buf.MovRMDisp(encode.R8, encode.RBP, off+16)
}

func (g *Gen) pushSliceHeader() {
	// push order: ptr, len, cap -> top = cap
	g.buf.Push(encode.RAX)
	g.buf.Push(encode.RDX)
	g.buf.Push(encode.R8)
}

func (g *Gen) popSliceHeader() {
	g.buf.Pop(encode.R8)
	g.buf.Pop(encode.RDX)
	g.buf.Pop(encode.RAX)
}

func (g *Gen) emitRuntimeAlloc() {
	// size in RAX -> ptr in RAX
	g.buf.MovRR(encode.RCX, encode.RAX)
	g.buf.SubRI(encode.RSP, 0x20)
	at := g.buf.CallRel32()
	g.calls = append(g.calls, relPatch{at: at, name: "runtime_Alloc"})
	g.buf.AddRI(encode.RSP, 0x20)
}

func (g *Gen) emitRuntimeFreeRCX() {
	g.buf.SubRI(encode.RSP, 0x20)
	at := g.buf.CallRel32()
	g.calls = append(g.calls, relPatch{at: at, name: "runtime_Free"})
	g.buf.AddRI(encode.RSP, 0x20)
}

func (g *Gen) emitMemsetZero(ptrReg, nReg int) {
	// zero nReg bytes at ptrReg; clobbers rax, rdi, rcx, rsi-ish
	g.buf.MovRR(encode.RDI, ptrReg)
	g.buf.MovRR(encode.RCX, nReg)
	g.buf.XorRR(encode.RAX, encode.RAX)
	loop := g.buf.Len()
	g.buf.TestRR(encode.RCX, encode.RCX)
	jz := g.buf.JccRel32(encode.CC_E)
	g.buf.Mov8MR(encode.RDI, encode.RAX)
	g.buf.AddRI(encode.RDI, 1)
	g.buf.SubRI(encode.RCX, 1)
	jmp := g.buf.JmpRel32()
	g.buf.PatchRel32(jmp, loop)
	g.buf.PatchRel32(jz, g.buf.Len())
}

func (g *Gen) emitMemcpyBytes() {
	// RSI=src, RDI=dst, RCX=n; preserves nothing except uses r11 for base restore of rdi
	g.buf.MovRR(encode.R11, encode.RDI)
	loop := g.buf.Len()
	g.buf.TestRR(encode.RCX, encode.RCX)
	jz := g.buf.JccRel32(encode.CC_E)
	g.buf.Movzx8RM(encode.RAX, encode.RSI)
	g.buf.Mov8MR(encode.RDI, encode.RAX)
	g.buf.AddRI(encode.RSI, 1)
	g.buf.AddRI(encode.RDI, 1)
	g.buf.SubRI(encode.RCX, 1)
	jmp := g.buf.JmpRel32()
	g.buf.PatchRel32(jmp, loop)
	g.buf.PatchRel32(jz, g.buf.Len())
	g.buf.MovRR(encode.RDI, encode.R11)
}

func (g *Gen) emitMake(e *ast.MakeExpr) {
	ty := g.chk.TypeOf(e)
	elemSz := g.sliceElemSize(ty)

	g.emitExpr(e.Len)
	g.buf.Push(encode.RAX) // len
	if e.Cap != nil {
		g.emitExpr(e.Cap)
	} else {
		g.buf.MovRMDisp(encode.RAX, encode.RSP, 0) // cap = len
	}
	// rax = cap, [rsp]=len
	g.buf.Push(encode.RAX) // cap

	// bytes = cap * elemSz; at least 1 if we want non-null for cap>0 - use 0 alloc as null ptr ok
	g.buf.MovRR(encode.RCX, encode.RAX) // cap
	g.buf.MovRI(encode.RAX, uint64(elemSz))
	g.buf.ImulRR(encode.RAX, encode.RCX)

	// if bytes == 0: ptr = null, skip alloc
	g.buf.TestRR(encode.RAX, encode.RAX)
	jz0 := g.buf.JccRel32(encode.CC_E)
	g.buf.Push(encode.RAX) // bytes
	g.emitRuntimeAlloc()
	g.buf.MovRR(encode.RDI, encode.RAX)
	g.buf.Pop(encode.RCX) // bytes
	g.buf.Push(encode.RDI)
	g.emitMemsetZero(encode.RDI, encode.RCX)
	g.buf.Pop(encode.RAX) // ptr
	jmpHdr := g.buf.JmpRel32()

	g.buf.PatchRel32(jz0, g.buf.Len())
	g.buf.XorRR(encode.RAX, encode.RAX) // null ptr

	g.buf.PatchRel32(jmpHdr, g.buf.Len())
	g.buf.Pop(encode.R11) // cap
	g.buf.Pop(encode.RDX) // len
	// R8 = pack(cap, owns=true)
	g.buf.MovRR(encode.R8, encode.R11)
	g.buf.MovRI(encode.R9, types.SliceOwnBit)
	g.buf.OrRR(encode.R8, encode.R9)
}

func (g *Gen) emitLen(e *ast.LenExpr) {
	xt := g.chk.TypeOf(e.X)
	if types.IsSlice(xt) {
		g.emitExpr(e.X)
		g.buf.MovRR(encode.RAX, encode.RDX)
		return
	}
	if a, ok := xt.(*types.ArrayType); ok {
		g.buf.MovRI(encode.RAX, uint64(a.Len))
		return
	}
	g.buf.XorRR(encode.RAX, encode.RAX)
}

func (g *Gen) emitCap(e *ast.CapExpr) {
	g.emitExpr(e.X)
	g.buf.MovRR(encode.RAX, encode.R8)
	g.buf.MovRI(encode.R9, types.SliceCapMask)
	g.buf.AndRR(encode.RAX, encode.R9)
}

func (g *Gen) emitFreeSlice(e *ast.FreeExpr) {
	g.emitExpr(e.X)
	// if (cap_field & OWN) && ptr != null -> Free(ptr)
	g.buf.MovRR(encode.R11, encode.R8)
	g.buf.MovRI(encode.R9, types.SliceOwnBit)
	g.buf.AndRR(encode.R11, encode.R9)
	g.buf.TestRR(encode.R11, encode.R11)
	jz := g.buf.JccRel32(encode.CC_E)
	g.buf.TestRR(encode.RAX, encode.RAX)
	jz2 := g.buf.JccRel32(encode.CC_E)
	g.buf.MovRR(encode.RCX, encode.RAX)
	g.emitRuntimeFreeRCX()
	g.buf.PatchRel32(jz, g.buf.Len())
	g.buf.PatchRel32(jz2, g.buf.Len())
	g.buf.XorRR(encode.RAX, encode.RAX)
	g.buf.XorRR(encode.RDX, encode.RDX)
	g.buf.XorRR(encode.R8, encode.R8)
}

func (g *Gen) emitSliceExpr(e *ast.SliceExpr) {
	xt := g.chk.TypeOf(e.X)
	elemSz := g.sliceElemSize(xt)

	g.emitExpr(e.X)
	g.pushSliceHeader()

	if e.Low != nil {
		g.emitExpr(e.Low)
	} else {
		g.buf.XorRR(encode.RAX, encode.RAX)
	}
	g.buf.Push(encode.RAX) // low

	if e.High != nil {
		g.emitExpr(e.High)
	} else {
		// default high = len; stack: low, cap, len, ptr
		g.buf.MovRMDisp(encode.RAX, encode.RSP, 16)
	}
	// rax = high
	g.buf.Pop(encode.R10) // low
	g.buf.Pop(encode.R8)  // old cap_field
	g.buf.Pop(encode.RDX) // old len
	g.buf.Pop(encode.R11) // old ptr

	// new_len = high - low
	g.buf.MovRR(encode.RDX, encode.RAX) // high
	g.buf.SubRR(encode.RDX, encode.R10)

	// new_ptr = old_ptr + low * elemSz
	g.buf.MovRR(encode.RAX, encode.R11)
	g.buf.MovRR(encode.RCX, encode.R10)
	if elemSz != 1 {
		g.buf.MovRI(encode.R9, uint64(elemSz))
		g.buf.ImulRR(encode.RCX, encode.R9)
	}
	g.buf.AddRR(encode.RAX, encode.RCX)

	// new_cap = (old_cap & MASK) - low; owns=false
	g.buf.MovRI(encode.R9, types.SliceCapMask)
	g.buf.AndRR(encode.R8, encode.R9)
	g.buf.SubRR(encode.R8, encode.R10)
}

func (g *Gen) emitSliceIndexLoad(e *ast.IndexExpr) {
	xt := g.chk.TypeOf(e.X)
	elemSz := g.sliceElemSize(xt)
	elem := types.SliceElem(xt)
	g.emitExpr(e.X)
	g.pushSliceHeader()
	g.emitExpr(e.Index)
	g.buf.MovRR(encode.RCX, encode.RAX)
	g.popSliceHeader()
	if elemSz != 1 {
		g.buf.MovRI(encode.R11, uint64(elemSz))
		g.buf.ImulRR(encode.RCX, encode.R11)
	}
	g.buf.AddRR(encode.RAX, encode.RCX)
	sz := int64(8)
	if elem != nil {
		sz = elem.Size()
	}
	g.loadAt(encode.RAX, sz)
}

func (g *Gen) emitSliceIndexAddr(e *ast.IndexExpr) {
	xt := g.chk.TypeOf(e.X)
	elemSz := g.sliceElemSize(xt)
	g.emitExpr(e.X)
	g.pushSliceHeader()
	g.emitExpr(e.Index)
	g.buf.MovRR(encode.RCX, encode.RAX)
	g.popSliceHeader()
	if elemSz != 1 {
		g.buf.MovRI(encode.R11, uint64(elemSz))
		g.buf.ImulRR(encode.RCX, encode.R11)
	}
	g.buf.AddRR(encode.RAX, encode.RCX)
}

// emitAppend implements s = append(s, e0, e1, ...) with owns-aware grow.
func (g *Gen) emitAppend(e *ast.AppendExpr) {
	st := g.chk.TypeOf(e.Slice)
	elemSz := g.sliceElemSize(st)
	nAdd := len(e.Elems)
	if nAdd == 0 {
		g.emitExpr(e.Slice)
		return
	}

	// --- evaluate everything into a linear stack frame ---
	// Push: slice.ptr, slice.len, slice.cap, elem0, elem1, ...
	g.emitExpr(e.Slice)
	g.buf.Push(encode.RAX)
	g.buf.Push(encode.RDX)
	g.buf.Push(encode.R8)
	for _, el := range e.Elems {
		g.emitExpr(el)
		g.buf.Push(encode.RAX)
	}
	// rsp+0 = last elem, …, rsp+8*(nAdd-1)=elem0, +8*nAdd=cap, +8=nAdd+1 len, +8*nAdd+2 ptr
	// Use: base = nAdd*8
	b := int32(8 * nAdd)

	// Load header into r12/r13/r14-ish - use r11,r10,r9 carefully; stick to stack temps.
	// old_ptr, old_len, cap_field at b+16, b+8, b
	g.buf.MovRMDisp(encode.RSI, encode.RSP, b+16) // old_ptr (will use as src)
	g.buf.MovRMDisp(encode.RDX, encode.RSP, b+8)  // old_len
	g.buf.MovRMDisp(encode.R8, encode.RSP, b)     // cap_field

	g.buf.MovRR(encode.R9, encode.R8)
	g.buf.MovRI(encode.RCX, types.SliceCapMask)
	g.buf.AndRR(encode.R9, encode.RCX) // old_cap
	g.buf.MovRR(encode.R10, encode.R8)
	g.buf.MovRI(encode.RCX, types.SliceOwnBit)
	g.buf.AndRR(encode.R10, encode.RCX) // owns

	g.buf.MovRR(encode.R11, encode.RDX)
	g.buf.AddRI(encode.R11, int32(nAdd)) // new_len

	// new_cap = old_cap; if new_len > old_cap { new_cap = max(2*old_cap, new_len); if 0 {1} }
	g.buf.MovRR(encode.RCX, encode.R9)
	g.buf.CmpRR(encode.R11, encode.R9)
	jFit := g.buf.JccRel32(encode.CC_BE)
	g.buf.MovRR(encode.RCX, encode.R9)
	g.buf.AddRR(encode.RCX, encode.R9)
	g.buf.CmpRR(encode.RCX, encode.R11)
	jOk := g.buf.JccRel32(encode.CC_AE)
	g.buf.MovRR(encode.RCX, encode.R11)
	g.buf.PatchRel32(jOk, g.buf.Len())
	g.buf.TestRR(encode.RCX, encode.RCX)
	jNz := g.buf.JccRel32(encode.CC_NE)
	g.buf.MovRI32(encode.RCX, 1)
	g.buf.PatchRel32(jNz, g.buf.Len())
	g.buf.PatchRel32(jFit, g.buf.Len())
	// rcx = new_cap

	// if new_cap == old_cap && ptr != 0 -> in-place
	g.buf.CmpRR(encode.RCX, encode.R9)
	jGrow := g.buf.JccRel32(encode.CC_NE)
	g.buf.TestRR(encode.RSI, encode.RSI)
	jGrow2 := g.buf.JccRel32(encode.CC_E)

	// ===== IN-PLACE =====
	// dest = old_ptr + old_len*elemSz
	g.buf.MovRR(encode.RDI, encode.RSI)
	g.buf.MovRR(encode.RAX, encode.RDX)
	if elemSz != 1 {
		g.buf.MovRI(encode.R9, uint64(elemSz))
		g.buf.ImulRR(encode.RAX, encode.R9)
	}
	g.buf.AddRR(encode.RDI, encode.RAX)
	// elems still at top of stack (base 0); header under them at b
	g.writeElemsFromStack(nAdd, 0, elemSz)
	// result: ptr=rsi, len=new_len, cap=old cap_field (same owns)
	g.buf.MovRR(encode.RAX, encode.RSI)
	g.buf.MovRR(encode.RDX, encode.R11)
	// R8 still old cap_field
	g.buf.AddRI(encode.RSP, int32(8*nAdd+24))
	jmpEnd := g.buf.JmpRel32()

	// ===== GROW =====
	g.buf.PatchRel32(jGrow, g.buf.Len())
	g.buf.PatchRel32(jGrow2, g.buf.Len())

	// save new_cap, new_len, old_len, old_ptr, owns on stack above elems
	g.buf.Push(encode.RSI) // old_ptr
	g.buf.Push(encode.RDX) // old_len
	g.buf.Push(encode.R11) // new_len
	g.buf.Push(encode.RCX) // new_cap
	g.buf.Push(encode.R10) // owns

	// alloc
	g.buf.MovRR(encode.RAX, encode.RCX)
	if elemSz != 1 {
		g.buf.MovRI(encode.R9, uint64(elemSz))
		g.buf.ImulRR(encode.RAX, encode.R9)
	}
	g.emitRuntimeAlloc()
	g.buf.MovRR(encode.RDI, encode.RAX) // new_ptr
	g.buf.Push(encode.RDI)

	// copy old_len * elemSz from old_ptr
	// stack: new_ptr, owns, ncap, nlen, olen, optr, elems..., hdr(3)
	// 0 nptr, 8 owns, 16 ncap, 24 nlen, 32 olen, 40 optr
	g.buf.MovRMDisp(encode.RSI, encode.RSP, 40)
	g.buf.MovRMDisp(encode.RCX, encode.RSP, 32)
	if elemSz != 1 {
		g.buf.MovRI(encode.R9, uint64(elemSz))
		g.buf.ImulRR(encode.RCX, encode.R9)
	}
	g.emitMemcpyBytes()

	// free old if owns
	g.buf.MovRMDisp(encode.R11, encode.RSP, 8)
	g.buf.TestRR(encode.R11, encode.R11)
	jzF := g.buf.JccRel32(encode.CC_E)
	g.buf.MovRMDisp(encode.RCX, encode.RSP, 40)
	g.buf.TestRR(encode.RCX, encode.RCX)
	jzF2 := g.buf.JccRel32(encode.CC_E)
	g.emitRuntimeFreeRCX()
	g.buf.PatchRel32(jzF, g.buf.Len())
	g.buf.PatchRel32(jzF2, g.buf.Len())

	// write new elems at new_ptr + old_len*esz
	g.buf.MovRMDisp(encode.RDI, encode.RSP, 0) // new_ptr
	g.buf.MovRMDisp(encode.RAX, encode.RSP, 32)
	if elemSz != 1 {
		g.buf.MovRI(encode.R9, uint64(elemSz))
		g.buf.ImulRR(encode.RAX, encode.R9)
	}
	g.buf.AddRR(encode.RDI, encode.RAX)
	// elems under 6 pushes: at rsp+48
	g.writeElemsFromStack(nAdd, 48, elemSz)

	// result header
	g.buf.MovRMDisp(encode.RAX, encode.RSP, 0)  // new_ptr
	g.buf.MovRMDisp(encode.RDX, encode.RSP, 24) // new_len
	g.buf.MovRMDisp(encode.R8, encode.RSP, 16)  // new_cap
	g.buf.MovRI(encode.R9, types.SliceOwnBit)
	g.buf.OrRR(encode.R8, encode.R9) // owns=true

	// drop: 6 saved + nAdd elems + 3 header
	g.buf.AddRI(encode.RSP, int32(8*(6+nAdd+3)))
	g.buf.PatchRel32(jmpEnd, g.buf.Len())
}

// writeElemsFromStack writes nAdd element values from stack onto [rdi], advancing rdi.
// Element i (0-based LTR) is at rsp+base+8*(nAdd-1-i).
func (g *Gen) writeElemsFromStack(nAdd int, base int32, elemSz int64) {
	for i := 0; i < nAdd; i++ {
		off := base + int32(8*(nAdd-1-i))
		g.buf.MovRMDisp(encode.RCX, encode.RSP, off)
		switch elemSz {
		case 1:
			g.buf.Mov8MR(encode.RDI, encode.RCX)
		case 2:
			g.buf.Mov16MR(encode.RDI, encode.RCX)
		case 4:
			g.buf.Mov32MR(encode.RDI, encode.RCX)
		default:
			g.buf.MovMR(encode.RDI, encode.RCX)
		}
		g.buf.AddRI(encode.RDI, int32(elemSz))
	}
}

func (g *Gen) emitCopy(e *ast.CopyExpr) {
	// copy(dst, src) -> n = min(len(dst), len(src)); memcpy; return n
	elemSz := g.sliceElemSize(g.chk.TypeOf(e.Dst))

	g.emitExpr(e.Dst)
	g.pushSliceHeader()
	g.emitExpr(e.Src)
	// rax,rdx,r8 = src; stack has dst cap,len,ptr
	g.buf.MovRR(encode.RSI, encode.RAX) // src ptr
	g.buf.MovRR(encode.R9, encode.RDX)  // src len
	g.buf.Pop(encode.R11)               // dst cap discard
	g.buf.Pop(encode.R10)               // dst len
	g.buf.Pop(encode.RDI)               // dst ptr

	// n = min(dstlen, srclen)
	g.buf.MovRR(encode.RCX, encode.R10)
	g.buf.CmpRR(encode.RCX, encode.R9)
	jbe := g.buf.JccRel32(encode.CC_BE)
	g.buf.MovRR(encode.RCX, encode.R9)
	g.buf.PatchRel32(jbe, g.buf.Len())
	g.buf.Push(encode.RCX) // save n elements
	if elemSz != 1 {
		g.buf.MovRI(encode.RAX, uint64(elemSz))
		g.buf.ImulRR(encode.RCX, encode.RAX)
	}
	g.emitMemcpyBytes()
	g.buf.Pop(encode.RAX) // return element count
}

// OrRR missing? check encode
func (g *Gen) ensureOrRR() {}
