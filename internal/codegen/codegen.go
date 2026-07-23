package codegen

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/piclang/piclang/internal/ast"
	"github.com/piclang/piclang/internal/encode"
	"github.com/piclang/piclang/internal/parser"
	"github.com/piclang/piclang/internal/sema"
	"github.com/piclang/piclang/internal/token"
	"github.com/piclang/piclang/internal/types"
)

// Layout of the PIC blob (Stardust-inspired):
//
//	[ entry stub  ]  offset 0 - stack align, call main, restore, ret
//	[ .text       ]  user functions (+ optional random pad)
//	[ .rdata      ]  encrypted string literals
//	[ page align  ]  pad to 0x1000 if globals present
//	[ .global     ]  mutable globals
//	[ end marker  ]  tiny stub for __end()
//
// Raw shellcode has no PE/ELF section table. "Section names" are the logical
// region labels used in maps / tooling; with RandSections they are randomized
// each build, and padding/crypto varies so blobs are harder to fingerprint.

const pageSize = 0x1000

// Options controls codegen / layout anti-fingerprint behaviour.
type Options struct {
	// RandSections randomizes logical section names, inter-region padding, and
	// string crypto constants. Default is true (use DefaultOptions).
	RandSections bool
	// Seed selects the PRNG seed. Zero means a fresh crypto/rand seed each build.
	// Set a fixed seed only for reproducible test builds.
	Seed int64
}

// DefaultOptions returns production defaults (randomized sections on).
func DefaultOptions() Options {
	return Options{RandSections: true, Seed: 0}
}

// Result is the linked shellcode image.
type Result struct {
	Code       []byte
	EntryOff   int
	MainOff    int
	RDataOff   int
	GlobalOff  int
	EndOff     int
	Size       int
	MapSymbols map[string]int
	// SectionNames maps logical role -> emitted name (e.g. "rdata" -> ".k9m2xq").
	SectionNames map[string]string
	// SeedUsed is the PRNG seed applied when RandSections was on (0 if off).
	SeedUsed int64
}

// Gen is the code generator.
type Gen struct {
	chk  *sema.Checker
	opts Options
	rng  *rand.Rand
	buf  encode.Buf

	fnOff map[string]int
	fnEnd map[string]int
	// pending patches
	calls []relPatch // call to function by name
	// string LEA patches: patch disp at `at` to point to string index
	strRefs []strPatch
	// global LEA/access patches
	globRefs []globPatch
	// base/end refs
	baseRefs []int // LeaRIP patch sites for __base
	endRefs  []int

	// per-function state
	locals        map[string]int32 // name -> rbp offset (negative)
	localSize     int32
	breakStack    [][]int
	continueStack [][]int

	// Go-style defer: LIFO stack in the frame (args evaluated at defer time)
	hasDefer       bool
	deferNeedsFree bool  // true if any defer free(s) in this function
	deferCap       int   // max entries
	deferCountOff  int32 // [rbp+off] = u64 count
	deferArenaOff  int32 // [rbp+off] = first entry (entry i at + i*deferEntrySize)
	retSaveOff     int32 // save return value across defer runs

	// string index counter during emit (matches sema order)
	strIndex int
	// length of each string payload (including NUL), for unlock
	strLens []int
	// string crypto (randomized when RandSections)
	strK1, strK2 byte
	// internal unlock symbol name (randomized when RandSections)
	strUnlockName string

	// logical section display names
	secNames map[string]string

	// global layout
	globOrder []*sema.Object
	globOff   map[string]int64 // offset within .global section
	globSize  int64

	// rdata raw - encrypted string table (see emitStrUnlock)
	rdata []byte

	errors []string
}

// defer entry layout (48 bytes):
//
//	+0  fn ptr
//	+8  nargs
//	+16 arg0
//	+24 arg1
//	+32 arg2
//	+40 arg3
const deferEntrySize = 48

func (g *Gen) strKeystream(i int) byte {
	return byte(i*131+17) ^ g.strK1 ^ byte(i<<3) ^ g.strK2
}

func (g *Gen) encryptString(plain []byte) []byte {
	out := make([]byte, len(plain))
	for i, b := range plain {
		out[i] = b ^ g.strKeystream(i)
	}
	return out
}

func newRNG(seed int64) (*rand.Rand, int64) {
	if seed == 0 {
		var b [8]byte
		if _, err := crand.Read(b[:]); err == nil {
			seed = int64(binary.LittleEndian.Uint64(b[:]))
		} else {
			seed = time.Now().UnixNano()
		}
	}
	return rand.New(rand.NewSource(seed)), seed
}

// randomSectionName returns a PE/ELF-looking section name unique for this rng.
func randomSectionName(rng *rand.Rand, used map[string]bool) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// Prefer formats that look like toolchain section names but aren't stock Stardust labels.
	prefixes := []string{".", ".t$", ".r$", ".d$", ".x$", ".$"}
	for tries := 0; tries < 64; tries++ {
		pre := prefixes[rng.Intn(len(prefixes))]
		n := 4 + rng.Intn(5) // 4–8 random chars
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		name := pre + string(b)
		if !used[name] {
			used[name] = true
			return name
		}
	}
	// fallback
	name := fmt.Sprintf(".s_%08x", rng.Uint32())
	used[name] = true
	return name
}

func randomSymName(rng *rand.Rand, used map[string]bool) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for {
		n := 8 + rng.Intn(5)
		b := make([]byte, n)
		b[0] = alphabet[rng.Intn(26)]
		for i := 1; i < n; i++ {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		name := string(b)
		if !used[name] {
			used[name] = true
			return name
		}
	}
}

func randomPad(rng *rand.Rand, n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	for i := range b {
		// avoid long runs of 0x00 / 0xCC that look like padding signatures
		b[i] = byte(rng.Intn(256))
	}
	return b
}

type relPatch struct {
	at   int
	name string
}

type strPatch struct {
	at  int // disp32 location
	idx int
}

type globPatch struct {
	at   int
	name string
}

// Generate compiles the checked program to a PIC blob using DefaultOptions().
func Generate(chk *sema.Checker, _ *ast.File) (*Result, error) {
	return GenerateWith(chk, DefaultOptions())
}

// GenerateWith compiles with explicit options.
// The AST is taken from chk.FuncUnits (all packages already type-checked).
func GenerateWith(chk *sema.Checker, opts Options) (*Result, error) {
	g := &Gen{
		chk:           chk,
		opts:          opts,
		fnOff:         make(map[string]int),
		fnEnd:         make(map[string]int),
		globOff:       make(map[string]int64),
		secNames:      make(map[string]string),
		strUnlockName: "__str_unlock",
		strK1:         0xA5,
		strK2:         0x5C,
	}

	var seedUsed int64
	if opts.RandSections {
		g.rng, seedUsed = newRNG(opts.Seed)
		used := map[string]bool{}
		// Logical roles -> random section-style names (not fixed .text/.rdata/.global).
		g.secNames["entry"] = randomSectionName(g.rng, used)
		g.secNames["text"] = randomSectionName(g.rng, used)
		g.secNames["rdata"] = randomSectionName(g.rng, used)
		g.secNames["global"] = randomSectionName(g.rng, used)
		g.secNames["end"] = randomSectionName(g.rng, used)
		g.strUnlockName = randomSymName(g.rng, used)
		// Per-build string crypto constants (embedded as immediates in unlock).
		g.strK1 = byte(g.rng.Intn(256))
		g.strK2 = byte(g.rng.Intn(256))
		if g.strK1 == 0 && g.strK2 == 0 {
			g.strK1 = 0xA5
			g.strK2 = 0x5C
		}
	} else {
		g.secNames["entry"] = "_start"
		g.secNames["text"] = "_text"
		g.secNames["rdata"] = "_rdata"
		g.secNames["global"] = "_global"
		g.secNames["end"] = "_end"
	}

	// Layout globals (keyed by link name for multi-package)
	var goff int64
	for _, obj := range chk.Globals {
		if obj.IsConst && obj.HasConst {
			continue
		}
		sz := obj.Type.Size()
		al := obj.Type.Align()
		goff = alignUp(goff, al)
		link := sema.LinkNameOf(obj)
		g.globOff[link] = goff
		obj.Offset = goff
		goff += sz
		g.globOrder = append(g.globOrder, obj)
	}
	g.globSize = alignUp(goff, 8)

	// Build encrypted rdata: [u8 ready=0][encrypted bytes incl. NUL] per string.
	// Plaintext never appears in the blob (defeats `strings` / Ghidra string scanner).
	for _, s := range chk.Strings {
		enc := g.encryptString(s.Data)
		g.strLens = append(g.strLens, len(enc))
		g.rdata = append(g.rdata, 0) // ready flag: 0=encrypted, 1=unlocked in-place
		g.rdata = append(g.rdata, enc...)
	}

	// Emit entry stub at 0
	entryOff := 0
	g.emitEntryStub()

	// Shared string unlock helper (must be before user code that calls it)
	g.emitStrUnlock()

	// Emit all functions from all packages (deps first via FuncUnits order)
	for _, u := range chk.FuncUnits {
		g.emitFunc(u.Decl, u.Obj)
	}

	if len(g.errors) > 0 {
		return nil, fmt.Errorf("codegen: %s", g.errors[0])
	}

	textLen := g.buf.Len()

	// Optional junk between code and rdata (breaks fixed layout signatures)
	if opts.RandSections && g.rng != nil {
		padN := 16 + g.rng.Intn(113) // 16–128 bytes
		g.buf.Bytes = append(g.buf.Bytes, randomPad(g.rng, padN)...)
		textLen = g.buf.Len()
	}

	// Append rdata
	rdataOff := textLen
	g.buf.Bytes = append(g.buf.Bytes, g.rdata...)

	// Page-align globals if any
	globalOff := g.buf.Len()
	if g.globSize > 0 {
		for g.buf.Len()%pageSize != 0 {
			var fill byte
			if opts.RandSections && g.rng != nil {
				fill = byte(g.rng.Intn(256))
			}
			g.buf.Bytes = append(g.buf.Bytes, fill)
		}
		globalOff = g.buf.Len()
		// zero-initialized space; apply initializers for simple integer consts later
		g.buf.Bytes = append(g.buf.Bytes, make([]byte, int(g.globSize))...)
		// write global initializers if constant
		for _, obj := range g.globOrder {
			vd, ok := obj.Node.(*ast.VarDecl)
			if !ok || vd.Value == nil {
				continue
			}
			if v, ok := g.constUint(vd.Value); ok {
				off := globalOff + int(obj.Offset)
				sz := int(obj.Type.Size())
				putInt(g.buf.Bytes[off:], v, sz)
			}
		}
	}

	// End marker: LEA targets for __end() point at the byte after the image.
	// Emit a ret so a fall-through into the end is safe.
	g.buf.Ret()
	trueEnd := g.buf.Len()

	// Patch relative calls
	for _, p := range g.calls {
		tgt, ok := g.fnOff[p.name]
		if !ok {
			return nil, fmt.Errorf("undefined function %s at patch", p.name)
		}
		g.buf.PatchRel32(p.at, tgt)
	}

	// Patch string LEAs to encrypted blob entries (flag byte at start)
	strOffsets := make([]int, len(chk.Strings))
	off := rdataOff
	for i := range chk.Strings {
		strOffsets[i] = off
		off += 1 + g.strLens[i] // flag + payload
	}
	for _, p := range g.strRefs {
		g.buf.PatchRel32(p.at, strOffsets[p.idx])
	}

	// Patch global LEAs: globalAbs = globalOff + globOff[name]
	for _, p := range g.globRefs {
		abs := globalOff + int(g.globOff[p.name])
		g.buf.PatchRel32(p.at, abs)
	}

	// Patch __base LEAs to entry/base (offset 0)
	for _, at := range g.baseRefs {
		g.buf.PatchRel32(at, entryOff) // base of implant
	}
	// Patch __end LEAs to trueEnd
	for _, at := range g.endRefs {
		g.buf.PatchRel32(at, trueEnd)
	}

	syms := map[string]int{
		g.secNames["entry"]: entryOff,
		g.secNames["end"]:   trueEnd,
		g.secNames["rdata"]: rdataOff,
		g.secNames["text"]:  g.fnOff["main"], // code region marker near main
	}
	if g.globSize > 0 {
		syms[g.secNames["global"]] = globalOff
	}
	for name, o := range g.fnOff {
		syms[name] = o
	}

	return &Result{
		Code:         g.buf.Bytes,
		EntryOff:     entryOff,
		MainOff:      g.fnOff["main"],
		RDataOff:     rdataOff,
		GlobalOff:    globalOff,
		EndOff:       trueEnd,
		Size:         len(g.buf.Bytes),
		MapSymbols:   syms,
		SectionNames: g.secNames,
		SeedUsed:     seedUsed,
	}, nil
}

func (g *Gen) errf(format string, args ...any) {
	g.errors = append(g.errors, fmt.Sprintf(format, args...))
}

// Entry stub (Windows/Linux friendly stack alignment):
//
//	push rbp
//	mov  rbp, rsp
//	mov  rcx, rbp           ; stack_hint for main (frame; [rbp+8]=caller retaddr)
//	and  rsp, -16
//	sub  rsp, 0x20          ; shadow space for MS x64
//	call main
//	mov  rsp, rbp
//	pop  rbp
//	ret
func (g *Gen) emitEntryStub() {
	g.buf.Push(encode.RBP)
	g.buf.MovRR(encode.RBP, encode.RSP)
	// Pass frame pointer as first arg (RCX) so Linux implants can recover the
	// caller's return address via stack_hint[1] for link_map / PEB discovery.
	g.buf.MovRR(encode.RCX, encode.RBP)
	g.buf.AndRI(encode.RSP, -16)
	g.buf.SubRI(encode.RSP, 0x20)
	at := g.buf.CallRel32()
	g.calls = append(g.calls, relPatch{at: at, name: "main"})
	g.buf.MovRR(encode.RSP, encode.RBP)
	g.buf.Pop(encode.RBP)
	g.buf.Ret()
}

func (g *Gen) emitFunc(fn *ast.FuncDecl, obj *sema.Object) {
	name := obj.LinkName
	if name == "" {
		name = fn.Name
	}
	g.fnOff[name] = g.buf.Len()
	// Also register bare name for main package entry
	if fn.Name == "main" {
		g.fnOff["main"] = g.buf.Len()
	}
	g.locals = make(map[string]int32)
	g.localSize = 0
	g.breakStack = nil
	g.continueStack = nil
	g.hasDefer = false
	g.deferNeedsFree = false
	g.deferCap = 0
	g.deferCountOff = 0
	g.deferArenaOff = 0
	g.retSaveOff = 0
	if n, _ := countDefers(fn.Body, false); n > 0 {
		g.deferNeedsFree = hasDeferFree(fn.Body)
	}

	// Prologue
	g.buf.Push(encode.RBP)
	g.buf.MovRR(encode.RBP, encode.RSP)

	// Assign local slots for params + locals (pre-scan)
	// Params: MS x64 RCX,RDX,R8,R9 then stack
	// We spill params to stack slots for easy addressing
	if obj == nil {
		obj = g.chk.Funcs[name]
	}
	ft := obj.Type.(*types.FuncType)

	// First pass: allocate slots for parameters
	paramRegs := []int{encode.RCX, encode.RDX, encode.R8, encode.R9}
	type pinfo struct {
		name string
		off  int32
		reg  int // -1 if stack
	}
	var params []pinfo
	for i, p := range fn.Params {
		sz := int32(alignUp(ft.Params[i].Size(), 8))
		g.localSize += sz
		off := -g.localSize
		g.locals[p.Name] = off
		reg := -1
		if i < 4 {
			reg = paramRegs[i]
		}
		params = append(params, pinfo{p.Name, off, reg})
	}

	// Pre-allocate locals by walking body
	g.allocLocals(fn.Body)
	allocDefineLocals(g, fn.Body)

	// Defer arena (Go LIFO; capacity grows if defer appears in a loop)
	nDef, inLoop := countDefers(fn.Body, false)
	if nDef > 0 {
		g.hasDefer = true
		cap := nDef
		if inLoop {
			cap = nDef * 64
			if cap < 64 {
				cap = 64
			}
		}
		if cap > 512 {
			cap = 512 // hard cap to keep frames reasonable
		}
		g.deferCap = cap
		g.localSize += 8
		g.deferCountOff = -g.localSize
		g.localSize += 32 // 4 result regs for multi-return across defers
		g.retSaveOff = -g.localSize
		arenaBytes := int32(cap * deferEntrySize)
		g.localSize += arenaBytes
		g.deferArenaOff = -g.localSize // entry i at deferArenaOff + i*deferEntrySize
	}

	// Align frame to 16
	if g.localSize%16 != 0 {
		g.localSize += 16 - (g.localSize % 16)
	}
	// Extra 32 bytes shadow space for nested calls (MS x64)
	frame := g.localSize + 32
	if frame%16 != 0 {
		frame += 16 - (frame % 16)
	}
	if frame > 0 {
		g.buf.SubRI(encode.RSP, frame)
	}

	// Spill param regs to slots
	for i, p := range params {
		if p.reg >= 0 {
			g.buf.MovMRDisp(encode.RBP, p.off, p.reg)
		} else {
			// MS x64: after push rbp; mov rbp,rsp:
			//   [rbp+0]=saved rbp, [rbp+8]=ret, [rbp+16..+40]=32-byte shadow,
			//   [rbp+48]=5th arg, [rbp+56]=6th, ...
			srcOff := int32(48 + 8*(i-4))
			g.buf.MovRMDisp(encode.RAX, encode.RBP, srcOff)
			g.buf.MovMRDisp(encode.RBP, p.off, encode.RAX)
		}
	}

	// defer_count = 0
	if g.hasDefer {
		g.buf.XorRR(encode.RAX, encode.RAX)
		g.buf.MovMRDisp(encode.RBP, g.deferCountOff, encode.RAX)
	}

	g.emitBlock(fn.Body)

	// Epilogue (fallthrough): return 0 after defers
	g.buf.XorRR(encode.RAX, encode.RAX)
	g.emitFuncLeave()
	g.fnEnd[name] = g.buf.Len()
}

// countDefers returns the number of defer statements and whether any sit inside a loop.
func countDefers(s ast.Stmt, inLoop bool) (n int, anyInLoop bool) {
	if s == nil {
		return 0, false
	}
	switch s := s.(type) {
	case *ast.DeferStmt:
		if inLoop {
			return 1, true
		}
		return 1, false
	case *ast.BlockStmt:
		for _, st := range s.Stmts {
			a, b := countDefers(st, inLoop)
			n += a
			anyInLoop = anyInLoop || b
		}
	case *ast.IfStmt:
		a, b := countDefers(s.Then, inLoop)
		n += a
		anyInLoop = anyInLoop || b
		if s.Else != nil {
			a, b = countDefers(s.Else, inLoop)
			n += a
			anyInLoop = anyInLoop || b
		}
	case *ast.WhileStmt:
		a, b := countDefers(s.Body, true)
		n += a
		anyInLoop = anyInLoop || b || a > 0
	case *ast.ForStmt:
		if s.Init != nil {
			a, b := countDefers(s.Init, inLoop)
			n += a
			anyInLoop = anyInLoop || b
		}
		a, b := countDefers(s.Body, true)
		n += a
		anyInLoop = anyInLoop || b || a > 0
	}
	return n, anyInLoop
}

func hasDeferFree(s ast.Stmt) bool {
	if s == nil {
		return false
	}
	switch s := s.(type) {
	case *ast.DeferStmt:
		return s.Free != nil
	case *ast.BlockStmt:
		for _, st := range s.Stmts {
			if hasDeferFree(st) {
				return true
			}
		}
	case *ast.IfStmt:
		if hasDeferFree(s.Then) || (s.Else != nil && hasDeferFree(s.Else)) {
			return true
		}
	case *ast.WhileStmt:
		return hasDeferFree(s.Body)
	case *ast.ForStmt:
		return hasDeferFree(s.Init) || hasDeferFree(s.Body)
	}
	return false
}

// emitFuncLeave runs deferred calls (LIFO), restores frame, returns (result regs preserved).
func (g *Gen) emitFuncLeave() {
	if g.hasDefer {
		g.saveResultRegs()
		g.emitRunDefers()
		g.restoreResultRegs()
	}
	g.buf.MovRR(encode.RSP, encode.RBP)
	g.buf.Pop(encode.RBP)
	g.buf.Ret()
}

// deferNargsFree is a sentinel nargs meaning "run free(slice)" with header in arg0..arg2.
const deferNargsFree = 0xFE

// emitDefer registers a deferred call: args evaluated now, call at function exit (LIFO).
func (g *Gen) emitDefer(s *ast.DeferStmt) {
	if !g.hasDefer {
		g.errf("defer used but no arena (internal error)")
		return
	}
	if s.Free != nil {
		g.emitDeferFree(s.Free)
		return
	}
	if s.Call == nil {
		g.errf("defer requires a function call or free(...)")
		return
	}
	nArgs := len(s.Call.Args)
	if nArgs > 4 {
		g.errf("defer supports at most 4 arguments")
		nArgs = 4
	}

	// Evaluate arguments left-to-right onto the stack (same safe convention as calls).
	for i := 0; i < nArgs; i++ {
		g.emitExpr(s.Call.Args[i])
		g.buf.Push(encode.RAX)
	}
	// Function address into r10
	g.emitDeferCalleeAddr(s.Call)
	g.buf.MovRR(encode.R10, encode.RAX)

	// count in rax; bounds check against cap
	g.buf.MovRMDisp(encode.RAX, encode.RBP, g.deferCountOff)
	g.buf.CmpRI(encode.RAX, int32(g.deferCap))
	jae := g.buf.JccRel32(encode.CC_AE) // skip if full (silent drop; capacity is generous)

	// r11 = &arena[count]
	g.buf.MovRR(encode.R11, encode.RAX)
	g.buf.MovRI(encode.RDX, uint64(deferEntrySize))
	g.buf.ImulRR(encode.R11, encode.RDX)
	g.buf.LeaRegDisp(encode.RAX, encode.RBP, g.deferArenaOff)
	g.buf.AddRR(encode.R11, encode.RAX)

	// store fn, nargs
	g.buf.MovMR(encode.R11, encode.R10)
	g.buf.MovRI32(encode.RAX, int32(nArgs))
	g.buf.MovMRDisp(encode.R11, 8, encode.RAX)

	// pop args into node (LTR eval pushed a0..a_{n-1}, top is last arg)
	// arg i is at [rsp + 8*(nArgs-1-i)]
	for i := 0; i < nArgs; i++ {
		off := int32(8 * (nArgs - 1 - i))
		g.buf.MovRMDisp(encode.RAX, encode.RSP, off)
		g.buf.MovMRDisp(encode.R11, int32(16+8*i), encode.RAX)
	}
	if nArgs > 0 {
		g.buf.AddRI(encode.RSP, int32(8*nArgs))
	}

	// count++
	g.buf.MovRMDisp(encode.RAX, encode.RBP, g.deferCountOff)
	g.buf.AddRI(encode.RAX, 1)
	g.buf.MovMRDisp(encode.RBP, g.deferCountOff, encode.RAX)

	// skip path if arena full: still drop pushed args
	jmpEnd := g.buf.JmpRel32()
	g.buf.PatchRel32(jae, g.buf.Len())
	if nArgs > 0 {
		g.buf.AddRI(encode.RSP, int32(8*nArgs))
	}
	g.buf.PatchRel32(jmpEnd, g.buf.Len())
}

func (g *Gen) emitDeferFree(fr *ast.FreeExpr) {
	// Evaluate slice now; store header; at exit run owns-aware free.
	g.emitExpr(fr.X)
	g.buf.MovRMDisp(encode.R11, encode.RBP, g.deferCountOff)
	g.buf.CmpRI(encode.R11, int32(g.deferCap))
	jae := g.buf.JccRel32(encode.CC_AE)

	g.buf.Push(encode.RAX)
	g.buf.Push(encode.RDX)
	g.buf.Push(encode.R8)

	g.buf.MovRR(encode.RAX, encode.R11) // count
	g.buf.MovRI(encode.RDX, uint64(deferEntrySize))
	g.buf.ImulRR(encode.RAX, encode.RDX)
	g.buf.LeaRegDisp(encode.R11, encode.RBP, g.deferArenaOff)
	g.buf.AddRR(encode.R11, encode.RAX)

	// fn = 0, nargs = FREE sentinel, args = ptr,len,cap
	g.buf.XorRR(encode.RAX, encode.RAX)
	g.buf.MovMR(encode.R11, encode.RAX)
	g.buf.MovRI32(encode.RAX, deferNargsFree)
	g.buf.MovMRDisp(encode.R11, 8, encode.RAX)
	g.buf.Pop(encode.RAX) // cap
	g.buf.MovMRDisp(encode.R11, 32, encode.RAX)
	g.buf.Pop(encode.RAX) // len
	g.buf.MovMRDisp(encode.R11, 24, encode.RAX)
	g.buf.Pop(encode.RAX) // ptr
	g.buf.MovMRDisp(encode.R11, 16, encode.RAX)

	g.buf.MovRMDisp(encode.RAX, encode.RBP, g.deferCountOff)
	g.buf.AddRI(encode.RAX, 1)
	g.buf.MovMRDisp(encode.RBP, g.deferCountOff, encode.RAX)

	g.buf.PatchRel32(jae, g.buf.Len())
}

// emitDeferCalleeAddr puts the callee address in RAX (direct LEA or pointer load).
func (g *Gen) emitDeferCalleeAddr(call *ast.CallExpr) {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		if obj := g.chk.Uses[f]; obj != nil && obj.IsFunc && !obj.IsBuiltin {
			at := g.buf.LeaRIP(encode.RAX)
			g.calls = append(g.calls, relPatch{at: at, name: sema.LinkNameOf(obj)})
			return
		}
		if obj := g.chk.Uses[f]; obj != nil && obj.IsBuiltin {
			g.errf("cannot defer builtin %s", f.Name)
			g.buf.XorRR(encode.RAX, encode.RAX)
			return
		}
		// function pointer variable
		g.emitExpr(f)
	case *ast.SelectorExpr:
		if obj := g.chk.SelObj[f]; obj != nil && obj.IsFunc {
			at := g.buf.LeaRIP(encode.RAX)
			g.calls = append(g.calls, relPatch{at: at, name: sema.LinkNameOf(obj)})
			return
		}
		g.emitExpr(f)
	default:
		g.emitExpr(call.Fun)
	}
}

// emitRunDefers executes registered defers in reverse order of registration.
func (g *Gen) emitRunDefers() {
	// while count > 0 { count--; call arena[count] }
	loop := g.buf.Len()
	g.buf.MovRMDisp(encode.RAX, encode.RBP, g.deferCountOff)
	g.buf.TestRR(encode.RAX, encode.RAX)
	jz := g.buf.JccRel32(encode.CC_E)

	// count--
	g.buf.SubRI(encode.RAX, 1)
	g.buf.MovMRDisp(encode.RBP, g.deferCountOff, encode.RAX)

	// r11 = &arena[count] = rbp + deferArenaOff + count*48
	g.buf.MovRR(encode.R11, encode.RAX)
	g.buf.MovRI(encode.RDX, uint64(deferEntrySize))
	g.buf.ImulRR(encode.R11, encode.RDX)
	g.buf.LeaRegDisp(encode.RAX, encode.RBP, g.deferArenaOff)
	g.buf.AddRR(encode.R11, encode.RAX)

	if g.deferNeedsFree {
		g.buf.MovRMDisp(encode.RAX, encode.R11, 8)
		g.buf.CmpRI(encode.RAX, deferNargsFree)
		jFree := g.buf.JccRel32(encode.CC_E)

		g.buf.MovRM(encode.R10, encode.R11)
		g.buf.MovRMDisp(encode.RCX, encode.R11, 16)
		g.buf.MovRMDisp(encode.RDX, encode.R11, 24)
		g.buf.MovRMDisp(encode.R8, encode.R11, 32)
		g.buf.MovRMDisp(encode.R9, encode.R11, 40)
		g.buf.SubRI(encode.RSP, 0x20)
		g.buf.CallReg(encode.R10)
		g.buf.AddRI(encode.RSP, 0x20)
		jmpLoop := g.buf.JmpRel32()

		g.buf.PatchRel32(jFree, g.buf.Len())
		g.buf.MovRMDisp(encode.RAX, encode.R11, 16)
		g.buf.MovRMDisp(encode.R8, encode.R11, 32)
		g.buf.MovRR(encode.R9, encode.R8)
		g.buf.MovRI(encode.RCX, types.SliceOwnBit)
		g.buf.AndRR(encode.R9, encode.RCX)
		g.buf.TestRR(encode.R9, encode.R9)
		jzNo := g.buf.JccRel32(encode.CC_E)
		g.buf.TestRR(encode.RAX, encode.RAX)
		jzNo2 := g.buf.JccRel32(encode.CC_E)
		g.buf.MovRR(encode.RCX, encode.RAX)
		g.emitRuntimeFreeRCX()
		g.buf.PatchRel32(jzNo, g.buf.Len())
		g.buf.PatchRel32(jzNo2, g.buf.Len())
		g.buf.PatchRel32(jmpLoop, g.buf.Len())
	} else {
		g.buf.MovRM(encode.R10, encode.R11)
		g.buf.MovRMDisp(encode.RCX, encode.R11, 16)
		g.buf.MovRMDisp(encode.RDX, encode.R11, 24)
		g.buf.MovRMDisp(encode.R8, encode.R11, 32)
		g.buf.MovRMDisp(encode.R9, encode.R11, 40)
		g.buf.SubRI(encode.RSP, 0x20)
		g.buf.CallReg(encode.R10)
		g.buf.AddRI(encode.RSP, 0x20)
	}

	jmp := g.buf.JmpRel32()
	g.buf.PatchRel32(jmp, loop)
	g.buf.PatchRel32(jz, g.buf.Len())
}

func (g *Gen) allocLocals(b *ast.BlockStmt) {
	if b == nil {
		return
	}
	for _, s := range b.Stmts {
		switch s := s.(type) {
		case *ast.VarDecl:
			if s.IsConst {
				// const folded at use; still reserve a slot for simplicity
			}
			sz := int64(8)
			if s.Type != nil {
				sz = g.sizeofType(s.Type)
			} else if s.Value != nil {
				if t := g.chk.TypeOf(s.Value); t != nil && t.Size() > 0 {
					sz = t.Size()
				}
			}
			// slice without explicit type still 24 bytes if value is slice
			if s.Value != nil {
				if t := g.chk.TypeOf(s.Value); types.IsSlice(t) {
					sz = 24
				}
			}
			if s.Type != nil {
				if _, ok := s.Type.(*ast.SliceTypeExpr); ok {
					sz = 24
				}
			}
			if sz < 8 {
				sz = 8
			}
			sz = alignUp(sz, 8)
			g.localSize += int32(sz)
			g.locals[s.Name] = -g.localSize
		case *ast.BlockStmt:
			g.allocLocals(s)
		case *ast.IfStmt:
			g.allocLocals(s.Then)
			if s.Else != nil {
				if bl, ok := s.Else.(*ast.BlockStmt); ok {
					g.allocLocals(bl)
				} else if iff, ok := s.Else.(*ast.IfStmt); ok {
					g.allocLocals(iff.Then)
				}
			}
		case *ast.WhileStmt:
			g.allocLocals(s.Body)
		case *ast.ForStmt:
			if vd, ok := s.Init.(*ast.VarDecl); ok {
				sz := int64(8)
				if vd.Type != nil {
					sz = g.sizeofType(vd.Type)
				}
				if sz < 8 {
					sz = 8
				}
				sz = alignUp(sz, 8)
				g.localSize += int32(sz)
				g.locals[vd.Name] = -g.localSize
			}
			g.allocLocals(s.Body)
		}
	}
}

func (g *Gen) emitBlock(b *ast.BlockStmt) {
	if b == nil {
		return
	}
	for _, s := range b.Stmts {
		g.emitStmt(s)
	}
}

func (g *Gen) emitStmt(s ast.Stmt) {
	switch s := s.(type) {
	case *ast.BlockStmt:
		g.emitBlock(s)
	case *ast.VarDecl:
		if s.Value != nil {
			g.emitExpr(s.Value)
			off, ok := g.locals[s.Name]
			if !ok {
				if _, gok := g.globOff[s.Name]; gok {
					g.storeGlobal(s.Name, encode.RAX)
					return
				}
				g.errf("unknown local %s", s.Name)
				return
			}
			if types.IsSlice(g.chk.TypeOf(s.Value)) {
				g.storeSliceLocal(off)
			} else {
				g.storeLocal(off, s)
			}
		}
	case *ast.AssignStmt:
		lhss := s.Lhss
		if len(lhss) == 0 && s.Lhs != nil {
			lhss = []ast.Expr{s.Lhs}
		}
		if len(lhss) > 1 || s.Define {
			// multi-assign or := - RHS is typically multi-return call
			if len(lhss) > 1 {
				g.emitMultiAssign(s)
			} else {
				// single :=
				g.emitExpr(s.Rhs)
				if id, ok := lhss[0].(*ast.Ident); ok && id.Name != "_" {
					if off, ok := g.locals[id.Name]; ok {
						if types.IsSlice(g.chk.TypeOf(s.Rhs)) {
							g.storeSliceLocal(off)
						} else {
							g.buf.MovMRDisp(encode.RBP, off, encode.RAX)
						}
					} else {
						// need local slot for := - allocLocals should have run?
						// := locals are defined in sema but may not be in allocLocals walk
						g.ensureLocal(id.Name, g.chk.TypeOf(s.Rhs))
						off := g.locals[id.Name]
						if types.IsSlice(g.chk.TypeOf(s.Rhs)) {
							g.storeSliceLocal(off)
						} else {
							g.buf.MovMRDisp(encode.RBP, off, encode.RAX)
						}
					}
				}
			}
		} else {
			g.emitAssign(s)
		}
	case *ast.ReturnStmt:
		g.emitReturn(s)
	case *ast.DeferStmt:
		g.emitDefer(s)
	case *ast.ExprStmt:
		g.emitExpr(s.X)
	case *ast.IfStmt:
		g.emitIf(s)
	case *ast.WhileStmt:
		g.emitWhile(s)
	case *ast.ForStmt:
		g.emitFor(s)
	case *ast.BreakStmt:
		at := g.buf.JmpRel32()
		if len(g.breakStack) == 0 {
			g.errf("break outside loop")
			return
		}
		top := len(g.breakStack) - 1
		g.breakStack[top] = append(g.breakStack[top], at)
	case *ast.ContinueStmt:
		at := g.buf.JmpRel32()
		if len(g.continueStack) == 0 {
			g.errf("continue outside loop")
			return
		}
		top := len(g.continueStack) - 1
		g.continueStack[top] = append(g.continueStack[top], at)
	}
}

func (g *Gen) storeLocal(off int32, n ast.Node) {
	// store rax to [rbp+off] with size from type if known
	g.buf.MovMRDisp(encode.RBP, off, encode.RAX)
}

func (g *Gen) emitAssign(s *ast.AssignStmt) {
	lhs := s.Lhs
	if lhs == nil && len(s.Lhss) > 0 {
		lhs = s.Lhss[0]
	}
	// Evaluate RHS first
	if s.Op != token.Assign && s.Op != token.Define {
		// compound: load lhs, op, store
		g.emitAddrOrLoad(lhs, true)
		g.buf.Push(encode.RAX) // old value
		g.emitExpr(s.Rhs)
		g.buf.MovRR(encode.RCX, encode.RAX) // rhs
		g.buf.Pop(encode.RAX)               // lhs val
		switch s.Op {
		case token.PlusEq:
			g.buf.AddRR(encode.RAX, encode.RCX)
		case token.MinusEq:
			g.buf.SubRR(encode.RAX, encode.RCX)
		case token.StarEq:
			g.buf.ImulRR(encode.RAX, encode.RCX)
		case token.SlashEq:
			g.buf.XorRR(encode.RDX, encode.RDX)
			g.buf.Div(encode.RCX)
		}
		g.storeTo(lhs)
		return
	}
	g.emitExpr(s.Rhs)
	if types.IsSlice(g.chk.TypeOf(s.Rhs)) {
		if id, ok := lhs.(*ast.Ident); ok {
			if off, ok := g.locals[id.Name]; ok {
				g.storeSliceLocal(off)
				return
			}
		}
	}
	g.storeTo(lhs)
}

// storeTo stores RAX into lhs lvalue.
func (g *Gen) storeTo(lhs ast.Expr) {
	switch e := lhs.(type) {
	case *ast.Ident:
		if off, ok := g.locals[e.Name]; ok {
			// slice local: 24-byte header in RAX/RDX/R8
			if obj := g.chk.Uses[e]; obj != nil && types.IsSlice(obj.Type) {
				g.storeSliceLocal(off)
				return
			}
			// infer from TypeOf of ident via checker Uses
			if t := g.chk.TypeOf(e); types.IsSlice(t) {
				g.storeSliceLocal(off)
				return
			}
			g.buf.MovMRDisp(encode.RBP, off, encode.RAX)
			return
		}
		if obj := g.chk.Uses[e]; obj != nil && obj.IsGlobal {
			if types.IsSlice(obj.Type) {
				// store 24-byte global - three stores
				link := sema.LinkNameOf(obj)
				at := g.buf.LeaRIP(encode.R11)
				g.globRefs = append(g.globRefs, globPatch{at: at, name: link})
				g.buf.MovMR(encode.R11, encode.RAX)
				g.buf.MovMRDisp(encode.R11, 8, encode.RDX)
				g.buf.MovMRDisp(encode.R11, 16, encode.R8)
				return
			}
			g.storeGlobal(sema.LinkNameOf(obj), encode.RAX)
			return
		}
		if _, ok := g.globOff[e.Name]; ok {
			g.storeGlobal(e.Name, encode.RAX)
			return
		}
		g.errf("cannot assign to %s", e.Name)
	case *ast.UnaryExpr:
		if e.Op == token.Star {
			g.buf.Push(encode.RAX)
			g.emitExpr(e.X)
			g.buf.MovRR(encode.RCX, encode.RAX) // address
			g.buf.Pop(encode.RAX)
			// store by size
			sz := int64(8)
			if t := g.chk.TypeOf(e); t != nil {
				sz = t.Size()
			}
			g.storeAt(encode.RCX, encode.RAX, sz)
			return
		}
	case *ast.IndexExpr:
		g.buf.Push(encode.RAX)
		if types.IsSlice(g.chk.TypeOf(e.X)) {
			g.emitSliceIndexAddr(e)
		} else {
			g.emitIndexAddr(e)
		}
		g.buf.MovRR(encode.RCX, encode.RAX)
		g.buf.Pop(encode.RAX)
		sz := int64(8)
		if t := g.chk.TypeOf(e); t != nil {
			sz = t.Size()
		}
		g.storeAt(encode.RCX, encode.RAX, sz)
	case *ast.SelectorExpr:
		g.buf.Push(encode.RAX)
		g.emitSelectorAddr(e)
		g.buf.MovRR(encode.RCX, encode.RAX)
		g.buf.Pop(encode.RAX)
		sz := int64(8)
		if t := g.chk.TypeOf(e); t != nil {
			sz = t.Size()
		}
		g.storeAt(encode.RCX, encode.RAX, sz)
	default:
		g.errf("invalid assignment target")
	}
}

func (g *Gen) storeAt(baseReg, valReg int, sz int64) {
	// assumes base in baseReg, value in valReg; may clobber
	if baseReg != encode.RCX {
		g.buf.MovRR(encode.RCX, baseReg)
	}
	if valReg != encode.RAX {
		g.buf.MovRR(encode.RAX, valReg)
	}
	switch sz {
	case 1:
		g.buf.Mov8MR(encode.RCX, encode.RAX)
	case 2:
		g.buf.Mov16MR(encode.RCX, encode.RAX)
	case 4:
		g.buf.Mov32MR(encode.RCX, encode.RAX)
	default:
		g.buf.MovMR(encode.RCX, encode.RAX)
	}
}

func (g *Gen) storeGlobal(name string, reg int) {
	// lea r11, [rip+glob]; mov [r11], reg
	if reg != encode.RAX {
		g.buf.MovRR(encode.RAX, reg)
	}
	at := g.buf.LeaRIP(encode.R11)
	g.globRefs = append(g.globRefs, globPatch{at: at, name: name})
	g.buf.MovMR(encode.R11, encode.RAX)
}

func (g *Gen) loadGlobal(name string) {
	at := g.buf.LeaRIP(encode.R11)
	g.globRefs = append(g.globRefs, globPatch{at: at, name: name})
	g.buf.MovRM(encode.RAX, encode.R11)
}

func (g *Gen) emitIf(s *ast.IfStmt) {
	g.emitExpr(s.Cond)
	g.buf.TestRR(encode.RAX, encode.RAX)
	jelse := g.buf.JccRel32(encode.CC_E) // jz else
	g.emitBlock(s.Then)
	if s.Else != nil {
		jend := g.buf.JmpRel32()
		elsePC := g.buf.Len()
		g.buf.PatchRel32(jelse, elsePC)
		g.emitStmt(s.Else)
		g.buf.PatchRel32(jend, g.buf.Len())
	} else {
		g.buf.PatchRel32(jelse, g.buf.Len())
	}
}

func (g *Gen) emitWhile(s *ast.WhileStmt) {
	g.breakStack = append(g.breakStack, nil)
	g.continueStack = append(g.continueStack, nil)
	condPC := g.buf.Len()
	g.emitExpr(s.Cond)
	g.buf.TestRR(encode.RAX, encode.RAX)
	jout := g.buf.JccRel32(encode.CC_E)
	g.emitBlock(s.Body)
	// continue target
	contPC := g.buf.Len()
	jback := g.buf.JmpRel32()
	g.buf.PatchRel32(jback, condPC)
	endPC := g.buf.Len()
	g.buf.PatchRel32(jout, endPC)
	// patch breaks/continues
	bi := len(g.breakStack) - 1
	for _, at := range g.breakStack[bi] {
		g.buf.PatchRel32(at, endPC)
	}
	for _, at := range g.continueStack[bi] {
		g.buf.PatchRel32(at, contPC)
	}
	g.breakStack = g.breakStack[:bi]
	g.continueStack = g.continueStack[:bi]
	_ = contPC
}

func (g *Gen) emitFor(s *ast.ForStmt) {
	g.breakStack = append(g.breakStack, nil)
	g.continueStack = append(g.continueStack, nil)
	if s.Init != nil {
		g.emitStmt(s.Init)
	}
	condPC := g.buf.Len()
	var jout int = -1
	if s.Cond != nil {
		g.emitExpr(s.Cond)
		g.buf.TestRR(encode.RAX, encode.RAX)
		jout = g.buf.JccRel32(encode.CC_E)
	}
	g.emitBlock(s.Body)
	contPC := g.buf.Len()
	if s.Post != nil {
		g.emitExpr(s.Post)
	}
	jback := g.buf.JmpRel32()
	g.buf.PatchRel32(jback, condPC)
	endPC := g.buf.Len()
	if jout >= 0 {
		g.buf.PatchRel32(jout, endPC)
	}
	bi := len(g.breakStack) - 1
	for _, at := range g.breakStack[bi] {
		g.buf.PatchRel32(at, endPC)
	}
	for _, at := range g.continueStack[bi] {
		g.buf.PatchRel32(at, contPC)
	}
	g.breakStack = g.breakStack[:bi]
	g.continueStack = g.continueStack[:bi]
}

// emitExpr evaluates expression; result in RAX.
func (g *Gen) emitExpr(e ast.Expr) {
	switch e := e.(type) {
	case *ast.BasicLit:
		g.emitLit(e)
	case *ast.Ident:
		g.emitIdent(e)
	case *ast.UnaryExpr:
		g.emitUnary(e)
	case *ast.AddrOf:
		g.emitAddrOf(e)
	case *ast.BinaryExpr:
		g.emitBinary(e)
	case *ast.CallExpr:
		g.emitCall(e)
	case *ast.IndexExpr:
		g.emitIndex(e)
	case *ast.SelectorExpr:
		g.emitSelector(e)
	case *ast.CastExpr:
		g.emitExpr(e.X)
		// casts are mostly no-ops at machine level for integers/pointers
	case *ast.SizeofExpr:
		// re-resolve size
		// Use checker - Sizeof was typed; compute from TypeExpr via a const if possible
		// Fallback: emit 0
		// We don't have resolveType here; use expression type map... SizeofExpr type is u64
		// Store size during check? Recompute simply:
		sz := g.sizeofType(e.Type)
		g.buf.MovRI(encode.RAX, uint64(sz))
	case *ast.ParenExpr:
		g.emitExpr(e.X)
	case *ast.MakeExpr:
		g.emitMake(e)
	case *ast.LenExpr:
		g.emitLen(e)
	case *ast.CapExpr:
		g.emitCap(e)
	case *ast.FreeExpr:
		g.emitFreeSlice(e)
	case *ast.SliceExpr:
		g.emitSliceExpr(e)
	case *ast.AppendExpr:
		g.emitAppend(e)
	case *ast.CopyExpr:
		g.emitCopy(e)
	default:
		g.buf.XorRR(encode.RAX, encode.RAX)
	}
}

func (g *Gen) emitLit(e *ast.BasicLit) {
	switch e.Kind {
	case token.Int:
		v, _ := parser.ParseInt(e.Value)
		if v == 0 {
			g.buf.XorRR(encode.RAX, encode.RAX)
		} else if v <= 0x7fffffff {
			g.buf.MovRI32(encode.RAX, int32(v))
		} else {
			g.buf.MovRI(encode.RAX, v)
		}
	case token.Char:
		if len(e.Value) > 0 {
			g.buf.MovRI32(encode.RAX, int32(e.Value[0]))
		} else {
			g.buf.XorRR(encode.RAX, encode.RAX)
		}
	case token.String:
		// Encrypted in .rdata; unlock in-place (needs RW on image, typical for shellcode).
		// Index comes from typecheck (BasicLit.StrIndex), not emit order.
		idx := e.StrIndex
		if idx < 0 || idx >= len(g.strLens) {
			g.errf("string index out of range (%d)", idx)
			g.buf.XorRR(encode.RAX, encode.RAX)
			return
		}
		at := g.buf.LeaRIP(encode.RCX)
		g.strRefs = append(g.strRefs, strPatch{at: at, idx: idx})
		g.buf.MovRI32(encode.RDX, int32(g.strLens[idx]))
		g.buf.SubRI(encode.RSP, 0x20)
		callAt := g.buf.CallRel32()
		g.calls = append(g.calls, relPatch{at: callAt, name: g.strUnlockName})
		g.buf.AddRI(encode.RSP, 0x20)
		// rax = pointer to decrypted NUL-terminated bytes
	case token.True:
		g.buf.MovRI32(encode.RAX, 1)
	case token.False, token.Null:
		g.buf.XorRR(encode.RAX, encode.RAX)
	}
}

func (g *Gen) emitIdent(e *ast.Ident) {
	// const?
	if obj := g.chk.Uses[e]; obj != nil {
		if obj.HasConst && obj.IsConst {
			g.buf.MovRI(encode.RAX, obj.ConstVal)
			return
		}
		if obj.IsFunc {
			// address of function: lea rax, [rip+fn]
			at := g.buf.LeaRIP(encode.RAX)
			g.calls = append(g.calls, relPatch{at: at, name: sema.LinkNameOf(obj)})
			return
		}
		if obj.IsBuiltin {
			g.errf("bare builtin %s", obj.Name)
			return
		}
		if types.IsSlice(obj.Type) {
			if off, ok := g.locals[e.Name]; ok {
				g.loadSliceLocal(off)
				return
			}
			if obj.IsGlobal {
				link := sema.LinkNameOf(obj)
				at := g.buf.LeaRIP(encode.R11)
				g.globRefs = append(g.globRefs, globPatch{at: at, name: link})
				g.buf.MovRM(encode.RAX, encode.R11)
				g.buf.MovRMDisp(encode.RDX, encode.R11, 8)
				g.buf.MovRMDisp(encode.R8, encode.R11, 16)
				return
			}
		}
	}
	if off, ok := g.locals[e.Name]; ok {
		if t := g.chk.TypeOf(e); types.IsSlice(t) {
			g.loadSliceLocal(off)
			return
		}
		g.buf.MovRMDisp(encode.RAX, encode.RBP, off)
		return
	}
	if obj := g.chk.Uses[e]; obj != nil && obj.IsGlobal {
		g.loadGlobal(sema.LinkNameOf(obj))
		return
	}
	if _, ok := g.globOff[e.Name]; ok {
		g.loadGlobal(e.Name)
		return
	}
	g.errf("unresolved ident %s", e.Name)
	g.buf.XorRR(encode.RAX, encode.RAX)
}

func (g *Gen) emitUnary(e *ast.UnaryExpr) {
	switch e.Op {
	case token.Star:
		g.emitExpr(e.X)
		sz := int64(8)
		if t := g.chk.TypeOf(e); t != nil {
			sz = t.Size()
		}
		g.loadAt(encode.RAX, sz)
	case token.Minus:
		g.emitExpr(e.X)
		g.buf.Neg(encode.RAX)
	case token.Tilde:
		g.emitExpr(e.X)
		g.buf.Not(encode.RAX)
	case token.Bang:
		g.emitExpr(e.X)
		g.buf.TestRR(encode.RAX, encode.RAX)
		g.buf.Setcc(encode.CC_E, encode.RAX)
		g.buf.Movzx8(encode.RAX, encode.RAX)
	case token.Plus:
		g.emitExpr(e.X)
	}
}

func (g *Gen) loadAt(baseReg int, sz int64) {
	// load from [baseReg] into RAX
	if baseReg != encode.RAX {
		g.buf.MovRR(encode.RAX, baseReg)
	}
	switch sz {
	case 1:
		g.buf.Movzx8RM(encode.RAX, encode.RAX)
	case 2:
		g.buf.Movzx16RM(encode.RAX, encode.RAX)
	case 4:
		g.buf.Movzx32RM(encode.RAX, encode.RAX)
	default:
		g.buf.MovRM(encode.RAX, encode.RAX)
	}
}

func (g *Gen) emitAddrOf(e *ast.AddrOf) {
	g.emitLValueAddr(e.X)
}

func (g *Gen) emitAddrOrLoad(e ast.Expr, load bool) {
	if load {
		g.emitExpr(e)
	} else {
		// address - limited
		if id, ok := e.(*ast.Ident); ok {
			g.emitAddrOf(&ast.AddrOf{X: id})
		}
	}
}

func (g *Gen) emitBinary(e *ast.BinaryExpr) {
	// short-circuit && ||
	if e.Op == token.AndAnd {
		g.emitExpr(e.X)
		g.buf.TestRR(encode.RAX, encode.RAX)
		jz := g.buf.JccRel32(encode.CC_E)
		g.emitExpr(e.Y)
		g.buf.TestRR(encode.RAX, encode.RAX)
		g.buf.Setcc(encode.CC_NE, encode.RAX)
		g.buf.Movzx8(encode.RAX, encode.RAX)
		jmp := g.buf.JmpRel32()
		g.buf.PatchRel32(jz, g.buf.Len())
		g.buf.XorRR(encode.RAX, encode.RAX)
		g.buf.PatchRel32(jmp, g.buf.Len())
		return
	}
	if e.Op == token.OrOr {
		g.emitExpr(e.X)
		g.buf.TestRR(encode.RAX, encode.RAX)
		jnz := g.buf.JccRel32(encode.CC_NE)
		g.emitExpr(e.Y)
		g.buf.TestRR(encode.RAX, encode.RAX)
		g.buf.Setcc(encode.CC_NE, encode.RAX)
		g.buf.Movzx8(encode.RAX, encode.RAX)
		jmp := g.buf.JmpRel32()
		g.buf.PatchRel32(jnz, g.buf.Len())
		g.buf.MovRI32(encode.RAX, 1)
		g.buf.PatchRel32(jmp, g.buf.Len())
		return
	}

	g.emitExpr(e.X)
	g.buf.Push(encode.RAX)
	g.emitExpr(e.Y)
	g.buf.MovRR(encode.RCX, encode.RAX) // right
	g.buf.Pop(encode.RAX)               // left

	// pointer arithmetic scaling
	lt := g.chk.TypeOf(e.X)
	rt := g.chk.TypeOf(e.Y)
	if e.Op == token.Plus || e.Op == token.Minus {
		if types.IsPointer(lt) && types.IsInteger(rt) {
			elem := lt.(*types.Pointer).Elem.Size()
			if elem > 1 {
				// rcx *= elem
				g.buf.MovRI(encode.RDX, uint64(elem))
				g.buf.ImulRR(encode.RCX, encode.RDX)
			}
		}
	}

	switch e.Op {
	case token.Plus:
		g.buf.AddRR(encode.RAX, encode.RCX)
	case token.Minus:
		g.buf.SubRR(encode.RAX, encode.RCX)
	case token.Star:
		g.buf.ImulRR(encode.RAX, encode.RCX)
	case token.Slash:
		g.buf.XorRR(encode.RDX, encode.RDX)
		g.buf.Div(encode.RCX)
	case token.Percent:
		g.buf.XorRR(encode.RDX, encode.RDX)
		g.buf.Div(encode.RCX)
		g.buf.MovRR(encode.RAX, encode.RDX)
	case token.Amp:
		g.buf.AndRR(encode.RAX, encode.RCX)
	case token.Pipe:
		g.buf.OrRR(encode.RAX, encode.RCX)
	case token.Caret:
		g.buf.XorRR(encode.RAX, encode.RCX)
	case token.Shl:
		g.buf.MovRR(encode.RCX, encode.RCX) // already
		// shl rax, cl
		g.buf.Emit(0x48, 0xD3, 0xE0)
	case token.Shr:
		g.buf.Emit(0x48, 0xD3, 0xE8)
	case token.Eq:
		g.buf.CmpRR(encode.RAX, encode.RCX)
		g.buf.Setcc(encode.CC_E, encode.RAX)
		g.buf.Movzx8(encode.RAX, encode.RAX)
	case token.Neq:
		g.buf.CmpRR(encode.RAX, encode.RCX)
		g.buf.Setcc(encode.CC_NE, encode.RAX)
		g.buf.Movzx8(encode.RAX, encode.RAX)
	case token.Lt:
		g.buf.CmpRR(encode.RAX, encode.RCX)
		if types.IsSigned(lt) || types.IsSigned(rt) {
			g.buf.Setcc(encode.CC_L, encode.RAX)
		} else {
			g.buf.Setcc(encode.CC_B, encode.RAX)
		}
		g.buf.Movzx8(encode.RAX, encode.RAX)
	case token.Gt:
		g.buf.CmpRR(encode.RAX, encode.RCX)
		if types.IsSigned(lt) || types.IsSigned(rt) {
			g.buf.Setcc(encode.CC_G, encode.RAX)
		} else {
			g.buf.Setcc(encode.CC_A, encode.RAX)
		}
		g.buf.Movzx8(encode.RAX, encode.RAX)
	case token.Le:
		g.buf.CmpRR(encode.RAX, encode.RCX)
		if types.IsSigned(lt) || types.IsSigned(rt) {
			g.buf.Setcc(encode.CC_LE, encode.RAX)
		} else {
			g.buf.Setcc(encode.CC_BE, encode.RAX)
		}
		g.buf.Movzx8(encode.RAX, encode.RAX)
	case token.Ge:
		g.buf.CmpRR(encode.RAX, encode.RCX)
		if types.IsSigned(lt) || types.IsSigned(rt) {
			g.buf.Setcc(encode.CC_GE, encode.RAX)
		} else {
			g.buf.Setcc(encode.CC_AE, encode.RAX)
		}
		g.buf.Movzx8(encode.RAX, encode.RAX)
	}
}

func (g *Gen) emitCall(e *ast.CallExpr) {
	// package.Func(...)
	if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
		if obj := g.chk.SelObj[sel]; obj != nil && obj.IsFunc {
			g.emitUserCall(sema.LinkNameOf(obj), e.Args, false)
			return
		}
	}
	// Builtin / local function?
	if id, ok := e.Fun.(*ast.Ident); ok {
		if obj := g.chk.Uses[id]; obj != nil && obj.IsBuiltin {
			g.emitBuiltin(id.Name, e.Args)
			return
		}
		if obj := g.chk.Uses[id]; obj != nil && obj.IsFunc && !obj.IsBuiltin {
			g.emitUserCall(sema.LinkNameOf(obj), e.Args, false)
			return
		}
		// maybe direct function name
		if obj, ok := g.chk.Funcs[id.Name]; ok {
			g.emitUserCall(sema.LinkNameOf(obj), e.Args, false)
			return
		}
	}
	// indirect call through expression
	g.emitIndirectCall(e)
}

func (g *Gen) emitUserCall(name string, args []ast.Expr, indirect bool) {
	// MS x64: RCX, RDX, R8, R9, then stack args at [rsp+0x20].
	// Evaluate LTR onto a temporary push stack so arg eval cannot clobber priors.
	n := len(args)
	for i := 0; i < n; i++ {
		g.emitExpr(args[i])
		g.buf.Push(encode.RAX)
	}
	cleanup := g.finishMSCallFrame(n)
	at := g.buf.CallRel32()
	g.calls = append(g.calls, relPatch{at: at, name: name})
	g.buf.AddRI(encode.RSP, cleanup)
	_ = indirect
}

func (g *Gen) emitIndirectCall(e *ast.CallExpr) {
	n := len(e.Args)
	for i := 0; i < n; i++ {
		g.emitExpr(e.Args[i])
		g.buf.Push(encode.RAX)
	}
	// Callee in R10 (not an MS arg reg).
	g.emitExpr(e.Fun)
	g.buf.MovRR(encode.R10, encode.RAX)
	cleanup := g.finishMSCallFrame(n)
	g.buf.CallReg(encode.R10)
	g.buf.AddRI(encode.RSP, cleanup)
}

// finishMSCallFrame assumes n args are already pushed LTR (arg0 at high address,
// arg[n-1] at [rsp]). Loads RCX/RDX/R8/R9 and builds shadow + stack-arg home space.
// Returns the byte count the caller must add to RSP after the call.
func (g *Gen) finishMSCallFrame(n int) int32 {
	regs := []int{encode.RCX, encode.RDX, encode.R8, encode.R9}
	for i := 0; i < n && i < 4; i++ {
		off := int32(8 * (n - 1 - i))
		g.buf.MovRMDisp(regs[i], encode.RSP, off)
	}
	if n <= 4 {
		if n > 0 {
			g.buf.AddRI(encode.RSP, int32(8*n))
		}
		g.buf.SubRI(encode.RSP, 0x20)
		return 0x20
	}
	// n > 4: keep spill values, allocate call frame under them, copy a4.. into homes.
	rem := n - 4
	frame := int32(0x20 + 8*rem)
	if frame%16 != 0 {
		frame += 8
	}
	g.buf.SubRI(encode.RSP, frame)
	// arg[4+i] was at old_rsp + 8*(n-1-(4+i)) = old_rsp + 8*(n-5-i)
	// old_rsp = new_rsp + frame -> offset frame + 8*(n-5-i)
	for i := 0; i < rem; i++ {
		oldOff := frame + int32(8*(n-5-i))
		g.buf.MovRMDisp(encode.RAX, encode.RSP, oldOff)
		g.buf.MovMRDisp(encode.RSP, int32(0x20+8*i), encode.RAX)
	}
	return frame + int32(8*n)
}

func (g *Gen) emitBuiltin(name string, args []ast.Expr) {
	switch name {
	case "__readgs":
		g.emitExpr(args[0])
		// mov r11, rax; then need gs:[r11] - our encoder only has abs.
		// Use: mov rax, gs:[rax] via 65 48 8B 00 is gs:[rax]
		// encoding: 65 REX.W 8B /0  for [rax]
		g.buf.Emit(0x65, 0x48, 0x8B, 0x00) // mov rax, gs:[rax]
	case "__writegs":
		g.emitExpr(args[1])
		g.buf.Push(encode.RAX)
		g.emitExpr(args[0])
		g.buf.MovRR(encode.RCX, encode.RAX)
		g.buf.Pop(encode.RAX)
		// mov gs:[rcx], rax
		g.buf.Emit(0x65, 0x48, 0x89, 0x01)
	case "__base":
		at := g.buf.LeaRIP(encode.RAX)
		g.baseRefs = append(g.baseRefs, at)
	case "__end":
		at := g.buf.LeaRIP(encode.RAX)
		g.endRefs = append(g.endRefs, at)
	case "__hash":
		// compile-time for string literals (no .rdata entry); runtime for pointers
		if lit, ok := args[0].(*ast.BasicLit); ok && lit.Kind == token.String {
			h := sema.HashStringA(lit.Value)
			// zero-extend to 64-bit (MovRI32 would sign-extend hashes with bit 31 set)
			g.buf.MovRI(encode.RAX, uint64(h))
		} else {
			g.emitExpr(args[0])
			g.emitRuntimeHash()
		}
	case "__breakpoint":
		g.buf.Int3()
	case "__rdtsc":
		g.buf.Rdtsc()
		// rdx:rax -> rax only low for simplicity; combine
		g.buf.ShlRI(encode.RDX, 32)
		g.buf.AddRR(encode.RAX, encode.RDX)
	case "__syscall":
		// Linux: rax=n, rdi,rsi,rdx,r10,r8,r9
		// args: num, a1, a2, a3, a4, a5, a6
		regs := []int{encode.RAX, encode.RDI, encode.RSI, encode.RDX, encode.R10, encode.R8, encode.R9}
		// push all then pop to avoid clobber
		for i := len(args) - 1; i >= 0; i-- {
			g.emitExpr(args[i])
			g.buf.Push(encode.RAX)
		}
		for i := 0; i < len(args) && i < 7; i++ {
			g.buf.Pop(regs[i])
		}
		g.buf.Syscall()
	case "__sysv_call":
		// __sysv_call(fn, a0..a5) - System V AMD64 (Linux): RDI,RSI,RDX,RCX,R8,R9
		g.emitSysvCall(args)
	case "__load8":
		g.emitExpr(args[0])
		g.buf.Movzx8RM(encode.RAX, encode.RAX)
	case "__load16":
		g.emitExpr(args[0])
		g.buf.Movzx16RM(encode.RAX, encode.RAX)
	case "__load32":
		g.emitExpr(args[0])
		g.buf.Movzx32RM(encode.RAX, encode.RAX)
	case "__load64":
		g.emitExpr(args[0])
		g.buf.MovRM(encode.RAX, encode.RAX)
	case "__store8":
		g.emitExpr(args[1])
		g.buf.Push(encode.RAX)
		g.emitExpr(args[0])
		g.buf.MovRR(encode.RCX, encode.RAX)
		g.buf.Pop(encode.RAX)
		g.buf.Mov8MR(encode.RCX, encode.RAX)
	case "__store16":
		g.emitExpr(args[1])
		g.buf.Push(encode.RAX)
		g.emitExpr(args[0])
		g.buf.MovRR(encode.RCX, encode.RAX)
		g.buf.Pop(encode.RAX)
		g.buf.Mov16MR(encode.RCX, encode.RAX)
	case "__store32":
		g.emitExpr(args[1])
		g.buf.Push(encode.RAX)
		g.emitExpr(args[0])
		g.buf.MovRR(encode.RCX, encode.RAX)
		g.buf.Pop(encode.RAX)
		g.buf.Mov32MR(encode.RCX, encode.RAX)
	case "__store64":
		g.emitExpr(args[1])
		g.buf.Push(encode.RAX)
		g.emitExpr(args[0])
		g.buf.MovRR(encode.RCX, encode.RAX)
		g.buf.Pop(encode.RAX)
		g.buf.MovMR(encode.RCX, encode.RAX)
	case "__memcpy":
		g.emitMemCopy(args)
	case "__memset":
		g.emitMemSet(args)
	case "__memcmp":
		g.emitMemCmp(args)
	case "__strlen":
		g.emitStrlen(args[0])
	default:
		g.errf("unknown builtin %s", name)
	}
}

// emitStrUnlock emits str-unlock helper (rcx=entry, rdx=len) -> rax=cstr.
//
// Entry layout: [u8 ready][u8 enc[len]...]
// ready==0: XOR-decrypt enc in place with strKeystream, set ready=1.
// ready==1: already plain (re-entrant).
// Returns pointer to the C string (byte after ready flag).
// Symbol name is g.strUnlockName (randomized when RandSections is on).
func (g *Gen) emitStrUnlock() {
	g.fnOff[g.strUnlockName] = g.buf.Len()

	// cmp byte ptr [rcx], 1
	g.buf.Emit(0x80, 0x39, 0x01)
	// je already (patch later)
	jeAlready := g.buf.JccRel32(encode.CC_E)

	// push rbx; push rsi; push rdi
	g.buf.Push(encode.RBX)
	g.buf.Push(encode.RSI)
	g.buf.Push(encode.RDI)

	// lea rsi, [rcx+1]  - payload
	g.buf.LeaRegDisp(encode.RSI, encode.RCX, 1)
	// rdi = len (rdx)
	g.buf.MovRR(encode.RDI, encode.RDX)
	// ebx = 0 (index)
	g.buf.XorRR(encode.RBX, encode.RBX)

	loop := g.buf.Len()
	// test rdi, rdi / jz done
	g.buf.TestRR(encode.RDI, encode.RDI)
	jzDone := g.buf.JccRel32(encode.CC_E)

	// al = [rsi]
	g.buf.Movzx8RM(encode.RAX, encode.RSI)

	// keystream = (i*131 + 17) ^ (i<<3) ^ K1 ^ K2  (K1/K2 per-build when randomized)
	// r8 = i
	g.buf.MovRR(encode.R8, encode.RBX)
	// r9 = i*131
	g.buf.MovRI(encode.R9, 131)
	g.buf.ImulRR(encode.R9, encode.R8)
	// r9 += 17
	g.buf.AddRI(encode.R9, 17)
	// r8 = i<<3
	g.buf.MovRR(encode.R8, encode.RBX)
	g.buf.ShlRI(encode.R8, 3)
	// r9 ^= r8
	g.buf.XorRR(encode.R9, encode.R8)
	// r9 ^= K1
	g.buf.MovRI(encode.R8, uint64(g.strK1))
	g.buf.XorRR(encode.R9, encode.R8)
	// r9 ^= K2
	g.buf.MovRI(encode.R8, uint64(g.strK2))
	g.buf.XorRR(encode.R9, encode.R8)
	// al ^= r9b
	g.buf.XorRR(encode.RAX, encode.R9)
	// [rsi] = al
	g.buf.Mov8MR(encode.RSI, encode.RAX)

	// rsi++, ebx++, rdi--
	g.buf.AddRI(encode.RSI, 1)
	g.buf.AddRI(encode.RBX, 1)
	g.buf.SubRI(encode.RDI, 1)
	jmpLoop := g.buf.JmpRel32()
	g.buf.PatchRel32(jmpLoop, loop)

	g.buf.PatchRel32(jzDone, g.buf.Len())
	// mov byte ptr [rcx], 1
	g.buf.Emit(0xC6, 0x01, 0x01)

	g.buf.Pop(encode.RDI)
	g.buf.Pop(encode.RSI)
	g.buf.Pop(encode.RBX)

	g.buf.PatchRel32(jeAlready, g.buf.Len())
	// lea rax, [rcx+1]
	g.buf.LeaRegDisp(encode.RAX, encode.RCX, 1)
	g.buf.Ret()
}

// emitSysvCall implements __sysv_call(fn, a0, a1, ...).
// Uses System V AMD64 argument registers so resolved Linux libc can be invoked.
func (g *Gen) emitSysvCall(args []ast.Expr) {
	if len(args) < 1 {
		g.errf("__sysv_call needs function pointer")
		return
	}
	// Evaluate fn + args onto stack (right-to-left)
	for i := len(args) - 1; i >= 0; i-- {
		g.emitExpr(args[i])
		g.buf.Push(encode.RAX)
	}
	// stack top = fn
	g.buf.Pop(encode.R11)
	sysvRegs := []int{encode.RDI, encode.RSI, encode.RDX, encode.RCX, encode.R8, encode.R9}
	nArgs := len(args) - 1
	for i := 0; i < nArgs && i < 6; i++ {
		g.buf.Pop(sysvRegs[i])
	}
	// 16-byte align for SysV call; restore via callee-saved RBX
	g.buf.Push(encode.RBX)
	g.buf.MovRR(encode.RBX, encode.RSP)
	g.buf.AndRI(encode.RSP, -16)
	g.buf.CallReg(encode.R11)
	g.buf.MovRR(encode.RSP, encode.RBX)
	g.buf.Pop(encode.RBX)
}

func (g *Gen) emitRuntimeHash() {
	// djb2 uppercase on [rax] C string; result is uint32 (mask to 32 bits)
	g.buf.MovRR(encode.RSI, encode.RAX)
	g.buf.MovRI(encode.RAX, 5381)
	loop := g.buf.Len()
	g.buf.Movzx8RM(encode.RCX, encode.RSI)
	g.buf.TestRR(encode.RCX, encode.RCX)
	jz := g.buf.JccRel32(encode.CC_E)
	// if ch >= 'a' && ch <= 'z': ch -= 0x20
	g.buf.CmpRI(encode.RCX, int32('a'))
	jb := g.buf.JccRel32(encode.CC_B)
	g.buf.CmpRI(encode.RCX, int32('z'))
	ja := g.buf.JccRel32(encode.CC_A)
	g.buf.SubRI(encode.RCX, 0x20)
	g.buf.PatchRel32(jb, g.buf.Len())
	g.buf.PatchRel32(ja, g.buf.Len())
	// hash = hash*33 + ch = (hash<<5)+hash+ch  (uint32 wrap via mov eax,eax)
	g.buf.MovRR(encode.RDX, encode.RAX)
	g.buf.ShlRI(encode.RAX, 5)
	g.buf.AddRR(encode.RAX, encode.RDX)
	g.buf.AddRR(encode.RAX, encode.RCX)
	g.buf.Emit(0x89, 0xC0) // mov eax, eax - truncate to uint32, zero-extend
	g.buf.AddRI(encode.RSI, 1)
	jmp := g.buf.JmpRel32()
	g.buf.PatchRel32(jmp, loop)
	g.buf.PatchRel32(jz, g.buf.Len())
}

func (g *Gen) emitMemCopy(args []ast.Expr) {
	// dst, src, n - simple byte loop
	g.emitExpr(args[2])
	g.buf.Push(encode.RAX)
	g.emitExpr(args[1])
	g.buf.Push(encode.RAX)
	g.emitExpr(args[0])
	g.buf.MovRR(encode.RDI, encode.RAX)
	g.buf.Pop(encode.RSI)
	g.buf.Pop(encode.RCX)
	// rax = dst for return
	g.buf.MovRR(encode.RAX, encode.RDI)
	loop := g.buf.Len()
	g.buf.TestRR(encode.RCX, encode.RCX)
	jz := g.buf.JccRel32(encode.CC_E)
	g.buf.Movzx8RM(encode.RDX, encode.RSI)
	g.buf.Mov8MR(encode.RDI, encode.RDX)
	g.buf.AddRI(encode.RSI, 1)
	g.buf.AddRI(encode.RDI, 1)
	g.buf.SubRI(encode.RCX, 1)
	jmp := g.buf.JmpRel32()
	g.buf.PatchRel32(jmp, loop)
	g.buf.PatchRel32(jz, g.buf.Len())
}

func (g *Gen) emitMemSet(args []ast.Expr) {
	g.emitExpr(args[2])
	g.buf.Push(encode.RAX)
	g.emitExpr(args[1])
	g.buf.Push(encode.RAX)
	g.emitExpr(args[0])
	g.buf.MovRR(encode.RDI, encode.RAX)
	g.buf.Pop(encode.RAX) // val
	g.buf.Pop(encode.RCX) // n
	g.buf.MovRR(encode.R8, encode.RDI)
	loop := g.buf.Len()
	g.buf.TestRR(encode.RCX, encode.RCX)
	jz := g.buf.JccRel32(encode.CC_E)
	g.buf.Mov8MR(encode.RDI, encode.RAX)
	g.buf.AddRI(encode.RDI, 1)
	g.buf.SubRI(encode.RCX, 1)
	jmp := g.buf.JmpRel32()
	g.buf.PatchRel32(jmp, loop)
	g.buf.PatchRel32(jz, g.buf.Len())
	g.buf.MovRR(encode.RAX, encode.R8)
}

func (g *Gen) emitMemCmp(args []ast.Expr) {
	g.emitExpr(args[2])
	g.buf.Push(encode.RAX)
	g.emitExpr(args[1])
	g.buf.Push(encode.RAX)
	g.emitExpr(args[0])
	g.buf.MovRR(encode.RDI, encode.RAX)
	g.buf.Pop(encode.RSI)
	g.buf.Pop(encode.RCX)
	loop := g.buf.Len()
	g.buf.TestRR(encode.RCX, encode.RCX)
	jz := g.buf.JccRel32(encode.CC_E)
	g.buf.Movzx8RM(encode.RAX, encode.RDI)
	g.buf.Movzx8RM(encode.RDX, encode.RSI)
	g.buf.CmpRR(encode.RAX, encode.RDX)
	jne := g.buf.JccRel32(encode.CC_NE)
	g.buf.AddRI(encode.RDI, 1)
	g.buf.AddRI(encode.RSI, 1)
	g.buf.SubRI(encode.RCX, 1)
	jmp := g.buf.JmpRel32()
	g.buf.PatchRel32(jmp, loop)
	// equal
	g.buf.PatchRel32(jz, g.buf.Len())
	g.buf.XorRR(encode.RAX, encode.RAX)
	end := g.buf.JmpRel32()
	// not equal
	g.buf.PatchRel32(jne, g.buf.Len())
	g.buf.SubRR(encode.RAX, encode.RDX)
	g.buf.PatchRel32(end, g.buf.Len())
}

func (g *Gen) emitStrlen(arg ast.Expr) {
	g.emitExpr(arg)
	g.buf.MovRR(encode.RSI, encode.RAX)
	g.buf.XorRR(encode.RAX, encode.RAX)
	loop := g.buf.Len()
	g.buf.Movzx8RM(encode.RCX, encode.RSI)
	g.buf.TestRR(encode.RCX, encode.RCX)
	jz := g.buf.JccRel32(encode.CC_E)
	g.buf.AddRI(encode.RAX, 1)
	g.buf.AddRI(encode.RSI, 1)
	jmp := g.buf.JmpRel32()
	g.buf.PatchRel32(jmp, loop)
	g.buf.PatchRel32(jz, g.buf.Len())
}

func (g *Gen) emitIndex(e *ast.IndexExpr) {
	if types.IsSlice(g.chk.TypeOf(e.X)) {
		g.emitSliceIndexLoad(e)
		return
	}
	g.emitIndexAddr(e)
	sz := int64(8)
	if t := g.chk.TypeOf(e); t != nil {
		sz = t.Size()
	}
	g.loadAt(encode.RAX, sz)
}

func (g *Gen) emitIndexAddr(e *ast.IndexExpr) {
	if types.IsSlice(g.chk.TypeOf(e.X)) {
		g.emitSliceIndexAddr(e)
		return
	}
	// Arrays are values in place - take the address of the array, not its first word.
	// Pointers: load the pointer value. (Same as C: a[i] vs p[i].)
	xt := g.chk.TypeOf(e.X)
	if _, ok := xt.(*types.ArrayType); ok {
		g.emitLValueAddr(e.X)
	} else {
		g.emitExpr(e.X)
	}
	g.buf.Push(encode.RAX)
	g.emitExpr(e.Index)
	g.buf.MovRR(encode.RCX, encode.RAX)
	g.buf.Pop(encode.RAX)
	elem := int64(1)
	if xt != nil {
		if p, ok := xt.(*types.Pointer); ok {
			elem = p.Elem.Size()
		} else if a, ok := xt.(*types.ArrayType); ok {
			elem = a.Elem.Size()
		}
	}
	if elem > 1 {
		g.buf.MovRI(encode.RDX, uint64(elem))
		g.buf.ImulRR(encode.RCX, encode.RDX)
	}
	g.buf.AddRR(encode.RAX, encode.RCX)
}

func (g *Gen) emitSelector(e *ast.SelectorExpr) {
	// package.Member (function value or global)
	if obj := g.chk.SelObj[e]; obj != nil {
		if obj.IsFunc {
			at := g.buf.LeaRIP(encode.RAX)
			g.calls = append(g.calls, relPatch{at: at, name: sema.LinkNameOf(obj)})
			return
		}
		if obj.IsGlobal {
			if obj.HasConst && obj.IsConst {
				g.buf.MovRI(encode.RAX, obj.ConstVal)
				return
			}
			g.loadGlobal(sema.LinkNameOf(obj))
			return
		}
	}
	g.emitSelectorAddr(e)
	sz := int64(8)
	if t := g.chk.TypeOf(e); t != nil {
		sz = t.Size()
		if sz > 8 {
			// large struct field: leave address in RAX
			return
		}
	}
	g.loadAt(encode.RAX, sz)
}

func (g *Gen) emitSelectorAddr(e *ast.SelectorExpr) {
	if obj := g.chk.SelObj[e]; obj != nil && obj.IsGlobal {
		at := g.buf.LeaRIP(encode.RAX)
		g.globRefs = append(g.globRefs, globPatch{at: at, name: sema.LinkNameOf(obj)})
		return
	}
	xt := g.chk.TypeOf(e.X)
	var st *types.StructType
	switch xt := xt.(type) {
	case *types.StructType:
		st = xt
		g.emitLValueAddr(e.X)
	case *types.Pointer:
		if s, ok := xt.Elem.(*types.StructType); ok {
			st = s
		}
		g.emitExpr(e.X)
	default:
		g.emitExpr(e.X)
	}
	if st == nil {
		g.errf("selector on non-struct")
		return
	}
	f, ok := st.Field(e.Sel)
	if !ok {
		g.errf("no field %s", e.Sel)
		return
	}
	if f.Offset != 0 {
		g.buf.AddRI(encode.RAX, int32(f.Offset))
	}
}

// emitLValueAddr puts the address of an lvalue into RAX.
func (g *Gen) emitLValueAddr(e ast.Expr) {
	switch e := e.(type) {
	case *ast.Ident:
		if off, ok := g.locals[e.Name]; ok {
			g.buf.LeaRegDisp(encode.RAX, encode.RBP, off)
			return
		}
		if obj := g.chk.Uses[e]; obj != nil && obj.IsGlobal {
			at := g.buf.LeaRIP(encode.RAX)
			g.globRefs = append(g.globRefs, globPatch{at: at, name: sema.LinkNameOf(obj)})
			return
		}
		if _, ok := g.globOff[e.Name]; ok {
			at := g.buf.LeaRIP(encode.RAX)
			g.globRefs = append(g.globRefs, globPatch{at: at, name: e.Name})
			return
		}
		g.errf("cannot take address of %s", e.Name)
	case *ast.UnaryExpr:
		if e.Op == token.Star {
			g.emitExpr(e.X)
			return
		}
		g.errf("not an lvalue")
	case *ast.IndexExpr:
		g.emitIndexAddr(e)
	case *ast.SelectorExpr:
		g.emitSelectorAddr(e)
	case *ast.ParenExpr:
		g.emitLValueAddr(e.X)
	default:
		g.errf("not an lvalue")
		g.buf.XorRR(encode.RAX, encode.RAX)
	}
}

func (g *Gen) sizeofType(te ast.TypeExpr) int64 {
	switch t := te.(type) {
	case *ast.IdentType:
		if ty := g.chk.LookupType(t.Name); ty != nil {
			return ty.Size()
		}
		return 8
	case *ast.QualType:
		if ty := g.chk.LookupType(t.Name); ty != nil {
			return ty.Size()
		}
		return 8
	case *ast.PtrType:
		return 8
	case *ast.SliceTypeExpr:
		return 24
	case *ast.ArrayType:
		n, _ := g.constUint(t.Len)
		return int64(n) * g.sizeofType(t.Elem)
	case *ast.FuncType:
		return 8
	}
	return 8
}

func (g *Gen) constUint(e ast.Expr) (uint64, bool) {
	if e == nil {
		return 0, false
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind == token.Int {
			v, err := parser.ParseInt(e.Value)
			return v, err == nil
		}
	}
	return 0, false
}

func alignUp(v, a int64) int64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) / a * a
}

func putInt(b []byte, v uint64, sz int) {
	for i := 0; i < sz && i < len(b); i++ {
		b[i] = byte(v >> (8 * i))
	}
}
