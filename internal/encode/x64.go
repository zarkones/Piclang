// Package encode provides minimal x86-64 machine-code emitters.
package encode

// Rex prefixes
const (
	RexW = 0x48
	RexR = 0x44
	RexX = 0x42
	RexB = 0x41
)

// Registers (low 3 bits; R8-R15 need REX.B/R)
const (
	RAX = 0
	RCX = 1
	RDX = 2
	RBX = 3
	RSP = 4
	RBP = 5
	RSI = 6
	RDI = 7
	R8  = 8
	R9  = 9
	R10 = 10
	R11 = 11
	R12 = 12
	R13 = 13
	R14 = 14
	R15 = 15
)

// Buf is a growing code buffer with patch support.
type Buf struct {
	Bytes []byte
}

func (b *Buf) Len() int { return len(b.Bytes) }

func (b *Buf) emit(bs ...byte) {
	b.Bytes = append(b.Bytes, bs...)
}

func (b *Buf) Emit(bs ...byte) { b.emit(bs...) }

func (b *Buf) EmitU32(v uint32) {
	b.emit(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func (b *Buf) EmitU64(v uint64) {
	b.emit(
		byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
		byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56),
	)
}

func (b *Buf) EmitI32(v int32) { b.EmitU32(uint32(v)) }

func (b *Buf) PatchI32(at int, v int32) {
	u := uint32(v)
	b.Bytes[at] = byte(u)
	b.Bytes[at+1] = byte(u >> 8)
	b.Bytes[at+2] = byte(u >> 16)
	b.Bytes[at+3] = byte(u >> 24)
}

func rex(w bool, reg, rm int) byte {
	r := byte(0x40)
	if w {
		r |= 0x08
	}
	if reg >= 8 {
		r |= 0x04
	}
	if rm >= 8 {
		r |= 0x01
	}
	return r
}

func modrm(mod, reg, rm int) byte {
	return byte((mod << 6) | ((reg & 7) << 3) | (rm & 7))
}

func needsRex(regs ...int) bool {
	for _, r := range regs {
		if r >= 8 {
			return true
		}
	}
	return false
}

// ---- Instructions ----

// Ret: C3
func (b *Buf) Ret() { b.emit(0xC3) }

// Int3: CC
func (b *Buf) Int3() { b.emit(0xCC) }

// Nop
func (b *Buf) Nop() { b.emit(0x90) }

// Push r
func (b *Buf) Push(r int) {
	if r >= 8 {
		b.emit(0x41, byte(0x50+(r&7)))
	} else {
		b.emit(byte(0x50 + r))
	}
}

// Pop r
func (b *Buf) Pop(r int) {
	if r >= 8 {
		b.emit(0x41, byte(0x58+(r&7)))
	} else {
		b.emit(byte(0x58 + r))
	}
}

// MovRR: mov dst, src  (64-bit)
func (b *Buf) MovRR(dst, src int) {
	// REX.W + 89 /r  : mov r/m64, r64  (src is reg, dst is rm)
	r := rex(true, src, dst)
	b.emit(r, 0x89, modrm(3, src, dst))
}

// MovRI: mov reg, imm64
func (b *Buf) MovRI(dst int, imm uint64) {
	// REX.W + B8+rd io
	r := byte(0x48)
	if dst >= 8 {
		r |= 0x01
	}
	b.emit(r, byte(0xB8+(dst&7)))
	b.EmitU64(imm)
}

// MovRI32: mov reg, imm32 sign-extended (shorter when fits)
func (b *Buf) MovRI32(dst int, imm int32) {
	// REX.W + C7 /0 id
	r := rex(true, 0, dst)
	b.emit(r, 0xC7, modrm(3, 0, dst))
	b.EmitI32(imm)
}

// XorRR: xor dst, src
func (b *Buf) XorRR(dst, src int) {
	r := rex(true, src, dst)
	b.emit(r, 0x31, modrm(3, src, dst))
}

// AddRR
func (b *Buf) AddRR(dst, src int) {
	r := rex(true, src, dst)
	b.emit(r, 0x01, modrm(3, src, dst))
}

// SubRR
func (b *Buf) SubRR(dst, src int) {
	r := rex(true, src, dst)
	b.emit(r, 0x29, modrm(3, src, dst))
}

// AndRR
func (b *Buf) AndRR(dst, src int) {
	r := rex(true, src, dst)
	b.emit(r, 0x21, modrm(3, src, dst))
}

// OrRR
func (b *Buf) OrRR(dst, src int) {
	r := rex(true, src, dst)
	b.emit(r, 0x09, modrm(3, src, dst))
}

// AddRI: add reg, imm32
func (b *Buf) AddRI(dst int, imm int32) {
	r := rex(true, 0, dst)
	if imm >= -128 && imm <= 127 {
		b.emit(r, 0x83, modrm(3, 0, dst), byte(imm))
		return
	}
	b.emit(r, 0x81, modrm(3, 0, dst))
	b.EmitI32(imm)
}

// SubRI: sub reg, imm32
func (b *Buf) SubRI(dst int, imm int32) {
	r := rex(true, 0, dst)
	if imm >= -128 && imm <= 127 {
		b.emit(r, 0x83, modrm(3, 5, dst), byte(imm))
		return
	}
	b.emit(r, 0x81, modrm(3, 5, dst))
	b.EmitI32(imm)
}

// AndRI
func (b *Buf) AndRI(dst int, imm int32) {
	r := rex(true, 0, dst)
	if imm >= -128 && imm <= 127 {
		b.emit(r, 0x83, modrm(3, 4, dst), byte(imm))
		return
	}
	b.emit(r, 0x81, modrm(3, 4, dst))
	b.EmitI32(imm)
}

// ImulRR: imul dst, src  (dst *= src)
func (b *Buf) ImulRR(dst, src int) {
	r := rex(true, dst, src)
	b.emit(r, 0x0F, 0xAF, modrm(3, dst, src))
}

// Idiv: idiv r  (rdx:rax / r)
func (b *Buf) Idiv(r int) {
	rx := rex(true, 0, r)
	b.emit(rx, 0xF7, modrm(3, 7, r))
}

// Div: div r (unsigned)
func (b *Buf) Div(r int) {
	rx := rex(true, 0, r)
	b.emit(rx, 0xF7, modrm(3, 6, r))
}

// Cqo: sign extend rax to rdx:rax
func (b *Buf) Cqo() { b.emit(0x48, 0x99) }

// Neg: neg reg
func (b *Buf) Neg(r int) {
	rx := rex(true, 0, r)
	b.emit(rx, 0xF7, modrm(3, 3, r))
}

// Not: not reg
func (b *Buf) Not(r int) {
	rx := rex(true, 0, r)
	b.emit(rx, 0xF7, modrm(3, 2, r))
}

// ShlRI / ShrRI / SarRI
func (b *Buf) ShlRI(dst int, imm byte) {
	r := rex(true, 0, dst)
	b.emit(r, 0xC1, modrm(3, 4, dst), imm)
}
func (b *Buf) ShrRI(dst int, imm byte) {
	r := rex(true, 0, dst)
	b.emit(r, 0xC1, modrm(3, 5, dst), imm)
}
func (b *Buf) SarRI(dst int, imm byte) {
	r := rex(true, 0, dst)
	b.emit(r, 0xC1, modrm(3, 7, dst), imm)
}

// ShlRCL / ShrRCL : shift by CL
func (b *Buf) ShlRCL(dst int) {
	r := rex(true, 0, dst)
	b.emit(r, 0xD3, modrm(3, 4, dst))
}
func (b *Buf) ShrRCL(dst int) {
	r := rex(true, 0, dst)
	b.emit(r, 0xD3, modrm(3, 5, dst))
}

// CmpRR
func (b *Buf) CmpRR(left, right int) {
	// cmp left, right : 3B /r (reg = left, rm = right)?
	// 39 /r: cmp r/m64, r64  => cmp left(rm), right(reg)
	r := rex(true, right, left)
	b.emit(r, 0x39, modrm(3, right, left))
}

// CmpRI
func (b *Buf) CmpRI(dst int, imm int32) {
	r := rex(true, 0, dst)
	if imm >= -128 && imm <= 127 {
		b.emit(r, 0x83, modrm(3, 7, dst), byte(imm))
		return
	}
	b.emit(r, 0x81, modrm(3, 7, dst))
	b.EmitI32(imm)
}

// TestRR
func (b *Buf) TestRR(a, reg int) {
	r := rex(true, reg, a)
	b.emit(r, 0x85, modrm(3, reg, a))
}

// Setcc: set destination byte based on flags. reg must be low byte capable.
func (b *Buf) Setcc(cc byte, dst int) {
	// 0F 9x /0  setcc r/m8
	// Need REX if dst >= 4 for SIL etc. Use REX always for safety with high regs.
	r := byte(0x40)
	if dst >= 8 {
		r |= 0x01
	}
	// for AH-style avoid; RAX-RDX fine with REX for SIL/DIL
	if dst >= 4 {
		r |= 0x00 // still emit REX for SPL etc
	}
	b.emit(r, 0x0F, 0x90+cc, modrm(3, 0, dst))
}

// Movzx8: movzx dst64, src8
func (b *Buf) Movzx8(dst, src int) {
	r := rex(true, dst, src)
	b.emit(r, 0x0F, 0xB6, modrm(3, dst, src))
}

// JmpRel32 placeholder; returns offset of disp32
func (b *Buf) JmpRel32() int {
	b.emit(0xE9)
	pos := b.Len()
	b.EmitI32(0)
	return pos
}

// JccRel32: 0F 8x rel32; returns offset of disp32
func (b *Buf) JccRel32(cc byte) int {
	b.emit(0x0F, 0x80+cc)
	pos := b.Len()
	b.EmitI32(0)
	return pos
}

// CallRel32 placeholder
func (b *Buf) CallRel32() int {
	b.emit(0xE8)
	pos := b.Len()
	b.EmitI32(0)
	return pos
}

// CallReg: call reg
func (b *Buf) CallReg(r int) {
	if r >= 8 {
		b.emit(0x41, 0xFF, modrm(3, 2, r))
	} else {
		b.emit(0xFF, modrm(3, 2, r))
	}
}

// JmpReg
func (b *Buf) JmpReg(r int) {
	if r >= 8 {
		b.emit(0x41, 0xFF, modrm(3, 4, r))
	} else {
		b.emit(0xFF, modrm(3, 4, r))
	}
}

// LeaRIP: lea reg, [rip+disp32]; returns offset of disp32 for patching
func (b *Buf) LeaRIP(dst int) int {
	r := rex(true, dst, 0)
	// lea r64, m  : 8D /r  with mod=0 rm=5 means [rip+disp32]
	b.emit(r, 0x8D, modrm(0, dst, 5))
	pos := b.Len()
	b.EmitI32(0)
	return pos
}

// MovFromRAXMem: mov dst, [base]  (64-bit)
func (b *Buf) MovRM(dst, base int) {
	// mov r64, r/m64 : 8B /r
	r := rex(true, dst, base)
	if base == RSP || base == R12 {
		b.emit(r, 0x8B, modrm(0, dst, 4), 0x24) // SIB
		return
	}
	if base == RBP || base == R13 {
		b.emit(r, 0x8B, modrm(1, dst, base), 0x00)
		return
	}
	b.emit(r, 0x8B, modrm(0, dst, base))
}

// MovMR: mov [base], src
func (b *Buf) MovMR(base, src int) {
	r := rex(true, src, base)
	if base == RSP || base == R12 {
		b.emit(r, 0x89, modrm(0, src, 4), 0x24)
		return
	}
	if base == RBP || base == R13 {
		b.emit(r, 0x89, modrm(1, src, base), 0x00)
		return
	}
	b.emit(r, 0x89, modrm(0, src, base))
}

// MovRMDisp: mov dst, [base+disp]
func (b *Buf) MovRMDisp(dst, base int, disp int32) {
	r := rex(true, dst, base)
	b.emitRMDisp(r, 0x8B, dst, base, disp)
}

// MovMRDisp: mov [base+disp], src
func (b *Buf) MovMRDisp(base int, disp int32, src int) {
	r := rex(true, src, base)
	b.emitRMDisp(r, 0x89, src, base, disp)
}

func (b *Buf) emitRMDisp(rexB byte, opcode byte, reg, base int, disp int32) {
	if base == RSP || base == R12 {
		if disp == 0 {
			b.emit(rexB, opcode, modrm(0, reg, 4), 0x24)
		} else if disp >= -128 && disp <= 127 {
			b.emit(rexB, opcode, modrm(1, reg, 4), 0x24, byte(disp))
		} else {
			b.emit(rexB, opcode, modrm(2, reg, 4), 0x24)
			b.EmitI32(disp)
		}
		return
	}
	if disp == 0 && base != RBP && base != R13 {
		b.emit(rexB, opcode, modrm(0, reg, base))
		return
	}
	if disp >= -128 && disp <= 127 {
		b.emit(rexB, opcode, modrm(1, reg, base), byte(disp))
		return
	}
	b.emit(rexB, opcode, modrm(2, reg, base))
	b.EmitI32(disp)
}

// Load sizes
func (b *Buf) Movzx8RM(dst, base int) {
	r := rex(true, dst, base)
	if base == RSP || base == R12 {
		b.emit(r, 0x0F, 0xB6, modrm(0, dst, 4), 0x24)
		return
	}
	if base == RBP || base == R13 {
		b.emit(r, 0x0F, 0xB6, modrm(1, dst, base), 0)
		return
	}
	b.emit(r, 0x0F, 0xB6, modrm(0, dst, base))
}

func (b *Buf) Movzx16RM(dst, base int) {
	r := rex(true, dst, base)
	if base == RSP || base == R12 {
		b.emit(r, 0x0F, 0xB7, modrm(0, dst, 4), 0x24)
		return
	}
	if base == RBP || base == R13 {
		b.emit(r, 0x0F, 0xB7, modrm(1, dst, base), 0)
		return
	}
	b.emit(r, 0x0F, 0xB7, modrm(0, dst, base))
}

func (b *Buf) Movzx32RM(dst, base int) {
	// mov r32, [base] - zero-extends into r64
	if dst >= 8 || base >= 8 {
		b.emit(rex(false, dst, base))
	}
	if base == RSP || base == R12 {
		b.emit(0x8B, modrm(0, dst, 4), 0x24)
	} else if base == RBP || base == R13 {
		b.emit(0x8B, modrm(1, dst, base), 0)
	} else {
		b.emit(0x8B, modrm(0, dst, base))
	}
}

// Store sizes from RAX-style (low part of src)
func (b *Buf) Mov8MR(base, src int) {
	// mov r/m8, r8 : 88 /r
	r := byte(0x40)
	if src >= 8 {
		r |= 0x04
	}
	if base >= 8 {
		r |= 0x01
	}
	// always REX for SIL/DIL when src is RSI/RDI etc.
	if src >= 4 || base >= 8 || src >= 8 {
		b.emit(r)
	}
	if base == RSP || base == R12 {
		b.emit(0x88, modrm(0, src, 4), 0x24)
	} else if base == RBP || base == R13 {
		b.emit(0x88, modrm(1, src, base), 0)
	} else {
		b.emit(0x88, modrm(0, src, base))
	}
}

func (b *Buf) Mov16MR(base, src int) {
	// 66 89 /r
	r := byte(0x40)
	if src >= 8 {
		r |= 0x04
	}
	if base >= 8 {
		r |= 0x01
	}
	b.emit(0x66)
	if src >= 8 || base >= 8 {
		b.emit(r)
	}
	if base == RSP || base == R12 {
		b.emit(0x89, modrm(0, src, 4), 0x24)
	} else if base == RBP || base == R13 {
		b.emit(0x89, modrm(1, src, base), 0)
	} else {
		b.emit(0x89, modrm(0, src, base))
	}
}

func (b *Buf) Mov32MR(base, src int) {
	r := byte(0x40)
	if src >= 8 {
		r |= 0x04
	}
	if base >= 8 {
		r |= 0x01
	}
	if src >= 8 || base >= 8 {
		b.emit(r)
	}
	if base == RSP || base == R12 {
		b.emit(0x89, modrm(0, src, 4), 0x24)
	} else if base == RBP || base == R13 {
		b.emit(0x89, modrm(1, src, base), 0)
	} else {
		b.emit(0x89, modrm(0, src, base))
	}
}

// GS segment loads: mov reg, qword gs:[offset]
// encoding: 65 REX.W 8B /r  with modrm for abs disp32 (mod=0 rm=4/5 tricks)
// Use: 65 48 8B 04 25 XX XX XX XX  => mov rax, gs:[imm32]  (SIB special)
func (b *Buf) MovGSAbs(dst int, offset uint32) {
	// segment override GS=65
	r := rex(true, dst, 0)
	b.emit(0x65, r, 0x8B, modrm(0, dst, 4), 0x25) // SIB: index=none base=none disp32
	b.EmitU32(offset)
}

// mov gs:[offset], src
func (b *Buf) MovGSAbsStore(offset uint32, src int) {
	r := rex(true, src, 0)
	b.emit(0x65, r, 0x89, modrm(0, src, 4), 0x25)
	b.EmitU32(offset)
}

// Syscall instruction
func (b *Buf) Syscall() { b.emit(0x0F, 0x05) }

// Rdtsc
func (b *Buf) Rdtsc() { b.emit(0x0F, 0x31) }

// LeaRegDisp: lea dst, [base+disp]
func (b *Buf) LeaRegDisp(dst, base int, disp int32) {
	r := rex(true, dst, base)
	b.emitRMDisp(r, 0x8D, dst, base, disp)
}

// Condition codes for jcc/setcc
const (
	CC_O  = 0x0
	CC_NO = 0x1
	CC_B  = 0x2 // CF
	CC_AE = 0x3
	CC_E  = 0x4 // ZF
	CC_NE = 0x5
	CC_BE = 0x6
	CC_A  = 0x7
	CC_S  = 0x8
	CC_NS = 0x9
	CC_P  = 0xA
	CC_NP = 0xB
	CC_L  = 0xC // SF!=OF
	CC_GE = 0xD
	CC_LE = 0xE
	CC_G  = 0xF
)

// PatchRel32 patches a relative displacement at `at` to target absolute offset `target`.
// Instruction end is at+4.
func (b *Buf) PatchRel32(at int, target int) {
	// rel = target - (at+4)
	rel := int32(target - (at + 4))
	b.PatchI32(at, rel)
}

// Align pads with nops to alignment.
func (b *Buf) Align(a int) {
	for b.Len()%a != 0 {
		b.Nop()
	}
}
