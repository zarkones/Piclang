package types

import "fmt"

// Kind of a type.
type Kind int

const (
	Invalid Kind = iota
	Void
	Bool
	U8
	U16
	U32
	U64
	I8
	I16
	I32
	I64
	Ptr
	Array
	Slice
	Struct
	Func
	TupleKind
	String // *u8 string literal type (decays to *u8)
)

// Slice header packing: owns flag in high bit of cap field (ABI: 3×u64).
const (
	SliceOwnBit  uint64 = 1 << 63
	SliceCapMask uint64 = (1 << 63) - 1
)

// PackCap stores capacity and owns flag into one u64.
func PackCap(cap uint64, owns bool) uint64 {
	c := cap & SliceCapMask
	if owns {
		return c | SliceOwnBit
	}
	return c
}

// UnpackCap extracts capacity and owns flag.
func UnpackCap(capField uint64) (cap uint64, owns bool) {
	return capField & SliceCapMask, capField&SliceOwnBit != 0
}

// Type is a resolved type.
type Type interface {
	Kind() Kind
	Size() int64
	Align() int64
	String() string
	Equals(Type) bool
}

// Basic is a primitive type.
type Basic struct {
	K Kind
}

func (b *Basic) Kind() Kind { return b.K }
func (b *Basic) Size() int64 {
	switch b.K {
	case Void:
		return 0
	case Bool, U8, I8:
		return 1
	case U16, I16:
		return 2
	case U32, I32:
		return 4
	case U64, I64:
		return 8
	}
	return 0
}
func (b *Basic) Align() int64 {
	s := b.Size()
	if s == 0 {
		return 1
	}
	return s
}
func (b *Basic) String() string {
	names := map[Kind]string{
		Void: "void", Bool: "bool",
		U8: "u8", U16: "u16", U32: "u32", U64: "u64",
		I8: "i8", I16: "i16", I32: "i32", I64: "i64",
	}
	return names[b.K]
}
func (b *Basic) Equals(o Type) bool {
	ob, ok := o.(*Basic)
	return ok && ob.K == b.K
}

// Pointer type.
type Pointer struct {
	Elem Type
}

func (p *Pointer) Kind() Kind   { return Ptr }
func (p *Pointer) Size() int64  { return 8 }
func (p *Pointer) Align() int64 { return 8 }
func (p *Pointer) String() string {
	if p.Elem == nil {
		return "*<?>"
	}
	return "*" + p.Elem.String()
}
func (p *Pointer) Equals(o Type) bool {
	op, ok := o.(*Pointer)
	if !ok {
		return false
	}
	if p.Elem == nil || op.Elem == nil {
		return p.Elem == op.Elem
	}
	// *void matches any pointer for assignment purposes in Equals strict check -
	// keep strict; use Assignable separately.
	return p.Elem.Equals(op.Elem)
}

// ArrayType [N]T
type ArrayType struct {
	Elem Type
	Len  int64
}

func (a *ArrayType) Kind() Kind   { return Array }
func (a *ArrayType) Size() int64  { return a.Elem.Size() * a.Len }
func (a *ArrayType) Align() int64 { return a.Elem.Align() }
func (a *ArrayType) String() string {
	return fmt.Sprintf("[%d]%s", a.Len, a.Elem.String())
}
func (a *ArrayType) Equals(o Type) bool {
	oa, ok := o.(*ArrayType)
	return ok && a.Len == oa.Len && a.Elem.Equals(oa.Elem)
}

// SliceType is []T - header (ptr, len, cap_field), 24 bytes.
type SliceType struct {
	Elem Type
}

func (s *SliceType) Kind() Kind   { return Slice }
func (s *SliceType) Size() int64  { return 24 }
func (s *SliceType) Align() int64 { return 8 }
func (s *SliceType) String() string {
	if s.Elem == nil {
		return "[]<?>"
	}
	return "[]" + s.Elem.String()
}
func (s *SliceType) Equals(o Type) bool {
	os, ok := o.(*SliceType)
	return ok && s.Elem.Equals(os.Elem)
}

// StructType
type StructType struct {
	Name   string
	Fields []StructField
	size   int64
	align  int64
}

type StructField struct {
	Name   string
	Type   Type
	Offset int64
}

func (s *StructType) Kind() Kind   { return Struct }
func (s *StructType) Size() int64  { return s.size }
func (s *StructType) Align() int64 { return s.align }
func (s *StructType) String() string {
	if s.Name != "" {
		return s.Name
	}
	return "struct"
}
func (s *StructType) Equals(o Type) bool {
	os, ok := o.(*StructType)
	return ok && s == os // identity
}

func (s *StructType) Field(name string) (StructField, bool) {
	for _, f := range s.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return StructField{}, false
}

// Layout computes field offsets.
func (s *StructType) Layout() {
	var off int64
	var maxAlign int64 = 1
	for i := range s.Fields {
		a := s.Fields[i].Type.Align()
		if a > maxAlign {
			maxAlign = a
		}
		off = alignUp(off, a)
		s.Fields[i].Offset = off
		off += s.Fields[i].Type.Size()
	}
	s.align = maxAlign
	s.size = alignUp(off, maxAlign)
	if s.size == 0 {
		s.size = 1
	}
}

// FuncType is a function (or function pointer) signature.
// Results: empty = void; one element = single return; multiple = multi-return.
type FuncType struct {
	Params  []Type
	Results []Type
	// Ret is kept for compatibility: same as Results[0] when len==1, else Void or first.
	// Prefer Results. SetRet/Result helpers below.
	Ret Type
}

// SetResults sets Results and synchronizes Ret for single-result APIs.
func (f *FuncType) SetResults(rs []Type) {
	f.Results = rs
	if len(rs) == 0 {
		f.Ret = TyVoid
	} else if len(rs) == 1 {
		f.Ret = rs[0]
	} else {
		f.Ret = &Tuple{Elems: rs}
	}
}

// ResultTypes returns Results, falling back to Ret for older construction.
func (f *FuncType) ResultTypes() []Type {
	if len(f.Results) > 0 {
		return f.Results
	}
	if f.Ret == nil || f.Ret.Kind() == Void {
		return nil
	}
	if t, ok := f.Ret.(*Tuple); ok {
		return t.Elems
	}
	return []Type{f.Ret}
}

// NumResults is the count of logical results (0 = void).
func (f *FuncType) NumResults() int {
	return len(f.ResultTypes())
}

func (f *FuncType) Kind() Kind   { return Func }
func (f *FuncType) Size() int64  { return 8 } // as pointer
func (f *FuncType) Align() int64 { return 8 }
func (f *FuncType) String() string {
	s := "fn("
	for i, p := range f.Params {
		if i > 0 {
			s += ", "
		}
		s += p.String()
	}
	s += ")"
	rs := f.ResultTypes()
	if len(rs) == 1 && rs[0].Kind() != Void {
		s += " -> " + rs[0].String()
	} else if len(rs) > 1 {
		s += " -> ("
		for i, r := range rs {
			if i > 0 {
				s += ", "
			}
			s += r.String()
		}
		s += ")"
	}
	return s
}
func (f *FuncType) Equals(o Type) bool {
	of, ok := o.(*FuncType)
	if !ok || len(f.Params) != len(of.Params) {
		return false
	}
	for i := range f.Params {
		if !f.Params[i].Equals(of.Params[i]) {
			return false
		}
	}
	a, b := f.ResultTypes(), of.ResultTypes()
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equals(b[i]) {
			return false
		}
	}
	return true
}

// Tuple is a multi-value type (function results / multi-assign RHS).
type Tuple struct {
	Elems []Type
}

func (t *Tuple) Kind() Kind   { return TupleKind }
func (t *Tuple) Size() int64  { return 0 } // not a first-class stack value as a blob
func (t *Tuple) Align() int64 { return 8 }
func (t *Tuple) String() string {
	s := "("
	for i, e := range t.Elems {
		if i > 0 {
			s += ", "
		}
		s += e.String()
	}
	return s + ")"
}
func (t *Tuple) Equals(o Type) bool {
	ot, ok := o.(*Tuple)
	if !ok || len(t.Elems) != len(ot.Elems) {
		return false
	}
	for i := range t.Elems {
		if !t.Elems[i].Equals(ot.Elems[i]) {
			return false
		}
	}
	return true
}

// ABICells returns how many integer registers/stack slots a type occupies when
// returned from a function (slice = 3, most scalars = 1).
func ABICells(t Type) int {
	if t == nil || t.Kind() == Void {
		return 0
	}
	if t.Kind() == Slice {
		return 3
	}
	return 1
}

// TotalABICells sums ABI cells for a result list (max useful = 4).
func TotalABICells(rs []Type) int {
	n := 0
	for _, t := range rs {
		n += ABICells(t)
	}
	return n
}

// Predeclared basics
var (
	TyVoid  = &Basic{K: Void}
	TyBool  = &Basic{K: Bool}
	TyU8    = &Basic{K: U8}
	TyU16   = &Basic{K: U16}
	TyU32   = &Basic{K: U32}
	TyU64   = &Basic{K: U64}
	TyI8    = &Basic{K: I8}
	TyI16   = &Basic{K: I16}
	TyI32   = &Basic{K: I32}
	TyI64   = &Basic{K: I64}
	TyPU8   = &Pointer{Elem: TyU8}
	TyPVoid = &Pointer{Elem: TyVoid}
)

// BuiltinMap maps type names to types.
func BuiltinMap() map[string]Type {
	return map[string]Type{
		"void": TyVoid,
		"bool": TyBool,
		"u8":   TyU8,
		"u16":  TyU16,
		"u32":  TyU32,
		"u64":  TyU64,
		"i8":   TyI8,
		"i16":  TyI16,
		"i32":  TyI32,
		"i64":  TyI64,
		// C-ish aliases
		"byte":    TyU8,
		"char":    TyU8,
		"usize":   TyU64,
		"isize":   TyI64,
		"intptr":  TyI64,
		"uintptr": TyU64,
	}
}

func alignUp(v, a int64) int64 {
	if a <= 1 {
		return v
	}
	return (v + a - 1) / a * a
}

// IsInteger reports integer kinds.
func IsInteger(t Type) bool {
	if t == nil {
		return false
	}
	switch t.Kind() {
	case U8, U16, U32, U64, I8, I16, I32, I64, Bool:
		return true
	}
	return false
}

// IsSigned reports signed integer.
func IsSigned(t Type) bool {
	if t == nil {
		return false
	}
	switch t.Kind() {
	case I8, I16, I32, I64:
		return true
	}
	return false
}

// IsPointer reports pointer type.
func IsPointer(t Type) bool {
	return t != nil && t.Kind() == Ptr
}

// IsFunc reports function type.
func IsFunc(t Type) bool {
	return t != nil && t.Kind() == Func
}

// IsSlice reports slice type.
func IsSlice(t Type) bool {
	return t != nil && t.Kind() == Slice
}

// SliceElem returns element type of a slice, or nil.
func SliceElem(t Type) Type {
	if s, ok := t.(*SliceType); ok {
		return s.Elem
	}
	return nil
}

// Assignable reports if value of src can be assigned to dst.
func Assignable(dst, src Type) bool {
	if dst == nil || src == nil {
		return false
	}
	if dst.Equals(src) {
		return true
	}
	// slices: same element type only (strict)
	if dst.Kind() == Slice && src.Kind() == Slice {
		return dst.(*SliceType).Elem.Equals(src.(*SliceType).Elem)
	}
	// integer widening / same class
	if IsInteger(dst) && IsInteger(src) {
		return true
	}
	// any pointer <-> *void
	if IsPointer(dst) && IsPointer(src) {
		de := dst.(*Pointer).Elem
		se := src.(*Pointer).Elem
		if de.Kind() == Void || se.Kind() == Void {
			return true
		}
		// *u8 and string-like
		if de.Equals(se) {
			return true
		}
		// allow pointer cast between any pointers (implant code needs this)
		return true
	}
	// function pointer to *void or another fn
	if IsFunc(src) && IsPointer(dst) {
		return true
	}
	if IsFunc(dst) && IsPointer(src) {
		return true
	}
	if IsFunc(dst) && IsFunc(src) {
		return dst.Equals(src)
	}
	// integer to pointer and reverse (common in PEB code)
	if IsPointer(dst) && IsInteger(src) {
		return true
	}
	if IsInteger(dst) && IsPointer(src) {
		return true
	}
	if IsFunc(dst) && IsInteger(src) {
		return true
	}
	return false
}

// Underlying peels nothing for now (aliases resolved at check time).
func Underlying(t Type) Type { return t }
