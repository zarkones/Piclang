package token

// Kind identifies a lexical token.
type Kind int

const (
	Illegal Kind = iota
	EOF
	Comment

	// Identifiers and literals
	Ident
	Int
	Float
	String
	Char

	// Keywords
	Fn
	Var
	Const
	Type
	Struct
	If
	Else
	While
	For
	Return
	Defer
	Break
	Continue
	True
	False
	Null
	Cast
	Sizeof
	Make
	Append
	Len
	Cap
	Copy
	Free
	As
	Import
	Package
	Pub
	Extern
	Asm

	// Operators
	Assign    // =
	Define    // :=
	Plus      // +
	Minus     // -
	Star      // *
	Slash     // /
	Percent   // %
	Amp       // &
	Pipe      // |
	Caret     // ^
	Tilde     // ~
	Bang      // !
	Lt        // <
	Gt        // >
	Question  // ?
	Colon     // :
	Semicolon // ;
	Comma     // ,
	Dot       // .
	LParen    // (
	RParen    // )
	LBrace    // {
	RBrace    // }
	LBracket  // [
	RBracket  // ]
	Arrow     // ->
	Ellipsis  // ...

	Eq      // ==
	Neq     // !=
	Le      // <=
	Ge      // >=
	AndAnd  // &&
	OrOr    // ||
	Shl     // <<
	Shr     // >>
	PlusEq  // +=
	MinusEq // -=
	StarEq  // *=
	SlashEq // /=
	Inc     // ++
	Dec     // --
)

var keywords = map[string]Kind{
	"fn":       Fn,
	"var":      Var,
	"const":    Const,
	"type":     Type,
	"struct":   Struct,
	"if":       If,
	"else":     Else,
	"while":    While,
	"for":      For,
	"return":   Return,
	"defer":    Defer,
	"break":    Break,
	"continue": Continue,
	"true":     True,
	"false":    False,
	"null":     Null,
	"nil":      Null,
	"cast":     Cast,
	"sizeof":   Sizeof,
	"make":     Make,
	"append":   Append,
	"len":      Len,
	"cap":      Cap,
	"copy":     Copy,
	"free":     Free,
	"as":       As,
	"import":   Import,
	"package":  Package,
	"pub":      Pub,
	"extern":   Extern,
	"asm":      Asm,
}

// LookupIdent returns the keyword kind or Ident.
func LookupIdent(s string) Kind {
	if k, ok := keywords[s]; ok {
		return k
	}
	return Ident
}

func (k Kind) String() string {
	names := map[Kind]string{
		Illegal: "ILLEGAL", EOF: "EOF", Comment: "COMMENT",
		Ident: "IDENT", Int: "INT", Float: "FLOAT", String: "STRING", Char: "CHAR",
		Fn: "fn", Var: "var", Const: "const", Type: "type", Struct: "struct",
		If: "if", Else: "else", While: "while", For: "for",
		Return: "return", Defer: "defer", Break: "break", Continue: "continue",
		True: "true", False: "false", Null: "null", Cast: "cast", Sizeof: "sizeof",
		Make: "make", Append: "append", Len: "len", Cap: "cap", Copy: "copy", Free: "free",
		As: "as", Import: "import", Package: "package", Pub: "pub", Extern: "extern", Asm: "asm",
		Assign: "=", Define: ":=", Plus: "+", Minus: "-", Star: "*", Slash: "/", Percent: "%",
		Amp: "&", Pipe: "|", Caret: "^", Tilde: "~", Bang: "!",
		Lt: "<", Gt: ">", Question: "?", Colon: ":", Semicolon: ";", Comma: ",",
		Dot: ".", LParen: "(", RParen: ")", LBrace: "{", RBrace: "}",
		LBracket: "[", RBracket: "]", Arrow: "->", Ellipsis: "...",
		Eq: "==", Neq: "!=", Le: "<=", Ge: ">=", AndAnd: "&&", OrOr: "||",
		Shl: "<<", Shr: ">>", PlusEq: "+=", MinusEq: "-=", StarEq: "*=", SlashEq: "/=",
		Inc: "++", Dec: "--",
	}
	if s, ok := names[k]; ok {
		return s
	}
	return "UNKNOWN"
}

// Token is a single lexeme with source position.
type Token struct {
	Kind   Kind
	Lit    string
	Line   int
	Column int
	Offset int
}
