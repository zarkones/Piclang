package lexer

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/piclang/piclang/internal/token"
)

// Lexer tokenizes Piclang source.
type Lexer struct {
	src    string
	pos    int
	line   int
	col    int
	ch     rune
	width  int
	errors []string

	// Go-style automatic semicolon insertion
	lastKind   token.Kind
	insertSemi bool // pending synthetic ';'
	sawNewline bool // newline skipped since last real token
}

// New creates a lexer for src.
func New(src string) *Lexer {
	l := &Lexer{src: src, line: 1, col: 0, lastKind: token.Illegal}
	l.advance()
	return l
}

// Errors returns accumulated lexing errors.
func (l *Lexer) Errors() []string { return l.errors }

// endsStatement reports tokens after which a newline inserts ';'.
func endsStatement(k token.Kind) bool {
	switch k {
	case token.Ident, token.Int, token.Float, token.String, token.Char,
		token.True, token.False, token.Null,
		token.Return, token.Break, token.Continue,
		token.RParen, token.RBracket, token.RBrace,
		token.Inc, token.Dec:
		return true
	}
	return false
}

// noASIBefore: do not insert ';' when the next char continues a list/group.
func noASIBefore(ch rune) bool {
	switch ch {
	case ')', ']', '}', ',', '.', ':':
		return true
	}
	return false
}

func (l *Lexer) advance() {
	if l.pos >= len(l.src) {
		l.ch = 0
		l.width = 0
		return
	}
	r, w := utf8.DecodeRuneInString(l.src[l.pos:])
	l.ch = r
	l.width = w
	l.pos += w
	if r == '\n' {
		l.line++
		l.col = 0
	} else {
		l.col++
	}
}

func (l *Lexer) peek() rune {
	if l.pos >= len(l.src) {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(l.src[l.pos:])
	return r
}

func (l *Lexer) at(off int) rune {
	p := l.pos
	for i := 0; i < off; i++ {
		if p >= len(l.src) {
			return 0
		}
		_, w := utf8.DecodeRuneInString(l.src[p:])
		p += w
	}
	if p >= len(l.src) {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(l.src[p:])
	return r
}

// Next returns the next token.
func (l *Lexer) Next() token.Token {
	if l.insertSemi {
		l.insertSemi = false
		tok := token.Token{Kind: token.Semicolon, Lit: ";", Line: l.line, Column: l.col}
		l.lastKind = token.Semicolon
		return tok
	}

	l.sawNewline = false
	l.skipSpaceAndComments()
	tok := token.Token{Line: l.line, Column: l.col, Offset: l.pos - l.width}

	if l.ch == 0 {
		tok.Kind = token.EOF
		l.lastKind = token.EOF
		return tok
	}

	// ASI: newline after statement-ending token before next token.
	// Skip insertion before closers/comma so multi-line calls/params stay valid:
	//   foo(\n  1\n)  and  fn f(\n  a: u64\n)
	if l.sawNewline && endsStatement(l.lastKind) && !noASIBefore(l.ch) {
		semi := token.Token{Kind: token.Semicolon, Lit: ";", Line: tok.Line, Column: tok.Column}
		l.lastKind = token.Semicolon
		return semi
	}

	switch {
	case isIdentStart(l.ch):
		t := l.ident()
		l.lastKind = t.Kind
		return t
	case unicode.IsDigit(l.ch):
		t := l.number()
		l.lastKind = t.Kind
		return t
	case l.ch == '"':
		t := l.stringLit()
		l.lastKind = t.Kind
		return t
	case l.ch == '\'':
		t := l.charLit()
		l.lastKind = t.Kind
		return t
	}

	ch := l.ch
	l.advance()
	switch ch {
	case '=':
		if l.ch == '=' {
			l.advance()
			tok.Kind = token.Eq
			tok.Lit = "=="
			return tok
		}
		tok.Kind = token.Assign
		tok.Lit = "="
	case '+':
		if l.ch == '=' {
			l.advance()
			tok.Kind = token.PlusEq
			tok.Lit = "+="
			return tok
		}
		if l.ch == '+' {
			l.advance()
			tok.Kind = token.Inc
			tok.Lit = "++"
			return tok
		}
		tok.Kind = token.Plus
		tok.Lit = "+"
	case '-':
		if l.ch == '=' {
			l.advance()
			tok.Kind = token.MinusEq
			tok.Lit = "-="
			return tok
		}
		if l.ch == '-' {
			l.advance()
			tok.Kind = token.Dec
			tok.Lit = "--"
			return tok
		}
		if l.ch == '>' {
			l.advance()
			tok.Kind = token.Arrow
			tok.Lit = "->"
			return tok
		}
		tok.Kind = token.Minus
		tok.Lit = "-"
	case '*':
		if l.ch == '=' {
			l.advance()
			tok.Kind = token.StarEq
			tok.Lit = "*="
			return tok
		}
		tok.Kind = token.Star
		tok.Lit = "*"
	case '/':
		if l.ch == '=' {
			l.advance()
			tok.Kind = token.SlashEq
			tok.Lit = "/="
			return tok
		}
		tok.Kind = token.Slash
		tok.Lit = "/"
	case '%':
		tok.Kind = token.Percent
		tok.Lit = "%"
	case '&':
		if l.ch == '&' {
			l.advance()
			tok.Kind = token.AndAnd
			tok.Lit = "&&"
			return tok
		}
		tok.Kind = token.Amp
		tok.Lit = "&"
	case '|':
		if l.ch == '|' {
			l.advance()
			tok.Kind = token.OrOr
			tok.Lit = "||"
			return tok
		}
		tok.Kind = token.Pipe
		tok.Lit = "|"
	case '^':
		tok.Kind = token.Caret
		tok.Lit = "^"
	case '~':
		tok.Kind = token.Tilde
		tok.Lit = "~"
	case '!':
		if l.ch == '=' {
			l.advance()
			tok.Kind = token.Neq
			tok.Lit = "!="
			return tok
		}
		tok.Kind = token.Bang
		tok.Lit = "!"
	case '<':
		if l.ch == '=' {
			l.advance()
			tok.Kind = token.Le
			tok.Lit = "<="
			return tok
		}
		if l.ch == '<' {
			l.advance()
			tok.Kind = token.Shl
			tok.Lit = "<<"
			return tok
		}
		tok.Kind = token.Lt
		tok.Lit = "<"
	case '>':
		if l.ch == '=' {
			l.advance()
			tok.Kind = token.Ge
			tok.Lit = ">="
			return tok
		}
		if l.ch == '>' {
			l.advance()
			tok.Kind = token.Shr
			tok.Lit = ">>"
			return tok
		}
		tok.Kind = token.Gt
		tok.Lit = ">"
	case '.':
		if l.ch == '.' && l.peek() == '.' {
			l.advance()
			l.advance()
			tok.Kind = token.Ellipsis
			tok.Lit = "..."
			return tok
		}
		tok.Kind = token.Dot
		tok.Lit = "."
	case ',':
		tok.Kind = token.Comma
		tok.Lit = ","
	case ';':
		tok.Kind = token.Semicolon
		tok.Lit = ";"
	case ':':
		if l.ch == '=' {
			l.advance()
			tok.Kind = token.Define
			tok.Lit = ":="
			return tok
		}
		tok.Kind = token.Colon
		tok.Lit = ":"
	case '?':
		tok.Kind = token.Question
		tok.Lit = "?"
	case '(':
		tok.Kind = token.LParen
		tok.Lit = "("
	case ')':
		tok.Kind = token.RParen
		tok.Lit = ")"
	case '{':
		tok.Kind = token.LBrace
		tok.Lit = "{"
	case '}':
		tok.Kind = token.RBrace
		tok.Lit = "}"
	case '[':
		tok.Kind = token.LBracket
		tok.Lit = "["
	case ']':
		tok.Kind = token.RBracket
		tok.Lit = "]"
	default:
		tok.Kind = token.Illegal
		tok.Lit = string(ch)
		l.errors = append(l.errors, fmt.Sprintf("%d:%d: illegal character %q", tok.Line, tok.Column, ch))
	}
	l.lastKind = tok.Kind
	return tok
}

func (l *Lexer) skipSpaceAndComments() {
	for {
		for unicode.IsSpace(l.ch) {
			if l.ch == '\n' {
				l.sawNewline = true
			}
			l.advance()
		}
		if l.ch == '/' && l.peek() == '/' {
			for l.ch != 0 && l.ch != '\n' {
				l.advance()
			}
			continue
		}
		if l.ch == '/' && l.peek() == '*' {
			l.advance()
			l.advance()
			for l.ch != 0 {
				if l.ch == '*' && l.peek() == '/' {
					l.advance()
					l.advance()
					break
				}
				l.advance()
			}
			continue
		}
		break
	}
}

func (l *Lexer) ident() token.Token {
	start := l.pos - l.width
	line, col := l.line, l.col
	for isIdentPart(l.ch) {
		l.advance()
	}
	lit := l.src[start : l.pos-l.width]
	if l.width == 0 && l.pos == len(l.src) {
		lit = l.src[start:]
	} else {
		// recompute end: pos is after last consumed; last char width already counted
		end := l.pos - l.width
		if end < start {
			end = l.pos
		}
		// fix: after loop, ch is first non-ident; lit should be [start, pos-width)
		// Actually when we exit, pos points past first non-matching. width is that char.
		// So ident is [start, pos-width)
		lit = l.src[start : l.pos-l.width]
		if l.ch == 0 {
			lit = l.src[start:]
		}
	}
	// Clean approach:
	end := l.pos
	if l.ch != 0 {
		end = l.pos - l.width
	}
	lit = l.src[start:end]
	return token.Token{
		Kind:   token.LookupIdent(lit),
		Lit:    lit,
		Line:   line,
		Column: col,
		Offset: start,
	}
}

func (l *Lexer) number() token.Token {
	start := l.pos - l.width
	line, col := l.line, l.col
	// hex
	if l.ch == '0' && (l.peek() == 'x' || l.peek() == 'X') {
		l.advance()
		l.advance()
		for isHex(l.ch) {
			l.advance()
		}
	} else {
		for unicode.IsDigit(l.ch) {
			l.advance()
		}
	}
	end := l.pos
	if l.ch != 0 {
		end = l.pos - l.width
	}
	lit := l.src[start:end]
	return token.Token{Kind: token.Int, Lit: lit, Line: line, Column: col, Offset: start}
}

func (l *Lexer) stringLit() token.Token {
	line, col := l.line, l.col
	start := l.pos - l.width
	l.advance() // skip "
	var b []byte
	for l.ch != 0 && l.ch != '"' {
		if l.ch == '\\' {
			l.advance()
			switch l.ch {
			case 'n':
				b = append(b, '\n')
			case 'r':
				b = append(b, '\r')
			case 't':
				b = append(b, '\t')
			case '0':
				b = append(b, 0)
			case '\\':
				b = append(b, '\\')
			case '"':
				b = append(b, '"')
			case 'x':
				l.advance()
				h1, h2 := l.ch, rune(0)
				l.advance()
				h2 = l.ch
				b = append(b, byte(hexVal(h1)<<4|hexVal(h2)))
			default:
				b = append(b, byte(l.ch))
			}
			l.advance()
			continue
		}
		// encode rune as UTF-8
		var buf [utf8.UTFMax]byte
		n := utf8.EncodeRune(buf[:], l.ch)
		b = append(b, buf[:n]...)
		l.advance()
	}
	if l.ch != '"' {
		l.errors = append(l.errors, fmt.Sprintf("%d:%d: unterminated string", line, col))
	} else {
		l.advance()
	}
	return token.Token{Kind: token.String, Lit: string(b), Line: line, Column: col, Offset: start}
}

func (l *Lexer) charLit() token.Token {
	line, col := l.line, l.col
	start := l.pos - l.width
	l.advance()
	var val byte
	if l.ch == '\\' {
		l.advance()
		switch l.ch {
		case 'n':
			val = '\n'
		case 'r':
			val = '\r'
		case 't':
			val = '\t'
		case '0':
			val = 0
		case '\'':
			val = '\''
		case '\\':
			val = '\\'
		default:
			val = byte(l.ch)
		}
		l.advance()
	} else {
		val = byte(l.ch)
		l.advance()
	}
	if l.ch == '\'' {
		l.advance()
	}
	return token.Token{Kind: token.Char, Lit: string([]byte{val}), Line: line, Column: col, Offset: start}
}

func isIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isHex(r rune) bool {
	return unicode.IsDigit(r) || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func hexVal(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0')
	case r >= 'a' && r <= 'f':
		return int(r-'a') + 10
	case r >= 'A' && r <= 'F':
		return int(r-'A') + 10
	}
	return 0
}
