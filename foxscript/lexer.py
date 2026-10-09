"""FoxScript lexer: source text -> token stream.

Tokens carry type, lexeme, literal value, and line number. NEWLINE tokens are
emitted as statement terminators, but suppressed inside ([{...}] so
multi-line expressions just work. `//` comments run to end of line.
"""


class LexError(Exception):
    pass


class Token:
    __slots__ = ("type", "lexeme", "literal", "line")

    def __init__(self, type, lexeme, literal, line):
        self.type = type
        self.lexeme = lexeme
        self.literal = literal
        self.line = line

    def __repr__(self):
        return "Token(%s, %r, %r, line %d)" % (
            self.type, self.lexeme, self.literal, self.line)


KEYWORDS = {
    "let": "LET", "fn": "FN", "if": "IF", "else": "ELSE",
    "while": "WHILE", "for": "FOR", "return": "RETURN",
    "true": "TRUE", "false": "FALSE", "nil": "NIL",
}

ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "0": "\0"}


class Lexer:
    def __init__(self, source):
        self.src = source
        self.tokens = []
        self.start = 0
        self.pos = 0
        self.line = 1
        self.depth = 0  # ([{ nesting level; NEWLINE suppressed when > 0

    # ---- driver ------------------------------------------------------
    def tokenize(self):
        while not self._at_end():
            self.start = self.pos
            self._scan()
        self.tokens.append(Token("EOF", "", None, self.line))
        return self.tokens

    # ---- char helpers -------------------------------------------------
    def _at_end(self):
        return self.pos >= len(self.src)

    def _advance(self):
        c = self.src[self.pos]
        self.pos += 1
        return c

    def _peek(self):
        return "\0" if self._at_end() else self.src[self.pos]

    def _peek2(self):
        i = self.pos + 1
        return "\0" if i >= len(self.src) else self.src[i]

    def _match(self, c):
        if self._at_end() or self.src[self.pos] != c:
            return False
        self.pos += 1
        return True

    def _add(self, type, literal=None):
        self.tokens.append(Token(type, self.src[self.start:self.pos],
                                literal, self.line))

    def _error(self, msg):
        raise LexError("line %d: %s" % (self.line, msg))

    # ---- main scan ----------------------------------------------------
    def _scan(self):
        c = self._advance()
        if c in " \t\r":
            return
        if c == "\n":
            self.line += 1
            if self.depth == 0:
                self._add("NEWLINE")
            return
        if c == "/" and self._peek() == "/":
            while self._peek() != "\n" and not self._at_end():
                self._advance()
            return
        if c == "(":
            self.depth += 1
            self._add("LPAREN")
        elif c == ")":
            self._bracket("RPAREN")
        elif c == "{":
            self.depth += 1
            self._add("LBRACE")
        elif c == "}":
            self._bracket("RBRACE")
        elif c == "[":
            self.depth += 1
            self._add("LBRACKET")
        elif c == "]":
            self._bracket("RBRACKET")
        elif c == ",":
            self._add("COMMA")
        elif c == ";":
            self._add("SEMI")
        elif c == ":":
            self._add("COLON")
        elif c == "+":
            self._add("PLUS")
        elif c == "-":
            self._add("MINUS")
        elif c == "*":
            self._add("STAR")
        elif c == "/":
            self._add("SLASH")
        elif c == "%":
            self._add("PERCENT")
        elif c == "^":
            self._add("CARET")
        elif c == "=":
            self._add("EQEQ" if self._match("=") else "EQ")
        elif c == "!":
            self._add("BANGEQ" if self._match("=") else "BANG")
        elif c == "<":
            self._add("LTEQ" if self._match("=") else "LT")
        elif c == ">":
            self._add("GTEQ" if self._match("=") else "GT")
        elif c == "&":
            if self._match("&"):
                self._add("ANDAND")
            else:
                self._error("expected '&&', found lone '&'")
        elif c == "|":
            if self._match("|"):
                self._add("OROR")
            else:
                self._error("expected '||', found lone '|'")
        elif c == '"':
            self._string()
        elif c.isdigit():
            self._number()
        elif c.isalpha() or c == "_":
            self._identifier()
        else:
            self._error("unexpected character %r" % c)

    def _bracket(self, type):
        if self.depth == 0:
            self._error("unmatched closing bracket")
        self.depth -= 1
        self._add(type)

    def _string(self):
        chars = []
        while True:
            if self._at_end():
                self._error("unterminated string")
            c = self._advance()
            if c == '"':
                break
            if c == "\n":
                self._error("unterminated string (newline inside)")
            if c == "\\":
                e = self._advance()
                if e not in ESCAPES:
                    self._error("unknown escape '\\%s'" % e)
                chars.append(ESCAPES[e])
            else:
                chars.append(c)
        self._add("STRING", "".join(chars))

    def _number(self):
        while self._peek().isdigit():
            self._advance()
        if self._peek() == "." and self._peek2().isdigit():
            self._advance()
            while self._peek().isdigit():
                self._advance()
        self._add("NUMBER", float(self.src[self.start:self.pos]))

    def _identifier(self):
        while self._peek().isalnum() or self._peek() == "_":
            self._advance()
        text = self.src[self.start:self.pos]
        self._add(KEYWORDS.get(text, "IDENT"))
