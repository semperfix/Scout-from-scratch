"""FoxScript parser: tokens -> AST.

Recursive descent. `for` loops are desugared into blocks + while (the
classic transform), so the compiler never sees a For node.
"""


class ParseError(Exception):
    pass


# ---- AST nodes ---------------------------------------------------------
class Node:
    __slots__ = ("line",)

    def __init__(self, line):
        self.line = line


class Program(Node):
    __slots__ = ("decls",)

    def __init__(self, decls, line=1):
        super().__init__(line)
        self.decls = decls


class Block(Node):
    __slots__ = ("decls",)

    def __init__(self, decls, line):
        super().__init__(line)
        self.decls = decls


class VarDecl(Node):
    __slots__ = ("name", "init")

    def __init__(self, name, init, line):
        super().__init__(line)
        self.name = name
        self.init = init  # may be None -> nil


class FnDecl(Node):
    __slots__ = ("name", "params", "body")

    def __init__(self, name, params, body, line):
        super().__init__(line)
        self.name = name
        self.params = params
        self.body = body


class If(Node):
    __slots__ = ("cond", "then", "els")

    def __init__(self, cond, then, els, line):
        super().__init__(line)
        self.cond = cond
        self.then = then
        self.els = els


class While(Node):
    __slots__ = ("cond", "body")

    def __init__(self, cond, body, line):
        super().__init__(line)
        self.cond = cond
        self.body = body


class Return(Node):
    __slots__ = ("value",)

    def __init__(self, value, line):
        super().__init__(line)
        self.value = value  # may be None -> nil


class ExprStmt(Node):
    __slots__ = ("expr",)

    def __init__(self, expr, line):
        super().__init__(line)
        self.expr = expr


class Assign(Node):
    __slots__ = ("name", "value")

    def __init__(self, name, value, line):
        super().__init__(line)
        self.name = name
        self.value = value


class SetIndex(Node):
    __slots__ = ("obj", "index", "value")

    def __init__(self, obj, index, value, line):
        super().__init__(line)
        self.obj = obj
        self.index = index
        self.value = value


class Binary(Node):
    __slots__ = ("op", "left", "right")

    def __init__(self, op, left, right, line):
        super().__init__(line)
        self.op = op
        self.left = left
        self.right = right


class Unary(Node):
    __slots__ = ("op", "expr")

    def __init__(self, op, expr, line):
        super().__init__(line)
        self.op = op
        self.expr = expr


class Call(Node):
    __slots__ = ("callee", "args")

    def __init__(self, callee, args, line):
        super().__init__(line)
        self.callee = callee
        self.args = args


class GetIndex(Node):
    __slots__ = ("obj", "index")

    def __init__(self, obj, index, line):
        super().__init__(line)
        self.obj = obj
        self.index = index


class Var(Node):
    __slots__ = ("name",)

    def __init__(self, name, line):
        super().__init__(line)
        self.name = name


class Literal(Node):
    __slots__ = ("value",)

    def __init__(self, value, line):
        super().__init__(line)
        self.value = value


class FnExpr(Node):
    __slots__ = ("params", "body")

    def __init__(self, params, body, line):
        super().__init__(line)
        self.params = params
        self.body = body


class ArrayLit(Node):
    __slots__ = ("elems",)

    def __init__(self, elems, line):
        super().__init__(line)
        self.elems = elems


class MapLit(Node):
    __slots__ = ("pairs",)  # list of (key_string, value_node)

    def __init__(self, pairs, line):
        super().__init__(line)
        self.pairs = pairs


# ---- parser ------------------------------------------------------------
class Parser:
    def __init__(self, tokens):
        self.toks = tokens
        self.pos = 0

    def parse(self):
        decls = []
        self._skip_newlines()
        while not self._check("EOF"):
            decls.append(self._declaration())
            self._skip_newlines()
        return Program(decls)

    # -- token helpers --
    def _peek(self):
        return self.toks[self.pos]

    def _prev(self):
        return self.toks[self.pos - 1]

    def _check(self, type):
        return self._peek().type == type

    def _match(self, *types):
        if self._peek().type in types:
            self.pos += 1
            return True
        return False

    def _consume(self, type, msg):
        if self._check(type):
            self.pos += 1
            return self._prev()
        raise ParseError("line %d: %s (found %r)" % (
            self._peek().line, msg, self._peek().lexeme))

    def _error(self, msg):
        raise ParseError("line %d: %s" % (self._peek().line, msg))

    def _skip_newlines(self):
        while self._match("NEWLINE"):
            pass

    def _terminator(self):
        # at least one of ; or NEWLINE (or a closing bracket / EOF)
        if self._match("SEMI", "NEWLINE"):
            self._skip_newlines()
            return
        if self._check("RBRACE") or self._check("EOF"):
            return
        self._error("expected end of statement")

    # -- declarations --
    def _declaration(self):
        if self._match("FN"):
            return self._fn_decl(require_name=True)
        if self._match("LET"):
            return self._var_decl()
        return self._statement()

    def _var_decl(self):
        tok = self._consume("IDENT", "expected variable name after 'let'")
        init = None
        if self._match("EQ"):
            init = self._expression()
        self._terminator()
        return VarDecl(tok.lexeme, init, tok.line)

    def _fn_decl(self, require_name):
        line = self._prev().line
        name = None
        if require_name:
            name = self._consume("IDENT", "expected function name").lexeme
        params, body = self._fn_parts(line)
        self._skip_newlines()
        if require_name:
            return FnDecl(name, params, body, line)
        return FnExpr(params, body, line)

    def _fn_parts(self, line):
        self._consume("LPAREN", "expected '(' after 'fn'")
        params = []
        if not self._check("RPAREN"):
            while True:
                t = self._consume("IDENT", "expected parameter name")
                if t.lexeme in params:
                    raise ParseError("line %d: duplicate parameter %r"
                                     % (t.line, t.lexeme))
                params.append(t.lexeme)
                if len(params) > 255:
                    raise ParseError("line %d: too many parameters" % t.line)
                if not self._match("COMMA"):
                    break
        self._consume("RPAREN", "expected ')' after parameters")
        self._skip_newlines()
        body = self._block()
        return params, body

    # -- statements --
    def _statement(self):
        if self._match("IF"):
            return self._if_stmt()
        if self._match("WHILE"):
            return self._while_stmt()
        if self._match("FOR"):
            return self._for_stmt()
        if self._match("RETURN"):
            return self._return_stmt()
        if self._check("LBRACE"):
            return self._block()
        expr = self._expression()
        self._terminator()
        return ExprStmt(expr, expr.line)

    def _block(self):
        line = self._consume("LBRACE", "expected '{'").line
        decls = []
        self._skip_newlines()
        while not self._check("RBRACE") and not self._check("EOF"):
            decls.append(self._declaration())
            self._skip_newlines()
        self._consume("RBRACE", "expected '}' to close block")
        return Block(decls, line)

    def _if_stmt(self):
        line = self._prev().line
        self._consume("LPAREN", "expected '(' after 'if'")
        cond = self._expression()
        self._consume("RPAREN", "expected ')' after condition")
        self._skip_newlines()
        then = self._statement()
        els = None
        # allow `else` on the next line
        save = self.pos
        self._skip_newlines()
        if self._match("ELSE"):
            self._skip_newlines()
            els = self._statement()
        else:
            self.pos = save
        return If(cond, then, els, line)

    def _while_stmt(self):
        line = self._prev().line
        self._consume("LPAREN", "expected '(' after 'while'")
        cond = self._expression()
        self._consume("RPAREN", "expected ')' after condition")
        self._skip_newlines()
        return While(cond, self._statement(), line)

    def _for_stmt(self):
        # desugar: for (init; cond; incr) body
        #   -> { init; while (cond) { body; incr; } }
        line = self._prev().line
        self._consume("LPAREN", "expected '(' after 'for'")
        if self._match("SEMI"):
            init = None
        elif self._check("LET"):
            self.pos += 1
            init = self._var_decl()
        else:
            expr = self._expression()
            self._terminator()
            init = ExprStmt(expr, expr.line)
        cond = None
        if not self._check("SEMI"):
            cond = self._expression()
        self._consume("SEMI", "expected ';' after for-condition")
        incr = None
        if not self._check("RPAREN"):
            incr = self._expression()
        self._consume("RPAREN", "expected ')' after for-clauses")
        self._skip_newlines()
        body = self._statement()
        if incr is not None:
            body = Block([body, ExprStmt(incr, incr.line)], body.line)
        else:
            body = Block([body], body.line)
        loop = While(cond if cond is not None else Literal(True, line),
                     body, line)
        decls = ([init] if init is not None else []) + [loop]
        return Block(decls, line)

    def _return_stmt(self):
        line = self._prev().line
        value = None
        if not self._check("SEMI") and not self._check("NEWLINE") \
                and not self._check("RBRACE") and not self._check("EOF"):
            value = self._expression()
        self._terminator()
        return Return(value, line)

    # -- expressions --
    def _expression(self):
        return self._assignment()

    def _assignment(self):
        expr = self._logic_or()
        if self._match("EQ"):
            line = self._prev().line
            value = self._assignment()  # right-associative
            if isinstance(expr, Var):
                return Assign(expr.name, value, line)
            if isinstance(expr, GetIndex):
                return SetIndex(expr.obj, expr.index, value, line)
            raise ParseError("line %d: invalid assignment target" % line)
        return expr

    def _logic_or(self):
        expr = self._logic_and()
        while self._match("OROR"):
            right = self._logic_and()
            expr = Binary("or", expr, right, self._prev().line)
        return expr

    def _logic_and(self):
        expr = self._equality()
        while self._match("ANDAND"):
            right = self._equality()
            expr = Binary("and", expr, right, self._prev().line)
        return expr

    def _equality(self):
        expr = self._comparison()
        while self._match("EQEQ", "BANGEQ"):
            op = self._prev().type
            right = self._comparison()
            expr = Binary("==" if op == "EQEQ" else "!=", expr, right,
                          self._prev().line)
        return expr

    def _comparison(self):
        expr = self._term()
        while self._match("LT", "LTEQ", "GT", "GTEQ"):
            op = {"LT": "<", "LTEQ": "<=", "GT": ">", "GTEQ": ">="}[
                self._prev().type]
            right = self._term()
            expr = Binary(op, expr, right, self._prev().line)
        return expr

    def _term(self):
        expr = self._factor()
        while self._match("PLUS", "MINUS"):
            op = self._prev().lexeme
            right = self._factor()
            expr = Binary(op, expr, right, self._prev().line)
        return expr

    def _factor(self):
        expr = self._power()
        while self._match("STAR", "SLASH", "PERCENT"):
            op = self._prev().lexeme
            right = self._power()
            expr = Binary(op, expr, right, self._prev().line)
        return expr

    def _power(self):
        # right-associative: 2 ^ 3 ^ 2 == 2 ^ (3 ^ 2)
        base = self._unary()
        if self._match("CARET"):
            exp = self._power()
            return Binary("^", base, exp, self._prev().line)
        return base

    def _unary(self):
        if self._match("BANG", "MINUS"):
            op = self._prev().lexeme
            return Unary(op, self._unary(), self._prev().line)
        return self._call()

    def _call(self):
        expr = self._primary()
        while True:
            if self._match("LPAREN"):
                args = []
                if not self._check("RPAREN"):
                    while True:
                        args.append(self._expression())
                        if len(args) > 255:
                            self._error("too many arguments")
                        if not self._match("COMMA"):
                            break
                        if self._check("RPAREN"):
                            break  # trailing comma
                self._consume("RPAREN", "expected ')' after arguments")
                expr = Call(expr, args, self._prev().line)
            elif self._match("LBRACKET"):
                index = self._expression()
                self._consume("RBRACKET", "expected ']' after index")
                expr = GetIndex(expr, index, self._prev().line)
            else:
                return expr

    def _primary(self):
        t = self._peek()
        if self._match("NUMBER", "STRING"):
            return Literal(self._prev().literal, self._prev().line)
        if self._match("TRUE"):
            return Literal(True, self._prev().line)
        if self._match("FALSE"):
            return Literal(False, self._prev().line)
        if self._match("NIL"):
            return Literal(None, self._prev().line)
        if self._match("IDENT"):
            return Var(self._prev().lexeme, self._prev().line)
        if self._match("LPAREN"):
            expr = self._expression()
            self._consume("RPAREN", "expected ')' after expression")
            return expr
        if self._match("LBRACKET"):
            return self._array_lit(t.line)
        if self._match("LBRACE"):
            return self._map_lit(t.line)
        if self._match("FN"):
            return self._fn_decl(require_name=False)
        self._error("expected expression, found %r" % t.lexeme)

    def _array_lit(self, line):
        elems = []
        if not self._check("RBRACKET"):
            while True:
                elems.append(self._expression())
                if not self._match("COMMA"):
                    break
                if self._check("RBRACKET"):
                    break  # trailing comma
        self._consume("RBRACKET", "expected ']' after array literal")
        return ArrayLit(elems, line)

    def _map_lit(self, line):
        pairs = []
        if not self._check("RBRACE"):
            while True:
                k = self._consume("STRING",
                                  "map keys must be string literals").literal
                self._consume("COLON", "expected ':' after map key")
                pairs.append((k, self._expression()))
                if not self._match("COMMA"):
                    break
                if self._check("RBRACE"):
                    break  # trailing comma
        self._consume("RBRACE", "expected '}' after map literal")
        return MapLit(pairs, line)
