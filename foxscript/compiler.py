"""FoxScript compiler: AST -> bytecode chunks.

Single-pass compiler in the classic style: lexical scopes map to stack
slots, free variables become upvalues (resolved recursively through
enclosing compilers), and control flow is built with jump patching.
"""


class CompileError(Exception):
    pass


# ---- opcodes -----------------------------------------------------------
(
    CONSTANT, NIL, TRUE, FALSE, POP,
    GET_LOCAL, SET_LOCAL, GET_UPVALUE, SET_UPVALUE,
    GET_GLOBAL, DEFINE_GLOBAL, SET_GLOBAL,
    EQUAL, GREATER, LESS,
    ADD, SUBTRACT, MULTIPLY, DIVIDE, MOD, POWER,
    NEGATE, NOT,
    JUMP, JUMP_IF_FALSE, JUMP_IF_TRUE, LOOP,
    CALL, CLOSURE, CLOSE_UPVALUE, RETURN,
    BUILD_ARRAY, BUILD_MAP, GET_INDEX, SET_INDEX,
) = range(35)

OP_NAMES = {
    CONSTANT: "CONSTANT", NIL: "NIL", TRUE: "TRUE", FALSE: "FALSE",
    POP: "POP", GET_LOCAL: "GET_LOCAL", SET_LOCAL: "SET_LOCAL",
    GET_UPVALUE: "GET_UPVALUE", SET_UPVALUE: "SET_UPVALUE",
    GET_GLOBAL: "GET_GLOBAL", DEFINE_GLOBAL: "DEFINE_GLOBAL",
    SET_GLOBAL: "SET_GLOBAL", EQUAL: "EQUAL", GREATER: "GREATER",
    LESS: "LESS", ADD: "ADD", SUBTRACT: "SUBTRACT", MULTIPLY: "MULTIPLY",
    DIVIDE: "DIVIDE", MOD: "MOD", POWER: "POWER", NEGATE: "NEGATE",
    NOT: "NOT", JUMP: "JUMP", JUMP_IF_FALSE: "JUMP_IF_FALSE",
    JUMP_IF_TRUE: "JUMP_IF_TRUE", LOOP: "LOOP", CALL: "CALL",
    CLOSURE: "CLOSURE", CLOSE_UPVALUE: "CLOSE_UPVALUE", RETURN: "RETURN",
    BUILD_ARRAY: "BUILD_ARRAY", BUILD_MAP: "BUILD_MAP",
    GET_INDEX: "GET_INDEX", SET_INDEX: "SET_INDEX",
}

UINT8_MAX = 255
UINT16_MAX = 65535


# ---- chunk / function ---------------------------------------------------
class Chunk:
    def __init__(self):
        self.code = []       # flat list of ints (opcode + operand bytes)
        self.constants = []  # numbers, strings, Function objects
        self.lines = []      # source line per code byte


class Function:
    def __init__(self, name, arity):
        self.name = name
        self.arity = arity
        self.chunk = Chunk()
        self.upvalues = []  # list of (is_local: bool, index: int)

    def __repr__(self):
        return "<fn %s/%d>" % (self.name or "script", self.arity)


class _Local:
    __slots__ = ("name", "depth", "captured")

    def __init__(self, name, depth):
        self.name = name
        self.depth = depth
        self.captured = False


# ---- compiler -----------------------------------------------------------
class Compiler:
    def __init__(self, enclosing, name, arity, is_script):
        from parser import (Program, Block, VarDecl, FnDecl, If, While,
                            Return, ExprStmt, Assign, SetIndex, Binary,
                            Unary, Call, GetIndex, Var, Literal, FnExpr,
                            ArrayLit, MapLit)
        self.enclosing = enclosing
        self.function = Function(name, arity)
        self.is_script = is_script
        self.locals = [_Local("", 0)]  # slot 0 reserved, like clox
        self.scope_depth = 0
        self.upvalues = []  # (is_local, index), deduped
        self._nodes = (Program, Block, VarDecl, FnDecl, If, While, Return,
                       ExprStmt, Assign, SetIndex, Binary, Unary, Call,
                       GetIndex, Var, Literal, FnExpr, ArrayLit, MapLit)

    # -- emit helpers --
    def _emit(self, byte, line):
        self.function.chunk.code.append(byte & 0xFF)
        self.function.chunk.lines.append(line)

    def _emit_op(self, op, line):
        self._emit(op, line)

    def _emit_u8(self, value, line):
        if value > UINT8_MAX:
            raise CompileError("line %d: too many (limit 256)" % line)
        self._emit(value, line)

    def _constant(self, value, line):
        chunk = self.function.chunk
        try:
            idx = chunk.constants.index(value)
        except ValueError:
            idx = len(chunk.constants)
            if idx > UINT8_MAX:
                raise CompileError("line %d: too many constants" % line)
            chunk.constants.append(value)
        return idx

    def _emit_constant(self, value, line):
        self._emit_op(CONSTANT, line)
        self._emit_u8(self._constant(value, line), line)

    def _emit_jump(self, op, line):
        self._emit_op(op, line)
        self._emit(0xFF, line)
        self._emit(0xFF, line)
        return len(self.function.chunk.code) - 2

    def _patch_jump(self, offset, line):
        jump = len(self.function.chunk.code) - offset - 2
        if jump > UINT16_MAX:
            raise CompileError("line %d: jump too large" % line)
        code = self.function.chunk.code
        code[offset] = (jump >> 8) & 0xFF
        code[offset + 1] = jump & 0xFF

    def _emit_loop(self, start, line):
        self._emit_op(LOOP, line)
        offset = len(self.function.chunk.code) - start + 2
        if offset > UINT16_MAX:
            raise CompileError("line %d: loop body too large" % line)
        self._emit((offset >> 8) & 0xFF, line)
        self._emit(offset & 0xFF, line)

    # -- scopes / variables --
    def _begin_scope(self):
        self.scope_depth += 1

    def _end_scope(self, line):
        self.scope_depth -= 1
        while self.locals and self.locals[-1].depth > self.scope_depth:
            if self.locals[-1].captured:
                self._emit_op(CLOSE_UPVALUE, line)
            else:
                self._emit_op(POP, line)
            self.locals.pop()

    def _declare(self, name, line):
        if self.scope_depth == 0:
            return  # globals need no declaration
        for local in reversed(self.locals):
            if local.depth < self.scope_depth:
                break
            if local.name == name:
                raise CompileError(
                    "line %d: '%s' already defined in this scope"
                    % (line, name))
        if len(self.locals) > UINT8_MAX:
            raise CompileError("line %d: too many locals" % line)
        self.locals.append(_Local(name, self.scope_depth))

    def _define(self, name, line):
        if self.scope_depth > 0:
            return  # local value already sits in its slot
        self._emit_op(DEFINE_GLOBAL, line)
        self._emit_u8(self._constant(name, line), line)

    def _resolve_local(self, name):
        for i in range(len(self.locals) - 1, -1, -1):
            if self.locals[i].name == name:
                return i
        return None

    def _add_upvalue(self, index, is_local):
        for i, (il, ix) in enumerate(self.upvalues):
            if il == is_local and ix == index:
                return i
        self.upvalues.append((is_local, index))
        return len(self.upvalues) - 1

    def _resolve_upvalue(self, name):
        if self.enclosing is None:
            return None
        enc = self.enclosing
        local = enc._resolve_local(name)
        if local is not None:
            enc.locals[local].captured = True
            return self._add_upvalue(local, True)
        up = enc._resolve_upvalue(name)
        if up is not None:
            return self._add_upvalue(up, False)
        return None

    def _named_var(self, name, line, assign):
        local = self._resolve_local(name)
        if local is not None:
            self._emit_op(SET_LOCAL if assign else GET_LOCAL, line)
            self._emit_u8(local, line)
            return
        up = self._resolve_upvalue(name)
        if up is not None:
            self._emit_op(SET_UPVALUE if assign else GET_UPVALUE, line)
            self._emit_u8(up, line)
            return
        self._emit_op(SET_GLOBAL if assign else GET_GLOBAL, line)
        self._emit_u8(self._constant(name, line), line)

    # -- compile entry --
    def compile(self, program):
        for decl in program.decls:
            self._decl(decl)
        self._emit_op(NIL, 1)
        self._emit_op(RETURN, 1)
        return self.function

    # -- declarations / statements --
    def _decl(self, node):
        (Program, Block, VarDecl, FnDecl, If, While, Return, ExprStmt,
         Assign, SetIndex, Binary, Unary, Call, GetIndex, Var, Literal,
         FnExpr, ArrayLit, MapLit) = self._nodes
        if isinstance(node, VarDecl):
            if node.init is not None:
                self._expr(node.init)
            else:
                self._emit_op(NIL, node.line)
            self._declare(node.name, node.line)
            self._define(node.name, node.line)
        elif isinstance(node, FnDecl):
            self._function(node.params, node.body, node.name, node.line)
            self._declare(node.name, node.line)
            self._define(node.name, node.line)
        elif isinstance(node, Block):
            self._begin_scope()
            for d in node.decls:
                self._decl(d)
            self._end_scope(node.line)
        elif isinstance(node, If):
            self._expr(node.cond)
            else_jump = self._emit_jump(JUMP_IF_FALSE, node.line)
            self._emit_op(POP, node.line)
            self._decl(node.then)
            end_jump = self._emit_jump(JUMP, node.line)
            self._patch_jump(else_jump, node.line)
            self._emit_op(POP, node.line)
            if node.els is not None:
                self._decl(node.els)
            self._patch_jump(end_jump, node.line)
        elif isinstance(node, While):
            loop_start = len(self.function.chunk.code)
            self._expr(node.cond)
            exit_jump = self._emit_jump(JUMP_IF_FALSE, node.line)
            self._emit_op(POP, node.line)
            self._decl(node.body)
            self._emit_loop(loop_start, node.line)
            self._patch_jump(exit_jump, node.line)
            self._emit_op(POP, node.line)
        elif isinstance(node, Return):
            if self.is_script:
                raise CompileError(
                    "line %d: can't return from top-level code" % node.line)
            if node.value is not None:
                self._expr(node.value)
            else:
                self._emit_op(NIL, node.line)
            self._emit_op(RETURN, node.line)
        elif isinstance(node, ExprStmt):
            self._expr(node.expr)
            self._emit_op(POP, node.line)
        else:
            raise CompileError("line %d: unknown node %r"
                               % (node.line, type(node).__name__))

    def _function(self, params, body, name, line):
        if len(params) > UINT8_MAX:
            raise CompileError("line %d: too many parameters" % line)
        child = Compiler(self, name, len(params), is_script=False)
        child._begin_scope()
        for p in params:
            child._declare(p, line)
        for d in body.decls:
            child._decl(d)
        child._end_scope(line)
        child._emit_op(NIL, line)
        child._emit_op(RETURN, line)
        fn = child.function
        # upvalues were collected on the child Compiler; the Function
        # object (and the CLOSURE instruction) needs them
        fn.upvalues = child.upvalues
        self._emit_op(CLOSURE, line)
        self._emit_u8(self._constant(fn, line), line)
        for is_local, index in fn.upvalues:
            self._emit(1 if is_local else 0, line)
            self._emit_u8(index, line)

    # -- expressions (each leaves exactly one value on the stack) --
    def _expr(self, node):
        (Program, Block, VarDecl, FnDecl, If, While, Return, ExprStmt,
         Assign, SetIndex, Binary, Unary, Call, GetIndex, Var, Literal,
         FnExpr, ArrayLit, MapLit) = self._nodes
        line = node.line
        if isinstance(node, Literal):
            v = node.value
            if v is None:
                self._emit_op(NIL, line)
            elif v is True:
                self._emit_op(TRUE, line)
            elif v is False:
                self._emit_op(FALSE, line)
            else:
                self._emit_constant(v, line)
        elif isinstance(node, Var):
            self._named_var(node.name, line, assign=False)
        elif isinstance(node, Assign):
            self._expr(node.value)
            self._named_var(node.name, line, assign=True)
        elif isinstance(node, Binary):
            self._binary(node)
        elif isinstance(node, Unary):
            self._expr(node.expr)
            self._emit_op(NOT if node.op == "!" else NEGATE, line)
        elif isinstance(node, Call):
            self._expr(node.callee)
            for a in node.args:
                self._expr(a)
            self._emit_op(CALL, line)
            self._emit_u8(len(node.args), line)
        elif isinstance(node, GetIndex):
            self._expr(node.obj)
            self._expr(node.index)
            self._emit_op(GET_INDEX, line)
        elif isinstance(node, SetIndex):
            self._expr(node.obj)
            self._expr(node.index)
            self._expr(node.value)
            self._emit_op(SET_INDEX, line)
        elif isinstance(node, FnExpr):
            self._function(node.params, node.body, "<anon>", line)
        elif isinstance(node, ArrayLit):
            for e in node.elems:
                self._expr(e)
            self._emit_op(BUILD_ARRAY, line)
            self._emit_u8(len(node.elems), line)
        elif isinstance(node, MapLit):
            for k, v in node.pairs:
                self._emit_constant(k, line)
                self._expr(v)
            self._emit_op(BUILD_MAP, line)
            self._emit_u8(len(node.pairs), line)
        else:
            raise CompileError("line %d: unknown expr %r"
                               % (line, type(node).__name__))

    def _binary(self, node):
        line = node.line
        op = node.op
        if op == "and":
            self._expr(node.left)
            end = self._emit_jump(JUMP_IF_FALSE, line)
            self._emit_op(POP, line)
            self._expr(node.right)
            self._patch_jump(end, line)
            return
        if op == "or":
            self._expr(node.left)
            end = self._emit_jump(JUMP_IF_TRUE, line)
            self._emit_op(POP, line)
            self._expr(node.right)
            self._patch_jump(end, line)
            return
        self._expr(node.left)
        self._expr(node.right)
        emit = {
            "+": ADD, "-": SUBTRACT, "*": MULTIPLY, "/": DIVIDE,
            "%": MOD, "^": POWER, "==": EQUAL, ">": GREATER, "<": LESS,
        }[op] if op not in ("!=", "<=", ">=") else None
        if op == "!=":
            self._emit_op(EQUAL, line)
            self._emit_op(NOT, line)
        elif op == "<=":
            self._emit_op(GREATER, line)
            self._emit_op(NOT, line)
        elif op == ">=":
            self._emit_op(LESS, line)
            self._emit_op(NOT, line)
        else:
            self._emit_op(emit, line)


def compile_program(program):
    """Compile an AST Program into the top-level Function."""
    return Compiler(None, "<script>", 0, is_script=True).compile(program)
