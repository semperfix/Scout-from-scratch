"""FoxScript VM: stack-based bytecode interpreter.

Frames hold (closure, ip, base). Locals live in stack slots; closures
capture them via Upvalue objects that start as pointers into the stack
and get "closed over" (value copied out) when their scope exits.
"""


class FoxError(Exception):
    """Runtime error with a source line attached."""

    def __init__(self, message, line):
        super().__init__(message)
        self.line = line

    def __str__(self):
        return "line %d: %s" % (self.line, super().__str__())


class Upvalue:
    __slots__ = ("slot", "closed", "value")

    def __init__(self, slot):
        self.slot = slot      # stack index while open
        self.closed = False
        self.value = None     # heap copy once closed


class Closure:
    __slots__ = ("function", "upvalues")

    def __init__(self, function, upvalues):
        self.function = function
        self.upvalues = upvalues


class Frame:
    __slots__ = ("closure", "ip", "base")

    def __init__(self, closure, base):
        self.closure = closure
        self.ip = 0
        self.base = base


# re-exported so natives can isinstance-check without a cycle
from natives import Native  # noqa: E402,F401


MAX_FRAMES = 1000


class VM:
    def __init__(self, out=None):
        import sys
        self.out = out or sys.stdout
        self.stack = []
        self.frames = []
        self.globals = {}
        self.open_upvalues = []  # sorted by slot, ascending
        from natives import BUILTINS
        for b in BUILTINS:
            self.globals[b.name] = b

    # -- run entry --
    def interpret(self, function):
        self.stack = [Closure(function, [])]
        self.frames = [Frame(self.stack[0], 0)]
        self.open_upvalues = []
        try:
            self._run()
        except FoxError:
            raise
        except RecursionError:
            raise FoxError("stack overflow", -1)

    # -- helpers --
    def _frame(self):
        return self.frames[-1]

    def _chunk(self):
        return self._frame().closure.function.chunk

    def _read_byte(self):
        f = self._frame()
        b = f.closure.function.chunk.code[f.ip]
        f.ip += 1
        return b

    def _read_u16(self):
        return (self._read_byte() << 8) | self._read_byte()

    def _line(self):
        f = self._frame()
        return f.closure.function.chunk.lines[f.ip - 1]

    def _error(self, msg):
        raise FoxError(msg, self._line())

    def _pop(self):
        return self.stack.pop()

    def _peek(self, n=0):
        return self.stack[-1 - n]

    @staticmethod
    def _falsy(v):
        return v is None or v is False

    def _capture(self, slot):
        for uv in self.open_upvalues:
            if uv.slot == slot:
                return uv
            if uv.slot > slot:
                break
        uv = Upvalue(slot)
        # keep list sorted ascending by slot
        i = 0
        while i < len(self.open_upvalues) and \
                self.open_upvalues[i].slot < slot:
            i += 1
        self.open_upvalues.insert(i, uv)
        return uv

    def _close_from(self, slot):
        while self.open_upvalues and self.open_upvalues[-1].slot >= slot:
            uv = self.open_upvalues.pop()
            uv.value = self.stack[uv.slot]
            uv.closed = True

    def _call(self, callee, argc):
        if isinstance(callee, Closure):
            fn = callee.function
            if argc != fn.arity:
                self._error("expected %d arguments but got %d"
                            % (fn.arity, argc))
            if len(self.frames) >= MAX_FRAMES:
                self._error("stack overflow (call depth exceeded)")
            base = len(self.stack) - argc - 1
            self.frames.append(Frame(callee, base))
            return True
        if isinstance(callee, Native):
            if callee.arity != -1 and argc != callee.arity:
                self._error("expected %d arguments but got %d"
                            % (callee.arity, argc))
            args = self.stack[len(self.stack) - argc:] if argc else []
            del self.stack[len(self.stack) - argc - 1:]
            try:
                result = callee.call(list(args), self.out)
            except Exception as e:
                # NativeError -> clean runtime error; anything else likewise
                self._error(str(e))
            self.stack.append(result)
            return False
        self._error("can only call functions (got %s)"
                    % type(callee).__name__)
        return False

    # -- main loop --
    def _run(self):
        from compiler import (
            CONSTANT, NIL, TRUE, FALSE, POP,
            GET_LOCAL, SET_LOCAL, GET_UPVALUE, SET_UPVALUE,
            GET_GLOBAL, DEFINE_GLOBAL, SET_GLOBAL,
            EQUAL, GREATER, LESS,
            ADD, SUBTRACT, MULTIPLY, DIVIDE, MOD, POWER,
            NEGATE, NOT,
            JUMP, JUMP_IF_FALSE, JUMP_IF_TRUE, LOOP,
            CALL, CLOSURE, CLOSE_UPVALUE, RETURN,
            BUILD_ARRAY, BUILD_MAP, GET_INDEX, SET_INDEX,
        )
        stack = self.stack
        while True:
            op = self._read_byte()
            if op == CONSTANT:
                stack.append(self._chunk().constants[self._read_byte()])
            elif op == NIL:
                stack.append(None)
            elif op == TRUE:
                stack.append(True)
            elif op == FALSE:
                stack.append(False)
            elif op == POP:
                stack.pop()
            elif op == GET_LOCAL:
                stack.append(stack[self._frame().base + self._read_byte()])
            elif op == SET_LOCAL:
                stack[self._frame().base + self._read_byte()] = stack[-1]
            elif op == GET_UPVALUE:
                uv = self._frame().closure.upvalues[self._read_byte()]
                stack.append(uv.value if uv.closed else stack[uv.slot])
            elif op == SET_UPVALUE:
                uv = self._frame().closure.upvalues[self._read_byte()]
                if uv.closed:
                    uv.value = stack[-1]
                else:
                    stack[uv.slot] = stack[-1]
            elif op == GET_GLOBAL:
                name = self._chunk().constants[self._read_byte()]
                if name not in self.globals:
                    self._error("undefined variable '%s'" % name)
                stack.append(self.globals[name])
            elif op == DEFINE_GLOBAL:
                name = self._chunk().constants[self._read_byte()]
                self.globals[name] = stack.pop()
            elif op == SET_GLOBAL:
                name = self._chunk().constants[self._read_byte()]
                if name not in self.globals:
                    self._error("undefined variable '%s'" % name)
                self.globals[name] = stack[-1]
            elif op == EQUAL:
                b = stack.pop()
                stack.append(self._eq(stack.pop(), b))
            elif op == GREATER:
                b = stack.pop()
                a = stack.pop()
                stack.append(self._num_cmp(a, b, lambda x, y: x > y, ">"))
            elif op == LESS:
                b = stack.pop()
                a = stack.pop()
                stack.append(self._num_cmp(a, b, lambda x, y: x < y, "<"))
            elif op == ADD:
                b = stack.pop()
                a = stack.pop()
                if isinstance(a, float) and isinstance(b, float):
                    stack.append(a + b)
                elif isinstance(a, str) and isinstance(b, str):
                    stack.append(a + b)
                else:
                    self._error("operands must be two numbers or two "
                                "strings for '+'")
            elif op == SUBTRACT:
                self._arith(stack, lambda a, b: a - b, "-")
            elif op == MULTIPLY:
                self._arith(stack, lambda a, b: a * b, "*")
            elif op == DIVIDE:
                b = stack[-1]
                if isinstance(b, float) and b == 0.0:
                    self._error("division by zero")
                self._arith(stack, lambda a, b: a / b, "/")
            elif op == MOD:
                b = stack[-1]
                if isinstance(b, float) and b == 0.0:
                    self._error("division by zero")
                self._arith(stack, lambda a, b: a % b, "%")
            elif op == POWER:
                self._arith(stack, lambda a, b: a ** b, "^")
            elif op == NEGATE:
                v = stack.pop()
                if not isinstance(v, float):
                    self._error("operand must be a number for unary '-'")
                stack.append(-v)
            elif op == NOT:
                stack.append(self._falsy(stack.pop()))
            elif op == JUMP:
                # NB: never `self._frame().ip += self._read_u16()` --
                # augmented assignment loads ip BEFORE the RHS runs,
                # so the 2-byte operand advance would be discarded
                # and the jump would land 2 bytes early.
                offset = self._read_u16()
                self._frame().ip += offset
            elif op == JUMP_IF_FALSE:
                offset = self._read_u16()
                if self._falsy(stack[-1]):
                    self._frame().ip += offset
            elif op == JUMP_IF_TRUE:
                offset = self._read_u16()
                if not self._falsy(stack[-1]):
                    self._frame().ip += offset
            elif op == LOOP:
                # same augmented-assignment trap as JUMP: read first,
                # then adjust
                offset = self._read_u16()
                self._frame().ip -= offset
            elif op == CALL:
                argc = self._read_byte()
                callee = stack[-1 - argc]
                self._call(callee, argc)
            elif op == CLOSURE:
                fn = self._chunk().constants[self._read_byte()]
                ups = []
                for _ in fn.upvalues:
                    is_local = self._read_byte()
                    index = self._read_byte()
                    if is_local:
                        ups.append(
                            self._capture(self._frame().base + index))
                    else:
                        ups.append(self._frame().closure.upvalues[index])
                stack.append(Closure(fn, ups))
            elif op == CLOSE_UPVALUE:
                self._close_from(len(stack) - 1)
                stack.pop()
            elif op == RETURN:
                result = stack.pop()
                callee_base = self._frame().base
                self._close_from(callee_base)
                self.frames.pop()
                if not self.frames:
                    return
                # discard the returning frame's window only; the
                # caller's slots below callee_base stay intact, and
                # the result lands exactly where the callee was
                del stack[callee_base:]
                stack.append(result)
            elif op == BUILD_ARRAY:
                n = self._read_byte()
                arr = stack[len(stack) - n:] if n else []
                del stack[len(stack) - n:]
                stack.append(list(arr))
            elif op == BUILD_MAP:
                n = self._read_byte()
                items = stack[len(stack) - 2 * n:] if n else []
                del stack[len(stack) - 2 * n:]
                m = {}
                for i in range(0, len(items), 2):
                    m[items[i]] = items[i + 1]
                stack.append(m)
            elif op == GET_INDEX:
                index = stack.pop()
                obj = stack.pop()
                stack.append(self._get_index(obj, index))
            elif op == SET_INDEX:
                value = stack.pop()
                index = stack.pop()
                obj = stack.pop()
                self._set_index(obj, index, value)
                stack.append(value)
            else:
                self._error("unknown opcode %d" % op)

    # -- operand helpers --
    def _arith(self, stack, fn, sym):
        b = stack.pop()
        a = stack.pop()
        if not isinstance(a, float) or not isinstance(b, float):
            self._error("operands must be numbers for '%s'" % sym)
        r = fn(a, b)
        if isinstance(r, complex):
            self._error("'%s' produced a non-real result" % sym)
        stack.append(r)

    def _num_cmp(self, a, b, fn, sym):
        if not isinstance(a, float) or not isinstance(b, float):
            self._error("operands must be numbers for '%s'" % sym)
        return fn(a, b)

    @staticmethod
    def _eq(a, b):
        if isinstance(a, float) and isinstance(b, float):
            return a == b
        if isinstance(a, str) and isinstance(b, str):
            return a == b
        if isinstance(a, bool) and isinstance(b, bool):
            return a == b
        if a is None and b is None:
            return True
        # arrays, maps, functions: identity
        return a is b

    def _get_index(self, obj, index):
        if isinstance(obj, list):
            if not isinstance(index, float) or index != int(index):
                self._error("array index must be an integer")
            i = int(index)
            if i < 0 or i >= len(obj):
                self._error("array index %d out of bounds (len %d)"
                            % (i, len(obj)))
            return obj[i]
        if isinstance(obj, dict):
            if not isinstance(index, str):
                self._error("map key must be a string")
            if index not in obj:
                self._error("map has no key '%s'" % index)
            return obj[index]
        if isinstance(obj, str):
            if not isinstance(index, float) or index != int(index):
                self._error("string index must be an integer")
            i = int(index)
            if i < 0 or i >= len(obj):
                self._error("string index %d out of bounds" % i)
            return obj[i]
        self._error("can only index arrays, maps, and strings")

    def _set_index(self, obj, index, value):
        if isinstance(obj, list):
            if not isinstance(index, float) or index != int(index):
                self._error("array index must be an integer")
            i = int(index)
            if i < 0 or i >= len(obj):
                self._error("array index %d out of bounds (len %d)"
                            % (i, len(obj)))
            obj[i] = value
            return
        if isinstance(obj, dict):
            if not isinstance(index, str):
                self._error("map key must be a string")
            obj[index] = value
            return
        self._error("can only assign into arrays and maps")
