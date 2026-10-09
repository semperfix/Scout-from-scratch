"""FoxScript native (built-in) functions."""

import time as _time


class NativeError(Exception):
    pass


def _typename(v):
    if v is None:
        return "nil"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "map"
    return "function"


def _num_str(v):
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e15:
        return str(int(v))
    return repr(v)


def _display(v):
    from vm import Closure, Native  # deferred: avoids circular import
    if v is None:
        return "nil"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float):
        return _num_str(v)
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "[" + ", ".join(_display(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join("%s: %s" % (k, _display(x))
                               for k, x in v.items()) + "}"
    if isinstance(v, Closure):
        return "<fn %s>" % (v.function.name or "anon")
    if isinstance(v, Native):
        return "<native %s>" % v.name
    return repr(v)


class Native:
    def __init__(self, name, arity, fn):
        self.name = name
        self.arity = arity  # -1 = variadic
        self.fn = fn

    def call(self, args, out):
        return self.fn(args, out)


def _builtin_print(args, out):
    out.write(" ".join(_display(a) for a in args) + "\n")
    return None


def _builtin_len(args, out):
    v = args[0]
    if isinstance(v, (str, list, dict)):
        return float(len(v))
    raise NativeError("len() needs a string, array, or map (got %s)"
                      % _typename(v))


def _builtin_push(args, out):
    arr, v = args
    if not isinstance(arr, list):
        raise NativeError("push() needs an array (got %s)" % _typename(arr))
    arr.append(v)
    return arr


def _builtin_pop(args, out):
    arr = args[0]
    if not isinstance(arr, list):
        raise NativeError("pop() needs an array (got %s)" % _typename(arr))
    if not arr:
        raise NativeError("pop() from empty array")
    return arr.pop()


def _builtin_keys(args, out):
    m = args[0]
    if not isinstance(m, dict):
        raise NativeError("keys() needs a map (got %s)" % _typename(m))
    return list(m.keys())


def _builtin_has(args, out):
    m, k = args
    if not isinstance(m, dict):
        raise NativeError("has() needs a map (got %s)" % _typename(m))
    if not isinstance(k, str):
        raise NativeError("has() key must be a string")
    return k in m


def _builtin_str(args, out):
    return _display(args[0])


def _builtin_num(args, out):
    v = args[0]
    if isinstance(v, float):
        return v
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            raise NativeError("num() can't parse %r" % v)
    raise NativeError("num() needs a string or number (got %s)"
                      % _typename(v))


def _builtin_type(args, out):
    return _typename(args[0])


def _builtin_assert(args, out):
    if len(args) == 1:
        cond, msg = args[0], "assertion failed"
    else:
        cond, msg = args
    if cond is None or cond is False:
        raise NativeError("assert: %s" % _display(msg))
    return cond


def _builtin_range(args, out):
    if len(args) == 1:
        start, stop = 0.0, args[0]
    else:
        start, stop = args
    for v in (start, stop):
        if not isinstance(v, float):
            raise NativeError("range() needs numbers")
    return [float(i) for i in range(int(start), int(stop))]


def _builtin_clock(args, out):
    return float(_time.time())


BUILTINS = [
    Native("print", -1, _builtin_print),
    Native("len", 1, _builtin_len),
    Native("push", 2, _builtin_push),
    Native("pop", 1, _builtin_pop),
    Native("keys", 1, _builtin_keys),
    Native("has", 2, _builtin_has),
    Native("str", 1, _builtin_str),
    Native("num", 1, _builtin_num),
    Native("type", 1, _builtin_type),
    Native("assert", -1, _builtin_assert),
    Native("range", -1, _builtin_range),
    Native("clock", 0, _builtin_clock),
]
