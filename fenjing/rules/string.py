import re
import logging

# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,unused-argument,consider-using-f-string

from ..payload_gen import expression_gen, precedence
from ..rules_utils import (
    targets_from_pattern,
    str_escape,
    join_target,
)
from ..rules_types import *

from ..const import *


logger = logging.getLogger("rules.string")

# ---
# 以下的gen_string会互相依赖，但是产生互相依赖时传入的字符串长度会减少所以不会发生无限调用


@expression_gen
def gen_string_1(context: dict, value: str):
    chars = [str_escape(c, "'") for c in value]
    target_list = [(LITERAL, "'{}'".format("".join(chars)))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_2(context: dict, value: str):
    chars = [str_escape(c, '"') for c in value]
    target_list = [(LITERAL, '"{}"'.format("".join(chars)))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_manypercentlowerc(context: dict, value: str):
    if value.replace("%c", "") != "" or len(value) == "":
        return [(UNSATISFIED,)]
    return [(STRING_MANY_PERCENT_LOWER_C, value.count("%c"))]


@expression_gen
def gen_string_twostringconcat(context: dict, value: str):
    if len(value) < 2 or len(value) > 20:
        return [(UNSATISFIED,)]
    target_list = [
        # (LITERAL, "'"),  # ONEOF should output a valid expression
        (
            ONEOF,
            [
                [
                    (LITERAL, "'{}'".format(str_escape(value[:i], "'"))),
                    (LITERAL, "'{}'".format(str_escape(value[i:], "'"))),
                ]
                for i in range(1, len(value))
            ],
        ),
    ]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_twostringconcat2(context: dict, value: str):
    if len(value) < 2 or len(value) > 20:
        return [(UNSATISFIED,)]
    target_list = [
        # (LITERAL, '"'),  # ONEOF should output a valid expression
        (
            ONEOF,
            [
                [
                    (LITERAL, '"{}"'.format(str_escape(value[:i], '"'))),
                    (LITERAL, '"{}"'.format(str_escape(value[i:], '"'))),
                ]
                for i in range(1, len(value))
            ],
        ),
    ]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_concatdunder(context: dict, value: str):
    if not re.match("^__[A-Za-z0-9_]+__$", value):
        return [(UNSATISFIED,)]
    target_list = [
        (LITERAL, "'_'"),
        (LITERAL, "'{}'".format(str_escape(value[1:-1], "'"))),
        (LITERAL, "'_'"),
    ]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_concatdunder2(context: dict, value: str):
    if not re.match("^__[A-Za-z0-9_]+__$", value):
        return [(UNSATISFIED,)]
    target_list = [
        (LITERAL, '"_"'),
        (LITERAL, '"{}"'.format(str_escape(value[1:-1], '"'))),
        (LITERAL, '"_"'),
    ]
    return [(EXPRESSION, precedence["literal"], target_list)]


# 如果上面的规则能用那就不要随便用上下文中的变量，否则会增加payload长度
@expression_gen
def gen_string_context(context: dict, value: str):
    if value not in context.values():
        return [(UNSATISFIED,)]
    vs = [k for k, v in context.items() if v == value]
    alternatives = [[(LITERAL, v)] + [(WITH_CONTEXT_VAR, v)] for v in vs]
    return [(EXPRESSION, precedence["literal"], [(ONEOF, alternatives)])]


@expression_gen
def gen_string_dunder(context: dict, value: str):
    if value != "__":
        return [(UNSATISFIED,)]
    return [(STRING_TWOUNDERLINE,)]


# 如果将__xxx__拆分成_ _xxx_ _
# 那中间 _xxx_ 的表达式可能会过于复杂
# 为了缩短payload还是拆成 __ xxx __ 比较好


@expression_gen
def gen_string_removedunder2(context: dict, value: str):
    if not re.match("^__[A-Za-z0-9_]+__$", value):
        return [(UNSATISFIED,)]
    return [
        (
            STRING_CONCATMANY,
            [
                (STRING_TWOUNDERLINE,),
                (STRING, value[2:-2]),
                (STRING_TWOUNDERLINE,),
            ],
        )
    ]


@expression_gen
def gen_string_removedunder3(context: dict, value: str):
    if not re.match("^__[A-Za-z][A-Za-z0-9]+__$", value):
        return [(UNSATISFIED,)]
    # "%slo%%s"%("__")%("__")
    targets = targets_from_pattern(
        "STRING%DUNDER%DUNDER",
        {
            "STRING": (
                ENCLOSE_UNDER,
                precedence["mod"],
                (STRING, "%s" + value[2:-2] + "%%s"),
            ),
            "DUNDER": (ENCLOSE_UNDER, precedence["mod"], (STRING_TWOUNDERLINE,)),
        },
    )
    return [(EXPRESSION, precedence["mod"], targets)]


@expression_gen
def gen_string_removedunder4(context: dict, value: str):
    if not re.match("^__[A-Za-z][A-Za-z0-9]+__$", value):
        return [(UNSATISFIED,)]
    # "%slo%%s"|format("__")|format("__")
    targets = targets_from_pattern(
        "{STRING} | format( {DUNDER} ) | format( {DUNDER} )",
        {
            "{STRING}": (
                ENCLOSE_UNDER,
                precedence["mod"],
                (STRING, "%s" + value[2:-2] + "%%s"),
            ),
            "{DUNDER}": (ENCLOSE_UNDER, precedence["mod"], (STRING_TWOUNDERLINE,)),
            " ": (WHITESPACE,),
        },
    )
    return [(EXPRESSION, precedence["called_filter"], targets)]


@expression_gen
def gen_string_reverse1(context: dict, value: str):
    chars = [str_escape(c, "'") for c in value]
    target_list = [(LITERAL, "'{}'[::-1]".format("".join(chars[::-1])))]
    return [(EXPRESSION, precedence["slide"], target_list)]


@expression_gen
def gen_string_reverse2(context: dict, value: str):
    chars = [str_escape(c, '"') for c in value]
    target_list = [(LITERAL, '"{}"[::-1]'.format("".join(chars[::-1])))]
    return [(EXPRESSION, precedence["slide"], target_list)]


@expression_gen
def gen_string_lower1(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [str_escape(c, "'") for c in value.upper()]
    target_list = [(LITERAL, "'{}'.lower()".format("".join(chars)))]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_lower2(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [str_escape(c, '"') for c in value.upper()]
    target_list = [(LITERAL, '"{}".lower()'.format("".join(chars)))]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_lower3(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [str_escape(c, "'") for c in value.upper()]
    target_list = [(LITERAL, "'{}'.lower( )".format("".join(chars)))]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_lower4(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [str_escape(c, '"') for c in value.upper()]
    target_list = [(LITERAL, '"{}".lower( )'.format("".join(chars)))]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_lowerfilter1(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [str_escape(c, "'") for c in value.upper()]
    target_list = [(LITERAL, "'{}'|lower".format("".join(chars)))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_lowerfilter2(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [str_escape(c, '"') for c in value.upper()]
    target_list = [(LITERAL, '"{}"|lower'.format("".join(chars)))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_lowerfilterdict1(context: dict, value: str):
    if value.upper().lower() != value or not re.match(
        r"^[A-Za-z_][A-Za-z0-9_]+$", value
    ):
        return [(UNSATISFIED,)]
    chars = [str_escape(c, '"') for c in value.upper()]
    target_list = [(LITERAL, "dict({}=i)|first|lower".format("".join(chars)))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_lowerfilterdict2(context: dict, value: str):
    if value.upper().lower() != value or not re.match(
        r"^[A-Za-z_][A-Za-z0-9_]+$", value
    ):
        return [(UNSATISFIED,)]
    chars = [str_escape(c, '"') for c in value.upper()]
    target_list = [(LITERAL, "dict({}=i)|last|lower".format("".join(chars)))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_concat1(context: dict, value: str):
    target_list = [
        (
            LITERAL,
            "+".join("'{}'".format(str_escape(c, "'")) for c in value),
        )
    ]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_string_concat2(context: dict, value: str):
    target_list = [
        (
            LITERAL,
            "+".join('"{}"'.format(str_escape(c, '"')) for c in value),
        )
    ]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_string_concat3(context: dict, value: str):
    target_list = [(LITERAL, "".join('"{}"'.format(str_escape(c, '"')) for c in value))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_concat4(context: dict, value: str):
    target_list = [
        (LITERAL, " ".join('"{}"'.format(str_escape(c, '"')) for c in value))
    ]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_dictjoin(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, "dict({}=i)|join".format(value))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_dictfirst(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, "dict({}=i)|first".format(value))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_dictfirstreverse(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, "dict({}=i)|first|reverse".format(value[::-1]))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_dictlastreverse(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, "dict({}=i)|last|reverse".format(value[::-1]))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


# 以下规则生成的payload显著长于原string


@expression_gen
def gen_string_x1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\x" + hex(ord(c))[2:].zfill(2) for c in value)
    target_list = [(LITERAL, '"{}"'.format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_x2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\x" + hex(ord(c))[2:].zfill(2) for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_u1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\u00" + hex(ord(c))[2:].zfill(2) for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_u2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\u00" + hex(ord(c))[2:].zfill(2) for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_o1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\" + oct(ord(c))[2:].zfill(2) for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_o2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\" + oct(ord(c))[2:].zfill(2) for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_char(context: dict, value: str):
    if len(value) != 1:
        return [(UNSATISFIED,)]
    return [(CHAR, value)]


@expression_gen
def gen_string_lowerfilternamespaceattrs1(context: dict, value: str):
    if value.upper().lower() != value or not re.match(
        r"^[A-Za-z_][A-Za-z0-9_]+$", value
    ):
        return [(UNSATISFIED,)]
    chars = [str_escape(c, '"') for c in value.upper()]
    target_list = [
        (
            LITERAL,
            "namespace({}=x)._Namespace__attrs|first|lower".format("".join(chars)),
        )
    ]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_lowerfilternamespaceattrs2(context: dict, value: str):
    if value.upper().lower() != value or not re.match(
        r"^[A-Za-z_][A-Za-z0-9_]+$", value
    ):
        return [(UNSATISFIED,)]
    chars = [str_escape(c, '"') for c in value.upper()]
    target_list = [
        (LITERAL, "namespace({}=x)._Namespace__attrs|last|lower".format("".join(chars)))
    ]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_splitdictjoin(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    parts = [value[i : i + 3] for i in range(0, len(value), 3)]

    if len(set(parts)) != len(parts):
        return [(UNSATISFIED,)]

    target_list = [
        (LITERAL, "dict({})|join".format(",".join(f"{part}=x" for part in parts)))
    ]
    return [(EXPRESSION, precedence["plain_filter"], target_list), (REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_splitdictjoin2(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    parts = [value[i : i + 3] for i in range(0, len(value), 3)]
    targets = [(LITERAL, "dict({}=i)|join".format(part)) for part in parts]
    strings = [(EXPRESSION, precedence["plain_filter"], [target]) for target in targets]
    return [(STRING_CONCATMANY, strings), (REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_splitdictjoin3(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]

    if len(set(value)) != len(value):
        return [(UNSATISFIED,)]

    target_list = [
        (LITERAL, "dict({})|join".format(",".join(f"{part}=x" for part in value)))
    ]
    return [(EXPRESSION, precedence["plain_filter"], target_list), (REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_splitnamespacedictjoin(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    parts = [value[i : i + 3] for i in range(0, len(value), 3)]

    if len(set(parts)) != len(parts):
        return [(UNSATISFIED,)]

    target_list = [
        (
            LITERAL,
            "namespace({})._Namespace__attrs|join".format(
                ",".join(f"{part}=x" for part in parts)
            ),
        )
    ]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_splitnamespacedictjoin2(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    parts = [value[i : i + 3] for i in range(0, len(value), 3)]
    targets = [
        (LITERAL, "namespace({}=x)._Namespace__attrs|join".format(part))
        for part in parts
    ]
    strings = [(EXPRESSION, precedence["plain_filter"], [target]) for target in targets]
    return [(STRING_CONCATMANY, strings)]


@expression_gen
def gen_string_splitnamespacedictjoin3(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]

    if len(set(value)) != len(value):
        return [(UNSATISFIED,)]

    target_list = [
        (
            LITERAL,
            "namespace({})._Namespace__attrs|join".format(
                ",".join(f"{part}=x" for part in value)
            ),
        )
    ]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_formatpercent1(context: dict, value: str):
    # (('%c'*n)%(97,98,99))
    if len(value) != 1:
        return [(UNSATISFIED,)]
    number_tuple = [(ENCLOSE_UNDER, precedence["mod"], (INTEGER, ord(value)))]
    return [
        (
            MOD,
            (STRING_MANY_PERCENT_LOWER_C, len(value)),
            (EXPRESSION, precedence["mod"], number_tuple),
        )
    ]


@expression_gen
def gen_string_formatpercent(context: dict, value: str):
    # (('%c'*n)%(97,98,99))
    number_tuple = [
        (LITERAL, "("),
        (WHITESPACE,),
        *join_target((LITERAL, ","), [(INTEGER, ord(c)) for c in value]),
        (WHITESPACE,),
        (LITERAL, ")"),
    ]
    return [
        (
            MOD,
            (STRING_MANY_PERCENT_LOWER_C, len(value)),
            (EXPRESSION, precedence["literal"], number_tuple),
        )
    ]


@expression_gen
def gen_string_formatfunc(context: dict, value: str):
    # ('%c'*n)|format(97,98,99)
    req = []
    manypc = (STRING_MANY_PERCENT_LOWER_C, len(value))
    req.append((ENCLOSE_UNDER, precedence["plain_filter"], manypc))
    req.append((LITERAL, "|format("))
    req += join_target((LITERAL, ","), [(INTEGER, ord(c)) for c in value])
    req.append((LITERAL, ")"))
    return [(EXPRESSION, precedence["called_filter"], req)]


@expression_gen
def gen_string_formatfunc2(context: dict, value: str):
    # (FORMAT(97,98,99))
    # FORMAT = (CS.format)
    # CS = (C*L)
    if re.match("^[a-z]+$", value):  # avoid infinite recursion
        return [(UNSATISFIED,)]
    if "{:c}" not in context.values():
        return [(UNSATISFIED,)]
    k = [k for k, v in context.values() if v == "{:c}"][0]
    k = (EXPRESSION, precedence["literal"], (LITERAL, k))
    cs = (MULTIPLY, k, (INTEGER, len(value)))
    format_func = (ATTRIBUTE, (LITERAL, cs), "format")
    target_list = (
        [
            (ENCLOSE_UNDER, precedence["function_call"], format_func),
            (LITERAL, "("),
        ]
        + join_target((LITERAL, ","), [(INTEGER, ord(c)) for c in value])
        + [
            (LITERAL, ")"),
        ]
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_formatfunc3(context: dict, value: str):
    # (FORMAT(97,98,99))
    # FORMAT = (CS.format)
    # CS = (C*L)
    logger.debug("gen_string_formatfunc3: %s", value)
    if re.match("^[a-z]+$", value):  # avoid infinite recursion
        return [(UNSATISFIED,)]
    format_func = (ATTRIBUTE, (STRING_MANY_FORMAT_C, len(value)), "format")
    target_list = (
        [
            (ENCLOSE_UNDER, precedence["function_call"], format_func),
            (LITERAL, "("),
        ]
        + join_target((LITERAL, ","), [(INTEGER, ord(c)) for c in value])
        + [
            (LITERAL, ")"),
        ]
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_chars(context: dict, value: str):
    targets = [(CHAR, c) for c in value]
    return [(STRING_CONCATMANY, targets)]


@expression_gen
def gen_string_chars2(context: dict, value: str):
    target_list = (
        [(LITERAL, "(")]
        + join_target((LITERAL, ","), [(CHAR, c) for c in value])
        + [(LITERAL, ")|join")]
    )
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_joinbyreplace(context: dict, value: str):
    # 12|replace(1,a)|replace(2,b)
    if re.search(r"\d", value) or len(value) <= 1:
        return [(UNSATISFIED,)]
    if len(value) > 2 and value[:2] == "__":
        split = 2
    elif len(value) > 2 and value[-2:] == "__":
        split = -2
    else:
        return [(UNSATISFIED,)]
    targets = targets_from_pattern(
        "{12}|replace( {1} , {STR1} {,} )|replace( {2} , {STR2} {,} )",
        {
            " ": (WHITESPACE,),
            "{12}": (INTEGER, 12),
            "{1}": (INTEGER, 1),
            "{2}": (INTEGER, 2),
            "{STR1}": (STRING, value[:split]),
            "{STR2}": (STRING, value[split:]),
            "{,}": (ONEOF, [[(LITERAL, "")], [(LITERAL, ",")]]),
        },
    )
    return [(EXPRESSION, precedence["called_filter"], targets)]


@expression_gen
def gen_string_splitdictjoincycler(context: dict, value: str):
    if not re.match("^[a-zA-Z_]{1,20}$", value):
        return [(UNSATISFIED,)]
    parts = [value[i : i + 3] for i in range(0, len(value), 3)]

    if len(set(parts)) != len(parts):
        return [(UNSATISFIED,)]

    target_list = [
        (
            LITERAL,
            "cycler.next.__globals__.concat(dict({}))".format(
                ",".join(f"{part}=x" for part in parts)
            ),
        )
    ]
    return [(EXPRESSION, precedence["function_call"], target_list), (REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_lipsumtobytes4(context: dict, value: str):
    ints: List[Target] = join_target(
        sep=(LITERAL, ","), targets=[(INTEGER, ord(c)) for c in value]
    )
    bytes_targets = targets_from_pattern(
        "lipsum[GLOBALS][BUILTINS][BYTES]( ( INTS ) MAYBE_COMMA)[DECODE]( )",
        {
            "GLOBALS": (VARIABLE_OF, "__globals__"),
            "BUILTINS": (VARIABLE_OF, "__builtins__"),
            "BYTES": (VARIABLE_OF, "bytes"),
            " ": (WHITESPACE,),
            "INTS": ints,
            "MAYBE_COMMA": (ONEOF, [[(LITERAL, ",")], [(LITERAL, "")]]),
            "DECODE": (VARIABLE_OF, "decode"),
        },
    )
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            bytes_targets,
        )
    ] + [(REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_lipsumtobytes5(context: dict, value: str):

    bytes_targets = targets_from_pattern(
        "lipsum|attr( GLOBALS )|attr( GETITEM )( BUILTINS )"
        "|attr( GETITEM )( BYTES )( ( INTS ) MAYBE_COMMA)|attr(DECODE)( )",
        {
            "GLOBALS": (VARIABLE_OF, "__globals__"),
            "GETITEM": (VARIABLE_OF, "__getitem__"),
            "BUILTINS": (VARIABLE_OF, "__builtins__"),
            "BYTES": (VARIABLE_OF, "bytes"),
            " ": (WHITESPACE,),
            "INTS": join_target(
                sep=(LITERAL, ","), targets=[(INTEGER, ord(c)) for c in value]
            ),
            "MAYBE_COMMA": (ONEOF, [[(LITERAL, ",")], [(LITERAL, "")]]),
            "DECODE": (VARIABLE_OF, "decode"),
        },
    )
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            bytes_targets,
        )
    ] + [(REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_undefinedtobytes(context: dict, value: str):

    bytes_targets = targets_from_pattern(
        "UNDEFINED|attr( ADD )|attr( GLOBALS )|attr( GETITEM )( BUILTINS )"
        "|attr( GETITEM )( BYTES )( ( INTS ) MAYBE_COMMA)|attr(DECODE)( )",
        {
            "UNDEFINED": (
                ONEOF,
                [
                    [(LITERAL, "a")],
                    [(LITERAL, "t")],
                    [(LITERAL, "r")],
                    [(LITERAL, "x")],
                ],
            ),
            "ADD": (GENERATED_EXPR, (STRING, "__add__")),
            "GLOBALS": (GENERATED_EXPR, (STRING, "__globals__")),
            "GETITEM": (GENERATED_EXPR, (STRING, "__getitem__")),
            "BUILTINS": (GENERATED_EXPR, (STRING, "__builtins__")),
            "BYTES": (GENERATED_EXPR, (STRING, "bytes")),
            " ": (WHITESPACE,),
            "INTS": join_target(
                sep=(LITERAL, ","), targets=[(INTEGER, ord(c)) for c in value]
            ),
            "MAYBE_COMMA": (ONEOF, [[(LITERAL, ",")], [(LITERAL, "")]]),
            "DECODE": (GENERATED_EXPR, (STRING, "decode")),
        },
    )
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            bytes_targets,
        )
    ] + [(REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_intbytes1(context: dict, value: str):
    if not all(x < 128 for x in value.encode()):
        return [(UNSATISFIED,)]
    if re.match(r"^[a-zA-Z0-9]$", value):
        return [(UNSATISFIED,)]
    n = int.from_bytes(value.encode(), "big")
    targets = targets_from_pattern(
        "N.to_bytes(ARGS).decode()",
        {
            "N": (ENCLOSE_UNDER, precedence["attribute"], (INTEGER, n)),
            "ARGS": (
                ONEOF,
                [
                    [(INTEGER, len(value)), (REQUIRE_PYTHON3_SUBVERSION, 11)],
                    [(INTEGER, len(value)), (LITERAL, ","), (GENERATED_EXPR, (STRING, "big"))],
                ],
            ),
        },
    )
    return [(EXPRESSION, precedence["function_call"], targets), (REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_intbytes2(context: dict, value: str):
    if not all(x < 128 for x in value.encode()):
        return [(UNSATISFIED,)]
    if re.match(r"^[a-zA-Z0-9]$", value):
        return [(UNSATISFIED,)]
    n = int.from_bytes(value.encode(), "big")
    targets = targets_from_pattern(
        "( {BYTES:0}|map('attr','decode')|first)( )",
        {
            "BYTES": targets_from_pattern(
                "( {NUM:0}|map('attr','to_bytes')|first)(ARGS)",
                {
                    "NUM": (INTEGER, n),
                    "ARGS": (
                        ONEOF,
                        [
                            [(INTEGER, len(value)), (REQUIRE_PYTHON3_SUBVERSION, 11)],
                            [(INTEGER, len(value)), (LITERAL, ","), (GENERATED_EXPR, (STRING, "big"))],
                        ],
                    ),
                    "'attr'": (GENERATED_EXPR, (STRING, "attr")),
                    "'to_bytes'": (GENERATED_EXPR, (STRING, "to_bytes")),
                    "0": (INTEGER, 0),
                    " ": (WHITESPACE,),
                },
            ),
            "0": (INTEGER, 0),
            "'attr'": (GENERATED_EXPR, (STRING, "attr")),
            "'decode'": (GENERATED_EXPR, (STRING, "decode")),
            " ": (WHITESPACE,),
        },
    )
    return [(EXPRESSION, precedence["function_call"], targets), (REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_intbytes3(context: dict, value: str):
    if not all(x < 128 for x in value.encode()):
        return [(UNSATISFIED,)]
    if re.match(r"^[a-zA-Z0-9]$", value):
        return [(UNSATISFIED,)]
    n = int.from_bytes(value.encode(), "big")
    targets = targets_from_pattern(
        "( {BYTES:0}|map(**{'attribute':'decode'})|GETTHAT)( )",
        {
            "BYTES": targets_from_pattern(
                "( {NUM:0}|map(**{'attribute':'to_bytes'})|GETTHAT)(ARGS)",
                {
                    "NUM": (INTEGER, n),
                    "ARGS": (
                        ONEOF,
                        [
                            [(INTEGER, len(value)), (REQUIRE_PYTHON3_SUBVERSION, 11)],
                            [(INTEGER, len(value)), (LITERAL, ","), (GENERATED_EXPR, (STRING, "big"))],
                        ],
                    ),
                    "GETTHAT": (ONEOF, [[(LITERAL, "first")], [(LITERAL, "last")]]),
                    "'attribute'": (GENERATED_EXPR, (STRING, "attribute")),
                    "'to_bytes'": (GENERATED_EXPR, (STRING, "to_bytes")),
                    "0": (INTEGER, 0),
                    " ": (WHITESPACE,),
                },
            ),
            "0": (INTEGER, 0),
            "GETTHAT": (ONEOF, [[(LITERAL, "first")], [(LITERAL, "last")]]),
            "'attribute'": (GENERATED_EXPR, (STRING, "attribute")),
            "'decode'": (GENERATED_EXPR, (STRING, "decode")),
            " ": (WHITESPACE,),
        },
    )
    return [
        (EXPRESSION, precedence["function_call"], targets),
    ]
