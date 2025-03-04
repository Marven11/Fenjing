import math

# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,unused-argument

from ..payload_gen import expression_gen, precedence
from ..rules_utils import (
    transform_int_chars_unicode,
    join_target,
    targets_from_pattern,
    literal_to_target,
)
from ..rules_types import *
from ..const import *
from ..context_vars import const_exprs, const_exprs_py3

const_exprs_all = {
    k: v
    for d in [const_exprs, const_exprs_py3]
    for k, v in d.items()
    if isinstance(v, int)
}


# ---


@expression_gen
def gen_multiply_normal(context: dict, a, b):
    a = (ENCLOSE_UNDER, precedence["multiply"], a)
    b = (ENCLOSE_UNDER, precedence["multiply"], b)
    return [(EXPRESSION, precedence["multiply"], [a, (LITERAL, "*"), b])]


@expression_gen
def gen_multiply_func(context: dict, a, b):
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            [
                (ENCLOSE_UNDER, precedence["attribute"], a),
                (LITERAL, ".__mul__"),
                (
                    WRAP,
                    [
                        b,
                    ],
                ),
            ],
        )
    ]


@expression_gen
def gen_multiply_func2(context: dict, a, b):
    mul_func = (
        ONEOF,
        [
            [(LITERAL, "|attr('__mul__')")],
            [(LITERAL, '|attr("__mul__")')],
            [(LITERAL, "|attr"), (WRAP, [(VARIABLE_OF, "__mul__")])],
        ],
    )
    return [
        (
            EXPRESSION,
            precedence["called_filter"],
            [
                (ENCLOSE_UNDER, precedence["plain_filter"], a),
                mul_func,
                (
                    WRAP,
                    [
                        b,
                    ],
                ),
            ],
        )
    ]


# ---


@expression_gen
def gen_formular_sum_simplesum(context, num_targets):
    # simply sum up with `+` without touching complex rules for PLUS
    target_list = join_target(sep=(LITERAL, "+"), targets=num_targets)
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_formular_sum_tuplesum(context, num_targets):
    if len(num_targets) == 1:
        return [num_targets[0]]
    target_list = (
        [
            (LITERAL, "("),
        ]
        + join_target(sep=(LITERAL, ","), targets=num_targets)
        + [(LITERAL, ")|sum")]
    )
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_formular_sum_add(context, num_targets):
    final_target = num_targets[0]
    for target in num_targets[1:]:
        final_target = (PLUS, final_target, target)
    return [final_target]


# ---


@expression_gen
def gen_zero_literal(context: dict):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, "0")])]


@expression_gen
def gen_zero_2(context: dict):
    return [(EXPRESSION, precedence["plain_filter"], [(LITERAL, "{}|int")])]


@expression_gen
def gen_zero_3(context: dict):
    return [
        (
            EXPRESSION,
            precedence["plain_filter"],
            [(LITERAL, "g|urlencode|length"), (REQUIRE_FLASK,)],
        )
    ]


@expression_gen
def gen_zero_4(context: dict):
    return [(EXPRESSION, precedence["plain_filter"], [(LITERAL, "{}|urlencode|count")])]


@expression_gen
def gen_zero_cycler(context: dict):
    return [(EXPRESSION, precedence["attribute"], [(LITERAL, "cycler(cycler).pos")])]


@expression_gen
def gen_zero_cycler2(context: dict):
    targets = [
        (LITERAL, "cycler(cycler)["),
        (
            ONEOF,
            [
                [(LITERAL, "'pos'")],
                [(LITERAL, '"pos"')],
                [(VARIABLE_OF, "pos")],
            ],
        ),
        (LITERAL, "]"),
    ]
    return [(EXPRESSION, precedence["item"], targets)]


@expression_gen
def gen_zero_emptylength(context: dict):
    empty_things = [
        [(LITERAL, "''")],
        [(LITERAL, '""')],
        [(LITERAL, "()")],
        [(LITERAL, "( )")],
        [(LITERAL, "(\t)")],
        [(LITERAL, "(\n)")],
        [(LITERAL, "[]")],
        [(LITERAL, "{}")],
    ]
    get_length = [
        [(LITERAL, ".__len__()")],
        [(LITERAL, ".__len__( )")],
        [(LITERAL, ".__len__(\t)")],
        [(LITERAL, ".__len__(\n)")],
    ]
    target_list = [(ONEOF, empty_things), (ONEOF, get_length)]
    return [(EXPRESSION, precedence["function_call"], target_list)]


def gen_zero_const_expr(context):
    alternatives = [
        [literal_to_target(k)] for k, v in const_exprs.items() if v == 0
    ] + [
        [literal_to_target(k), (REQUIRE_PYTHON3,)]
        for k, v in const_exprs_py3.items()
        if v == 0
    ]
    if not alternatives:
        return [(UNSATISFIED,)]
    return [(ONEOF, alternatives)]


# ---


@expression_gen
def gen_positive_integer_simple(context: dict, value: int):
    if value < 0:
        return [(UNSATISFIED,)]
    return [(EXPRESSION, precedence["literal"], [(LITERAL, str(value))])]


@expression_gen
def gen_positive_integer_hex(context: dict, value: int):
    if value < 0:
        return [(UNSATISFIED,)]
    return [(EXPRESSION, precedence["literal"], [(LITERAL, hex(value))])]


@expression_gen
def gen_positive_integer_underline(context: dict, value: int):
    if value < 0:
        return [(UNSATISFIED,)]
    return [(EXPRESSION, precedence["literal"], [(LITERAL, "_".join(str(value)))])]


# jinja最新版的integer token正则如下：
# integer_re = re.compile(
#     r"""
#     (
#         0b(_?[0-1])+ # binary
#     |
#         0o(_?[0-7])+ # octal
#     |
#         0x(_?[\da-f])+ # hex    <--- 这个支持unicode
#     |
#         [1-9](_?\d)* # decimal    <--- 这个支持unicode
#     |
#         0(_?0)* # decimal zero
#     )
#     """,
#     re.IGNORECASE | re.VERBOSE,
# )


@expression_gen
def gen_positive_integer_unicode(context: dict, value: int):
    if value <= 9:
        return [(UNSATISFIED,)]
    payload_targets = [
        [(LITERAL, payload)] for payload in transform_int_chars_unicode(str(value)[1:])
    ]
    return [
        (REQUIRE_PYTHON3,),
        (
            EXPRESSION,
            precedence["literal"],
            [(LITERAL, str(value)[0]), (ONEOF, payload_targets)],
        ),
    ]


@expression_gen
def gen_positive_integer_unicodehex(context: dict, value: int):
    if value <= 0:
        return [(UNSATISFIED,)]
    value_hex_literal = hex(value)[2:]
    payload_targets = [
        [(LITERAL, payload)]
        for payload in transform_int_chars_unicode(value_hex_literal)
    ]
    targets_list = [(LITERAL, "0x"), (ONEOF, payload_targets)]
    return [(REQUIRE_PYTHON3,), (EXPRESSION, precedence["literal"], targets_list)]


@expression_gen
def gen_positive_integer_hexunderline(context: dict, value: int):
    if value < 0:
        return [(UNSATISFIED,)]
    digits = hex(value)[2:]
    literal = "0x_{}".format("_".join(digits))
    return [(EXPRESSION, precedence["literal"], [(LITERAL, literal)])]


@expression_gen
def gen_positive_integer_octunderline(context: dict, value: int):
    if value < 0:
        return [(UNSATISFIED,)]
    digits = oct(value)[2:]
    literal = "0o_{}".format("_".join(digits))
    return [(EXPRESSION, precedence["literal"], [(LITERAL, literal)])]


@expression_gen
def gen_positive_integer_sum(context: dict, value: int):
    if value < 0 or value > 1000:
        return [(UNSATISFIED,)]

    ints = [
        (var_name, var_value)
        for var_name, var_value in context.items()
        if isinstance(var_value, int) and var_value > 0
    ]

    if ints == []:
        return [(UNSATISFIED,)]

    ints.sort(key=lambda pair: pair[1], reverse=True)
    value_left = value
    payload_vars = []
    while value_left != 0:
        while ints and ints[0][1] > value_left:
            ints = ints[1:]
        if not ints:
            return [(UNSATISFIED,)]
        value_left -= ints[0][1]
        payload_vars.append(ints[0][0])
    ints = [(EXPRESSION, precedence["literal"], [(LITERAL, v)]) for v in payload_vars]
    return [(FORMULAR_SUM, ints)] + [(WITH_CONTEXT_VAR, v) for v in payload_vars]


@expression_gen
def gen_positive_integer_recurmulitiply(context: dict, value: int):
    if value > 1000:
        return [(UNSATISFIED,)]
    xs = [x for x in range(3, value // 2) if value % x == 0]
    xs.sort(key=lambda x: max(x, value // x))
    if xs == [] or value < 20:
        return [(UNSATISFIED,)]
    target_list = [
        (
            ONEOF,
            [
                [
                    (
                        MULTIPLY,
                        (POSITIVE_INTEGER, value // x),
                        (POSITIVE_INTEGER, x),
                    )
                ]
                for x in xs
            ],
        )
    ]
    return [(EXPRESSION, precedence["multiply"], target_list)]


@expression_gen
def gen_positive_integer_recurmultiply2(context: dict, value: int):
    if value <= 20 or value > 1000:
        return [(UNSATISFIED,)]
    alternatives = []
    for i in range(9, 3, -1):
        lst = [(LITERAL, "+"), (POSITIVE_INTEGER, value % i)] if value % i != 0 else []
        alternative = (
            [
                (LITERAL, "("),
                (ENCLOSE_UNDER, precedence["multiply"], (POSITIVE_INTEGER, value // i)),
                (LITERAL, "*"),
                (ENCLOSE_UNDER, precedence["multiply"], (POSITIVE_INTEGER, i)),
            ]
            + lst
            + [
                (LITERAL, ")"),
            ]
        )
        alternatives.append(alternative)
    if not alternatives:
        return [(UNSATISFIED,)]
    target_list = [(ONEOF, alternatives)]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_positive_integer_recurmulnoastral(context: dict, value: int):
    if value <= 20 or value > 1000:
        return [(UNSATISFIED,)]
    alternatives = []
    pieces_max = int(math.sqrt(value)) + 2
    for i in range(3, pieces_max):
        # value = a * i + b
        a, b = (value // i), (value % i)
        if a > pieces_max:
            continue
        if b == 0:

            alternative = [(MULTIPLY, (POSITIVE_INTEGER, a), (POSITIVE_INTEGER, i))]
            alternatives.insert(0, alternative)
        else:
            alternative = [
                (
                    PLUS,
                    (MULTIPLY, (POSITIVE_INTEGER, a), (POSITIVE_INTEGER, i)),
                    (POSITIVE_INTEGER, b),
                )
            ]
            alternatives.append(alternative)
    if not alternatives:
        return [(UNSATISFIED,)]
    return [(ONEOF, alternatives)]


@expression_gen
def gen_positive_integer_lengthything(context: dict, value: int):
    if value >= 10 or value <= 3:  # stop generating lengthy payload
        return [(UNSATISFIED,)]
    lengthy_thing: OneofTarget = (
        ONEOF,
        [
            [(LITERAL, "dict({}=x)|join".format("x" * value))],
            [(LITERAL, "({})".format(",".join("x" * value)))],
            [(LITERAL, "cycler({}).items".format(",".join("x" * value)))],
        ],
    )
    target_list = [
        (
            ONEOF,
            [
                [lengthy_thing, (LITERAL, "|length")],
                [lengthy_thing, (LITERAL, "|count")],
                targets_from_pattern(
                    "(LENGTHY_THING,)|map(LENGTH_OR_COUNT)|GETTHAT",
                    {
                        "LENGTHY_THING": lengthy_thing,
                        "LENGTH_OR_COUNT": (
                            ONEOF,
                            [
                                [(LITERAL, "'le''ngth'")],
                                [(LITERAL, '"le""ngth"')],
                                [(LITERAL, "'co''unt'")],
                                [(LITERAL, '"co""unt"')],
                                [(VARIABLE_OF, "length")],
                                [(VARIABLE_OF, "count")],
                            ],
                        ),
                        "GETTHAT": (
                            ONEOF,
                            [[(LITERAL, "first")], [(LITERAL, "last")]],
                        ),
                    },
                ),
            ],
        )
    ]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_positive_integer_length(context: dict, value: int):
    if not (1 < value < 10):
        return [(UNSATISFIED,)]
    lengthy_tuples_zero = (
        [
            (LITERAL, "("),
        ]
        + join_target((LITERAL, ","), [(ZERO,) for _ in range(value)])
        + [
            (LITERAL, ")"),
        ]
    )
    lengthy_tuples_x = (
        [
            (LITERAL, "("),
        ]
        + [
            (
                ONEOF,
                [
                    join_target(
                        (LITERAL, ","), [(LITERAL, chr(c)) for _ in range(value)]
                    )
                    for c in range(ord("a"), ord("z") + 1)
                ],
            )
        ]
        + [
            (LITERAL, ")"),
        ]
    )
    target_list = [
        (ONEOF, [lengthy_tuples_x, lengthy_tuples_zero]),
        (
            ONEOF,
            [
                [(LITERAL, ".__len__()")],
                [(LITERAL, ".__len__( )")],
                [(LITERAL, ".__len__(\t)")],
                [(LITERAL, ".__len__(\n)")],
            ],
            # [(LITERAL, "|length")],
        ),
    ]
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            target_list,
        )
    ]


@expression_gen
def gen_positive_integer_numbersum1(context: dict, value: int):
    if value < 5 or value > 1000:
        return [(UNSATISFIED,)]
    alternative = []
    for i in range(min(40, value - 1), 3, -1):
        if value % i != 0:
            numbers = [str(i)] * (value // i) + [str(value % i)]
        else:
            numbers = [str(i)] * (value // i)
        inner = "+".join(numbers)
        alternative.append([(LITERAL, inner)])
    target_list = [(ONEOF, alternative)]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_positive_integer_numbersum2(context: dict, value: int):
    if value < 5 or value > 1000:
        return [(UNSATISFIED,)]
    alternatives = []
    for i in range(min(40, value - 1), 3, -1):
        if value % i != 0:
            numbers = [str(i)] * (value // i) + [str(value % i)]
        else:
            numbers = [str(i)] * (value // i)
        inner = ",".join(numbers)
        alternatives.append([(LITERAL, "({})|sum".format(inner))])
    target_list = [(ONEOF, alternatives)]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_positive_integer_charint(context: dict, value: int):
    if value < 10:
        return [(UNSATISFIED,)]
    return [
        (
            EXPRESSION,
            precedence["plain_filter"],
            [
                (
                    WRAP,
                    join_target(
                        (LITERAL, "~"), [(INTEGER, int(x)) for x in str(value)]
                    ),
                ),
                (LITERAL, "|int"),
            ],
        )
    ]


@expression_gen
def gen_positive_integer_count(context: dict, value: int):
    if value > 10:
        return [(UNSATISFIED,)]
    s = ",".join("x" * value)
    if value == 1:
        s += ","
    target_list = [(LITERAL, "({})|count".format(s))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_positive_integer_strcount(context: dict, value: int):
    if not (3 <= value <= 9):
        return [(UNSATISFIED,)]
    length_str = "~".join("{}" for _ in range(value // 2))
    if value % 2 == 1:
        length_str += "~{}|int"
    targets = targets_from_pattern(
        f"({length_str})|count",
        {
            "{}": (
                ONEOF,
                [
                    [(LITERAL, "{}")],
                    [(LITERAL, "()")],
                    [(LITERAL, "{ }")],
                    [(LITERAL, "( )")],
                ],
            ),
            "count": (
                ONEOF,
                [
                    [(LITERAL, "count")],
                    [(LITERAL, "length")],
                ],
            ),
        },
    )
    return [(EXPRESSION, precedence["tilde"], targets)]


@expression_gen
def gen_positive_integer_onesum1(context: dict, value: int):
    if value > 10 or value < 2:
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, "{}".format("+".join(["1"] * value)))]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_positive_integer_onesum2(context: dict, value: int):
    if value > 10 or value < 2:
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, "({},)|sum".format(",".join(["1"] * value)))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_positive_integer_truesum1(context: dict, value: int):
    if value > 10 or value < 2:
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, "{}".format("+".join(["True"] * value)))]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_positive_integer_truesum2(context: dict, value: int):
    if value > 10 or value < 2:
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, "({},)|sum".format(",".join(["True"] * value)))]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_positive_integer_bool(context: dict, value: int):
    if value not in (0, 1):
        return [(UNSATISFIED,)]

    target_list = [(LITERAL, f"{value == 1}+False")]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_positive_integer_constexpr(context: dict, value: int):

    alternatives = [
        [literal_to_target(k)] for k, v in const_exprs.items() if v == value
    ] + [
        [literal_to_target(k), (REQUIRE_PYTHON3,)]
        for k, v in const_exprs_py3.items()
        if v == value
    ]
    if not alternatives:
        return [(UNSATISFIED,)]
    return [(ONEOF, alternatives)]


# ---


@expression_gen
def gen_integer_literal(context: dict, value: int):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, str(value))])]


@expression_gen
def gen_integer_context(context: dict, value: int):
    if value not in context.values():
        return [(UNSATISFIED,)]
    v = [k for k, v in context.items() if v == value][0]
    return [
        (EXPRESSION, precedence["literal"], [(LITERAL, v), (WITH_CONTEXT_VAR, v)]),
    ]


@expression_gen
def gen_integer_zero(context: dict, value: int):
    if value != 0:
        return [(UNSATISFIED,)]
    return [(ZERO,)]


@expression_gen
def gen_integer_positive(context: dict, value: int):
    if value <= 0:
        return [(UNSATISFIED,)]
    return [(POSITIVE_INTEGER, value)]


@expression_gen
def gen_integer_negative(context: dict, value: int):
    if value >= 0:
        return [(UNSATISFIED,)]
    target_list = [
        (LITERAL, "-"),
        (ENCLOSE_UNDER, precedence["subtract"], (POSITIVE_INTEGER, abs(value))),
    ]
    return [(EXPRESSION, precedence["subtract"], target_list)]


@expression_gen
def gen_integer_subtract(context: dict, value: int):
    if value > 1000:
        return [(UNSATISFIED,)]
    ints = [
        (var_name, var_value)
        for var_name, var_value in context.items()
        if isinstance(var_value, int) and var_value > 0
    ]

    if ints == []:
        return [(UNSATISFIED,)]

    ints.sort(key=lambda pair: pair[1], reverse=True)
    bigger = [pair for pair in ints if pair[1] >= value]
    if not bigger:
        return [(UNSATISFIED,)]
    to_sub_name, to_sub_value = min(bigger, key=lambda pair: pair[1])
    ints = [pair for pair in ints if pair[1] <= to_sub_value]
    value_left = to_sub_value - value

    sub_vars = []
    while value_left != 0:
        while ints and ints[0][1] > value_left:
            ints = ints[1:]
        if not ints:
            return [(UNSATISFIED,)]
        value_left -= ints[0][1]
        sub_vars.append(ints[0][0])
    targets = [
        (
            LITERAL,
            "({})".format(
                "-".join(
                    [
                        to_sub_name,
                    ]
                    + sub_vars
                )
            ),
        )
    ] + [
        (WITH_CONTEXT_VAR, v)
        for v in [
            to_sub_name,
        ]
        + sub_vars
    ]
    return [(EXPRESSION, precedence["subtract"], targets)]
