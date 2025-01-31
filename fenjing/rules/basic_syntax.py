from typing import List
import logging

# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,unused-argument

from ..payload_gen import expression_gen, precedence
from ..rules_utils import join_target, targets_from_pattern
from ..rules_types import Target
from ..const import *

logger = logging.getLogger("rules.basic_syntax")

# ---


@expression_gen
def gen_enclose_normal(context: dict, target):
    return [
        (
            EXPRESSION,
            precedence["enclose"],
            [
                (LITERAL, "("),
                (WHITESPACE,),
                target,
                (WHITESPACE,),
                (LITERAL, ")"),
            ],
        )
    ]


# ---


@expression_gen
def gen_wrap_normal(context: dict, targets: List[Target]):
    return [
        (LITERAL, "("),
        (WHITESPACE,),
        *targets,
        (WHITESPACE,),
        (LITERAL, ")"),
    ]


# ---


@expression_gen
def gen_string_concat_plus(context: dict, a, b):
    return [(PLUS, a, b)]


@expression_gen
def gen_string_concat_tilde(context: dict, a, b):
    target_list = [
        (ENCLOSE_UNDER, precedence["tilde"], a),
        (LITERAL, "~"),
        (ENCLOSE_UNDER, precedence["tilde"], b),
    ]
    return [(EXPRESSION, precedence["tilde"], target_list)]


@expression_gen
def gen_string_concat_join(context: dict, a, b):
    return [
        (
            EXPRESSION,
            precedence["plain_filter"],
            targets_from_pattern(
                "(STR_A,STR_B)|join",
                {
                    "STR_A": a,
                    "STR_B": b,
                },
            ),
        )
    ]


@expression_gen
def gen_string_concat_format(context: dict, a, b):
    target_list = [
        (
            ONEOF,
            [[(LITERAL, "'%s%s'")], [(LITERAL, '"%s%s"')], [(VARIABLE_OF, "%s%s")]],
        ),
        (LITERAL, "%"),
        (
            WRAP,
            [
                a,
                (LITERAL, ","),
                b,
            ],
        ),
    ]
    return [(EXPRESSION, precedence["mod"], target_list)]


# ---


@expression_gen
def gen_string_concatmany_noconcat(context: dict, parts):
    if len(parts) == 1:
        return parts
    return [(UNSATISFIED,)]


@expression_gen
def gen_string_concatmany_onebyone(context: dict, parts):
    answer = parts[0]
    for part in parts[1:]:
        answer = (STRING_CONCAT, answer, part)
    return [answer]


@expression_gen
def gen_string_concatmany_join(context: dict, parts):
    targets = targets_from_pattern(
        "(PARTS)|join",
        {
            "PARTS": join_target(sep=(LITERAL, ","), targets=parts),
        },
    )
    return [(EXPRESSION, precedence["plain_filter"], targets)]


# lipsum.__globals__.concat(("a", "b"))


@expression_gen
def gen_string_concatmany_lipsumglobals1(context: dict, parts):
    target_list = (
        [
            (LITERAL, "lipsum.__globals__.concat(("),
        ]
        + join_target(sep=(LITERAL, ","), targets=parts)
        + [
            (LITERAL, "))"),
        ]
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_concatmany_lipsumglobals2(context: dict, parts):
    return [
        (LITERAL, "lipsum["),
        (VARIABLE_OF, "__globals__"),
        (LITERAL, "]["),
        (VARIABLE_OF, "concat"),
        (LITERAL, "](("),
        *join_target(sep=(LITERAL, ","), targets=parts),
        (LITERAL, "))"),
    ]


@expression_gen
def gen_string_concatmany_lipsumglobals3(context: dict, parts):
    return [
        (LITERAL, "lipsum|attr("),
        (VARIABLE_OF, "__globals__"),
        (LITERAL, ")|attr("),
        (VARIABLE_OF, "__getitem__"),
        (LITERAL, ")("),
        (VARIABLE_OF, "concat"),
        (LITERAL, ")(("),
        *join_target(sep=(LITERAL, ","), targets=parts),
        (LITERAL, "))"),
    ]


# ---


@expression_gen
def gen_plus_normal(context: dict, a, b):
    a = (ENCLOSE_UNDER, precedence["plus"], a)
    b = (ENCLOSE_UNDER, precedence["plus"], b)
    return [(EXPRESSION, precedence["plus"], [a, (LITERAL, "+"), b])]


@expression_gen
def gen_plus_addfunc(context: dict, a, b):
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            [
                (ENCLOSE_UNDER, precedence["attribute"], a),
                (LITERAL, ".__add__"),
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
def gen_plus_addfuncbyfilter(context: dict, a, b):
    get_add_func = (
        ONEOF,
        [
            [(LITERAL, "|attr('__add__')")],
            [(LITERAL, '|attr("__add__")')],
            [(LITERAL, '|attr("\\x5f\\x5fadd\\x5f\\x5f")')],
            [(LITERAL, "|attr("), (VARIABLE_OF, "__add__"), (LITERAL, ")")],
        ],
    )
    logger.debug("gen_plus_addfuncbyfilter: %s", repr(a))
    return [
        (
            EXPRESSION,
            precedence["called_filter"],
            [
                (ENCLOSE_UNDER, precedence["plain_filter"], a),
                get_add_func,
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
def gen_mod_normal(context: dict, a, b):
    a = (ENCLOSE_UNDER, precedence["mod"], a)
    b = (ENCLOSE_UNDER, precedence["mod"], b)
    return [(EXPRESSION, precedence["mod"], [a, (LITERAL, "%"), b])]


@expression_gen
def gen_mod_func(context: dict, a, b):
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            [
                (ENCLOSE_UNDER, precedence["attribute"], a),
                (LITERAL, ".__mod__"),
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
def gen_mod_func2(context: dict, a, b):
    mod_func = (
        ONEOF,
        [
            [(LITERAL, "|attr('__mod__')")],
            [(LITERAL, '|attr("__mod__")')],
            [(LITERAL, "|attr("), (VARIABLE_OF, "__mod__"), (LITERAL, ")")],
        ],
    )
    return [
        (
            EXPRESSION,
            precedence["called_filter"],
            [
                (ENCLOSE_UNDER, precedence["plain_filter"], a),
                mod_func,
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
def gen_function_call_forattr(context: dict, function_target, args_target_list):
    target_list = (
        [
            (ENCLOSE_UNDER, precedence["function_call"], function_target),
            (LITERAL, "("),
            (WHITESPACE,),
        ]
        + join_target((LITERAL, ","), args_target_list)
        + [
            (WHITESPACE,),
            (LITERAL, ")"),
        ]
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_function_call_forattr2(context: dict, function_target, args_target_list):
    target_list = (
        [
            (ENCLOSE_UNDER, precedence["function_call"], function_target),
            (LITERAL, "("),
            (WHITESPACE,),
        ]
        + join_target((LITERAL, ","), args_target_list)
        + [
            (LITERAL, ","),
            (WHITESPACE,),
            (LITERAL, ")"),
        ]
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]
