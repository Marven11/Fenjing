from typing import List
import logging

# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,unused-argument,unused-imports

from ..payload_gen import expression_gen, precedence
from ..rules_utils import join_target, targets_from_pattern
from ..rules_types import Target
from ..const import *

logger = logging.getLogger("rules.list_ops")


@expression_gen
def gen_listify_normal(context, target):
    return [
        (LITERAL, "["),
        target,
        (LITERAL, "]"),
    ]


@expression_gen
def gen_listify_filter(context, target):
    return targets_from_pattern(
        "{1:OBJ}|items|list|map('last')|list",
        {"1": (INTEGER, 1), "OBJ": target, "'last'": (STRING, "last")},
    )


@expression_gen
def gen_listify_str(context, target):
    if target[0] != STRING:
        return [(UNSATISFIED)]
    return targets_from_pattern(
        "STR|slice(1)|map('join')|list",
        {
            "STR": (ENCLOSE_UNDER, precedence["plain_filter"], target),
            "1": (INTEGER, 1),
            "'join'": (STRING, "join"),
        },
    )


@expression_gen
def gen_listify_str2(context, target):
    if target[0] != STRING:
        return [(UNSATISFIED)]
    return targets_from_pattern(
        "STR|batch(LEN)|map('join')|list",
        {
            "STR": (ENCLOSE_UNDER, precedence["plain_filter"], target),
            "LEN": (INTEGER, len(target[1])),
            "'join'": (STRING, "join"),
        },
    )


@expression_gen
def gen_map_attr_normal(context, obj, name):
    targets = targets_from_pattern(
        "OBJ|map('attr','name')",
        {
            "OBJ": (ENCLOSE_UNDER, precedence["plain_filter"], obj),
            "'attr'": (STRING, "attr"),
            "'name'": (STRING, name),
        },
    )
    return [(EXPRESSION, precedence["called_filter"], targets)]


@expression_gen
def gen_map_attr_normal2(context, obj, name):
    targets = targets_from_pattern(
        "OBJ|map(attribute='name')",
        {"OBJ": (ENCLOSE_UNDER, precedence["plain_filter"], obj), "'name'": (STRING, name)},
    )
    return [(EXPRESSION, precedence["called_filter"], targets)]


@expression_gen
def gen_map_attr_dict(context, obj, name):
    targets = targets_from_pattern(
        "OBJ|map(**{'attribute':'name'})",
        {
            "OBJ": (ENCLOSE_UNDER, precedence["plain_filter"], obj),
            "'attribute'": (STRING, "attribute"),
            "'name'": (STRING, name),
        },
    )
    return [(EXPRESSION, precedence["called_filter"], targets)]
