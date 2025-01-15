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
