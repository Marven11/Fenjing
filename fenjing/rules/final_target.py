# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,unused-argument

from ..payload_gen import expression_gen, precedence
from ..rules_utils import targets_from_pattern


from ..const import *


# ---


@expression_gen
def gen_os_popen_obj_normal(context, cmd):
    return [(FUNCTION_CALL, (ATTRIBUTE, (MODULE_OS,), "popen"), [(STRING, cmd)])]


@expression_gen
def gen_os_popen_obj_eval(context, cmd):
    targets = targets_from_pattern(
        "__import__(OS).popen(CMD)", {"OS": (STRING, "os"), "CMD": (STRING, cmd)}
    )
    return [(EVAL, (EXPRESSION, precedence["function_call"], targets))]


# ---


@expression_gen
def gen_os_popen_read_normal(context, cmd):
    return [(FUNCTION_CALL, (ATTRIBUTE, (OS_POPEN_OBJ, cmd), "read"), [])]


@expression_gen
def gen_os_popen_read_normal2(context, cmd):
    return [(FUNCTION_CALL, (ATTRIBUTE, (OS_POPEN_OBJ, cmd), "read"), [(INTEGER, -1)])]


@expression_gen
def gen_os_popen_read_eval(context, cmd):
    targets = targets_from_pattern(
        "__import__(OS).popen(CMD).read()", {"OS": (STRING, "os"), "CMD": (STRING, cmd)}
    )
    return [
        (EVAL, (EXPRESSION, precedence["function_call"], targets)),
    ]
