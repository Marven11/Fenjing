import re

# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,unused-argument

from ..payload_gen import expression_gen, precedence
from ..rules_utils import targets_from_pattern


from ..const import *

# ---


@expression_gen
def gen_attribute_normal1(context, obj_req, attr_name):
    if not re.match("[A-Za-z_]([A-Za-z0-9_]+)?", attr_name):
        return [(UNSATISFIED,)]
    target_list = [
        (ENCLOSE_UNDER, precedence["attribute"], obj_req),
        (LITERAL, "."),
        (LITERAL, attr_name),
    ]
    return [(EXPRESSION, precedence["attribute"], target_list)]


@expression_gen
def gen_attribute_normal2(context, obj_req, attr_name):
    target_list = [
        (ENCLOSE_UNDER, precedence["item"], obj_req),
        (LITERAL, "["),
        (STRING, attr_name),
        (LITERAL, "]"),
    ]
    return [(EXPRESSION, precedence["item"], target_list)]


@expression_gen
def gen_attribute_attrfilter(context, obj_req, attr_name):
    target_list = [
        (ENCLOSE_UNDER, precedence["plain_filter"], obj_req),
        (LITERAL, "|attr"),
        (
            WRAP,
            [(STRING, attr_name)],
        ),
    ]
    return [(EXPRESSION, precedence["called_filter"], target_list)]


@expression_gen
def gen_attribute_attrfilter2(context, obj_req, attr_name):
    target_list = [
        (ENCLOSE_UNDER, precedence["plain_filter"], obj_req),
        (LITERAL, "|attr("),
        (WHITESPACE,),
        (STRING, attr_name),
        (WHITESPACE,),
        (LITERAL, ",)"),
    ]
    return [(EXPRESSION, precedence["called_filter"], target_list)]


@expression_gen
def gen_attribute_map(context, obj_req, attr_name):
    target_list = targets_from_pattern(
        "( OBJ , ) | map( ATTR , NAME ) | first",
        {
            "OBJ": obj_req,
            " ": (WHITESPACE,),
            "ATTR": (STRING, "attr"),
            "NAME": (STRING, attr_name),
        },
    )

    return [(EXPRESSION, precedence["plain_filter"], target_list)]


# ---


@expression_gen
def gen_item_normal1(context, obj_req, item_name):
    if not re.match("[A-Za-z_]([A-Za-z0-9_]+)?", item_name):
        return [(UNSATISFIED,)]
    target_list = [
        (ENCLOSE_UNDER, precedence["attribute"], obj_req),
        (LITERAL, "."),
        (LITERAL, item_name),
    ]
    return [(EXPRESSION, precedence["attribute"], target_list)]


@expression_gen
def gen_item_normal2(context, obj_req, item_name):
    target_list = [
        (ENCLOSE_UNDER, precedence["item"], obj_req),
        (LITERAL, "["),
        (STRING, item_name),
        (LITERAL, "]"),
    ]
    return [(EXPRESSION, precedence["item"], target_list)]


@expression_gen
def gen_item_getfunc(context, obj_req, item_name):
    target = (FUNCTION_CALL, (ATTRIBUTE, obj_req, "get"), [(STRING, item_name)])
    return [(EXPRESSION, precedence["function_call"], [target])]


@expression_gen
def gen_item_dunderfunc(context, obj_req, item_name):
    target = (FUNCTION_CALL, (ATTRIBUTE, obj_req, "__getitem__"), [(STRING, item_name)])
    return [(EXPRESSION, precedence["function_call"], [target])]

# ---


@expression_gen
def gen_class_attribute_literal(context, obj_req, attr_name):
    class_target = (
        ATTRIBUTE,
        obj_req,
        "__class__",
    )
    target_list = [
        (ENCLOSE_UNDER, precedence["attribute"], class_target),
        (LITERAL, "." + attr_name),
    ]
    return [(EXPRESSION, precedence["attribute"], target_list)]


@expression_gen
def gen_class_attribute_attrfilter(context, obj_req, attr_name):
    class_target = (
        ATTRIBUTE,
        obj_req,
        "__class__",
    )
    target_list = [
        (ENCLOSE_UNDER, precedence["plain_filter"], class_target),
        (LITERAL, "|attr"),
        (
            WRAP,
            [(STRING, attr_name)],
        ),
    ]
    return [(EXPRESSION, precedence["called_filter"], target_list)]


@expression_gen
def gen_class_attribute_attrfilter2(context, obj_req, attr_name):
    class_target = (
        ATTRIBUTE,
        obj_req,
        "__class__",
    )
    target_list = [
        (ENCLOSE_UNDER, precedence["plain_filter"], class_target),
        (LITERAL, "|attr("),
        (STRING, attr_name),
        (LITERAL, ",)"),
    ]
    return [(EXPRESSION, precedence["called_filter"], target_list)]


# ---


@expression_gen
def gen_chained_attribute_item_normal(context, obj_req, *attr_item_req):
    if not attr_item_req:
        return [
            obj_req,
        ]
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
