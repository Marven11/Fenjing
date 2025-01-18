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

from collections import defaultdict
from contextlib import contextmanager
from typing import (
    Callable,
    DefaultDict,
    List,
    Dict,
    Union,
)
from pprint import pformat

from rich.markup import escape as rich_escape

from .const import *
from .options import Options
from .rules_utils import (
    precedence,
    tree_precedence,
    unwrap_whitespace,
)
from .rules_types import *
from .pbar import pbar_manager, Pbar

expression_gens: DefaultDict[str, List[ExpressionGenerator]] = defaultdict(list)
logger = logging.getLogger("payload_gen")


gen_weight_default = {
    "gen_string_percent_lower_c_concat": 1,
    "gen_string_lower_c_joinerbatch": 1,
    "gen_string_percent_urlencode2": 1,
    "gen_string_twostringconcat": 1,
    "gen_string_concat1": 1,
    "gen_string_concat2": 1,
    "gen_string_formatpercent": 1,
    "gen_attribute_attrfilter": 1,
    "gen_item_dunderfunc": 1,
}


@contextmanager
def optional_context(condition, data, mapper):
    """让一个contextmanager变为可选的"""
    if condition:
        with mapper(data) as result:
            yield result
    else:
        yield data


def expression_gen(f: ExpressionGenerator):
    gen_type = re.match("gen_([a-z_]+)_([a-z0-9]+)", f.__name__)
    if not gen_type:
        raise RuntimeError(f"Error found when register payload generator {f.__name__}")
    expression_gens[gen_type.group(1)].append(f)
    return f


class CacheByRepr:
    """缓存传入的对象，其中键可以是任意对象
    会将键的repr表达式作为键进行存储
    """

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

    def __delitem__(self, k):
        del self.cache[repr(k)]

    def __contains__(self, k):
        repr_k = repr(k)
        for k_store, _ in self.cache.get(repr_k, []):
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
        waf_func: WafFunc,
        context: Union[Dict, None] = None,
        callback: Union[Callable[[str, Dict], None], None] = None,
        options: Union[Options, None] = None,
        waf_expr_func: Union[WafFunc, None] = None,
        generated_exprs: Union[Dict[Target, PayloadGeneratorResult], None] = None,
    ):
        self.waf_func = (
            waf_func
            if waf_expr_func is None
            else (lambda x: waf_func(x) and waf_expr_func(x))
        )
        self.context = context if context else {}
        self.cache_by_repr = CacheByRepr()
        self.used_count = defaultdict(int)
        self.options = options if options else Options()
        if self.options.detect_mode == DetectMode.FAST:
            for k, v in gen_weight_default.items():
                self.used_count[k] += v
        self.callback = callback if callback else (lambda x, y: None)
        self.generated_exprs = generated_exprs if generated_exprs else {}

    def add_generated_expr(self, target, result):
        self.generated_exprs[target] = result

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
        targets = unwrap_whitespace(targets)
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
        # 事先测试literal中的某些片段，从而提速
        # 因为这些片段的种类比Literal少得多，利于缓存
        # 为了提升速度，literal也会被generate_by_list检查
        # 不应该在这里检测单双引号，因为引号对应的页面hash可能被收集了，导致误判
        words = set(re.findall(r"[a-z]{3,}|[0-9]", target[1]))
        if not all(self.waf_func(word) for word in words):
            return None
        return (target[1], {}, [])

    @register_generate_func(lambda self, target: target[0] == GENERATED_EXPR)
    def generated_generate(
        self, target: GeneratedExprTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """找到已经准备好的生成结果

        Args:
            target (GeneratedExprTarget): 生成目标

        Returns:
            Union[PayloadGeneratorResult, None]: 生成结果
        """
        return self.generated_exprs.get(target[1])

    @register_generate_func(lambda self, target: target in self.cache_by_repr)
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
        should_enclose = (
            result_precedence <= target[1]
            if result_precedence == precedence["mod"]
            else result_precedence < target[1]
        )
        if should_enclose:
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
        else:
            logger.debug(
                (
                    "enclose_under_generate: result_precedence >= "
                    + "target[1], result_precedence=%d, target[1]=%s"
                    + "target[2]=%s"
                ),
                result_precedence,
                target[1],
                pformat(target[2]),
            )
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
        _, alternative_targets = target
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
        return ("", {target[1]: self.context[target[1]]}, [])

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
        return (target[1], {}, [])

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
        if self.options.environment != TemplateEnvironment.FLASK:
            return None
        return (target[1], {}, [])

    @register_generate_func(lambda self, target: target[0] == REQUIRE_PYTHON3)
    def require_python3_generate(
        self, target: RequirePython3Target
    ) -> Union[PayloadGeneratorResult, None]:
        """生成类型为flask_context_var_generate的生成目标，将其中包含的变量名加入到已经使用的变量中

        Args:
            target (RequirePython3Target): 生成目标

        Returns:
            _type_: 生成结果
        """
        if self.options.python_version != PythonVersion.PYTHON3:
            return None
        return ("", {}, [])

    @register_generate_func(
        lambda self, target: target[0] == REQUIRE_PYTHON3_SUBVERSION
    )
    def require_python3_subversion_generate(
        self, target: RequirePython3SubversionTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """生成类型为flask_context_var_generate的生成目标，将其中包含的变量名加入到已经使用的变量中

        Args:
            target (RequirePython3SubversionTarget): 生成目标

        Returns:
            _type_: 生成结果
        """
        if (
            self.options.python_version != PythonVersion.PYTHON3
            or self.options.python_subversion is None
            or self.options.python_subversion < target[1]
        ):
            return None
        return ("", {}, [])

    @register_generate_func(lambda self, target: target[0] == REQUIRE_FLASK)
    def require_flask_generate(
        self, target: RequireFlaskTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """生成类型为flask_context_var_generate的生成目标，将其中包含的变量名加入到已经使用的变量中

        Args:
            target (RequireFlaskTarget): 生成目标

        Returns:
            _type_: 生成结果
        """
        if self.options.environment != TemplateEnvironment.FLASK:
            return None
        return ("", {}, [])

    @register_generate_func(lambda self, target: target[0] == VARIABLE_OF)
    def variable_of_generate(
        self, target: VariableOfTarget
    ) -> Union[PayloadGeneratorResult, None]:
        """在context中找到对应的变量

        Args:
            target (VariableOfTarget): 生成目标

        Returns:
            _type_: 生成结果
        """
        variables = [name for name, value in self.context.items() if value == target[1]]
        if not variables:
            return self.generate_by_list([(UNSATISFIED,)])
        targets_list: List[List[Target]] = [
            [(LITERAL, v), (WITH_CONTEXT_VAR, v)] for v in variables
        ]
        return self.generate_by_list([(ONEOF, targets_list)])

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
            raise RuntimeError(f"Unknown type: {gen_type}")

        gens = expression_gens[gen_type].copy()
        if self.options.detect_mode == DetectMode.FAST:
            gens.sort(key=lambda gen: self.used_count[gen.__name__], reverse=True)
        with optional_context(
            gen_type
            in [
                STRING,
                POSITIVE_INTEGER,
                ZERO,
                OS_POPEN_READ,
                EVAL,
            ],
            gens,
            lambda gens: pbar_manager.pbar(gens, "Rule"),
        ) as gens:
            for gen in gens:
                logger.debug("Trying gen rule: %s", gen.__name__)
                if isinstance(gens, Pbar):
                    gens.update(description="Rule: " + gen.__name__)
                gen_ret: List[Target] = gen(self.context, *args)
                try:
                    ret = self.generate_by_list(gen_ret)
                except Exception as e:
                    raise RuntimeError(f"Unknown error at {gen.__name__}") from e
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
                if (
                    gen_type in (POSITIVE_INTEGER, STRING) and result != str(args[0])
                ) or (gen_type == ZERO and result != "0"):
                    logger.info(
                        "[green bold]Great![/] [yellow bold]{gen_type}[/]"
                        "[yellow]({args_repl})[/] can be [blue]{result}[/]".format(
                            gen_type=gen_type,
                            args_repl=rich_escape(", ".join(repr(arg) for arg in args)),
                            result=rich_escape(result),
                        ),
                        extra={"markup": True, "highlighter": None},
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
                        "[green bold]Great![/green bold] we generate "
                        "[yellow bold]{gen_type}[/yellow bold]"
                        "[yellow]({args_repl})[/yellow]".format(
                            gen_type=gen_type,
                            args_repl=rich_escape(", ".join(repr(arg) for arg in args)),
                        ),
                        extra={"markup": True, "highlighter": None},
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
            STRING_CONCATMANY,
            ENCLOSE,
            ENCLOSE_UNDER,
            STRING_CONCAT,
            WRAP,
            FUNCTION_CALL,
        ):
            logger.info(
                "[red]Failed[/red] generating [yellow bold]{gen_type}[/yellow bold][yellow]({args_repl})[/yellow]. "
                "Hopefully it might not be an issue.".format(
                    gen_type=gen_type,
                    args_repl=rich_escape(", ".join(repr(arg) for arg in args)),
                ),
                extra={"markup": True, "highlighter": None},
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

    def delete_from_cache(self, gen_type, *args):
        if (gen_type, *args) in self.cache_by_repr:
            del self.cache_by_repr[(gen_type, *args)]
