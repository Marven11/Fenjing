from typing import (
    List,
    Dict,
    Union,
)
import re

from .const import *
from .rules_types import Target

# precedence of filter:
# a|xxx()()
#  2   1 3
# 1: filter call
# 2: filter
# 3: function call
# `|xxx`: plain_filter
# `|xxx()`: called_filter

precedence_lst = [
    ["enclose", "literal", "flask_context_var", "jinja_context_var"],
    ["attribute","item","slide",],
    [
        # xxx.a[b], xxx(a)[b] and xxx.a(b) works,
        # xxx|a(b)(c) works
        # but xxx|a[b] and xxx|a(yyy)[b] don't
        "function_call",
        "called_filter",
    ],
    ["plain_filter"],
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

precedence = {name: i for i, lst in enumerate(precedence_lst) for name in lst}


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


def join_target(sep: Target, targets: List[Target]) -> List[Target]:
    if len(targets) == 0:
        return []
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
        elif target[0] == EXPRESSION:
            answer = min(answer, target[1])
        elif target[0] in [
            PLUS,
            MULTIPLY,
            MOD,
            ATTRIBUTE,
            ITEM,
            MODULE_OS,
            FUNCTION_CALL,
        ]:
            # might be transformed into filters
            sub_target_answer = tree_precedence(sub_target_tree)
            if sub_target_answer:
                answer = min(answer, sub_target_answer)
        elif target[0] in precedence:
            answer = min(answer, precedence[target[0]])
        elif sub_target_tree:
            sub_target_answer = tree_precedence(sub_target_tree)
            if sub_target_answer:
                answer = min(answer, sub_target_answer)
    return answer if answer != float("inf") else None


def find_bad_exprs(tree, is_expr_bad_func):
    nodes = []
    for payload_unparsed, targetlist in iter_subtree(tree):
        if is_expr_bad_func(payload_unparsed):
            nodes.append((payload_unparsed, targetlist))
    return nodes


def str_escape(value: str, quote="'"):
    """
    转义字符串中的引号和反斜杠，但不会在两旁加上引号。
    用法："'{}'".format(str_escape("asdf", "'"))
    """
    return value.replace("\\", "\\\\").replace(quote, "\\" + quote)


def transform_int_chars_charcodes(int_chars, charcodes, keepfirst=False):
    charcode_dict = {str(int(chr(x), 0)): chr(x) for x in charcodes}
    return "".join(charcode_dict.get(c, c) for c in int_chars)


def transform_int_chars_unicode(int_chars):
    return [
        transform_int_chars_charcodes(int_chars, charcodes)
        for charcodes in UNICODE_INT_CHARCODES
    ]


def unwrap_whitespace(target_list: List[Target]) -> List[Target]:
    """替换target_list中的whitespace target为实际的literal
    会被payloadgen调用而不是被expression_gen调用

    Args:
        target_list (List[Target]): 输入的target list

    Returns:
        List[Target]: 输出，如果没有whitespace则返回原target list
    """
    if all(target != (WHITESPACE,) for target in target_list):
        return target_list
    alternatives = []
    for whitespace in WHITESPACES_AND_EMPTY:
        alternative = []
        for target in target_list:
            if target == (WHITESPACE,):
                alternative.append((LITERAL, whitespace))
            else:
                alternative.append(target)
        alternatives.append(alternative)
    return [(ONEOF, alternatives)]


def removeprefix_string(text: str, prefix: str) -> str:
    """兼容python 3.9及以下的removeprefix函数

    Args:
        text (str): text
        prefix (str): 需要去除的prefix

    Returns:
        str: 处理结果
    """
    if text.startswith(prefix):
        return text[len(prefix) :]
    return text


def targets_from_pattern(
    pattern: str, mapping: Dict[str, Union[Target, List[Target]]]
) -> List[Target]:
    """根据pattern将字符串转换成对应的target列表
    示例："'abcde'[NUM]", {"NUM": (INTEGER, 1)} ---> [
        (LITERAL, "'abcde'["),
        (INTEGER, 1),
        (LITERAL, "]")
    ]

    Args:
        pattern (str): 给定的pattern
        mapping (Dict[str, Union[Target, List[Target]]]): 关键字和target的对应关系

    Returns:
        List[Target]: 生成结果
    """
    result = []
    toparse = ""
    while pattern:
        found = False
        for keyword, value in mapping.items():
            if pattern.startswith(keyword):
                result.append((LITERAL, toparse))
                if isinstance(value, list):
                    result += value
                else:
                    result.append(value)
                toparse = ""
                pattern = removeprefix_string(pattern, keyword)
                found = True
                break
        if not found:
            toparse += pattern[0]
            pattern = pattern[1:]
    if toparse:
        result.append((LITERAL, toparse))
    return result


def literal_to_target(literal: str) -> Target:
    """将literal转成expression target
    如果literal是`aaa|bbb`的格式，那它就是一个带有filter的expression
    运算优先级和filter相同。

    Args:
        literal (str): literal

    Returns:
        Target: Target
    """
    # TODO: 我知道这里写得很烂但是暂时就用这种方式判断就好了，好好计算优先级
    # 从而省掉一些括号这种事情之后再说
    return (
        (EXPRESSION, precedence["plain_filter"], [(LITERAL, literal)])
        if re.match(r"^[a-z0-9\\|]+$", literal)
        else (EXPRESSION, precedence["enclose"], [(ENCLOSE, (LITERAL, literal))])
    )
