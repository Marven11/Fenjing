"""所有常用常数
"""

from typing import Callable
from enum import Enum
from pathlib import Path

CURRENT_FOLDER = Path(__file__).parent

DEFAULT_USER_AGENT = "Fenjing/0.1"

# 支持的生成类型

# 字面量
LITERAL = "literal"
# 生成失败
UNSATISFIED = "unsatisfied"
# 带有优先级标记的表达式
EXPRESSION = "expression"
# 选择后方的其中一条生成目标进行生成
ONEOF = "oneof"
# 当优先级小于n时对生成结果加上括号
ENCLOSE_UNDER = "enclose_under"
# 强制加上括号（包裹）
ENCLOSE = "enclose"
# 单纯地加上括号，用于函数调用等
WRAP = "wrap"
# 标记使用了某个上下文中的变量
WITH_CONTEXT_VAR = "with_context_var"
# jinja上下文内置的变量
JINJA_CONTEXT_VAR = "jinja_context_var"
# flask上下文内置的变量
FLASK_CONTEXT_VAR = "flask_context_var"
# 需要python3环境
REQUIRE_PYTHON3 = "require_python3"


PLUS = "plus"
MULTIPLY = "multiply"
MOD = "mod"
FUNCTION_CALL = "function_call"
STRING_CONCAT = "string_concat"
STRING_CONCATMANY = "string_concatmany"

VARIABLE_OF = "variable_of"
WHITESPACE = "whitespace"
ZERO = "zero"
POSITIVE_INTEGER = "positive_integer"
INTEGER = "integer"
STRING_PERCENT = "string_percent"
STRING_PERCENT_LOWER_C = "string_percent_lower_c"
STRING_UNDERLINE = "string_underline"
STRING_TWOUNDERLINE = "string_twounderline"
STRING_LOWERC = "string_lower_c"
STRING_MANY_PERCENT_LOWER_C = "string_many_percent_lower_c"
STRING_MANY_FORMAT_C = "string_many_format_c"
CHAR = "char"
STRING = "string"
FORMULAR_SUM = "formular_sum"
ATTRIBUTE = "attribute"
ITEM = "item"
CLASS_ATTRIBUTE = "class_attribute"
CHAINED_ATTRIBUTE_ITEM = "chained_attribute_item"
BUILTINS_DICT = "builtins_dict"
IMPORT_FUNC = "import_func"
EVAL_FUNC = "eval_func"
EVAL = "eval"
CONFIG = "config"
MODULE_OS = "module_os"
OS_POPEN_OBJ = "os_popen_obj"
OS_POPEN_READ = "os_popen_read"

# callback函数的参数

CALLBACK_PREPARE_FULLPAYLOADGEN = "prepare_fullpayloadgen"
CALLBACK_GENERATE_FULLPAYLOAD = "generate_full_payload"
CALLBACK_GENERATE_PAYLOAD = "payload_gen"
CALLBACK_SUBMIT = "submit"
CALLBACK_TEST_FORM_INPUT = "test_form_input"

# WEBUI的接口返回值

APICODE_OK = 200
APICODE_WRONG_INPUT = 401


class DetectMode(Enum):
    """程序检测的目标模式：快速或精确"""

    FAST = "fast"
    ACCURATE = "accurate"


class TemplateEnvironment(Enum):
    """模板的执行环境：flask或者普通的Jinja"""

    FLASK = "flask"
    JINJA2 = "jinja2"


class PythonEnvironment(Enum):
    """模板的python执行环境：手动指定python3或者python2，或者让脚本猜测"""

    UNKNOWN = "unknown"
    PYTHON2 = "python2"
    PYTHON3 = "python3"


class ReplacedKeywordStrategy(Enum):
    """在WAF替换危险keywords时的策略"""

    AVOID = "avoid"
    IGNORE = "ignore"
    DOUBLETAPPING = "doubletapping"


class AutoFix500Code(Enum):
    """是否开启自动修复500响应码"""

    ENABLED = "enabled"
    DISABLED = "disabled"


class DetectWafKeywords(Enum):
    """是否检测被waf的关键字"""

    FULL = "full"
    FAST = "fast"
    NONE = "none"

WafFunc = Callable[[str], bool]

SET_STMT_PATTERNS = [
    ("{%set NAME=EXPR%}", "{%set =%}"),
    ("{%set\tNAME=EXPR%}", "{%set\t=%}"),
    ("{%set\nNAME=EXPR%}", "{%set\n=%}"),
    ("{%set\rNAME=EXPR%}", "{%set\r=%}"),
    ("{%set(NAME)=EXPR%}", "{%set(a)=%}"),
]

DANGEROUS_KEYWORDS = [
    '"',
    "%",
    "'",
    "))",
    "),)",
    "*",
    "+",
    "-",
    ".",
    "/",
    "0",
    '0"',
    "1",
    "2",
    "3",
    "37",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    ":",
    ";",
    "=",
    "[",
    "\\",
    "\\u",
    "\\x",
    "]",
    "_",
    "__",
    "app",
    "arg",
    "attr",
    "base",
    "batch",
    "builtin",
    "builtins",
    "cat",
    "cd",
    "chr",
    "class",
    "compile",
    "config",
    "count",
    "cycler",
    "dict",
    "echo",
    "env",
    "escape",
    "eval",
    "exec",
    "execfile",
    "f3n",
    "file",
    "flag",
    "flashed",
    "for",
    "format",
    "from_pyfile",
    "func_globals",
    "get_flashed_messages",
    "getattr",
    "getattribute",
    "getitem",
    "global",
    "globals",
    "if",
    "import",
    "include",
    "index",
    "init",
    "item",
    "j1ng",
    "join",
    "joiner",
    "length",
    "lipsum",
    "local",
    "mro",
    "namespace",
    "not",
    "open",
    "ord",
    "os",
    "pop",
    "popen",
    "posix",
    "range",
    "read",
    "replace",
    "request",
    "reverse",
    "self",
    "subclasses",
    "subprocess",
    "system",
    "url",
    "url_for",
    "value",
    "{{",
    "{{}}",
    "{%",
    "%}",
    "{%%}",
    "|",
    "}}",
    "~",
]

# charcodes that not supported by python3.2 are removed.
UNICODE_INT_CHARCODES = [
    [1632, 1633, 1634, 1635, 1636, 1637, 1638, 1639, 1640, 1641],
    [1776, 1777, 1778, 1779, 1780, 1781, 1782, 1783, 1784, 1785],
    [1984, 1985, 1986, 1987, 1988, 1989, 1990, 1991, 1992, 1993],
    [2406, 2407, 2408, 2409, 2410, 2411, 2412, 2413, 2414, 2415],
    [2534, 2535, 2536, 2537, 2538, 2539, 2540, 2541, 2542, 2543],
    [2662, 2663, 2664, 2665, 2666, 2667, 2668, 2669, 2670, 2671],
    [2790, 2791, 2792, 2793, 2794, 2795, 2796, 2797, 2798, 2799],
    [2918, 2919, 2920, 2921, 2922, 2923, 2924, 2925, 2926, 2927],
    [3046, 3047, 3048, 3049, 3050, 3051, 3052, 3053, 3054, 3055],
    [3174, 3175, 3176, 3177, 3178, 3179, 3180, 3181, 3182, 3183],
    [3302, 3303, 3304, 3305, 3306, 3307, 3308, 3309, 3310, 3311],
    [3430, 3431, 3432, 3433, 3434, 3435, 3436, 3437, 3438, 3439],
    # [3558, 3559, 3560, 3561, 3562, 3563, 3564, 3565, 3566, 3567],
    [3664, 3665, 3666, 3667, 3668, 3669, 3670, 3671, 3672, 3673],
    [3792, 3793, 3794, 3795, 3796, 3797, 3798, 3799, 3800, 3801],
    [3872, 3873, 3874, 3875, 3876, 3877, 3878, 3879, 3880, 3881],
    [4160, 4161, 4162, 4163, 4164, 4165, 4166, 4167, 4168, 4169],
    [4240, 4241, 4242, 4243, 4244, 4245, 4246, 4247, 4248, 4249],
    [6112, 6113, 6114, 6115, 6116, 6117, 6118, 6119, 6120, 6121],
    [6160, 6161, 6162, 6163, 6164, 6165, 6166, 6167, 6168, 6169],
    [6470, 6471, 6472, 6473, 6474, 6475, 6476, 6477, 6478, 6479],
    [6608, 6609, 6610, 6611, 6612, 6613, 6614, 6615, 6616, 6617],
    [6784, 6785, 6786, 6787, 6788, 6789, 6790, 6791, 6792, 6793],
    [6800, 6801, 6802, 6803, 6804, 6805, 6806, 6807, 6808, 6809],
    [6992, 6993, 6994, 6995, 6996, 6997, 6998, 6999, 7000, 7001],
    [7088, 7089, 7090, 7091, 7092, 7093, 7094, 7095, 7096, 7097],
    [7232, 7233, 7234, 7235, 7236, 7237, 7238, 7239, 7240, 7241],
    [7248, 7249, 7250, 7251, 7252, 7253, 7254, 7255, 7256, 7257],
    [42528, 42529, 42530, 42531, 42532, 42533, 42534, 42535, 42536, 42537],
    [43216, 43217, 43218, 43219, 43220, 43221, 43222, 43223, 43224, 43225],
    [43264, 43265, 43266, 43267, 43268, 43269, 43270, 43271, 43272, 43273],
    [43472, 43473, 43474, 43475, 43476, 43477, 43478, 43479, 43480, 43481],
    # [43504, 43505, 43506, 43507, 43508, 43509, 43510, 43511, 43512, 43513],
    [43600, 43601, 43602, 43603, 43604, 43605, 43606, 43607, 43608, 43609],
    [44016, 44017, 44018, 44019, 44020, 44021, 44022, 44023, 44024, 44025],
    [65296, 65297, 65298, 65299, 65300, 65301, 65302, 65303, 65304, 65305],
]
