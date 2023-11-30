"""所有常用常数
"""

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
# 强制加上括号
ENCLOSE = "enclose"
# 标记使用了某个上下文中的变量
WITH_CONTEXT_VAR = "with_context_var"
# jinja上下文内置的变量
JINJA_CONTEXT_VAR = "jinja_context_var"
# flask上下文内置的变量
FLASK_CONTEXT_VAR = "flask_context_var"

PLUS = "plus"
MULTIPLY = "multiply"
MOD = "mod"
FUNCTION_CALL = "function_call"
STRING_CONCAT = "string_concat"
STRING_CONCATMANY = "string_concatmany"

VARIABLE_OF = "variable_of"
ZERO = "zero"
POSITIVE_INTEGER = "positive_integer"
INTEGER = "integer"
STRING_PERCENT = "string_percent"
STRING_PERCENT_LOWER_C = "string_percent_lower_c"
STRING_UNDERLINE = "string_underline"
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

# 程序检测的目标模式：快速或精确

DETECT_MODE_FAST = "fast"
DETECT_MODE_ACCURATE = "accurate"

# 模板的执行环境：flask或者普通的Jinja

ENVIRONMENT_FLASK = "flask"
ENVIRONMENT_JINJA = "jinja"

# 在WAF替换危险keywords时的策略

REPLACED_KEYWORDS_STRATEGY_AVOID = "avoid"  # 避免使用这些keywords
REPLACED_KEYWORDS_STRATEGY_IGNORE = "ignore"  # 忽略检测出的keywords并继续使用
REPLACED_KEYWORDS_STRATEGY_DOUBLETAPPING = "doubletapping"  # 对payload使用doubletapping

DANGEROUS_KEYWORDS = [
    '"',
    "%",
    "'",
    "),)",
    "+",
    ".",
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
    "=",
    "[",
    "\\",
    "\\u",
    "))",
    "\\x",
    "]",
    "_",
    "app",
    "arg",
    "attr",
    "base",
    "builtins",
    "cat",
    "cd",
    "chr",
    "class",
    "config",
    "count",
    "dict",
    "env",
    "eval",
    "exec",
    "flag",
    "flashed",
    "for",
    "get_flashed_messages",
    "getitem",
    "global",
    "globals",
    "if",
    "import",
    "include",
    "index",
    "init",
    "length",
    "lipsum",
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
    "request",
    "self",
    "subclasses",
    "subprocess",
    "system",
    "url",
    "url_for",
    "value",
    "{{",
    "|",
    "}}",
    "~",
]
