"""所有常用常数
"""

DEFAULT_USER_AGENT = "Fenjing/0.1"

# 支持的类型

LITERAL = "literal"
UNSATISFIED = "unsatisfied"
ONEOF = "oneof"
WITH_CONTEXT_VAR = "with_context_var"
FLASK_CONTEXT_VAR = "flask_context_var"
ZERO = "zero"
POSITIVE_INTEGER = "positive_integer"
INTEGER = "integer"
STRING_STRING_CONCAT = "string_string_concat"
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
    "+",
    ".",
    "0",
    '0"',
    "1",
    "2",
    "=",
    "[",
    "_",
    "attr",
    "base",
    "builtins",
    "chr",
    "class",
    "config",
    "eval",
    "exec",
    "global",
    "import",
    "include",
    "init",
    "lipsum",
    "mro",
    "namespace",
    "open",
    "pop",
    "popen",
    "posix",
    "read",
    "request",
    "self",
    "subprocess",
    "system",
    "url_for",
    "value",
    "{{",
    "|",
    "}}",
    "~",
]
