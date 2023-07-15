"""所有常用常数
"""

DEFAULT_USER_AGENT = "Fenjing/0.1"

# 支持的类型

LITERAL = "literal"
UNSATISFIED = "unsatisfied"
WITH_CONTEXT_VAR = "with_context_var"
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
EVAL_FUNC = "eval_func"
EVAL = "eval"
CONFIG = "config"
MODULE_OS = "module_os"
OS_POPEN_OBJ = "os_popen_obj"
OS_POPEN_READ = "os_popen_read"

GEN_TYPES = [
    "literal",
    "unsatisfied",
    "zero",
    "positive_integer",
    "integer",
    "string_string_concat",
    "string_percent",
    "string_percent_lower_c",
    "string_underline",
    "string_lower_c",
    "string_many_percent_lower_c",
    "string_many_format_c",
    "char",
    "string",
    "formular_sum",
    "attribute",
    "item",
    "class_attribute",
    "chained_attribute_item",
    "eval_func",
    "eval",
    "config",
    "module_os",
    "os_popen_obj",
    "os_popen_read",
]

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

DANGEROUS_KEYWORDS = [
    '"',
    "'",
    "+",
    ".",
    "0",
    "1",
    "2",
    "=",
    "[",
    "_",
    "%",
    "attr",
    "builtins",
    "chr",
    "class",
    "config",
    "eval",
    "global",
    "include",
    "lipsum",
    "mro",
    "namespace",
    "open",
    "pop",
    "popen",
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
