import sys
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Tuple,
    TypeVar,
    Union,
)


if sys.version_info >= (3, 8):
    from typing import Literal

    LiteralTarget = Tuple[Literal["literal"], str]
    ExpressionTarget = Tuple[Literal["expression"], int, List["Target"]]
    EncloseUnderTarget = Tuple[Literal["enclose_under"], int, "Target"]
    EncloseTarget = Tuple[Literal["enclose"], "Target"]
    UnsatisfiedTarget = Tuple[Literal["unsatisfied"],]
    OneofTarget = Tuple[Literal["oneof"], List[List["Target"]]]
    GeneratedExprTarget = Tuple[Literal["generated_expr"], "Target"]
    ListifyTarget = Tuple[Literal["listify"], "Target"]

    WithContextVarTarget = Tuple[Literal["with_context_var"], str]
    JinjaContextVarTarget = Tuple[Literal["jinja_context_var"], str]
    FlaskContextVarTarget = Tuple[Literal["flask_context_var"], str]
    RequirePython3Target = Tuple[Literal["require_python3"]]
    RequirePython3SubversionTarget = Tuple[Literal["require_python3_subversion"], int]
    RequireFlaskTarget = Tuple[Literal["require_flask"]]
    VariableOfTarget = Tuple[Literal["variable_of"], str]

    ZeroTarget = Tuple[Literal["zero"],]
    PositiveIntegerTarget = Tuple[Literal["positive_integer"], int]
    IntegerTarget = Tuple[Literal["integer"], int]

    WhiteSpaceTarget = Tuple[Literal["whitespace"]]

    StringConcatTarget = Tuple[Literal["string_string_concat"],]
    StringPercentTarget = Tuple[Literal["string_percent"],]
    StringPercentLowerCTarget = Tuple[Literal["string_percent_lower_c"],]
    StringUnderlineTarget = Tuple[Literal["string_underline"],]
    StringLowerCTarget = Tuple[Literal["string_lower_c"],]
    StringTwoUnderlineTarget = Tuple[Literal["string_twounderline"],]

    StringManyPercentLowerCTarget = Tuple[Literal["string_many_percent_lower_c"], int]
    StringManyFormatCTarget = Tuple[Literal["string_many_format_c"], int]
    CharTarget = Tuple[Literal["char"], str]
    StringTarget = Tuple[Literal["string"], str]

    FormularSumTarget = Tuple[Literal["formular_sum"], List["Target"]]
    AttributeTarget = Tuple[Literal["attribute"], "Target", str]
    ItemTarget = Tuple[Literal["item"], "Target", str]
    ChassAttributeTarget = Tuple[Literal["class_attribute"], "Target", str]
    ChainedAttriuteItemTarget = Tuple[Literal["chained_attribute_item"], ...]
    ImportFuncTarget = Tuple[Literal["import_func"],]
    EvalFuncTarget = Tuple[Literal["eval_func"],]
    EvalTarget = Tuple[Literal["eval"], str]
    ConfigTarget = Tuple[Literal["config"],]
    ModuleOSTarget = Tuple[Literal["module_os"],]
    OSPopenObj = Tuple[Literal["os_popen_obj"],]
    OSPopenRead = Tuple[Literal["os_popen_read"],]
    # Target = LiteralTarget
    Target = Union[
        LiteralTarget,
        ExpressionTarget,
        EncloseUnderTarget,
        EncloseTarget,
        UnsatisfiedTarget,
        OneofTarget,
        GeneratedExprTarget,
        ListifyTarget,
        WithContextVarTarget,
        JinjaContextVarTarget,
        FlaskContextVarTarget,
        RequirePython3Target,
        RequirePython3SubversionTarget,
        RequireFlaskTarget,
        VariableOfTarget,
        ZeroTarget,
        PositiveIntegerTarget,
        IntegerTarget,
        WhiteSpaceTarget,
        StringConcatTarget,
        StringPercentTarget,
        StringPercentLowerCTarget,
        StringUnderlineTarget,
        StringLowerCTarget,
        StringTwoUnderlineTarget,
        StringManyPercentLowerCTarget,
        StringManyFormatCTarget,
        CharTarget,
        StringTarget,
        FormularSumTarget,
        AttributeTarget,
        ItemTarget,
        ChassAttributeTarget,
        ChainedAttriuteItemTarget,
        ImportFuncTarget,
        EvalFuncTarget,
        EvalTarget,
        ConfigTarget,
        ModuleOSTarget,
        OSPopenObj,
        OSPopenRead,
    ]
else:
    LiteralTarget = Tuple
    ExpressionTarget = Tuple
    EncloseUnderTarget = Tuple
    EncloseTarget = Tuple
    UnsatisfiedTarget = Tuple
    OneofTarget = Tuple
    WithContextVarTarget = Tuple
    FlaskContextVarTarget = Tuple
    JinjaContextVarTarget = Tuple
    RequirePython3Target = Tuple
    Target = Tuple

ContextVariable = Dict[str, Any]


ExpressionGeneratorReturn = TypeVar("ExpressionGeneratorReturn", bound=List[Target])
ExpressionGenerator = Callable[..., ExpressionGeneratorReturn]
TargetAndSubTargets = List[Tuple[Target, List[Target]]]
PayloadGeneratorResult = Tuple[str, ContextVariable, TargetAndSubTargets]
