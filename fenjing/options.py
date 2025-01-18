from typing import Sequence, Union
from dataclasses import dataclass
from .const import (
    DetectMode,
    TemplateEnvironment,
    PythonVersion,
    ReplacedKeywordStrategy,
    AutoFix500Code,
    DetectWafKeywords,
)


@dataclass
class Options:
    """影响到攻击逻辑的选项"""

    detect_mode: DetectMode = DetectMode.ACCURATE
    environment: TemplateEnvironment = TemplateEnvironment.FLASK
    replaced_keyword_strategy: ReplacedKeywordStrategy = ReplacedKeywordStrategy.AVOID
    python_version: PythonVersion = PythonVersion.UNKNOWN
    python_subversion: Union[int, None] = None
    autofix_500: AutoFix500Code = AutoFix500Code.ENABLED
    detect_waf_keywords: DetectWafKeywords = DetectWafKeywords.NONE
    waf_keywords: Sequence[str] = tuple()
