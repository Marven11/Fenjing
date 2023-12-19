from dataclasses import dataclass
from .const import (
    DETECT_MODE_ACCURATE,
    DETECT_MODE_FAST,
    REPLACED_KEYWORDS_STRATEGY_AVOID,
    REPLACED_KEYWORDS_STRATEGY_DOUBLETAPPING,
    REPLACED_KEYWORDS_STRATEGY_IGNORE,
    ENVIRONMENT_FLASK,
    ENVIRONMENT_JINJA,
    PYTHON_VERSION_UNKNOWN,
    PYTHON_VERSION_2,
    PYTHON_VERSION_3,
)
import sys

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal


@dataclass
class Options:
    """影响到攻击逻辑的选项"""

    detect_mode: Literal[DETECT_MODE_ACCURATE, DETECT_MODE_FAST] = DETECT_MODE_ACCURATE
    replaced_keyword_strategy: Literal[
        REPLACED_KEYWORDS_STRATEGY_AVOID,
        REPLACED_KEYWORDS_STRATEGY_DOUBLETAPPING,
        REPLACED_KEYWORDS_STRATEGY_IGNORE,
    ] = REPLACED_KEYWORDS_STRATEGY_AVOID
    environment: Literal[ENVIRONMENT_FLASK, ENVIRONMENT_JINJA] = ENVIRONMENT_FLASK
    python_version: Literal[
        PYTHON_VERSION_UNKNOWN, PYTHON_VERSION_2, PYTHON_VERSION_3
    ] = PYTHON_VERSION_UNKNOWN
