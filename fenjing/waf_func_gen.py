"""根据指定的表单生成对应的WAF函数

"""

from collections import Counter, namedtuple
from functools import lru_cache
import logging
from typing import Dict, Callable, Union, List
import random
import string
from copy import copy

from .const import DETECT_MODE_ACCURATE, DETECT_MODE_FAST, DANGEROUS_KEYWORDS
from .submitter import Submitter
from .colorize import colored


logger = logging.getLogger("waf_func_gen")
Result = namedtuple("Result", "payload_generate_func input_field")

dangerous_keywords = copy(DANGEROUS_KEYWORDS)

random.shuffle(dangerous_keywords)
render_error_keywords = ["TemplateSyntaxError", "Internal Server Error"]


class WafFuncGen:
    """
    根据指定的Submitter(表单submitter或者路径submitter)生成对应的WAF函数
    其会使用一系列经常被waf的payload进行测试，然后根据返回页面的哈希判断其他payload是否被waf
    """

    def __init__(
        self,
        submitter: Submitter,
        callback: Union[Callable[[str, Dict], None], None] = None,
        detect_mode: str = DETECT_MODE_ACCURATE,
    ):
        self.subm = submitter
        self.callback: Callable[[str, Dict], None] = (
            callback if callback else (lambda x, y: None)
        )
        self.detect_mode = detect_mode

    def waf_page_hash(self):
        """使用危险的payload测试对应的input，得到一系列响应后，求出响应中最常见的几个hash

        Returns:
            List[int]: payload被waf后页面对应的hash
        """
        composed_test_keywords = [
            "".join(dangerous_keywords[i: i + 3])  # flake8: noqa
            for i in range(0, len(dangerous_keywords), 3)
        ]
        test_keywords = composed_test_keywords
        if self.detect_mode == DETECT_MODE_ACCURATE:
            test_keywords += dangerous_keywords
        hashes: List[int] = []
        for keyword in test_keywords:
            logger.info(
                "Testing dangerous keyword %s",
                colored("yellow", repr(keyword * 2)),
            )
            result = self.subm.submit(keyword * 2)
            if result is None:
                logger.info(
                    "Submit %s for %s",
                    colored("yellow", "failed"),
                    colored("yellow", repr(keyword * 2)),
                )
                continue
            status_code, text = result
            if status_code == 500:
                continue
            hashes.append(hash(text))

        return [k for k, v in Counter(hashes).items() if v >= 2]

    def generate(self) -> Callable:
        """生成WAF函数

        Returns:
            Callable: WAF函数
        """
        waf_hashes = self.waf_page_hash()
        # 随着检测payload一起提交的附加内容
        # content: 内容本身，passed: 内容是否确认可以通过waf
        extra_content, extra_passed = (
            "".join(random.choices(string.ascii_lowercase, k=6)),
            False,
        )

        @lru_cache(1000)
        def waf_func(value):
            nonlocal extra_content, extra_passed
            for _ in range(5):
                result = self.subm.submit(extra_content + value)
                if result is None:
                    return False
                # status_code, text = result

                # 遇到500时，判断是否是Jinja渲染错误，是则返回True
                if result.status_code == 500:
                    return any(
                        w in result.text for w in render_error_keywords
                    )
                # 产生回显
                if extra_content in result.text:
                    return True
                # 页面的hash和waf页面的hash不相同
                if hash(result.text) not in waf_hashes:
                    return True
                # 页面的hash和waf的相同，但是用户要求检测模式为快速
                # 因此我们选择直接返回False
                if self.detect_mode == DETECT_MODE_FAST:
                    return False
                # 如果extra_content之前检测过，则可以确定不是它产生的问题，返回False
                if extra_passed:
                    return False
                # 检测是否是extra_content导致的WAF
                # 如果是的话更换extra_content并重新检测
                extra_content_result = self.subm.submit(extra_content)
                if (
                    extra_content_result is not None
                    and extra_content_result.status_code != 500
                    and hash(extra_content_result.text) in waf_hashes
                ):
                    extra_content = "".join(
                        random.choices(string.ascii_lowercase, k=6)
                    )
                    continue
                extra_passed = True
                return False
            # 五次检测都失败，我们选择直接返回False
            return False

        return waf_func
