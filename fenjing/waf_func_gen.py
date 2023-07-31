"""根据指定的表单生成对应的WAF函数

"""
import logging
import random
import string

from copy import copy
from collections import Counter, namedtuple
from functools import lru_cache
from typing import Dict, Callable, Union, List

from .const import DETECT_MODE_ACCURATE, DETECT_MODE_FAST, DANGEROUS_KEYWORDS
from .colorize import colored
from .submitter import Submitter


logger = logging.getLogger("waf_func_gen")
Result = namedtuple("Result", "payload_generate_func input_field")

dangerous_keywords = copy(DANGEROUS_KEYWORDS)

random.shuffle(dangerous_keywords)
render_error_keywords = [
    "TemplateSyntaxError",
    "Internal Server Error",
    "Traceback (most recent call last):",
]


def grouped_payloads(size=3) -> List[str]:
    """将所有payload按照size个一组拼接在一起
    即：['a', 'b', 'c', 'd'] -> ['ab', 'cd']

    Args:
        size (int, optional): 拼接的size. Defaults to 3.

    Returns:
        List[str]: 拼接结果
    """
    return [
        "".join(dangerous_keywords[i : i + size])  # flake8: noqa
        for i in range(0, len(dangerous_keywords), size)
    ]


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
        test_keywords = (
            grouped_payloads(2) + dangerous_keywords
            if self.detect_mode == DETECT_MODE_ACCURATE
            else grouped_payloads(4)
        )
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

        # WAF函数，只有在payload一定可以通过WAF时才返回True
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
                    return any(w in result.text for w in render_error_keywords)
                # 产生回显
                if extra_content in result.text:
                    logger.debug("payload产生回显")
                    return True

                # 去除下方的规则，因为如果我们没有fuzz出所有的waf页面，而此时extra_content
                # 不在waf页面中的话，我们应该更加保守地认为payload应该是被waf拦住了

                # # 页面的hash和waf页面的hash不相同
                # if hash(result.text) not in waf_hashes:
                #     logger.debug("页面的hash和waf页面的hash不相同")
                #     return True
                # 页面的hash和waf的相同，但是用户要求检测模式为快速
                # 因此我们选择直接返回False
                if self.detect_mode == DETECT_MODE_FAST:
                    logger.debug("快速模式直接返回False")
                    return False
                # 如果extra_content之前检测过，则可以确定不是它产生的问题，返回False
                if extra_passed:
                    logger.debug("extra_content已经检查，直接返回False")
                    return False
                # 检测是否是extra_content导致的WAF
                # 如果是的话更换extra_content并重新检测
                extra_content_result = self.subm.submit(extra_content)
                if (
                    extra_content_result is not None
                    and extra_content_result.status_code != 500
                    and hash(extra_content_result.text) in waf_hashes
                ):
                    logger.debug("extra_content存在问题，重新检查")
                    extra_content = "".join(random.choices(string.ascii_lowercase, k=6))
                    continue
                extra_passed = True
                logger.debug("回显失败，返回False")
                return False
            # 五次检测都失败，我们选择直接返回False
            return False

        return waf_func
