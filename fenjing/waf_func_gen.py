"""根据指定的表单生成对应的WAF函数

"""
import logging
import random
import string
import traceback
import time

from copy import copy
from collections import Counter, namedtuple
from functools import lru_cache
from typing import Dict, Callable, Tuple, Union, List

from .const import (
    DETECT_MODE_ACCURATE,
    DETECT_MODE_FAST,
    DANGEROUS_KEYWORDS,
    REPLACED_KEYWORDS_STRATEGY_AVOID,
    REPLACED_KEYWORDS_STRATEGY_DOUBLETAPPING,
    REPLACED_KEYWORDS_STRATEGY_IGNORE,
)
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


def grouped_payloads(size=3, sep="") -> List[str]:
    """将所有payload按照size个一组拼接在一起
    即：['a', 'b', 'c', 'd'] -> ['ab', 'cd']

    Args:
        size (int, optional): 拼接的size. Defaults to 3.

    Returns:
        List[str]: 拼接结果
    """
    return [
        sep.join(dangerous_keywords[i : i + size])  # flake8: noqa
        for i in range(0, len(dangerous_keywords), size)
    ]


def removeprefix_compat(text: str, prefix: str) -> str:
    """兼容python 3.9及以下的removeprefix函数

    Args:
        text (str): text
        prefix (str): 需要去除的prefix

    Returns:
        str: 处理结果
    """
    if text.startswith(prefix):
        return text[len(prefix) :]
    return text


def get_next_p(b: str) -> List[int]:
    """KMP算法中，获取字符串B的next数组的算法过程

    Args:
        b (str): 字符串B，KMP匹配的目标

    Returns:
        List[int]: next数组，定义与KMP相同
    """
    answer = []
    for i, c in enumerate(b):
        if i == 0:
            answer.append(-1)
            continue
        p = answer[i - 1]
        while p >= 0 and b[p + 1] != c:
            assert answer[p] < p
            p = answer[p]

        if c == b[p + 1]:
            answer.append(p + 1)
        else:
            answer.append(p)
    return answer


def kmp(a: str, b: str) -> Tuple[int, Union[int, None]]:
    """KMP算法，在A中寻找B的最长匹配子串

    Args:
        a (str): KMP中的字符串A
        b (str): KMP中的字符串B

    Returns:
        Tuple[int, Union[int, None]]: 最长匹配子串的结尾长度和位置
    """
    logger.debug("kmp(len(a)=%d, len(b)=%d)", len(a), len(b))
    if b == "":
        return 0, None
    next_p = get_next_p(b)
    max_answer, max_answer_pos = 0, None
    j = -1
    for i, c in enumerate(a):
        while j >= 0 and b[j + 1] != c:
            assert next_p[j] < j
            j = next_p[j]
        if c == b[j + 1]:
            j += 1
        if j + 1 > max_answer:
            max_answer = j + 1
            max_answer_pos = i

        if j == len(b) - 1:
            j = -1
        logger.debug("%d, %s, %d", i, c, j)
    return max_answer, max_answer_pos


def find_pieces(resp_text, payload):
    """从HTTP响应的正文和对应的payload中分析出可能被替换的关键字

    Args:
        resp_text (str): HTTP响应正文
        payload (str): payload

    Returns:
        List[str]: 可能被替换的关键字
    """
    assert len(resp_text) < 1e5 and len(payload) < 1e5  # perf limit
    logger.debug("find_pieces(%s, %s)", resp_text[:20], payload[:20])
    max_answer, max_answer_pos = kmp(resp_text, payload)
    logger.debug("%d, %s", max_answer, str(max_answer_pos))
    if max_answer <= 2 or max_answer_pos is None:
        logger.debug("max answer too low")
        return []

    resp_text_matched = resp_text[max_answer_pos - max_answer + 1 : max_answer_pos + 1]
    resp_text_unmatched, payload_unmatched = (
        resp_text[max_answer_pos + 1 :],
        payload[len(resp_text_matched) :],
    )
    if payload_unmatched == "":
        logger.debug("read payload done")
        return []

    max_answer_unmatched, max_answer_pos_unmatched = kmp(
        payload_unmatched, resp_text_unmatched
    )

    if max_answer_pos_unmatched is None:
        return []

    payload_unmatched_before = payload_unmatched[
        : max_answer_pos_unmatched - max_answer_unmatched + 1
    ]
    resp_text_next = removeprefix_compat(resp_text_unmatched, payload_unmatched_before)
    payload_next = removeprefix_compat(payload_unmatched, payload_unmatched_before)

    assert len(resp_text_next) < len(resp_text) and len(payload_next) < len(payload)
    return [
        payload_unmatched_before,
    ] + find_pieces(resp_text_next, payload_next)


def combine_waf(waf_funcs):
    def new_waf_func(s):
        return all(waf(s) for waf in waf_funcs)

    return new_waf_func


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
        replaced_keyword_strategy: str = REPLACED_KEYWORDS_STRATEGY_AVOID,
    ):
        self.subm = submitter
        self.callback: Callable[[str, Dict], None] = (
            callback if callback else (lambda x, y: None)
        )
        self.detect_mode = detect_mode
        self.replaced_keyword_strategy = replaced_keyword_strategy

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

    def long_param_hash(self) -> List[int]:
        """测试目标是否会waf过长的payload

        Returns:
            List[int]: 过长payload页面的hash
        """
        logger.info("Testing long payloads...")
        keywords = [
            "".join(random.choices(string.ascii_lowercase, k=5)) * 40 for _ in range(20)
        ]
        hashes = []
        for keyword in keywords:
            result = self.subm.submit(keyword)
            if result is None:
                logger.info(
                    "Submit %s, continue",
                    colored("yellow", "failed"),
                )
                continue
            status_code, text = result
            if status_code == 500:
                continue
            hashes.append(hash(text))
        hashes_uniq = list(set(hashes))
        if len(hashes_uniq) <= 3:
            logger.warning(
                "%s detected!, maybe you should try `--eval-args-payload`"
                + " option to generate shorter payload.",
                colored("red", "Long payload waf", bold=True),
            )
            time.sleep(2)
        return [k for k, v in Counter(hashes).items() if v >= 2]

    def replaced_keyword(self) -> List[str]:
        """检测出所有可能被替换的keyword

        Returns:
            List[str]: 所有可能被替换的keyword
        """
        extra = "".join(random.choices(string.ascii_lowercase, k=4))
        test_payloads = (
            dangerous_keywords
            if self.detect_mode == DETECT_MODE_ACCURATE
            else grouped_payloads(4, sep=extra)
        )
        keywords = []
        for payload_raw in test_payloads:
            # 如果extra的开头或结尾和payload的相同，被替换后可能会因为错误拼合导致检测失效
            while extra[0] == payload_raw[0] or extra[-1] == payload_raw[-1]:
                extra = "".join(random.choices(string.ascii_lowercase, k=4))
            payload = extra + payload_raw + extra
            logger.info(
                "Testing dangerous keyword %s",
                colored("yellow", repr(payload)),
            )
            result = self.subm.submit(payload)
            if result is None:
                logger.info(
                    "Submit %s for %s",
                    colored("yellow", "failed"),
                    colored("yellow", repr(payload)),
                )
                continue

            status_code, text = result
            if status_code == 500:
                continue
            if len(text) > 5e4:
                continue
            try:
                payload_replaced_keyword = find_pieces(text, payload)
            except Exception:
                traceback.print_exc()
                continue
            if payload_replaced_keyword:
                payload_replaced_keyword = list(set(payload_replaced_keyword))
                if len(payload_replaced_keyword) > 10:
                    logger.info(
                        "Replaced keywords found, ignore because it's too long (length=%d)",
                        len(payload_replaced_keyword),
                    )
                else:
                    keywords += payload_replaced_keyword
        keywords = list(set(keywords))
        if keywords:
            logger.info(
                "These keywords might get %s: %s",
                colored("yellow", "replaced", bold=True),
                colored("yellow", repr(keywords)),
            )
        return keywords

    def doubletapping(self, payload: str, keywords: List[str]):
        if not keywords:
            return payload
        logger.info(
            "Perform %s for payload: %s",
            colored("blue", "doubletapping"),
            colored("yellow", payload),
        )
        exist_keywords = [w for w in keywords if w in payload]
        replacement = {
            w: w[: len(w) // 2] + w + w[len(w) // 2 :]
            for w in exist_keywords
            if len(w) >= 2
        }
        for k, v in sorted(replacement.items(), key=lambda item: len(item[0])):
            payload = payload.replace(k, v)
        return payload

    def generate(self) -> Callable:
        """生成WAF函数

        Returns:
            Callable: WAF函数
        """
        replaced_keyword = self.replaced_keyword()
        waf_hashes = self.waf_page_hash()
        long_param_hashes = self.long_param_hash()
        long_param_hashes = [h for h in long_param_hashes if h not in waf_hashes]
        if self.replaced_keyword_strategy == REPLACED_KEYWORDS_STRATEGY_DOUBLETAPPING:
            self.subm.add_tamperer(lambda s: self.doubletapping(s, replaced_keyword))

        # 随着检测payload一起提交的附加内容
        # content: 内容本身，passed: 内容是否确认可以通过waf
        extra_content, extra_passed = (
            "".join(random.choices(string.ascii_lowercase, k=4)),
            False,
        )

        # WAF函数，只有在payload一定可以通过WAF时才返回True
        @lru_cache(1000)
        def waf_func(value):
            nonlocal extra_content, extra_passed, replaced_keyword
            payload = extra_content + value
            for _ in range(5):
                if (
                    self.replaced_keyword_strategy == REPLACED_KEYWORDS_STRATEGY_AVOID
                    and any(w in payload for w in replaced_keyword)
                ):
                    return False
                result = self.subm.submit(payload)
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
                # 被ban
                if hash(result.text) in long_param_hashes:
                    logger.warning("payload被waf")
                    return False
                # 产生关键词替换
                replaced_list = find_pieces(result.text, payload)
                if replaced_list:
                    logger.info("发现了新的关键词替换：%s", colored("yellow", repr(replaced_list)))
                    replaced_keyword += replaced_list
                    # 如果策略为“忽略”则返回True, 否则返回False
                    return (
                        self.replaced_keyword_strategy
                        == REPLACED_KEYWORDS_STRATEGY_IGNORE
                    )
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
