"""根据指定的路径生成对应的WAF函数

"""

from collections import Counter
from functools import lru_cache
import logging
from typing import List
import random
import string
from copy import copy
from urllib.parse import quote

from .const import DETECT_MODE_ACCURATE, DANGEROUS_KEYWORDS
from .requester import Requester
from .colorize import colored

logger = logging.getLogger("waf_func_gen_path")

dangerous_keywords = copy(DANGEROUS_KEYWORDS)

random.shuffle(dangerous_keywords)


class WafFuncGenPath:
    """根据路径生成对应的回显"""

    def __init__(
        self, url: str, requester: Requester, detect_mode=DETECT_MODE_ACCURATE
    ):
        """根据路径生成对应的回显

        Args:
            url (str): 路径的URL
            requester (Requester): Requester实例
            detect_mode (_type_, optional):
                分析模式. Defaults to DETECT_MODE_ACCURATE.
        """
        self.url = url
        self.req = requester
        self.detect_mode = detect_mode

    def submit(self, payload: str):
        """向一个路径发送payload

        Args:
            payload (str): payload

        Returns:
            Response: HTTP返回值
        """
        if len(payload) > 2048:
            logger.warning(
                "inputs are extremely long (len=%d) "
                + "that the request might fail",
                len(payload),
            )
        resp = self.req.request(method="GET", url=self.url + quote(payload))
        return resp

    def waf_page_hash(self) -> List[int]:
        """猜测WAF页面的hash

        Returns:
            List[int]: 可能的hash
        """
        test_keywords = (
            dangerous_keywords
            if self.detect_mode == DETECT_MODE_ACCURATE
            else [
                "".join(dangerous_keywords[i : i + 3])  # flake8: noqa
                for i in range(0, len(dangerous_keywords), 3)
            ]
        )
        hashes = []
        for keyword in test_keywords:
            logger.info(
                "Testing dangerous keyword %s",
                colored("yellow", repr(keyword * 2)),
            )
            resp = self.submit(keyword * 2)
            if (
                resp is not None
                and resp.status_code != 500
                and keyword not in resp.text
            ):
                hashes.append(hash(resp.text))
        return [k for k, v in Counter(hashes).items() if v >= 3]

    def generate(self):
        """生成WAF函数

        Returns:
            Callable: 生成的WAF函数
        """
        waf_hashes = self.waf_page_hash()

        @lru_cache(1000)
        def waf_func(value):
            if "/" in value:  # payload应该被识别为路径的一部分
                return False
            extra_content = "".join(
                random.choices(string.ascii_lowercase, k=6)
            )
            resp = self.submit(extra_content + value)
            assert resp is not None
            if hash(resp.text) in waf_hashes:  # 页面的hash和waf页面的hash相同
                return False
            if resp.status_code == 500:  # Jinja渲染错误
                return True
            return extra_content in resp.text  # 产生回显

        return waf_func
