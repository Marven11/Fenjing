"""根据指定的表单生成对应的WAF函数

"""

from collections import Counter, namedtuple
from functools import lru_cache
import logging
from typing import Dict, Callable, Union
import random
import string
from copy import copy

from .const import (
    CALLBACK_SUBMIT,
    DETECT_MODE_ACCURATE,
    DANGEROUS_KEYWORDS
)
from .form import fill_form, Form
from .requester import Requester
from .colorize import colored


logger = logging.getLogger("waf_func_gen_form")
Result = namedtuple("Result", "payload_generate_func input_field")

dangerous_keywords = copy(DANGEROUS_KEYWORDS)

random.shuffle(dangerous_keywords)


class WafFuncGenForm:
    """
    根据指定的表单生成对应的WAF函数
    """

    def __init__(
        self,
        url: str,
        form: Form,
        requester: Requester,
        callback: Union[Callable[[str, Dict], None], None] = None,
        detect_mode: str = DETECT_MODE_ACCURATE,
    ):
        """根据指定的表单生成对应的WAF函数

        Args:
            url (str): form所在的url.
            form (dict): 解析后的form元素
            requester (Requester): 用于发出请求的requester，为None时自动构造.
            callback (Union[Callable[[str, Dict], None], None], optional):
                callback函数，默认为None
            detect_mode (str): 测试WAF页面hash的模式
                "fast": 一次发送多个危险的关键字
                "accurate": 一次发送一个危险的关键字
        """
        self.url = url
        self.form = form
        self.req = requester
        self.callback: Callable[[str, Dict], None] = (
            callback if callback else (lambda x, y: None)
        )
        self.detect_mode = detect_mode

    def submit(self, inputs: dict):
        """根据inputs提交form

        Args:
            inputs (dict): 需要提交的input

        Returns:
            requests.Response: 返回的reponse元素
        """
        all_length = sum(len(v) for v in inputs.values())
        if all_length > 2048 and self.form["method"] == "GET":
            logger.warning(
                "inputs are extremely long (len=%d) "
                + "that the request might fail",
                all_length,
            )
        resp = self.req.request(**fill_form(self.url, self.form, inputs))

        self.callback(
            CALLBACK_SUBMIT,
            {
                "form": self.form,
                "inputs": inputs,
                "response": resp,
            },
        )

        return resp

    def waf_page_hash(self, input_field: str):
        """使用危险的payload测试对应的input，得到一系列响应后，求出响应中最常见的几个hash

        Args:
            input_field (str): 需要测试的input

        Returns:
            List[int]: payload被waf后页面对应的hash
        """
        resps = {}
        test_keywords = (
            dangerous_keywords
            if self.detect_mode == DETECT_MODE_ACCURATE
            else [
                "".join(dangerous_keywords[i: i + 3])  # flake8: noqa
                for i in range(0, len(dangerous_keywords), 3)
            ]
        )
        for keyword in test_keywords:
            logger.info(
                "Testing dangerous keyword %s",
                colored("yellow", repr(keyword * 2)),
            )
            resps[keyword] = self.submit({input_field: keyword * 2})
        hashes = [
            hash(r.text)
            for keyword, r in resps.items()
            if r is not None
            and r.status_code != 500
            and keyword not in r.text
        ]
        return [k for k, v in Counter(hashes).items() if v >= 3]

    def generate(self, input_field: str) -> Callable:
        """生成WAF函数

        Args:
            input_field (str): 表格项

        Returns:
            Callable: WAF函数
        """
        waf_hashes = self.waf_page_hash(input_field)

        @lru_cache(1000)
        def waf_func(value):
            extra_content = "".join(
                random.choices(string.ascii_lowercase, k=6)
            )
            resp = self.submit({input_field: extra_content + value})
            assert resp is not None
            if hash(resp.text) in waf_hashes:  # 页面的hash和waf页面的hash相同
                return False
            if resp.status_code == 500:  # Jinja渲染错误
                return True
            return extra_content in resp.text  # 产生回显

        return waf_func
