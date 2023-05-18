from collections import Counter, namedtuple
from functools import lru_cache
import logging
from typing import List, Dict, Tuple, Callable, Any, Union

from .const import *
from .form import fill_form
from .requester import Requester
from .colorize import colored


logger = logging.getLogger("waf_func_gen")
Result = namedtuple("Result", "payload_generate_func input_field")


class WafFuncGen:
    """
    根据指定的表单生成对应的WAF函数
    """
    dangerous_keywords = [
        "config", "self", "os", "class", "mro", "base", "request",
        "attr", "open", "system",
        "[", '"', "'", "_", ".", "+", "{{", "|",
        "0", "1", "2",
    ]

    def __init__(
            self,
            url: str,
            form: Dict[str, Any],
            requester: Requester,
            callback: Union[Callable[[str, Dict], None], None] = None
    ):
        """根据指定的表单生成对应的WAF函数

        Args:
            url (str): form所在的url.
            form (dict): 解析后的form元素
            requester (Requester): 用于发出请求的requester，为None时自动构造.
            callback (Union[Callable[[str, Dict], None], None], optional): callback函数，默认为None
        """
        self.url = url
        self.form = form
        self.req = requester
        self.callback: Callable[[str, Dict], None] = callback if callback else (
            lambda x, y: None)

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
                f"inputs are extremely long (len={all_length}) that the request might fail")
        r = self.req.request(
            **fill_form(self.url, self.form, inputs))

        self.callback(CALLBACK_SUBMIT, {
            "form": self.form,
            "inputs": inputs,
            "response": r,
        })

        return r

    def waf_page_hash(self, input_field: str):
        """使用危险的payload测试对应的input，得到一系列响应后，求出响应中最常见的几个hash

        Args:
            input_field (str): 需要测试的input

        Returns:
            List[int]: payload被waf后页面对应的hash
        """
        resps = {}
        for keyword in self.dangerous_keywords:
            logger.info(
                f"Testing dangerous keyword {colored('yellow', repr(keyword * 3))}")
            resps[keyword] = self.submit({input_field: keyword * 3})
        hashes = [
            hash(r.text) for keyword, r in resps.items()
            if r is not None and r.status_code != 500 and keyword not in r.text
        ]
        return [pair[0] for pair in Counter(hashes).most_common(2)]

    def generate(self, input_field):
        waf_hashes = self.waf_page_hash(input_field)

        @lru_cache(1000)
        def waf_func(value):
            r = self.submit({input_field: value})
            assert r is not None
            return hash(r.text) not in waf_hashes
        return waf_func
