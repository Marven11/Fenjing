# pylint: skip-file
# flake8: noqa

import sys

sys.path.append("..")
from fenjing.form import get_form
from fenjing.requester import Requester
import unittest
import fenjing
from typing import Union
from fenjing.cracker import Cracker
from fenjing.submitter import FormSubmitter, PathSubmitter, Submitter, HTTPResponse
from fenjing import const, waf_func_gen
import logging
import os

VULUNSERVER_ADDR = os.environ["VULUNSERVER_ADDR"]
SLEEP_INTERVAL = float(os.environ.get("SLEEP_INTERVAL", 0.01))


class WrappedSubmitter(Submitter):
    def __init__(self, subm, blacklist):
        super().__init__()
        self.subm = subm
        self.blacklist = blacklist

    def submit_raw(self, raw_payload):
        if any(w in raw_payload for w in self.blacklist):
            return HTTPResponse(status_code=200, text="Nope")
        return self.subm.submit(raw_payload)


class TestBase(unittest.TestCase):
    def setup_local_waf(self, blacklist):
        self.local_blacklist = blacklist
        self.subm = WrappedSubmitter(
            FormSubmitter(
                url=VULUNSERVER_ADDR,
                form=get_form(action="/", inputs=["name"], method="GET"),
                target_field="name",
                requester=Requester(interval=SLEEP_INTERVAL),
            ),
            self.local_blacklist,
        )

    def setup_remote_waf(self, remote_uri):
        self.local_blacklist = None
        self.subm = FormSubmitter(
            url=VULUNSERVER_ADDR,
            form=get_form(action=remote_uri, inputs=["name"], method="GET"),
            target_field="name",
            requester=Requester(interval=SLEEP_INTERVAL),
        )

    def setUp(self):
        super().setUp()
        self.cracker_other_opts = {}
        self.setup_local_waf(["."])

    def test_waf(self):
        cracker = Cracker(self.subm, **self.cracker_other_opts)
        full_payload_gen = cracker.crack()
        assert full_payload_gen is not None, self.__class__.__name__
        payload, will_print = full_payload_gen.generate(
            const.OS_POPEN_READ,
            "echo 'cracked! @m WR171NG[]{}|;&&&\" S()METHING RANDON' " + self.__class__.__name__,
        )
        assert (
            payload is not None
        ), self.__class__.__name__  # 因为type hint无法认出.assertIsNotNone
        self.assertTrue(will_print)
        if self.local_blacklist:
            for w in self.local_blacklist:
                self.assertNotIn(w, payload)
        resp = self.subm.submit(payload)
        assert resp is not None
        self.assertIn('cracked! @m WR171NG[]{}|;&&&" S()METHING RANDON', resp.text, resp.text)


class TestEasy(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                '"',
                "'",
                "_",
                ".",
                "+",
                "~",
                "{{",
            ]
        )


class TestStringOct(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "lipsum",
                "x",
                "u",
                "''",
                '""',
                "+",
                "~",
                "%",
                "globals",
                "class",
                "mro",
                "base",
                ":",
                "lower",
            ]
        )


class TestStringHex(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "lipsum",
                "\\1",
                "u",
                "''",
                '""',
                "+",
                "~",
                "%",
                "globals",
                "class",
                "mro",
                "base",
                ":",
                "lower",
            ]
        )


class TestStringUnicodeHex(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "lipsum",
                "\\1",
                "x",
                "''",
                '""',
                "+",
                "~",
                "%",
                "globals",
                "class",
                "mro",
                "base",
                ":",
                "lower",
            ]
        )


class TestStringLower1(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "lipsum",
                "\\1",
                "u",
                "x",
                "''",
                '""',
                "+",
                "~",
                "%",
                "globals",
                "class",
                "mro",
                "base",
                ":",
                ".",
            ]
        )


class TestIntegerAdd(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "\\1",
                "'",
                '"',
                "~",
                ".",
                "[",
                "dict",
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
                "-",
                "*",
            ]
        )


class TestIntegerSub(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "\\1",
                "'",
                '"',
                "~",
                ".",
                "[",
                "dict",
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
                "+",
            ]
        )


class TestPath(TestBase):
    def setUp(self):
        super().setUp()
        self.local_blacklist = None
        self.subm = PathSubmitter(
            url=VULUNSERVER_ADDR + "/crackpath/",
            requester=Requester(interval=SLEEP_INTERVAL),
        )


class TestHard1(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "'",
                '"',
                ".",
                "_",
                "import",
                "request",
                "url",
                "\\x",
                "os",
                "system",
                "\\u",
            ]
        )


class TestHard2(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
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
        )


class TestHard3(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                '0"',
                ".",
                '"',
                "system",
                "eval",
                "exec",
                "popen",
                "subprocess",
                "posix",
                "builtins",
                "namespace",
                "read",
                "self",
                "mro",
                "base",
                "global",
                "init",
                "chr",
                "value",
                "pop",
                "import",
                "include",
                "request",
                "{{",
                "}}",
                "config",
                "=",
                "lipsum",
                "~",
                "url_for",
            ]
        )


class TestHard4(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
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
                "os",
                "import",
                "x",
                "globals",
                "cycler",
                "[",
                '"',
                "'",
                "_",
                ".",
                "+",
                "~",
                "{{",
            ]
        )


class TestHard5(TestBase):
    # geekgame2023 klf_2
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "_",
                "\\",
                "'",
                '"',
                "request",
                "+",
                "class",
                "init",
                "arg",
                "config",
                "app",
                "self",
                "cd",
                "chr",
                "request",
                "url",
                "builtins",
                "globals",
                "base",
                "pop",
                "import",
                "popen",
                "getitem",
                "subclasses",
                "/",
                "flashed",
                "os",
                "open",
                "read",
                "count",
                "*",
                "38",
                "124",
                "47",
                "59",
                "99",
                "100",
                "cat",
                "~",
                ":",
                "not",
                "0",
                "-",
                "ord",
                "37",
                "94",
                "96",
                "[",
                "]",
                "index",
                "length",
            ]
        )


class TestHard6(TestBase):
    # geekgame2023 klf_2 enhanced
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "_",
                "\\",
                "'",
                '"',
                "request",
                "+",
                "class",
                "init",
                "arg",
                "config",
                "app",
                "self",
                "cd",
                "chr",
                "request",
                "url",
                "builtins",
                "globals",
                "base",
                "pop",
                "import",
                "popen",
                "getitem",
                "subclasses",
                "/",
                "flashed",
                "os",
                "open",
                "read",
                "count",
                "*",
                "38",
                "124",
                "47",
                "59",
                "99",
                "100",
                "cat",
                "~",
                ":",
                "not",
                "0",
                "-",
                "ord",
                "37",
                "94",
                "96",
                "[",
                "]",
                "index",
                "length",
                "join",
            ]
        )


class TestHard7(TestBase):
    # geekgame2023 klf_3 enhanced
    def setUp(self):
        super().setUp()
        self.setup_local_waf(
            [
                "_",
                "\\",
                "'",
                '"',
                "[",
                "]",
                "~",
                "+",
                "@",
                "^",
                "#",
                "/",
                ":",
                "*",
                "-",
                "request",
                "class",
                "init",
                "arg",
                "config",
                "app",
                "self",
                "cd",
                "chr",
                "request",
                "url",
                "builtins",
                "globals",
                "base",
                "pop",
                "import",
                "popen",
                "getitem",
                "subclasses",
                "flashed",
                "os",
                "open",
                "read",
                "cat",
                "count",
                "not",
                "length",
                "index",
                "ord",
                "43",
                "45",
                "38",
                "124",
                "47",
                "59",
                "99",
                "100",
                "0",
                "37",
                "94",
                "96",
                "48",
                "49",
                "50",
                "51",
                "52",
                "53",
                "54",
                "55",
                "56",
                "57",
                "58",
                "59",
                "))",
            ]
        )


class TestStaticWAF(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_remote_waf("/static_waf")


class TestStaticWAF2(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_remote_waf("/static_waf2")


class TestDynamicWAF(TestBase):
    def setUp(self):
        super().setUp()
        self.blacklist = None
        self.setup_remote_waf("/dynamic_waf")


class TestWeirdWAF(TestBase):
    def setUp(self):
        super().setUp()
        self.blacklist = None
        self.setup_remote_waf("/weird_waf")


class TestReversedWAF(TestBase):
    def setUp(self):
        super().setUp()
        self.blacklist = None
        self.setup_remote_waf("/reversed_waf")
        self.subm.add_tamperer(lambda x: x[::-1])


class TestLengthLimit1WAF(TestBase):
    def setUp(self):
        super().setUp()
        self.blacklist = None
        self.setup_remote_waf("/lengthlimit1_waf")

    def test_waf(self):
        cracker = Cracker(self.subm, **self.cracker_other_opts)
        full_payload_gen = cracker.crack()
        assert full_payload_gen is not None, self.__class__.__name__
        payload, will_print = full_payload_gen.generate(
            const.OS_POPEN_READ,
            "echo 'cracked!!!' " + self.__class__.__name__,
        )
        assert (
            payload is not None
        ), self.__class__.__name__  # 因为type hint无法认出.assertIsNotNone
        self.assertTrue(will_print)
        if self.local_blacklist:
            for w in self.local_blacklist:
                self.assertNotIn(w, payload)
        resp = self.subm.submit(payload)
        assert resp is not None
        self.assertIn('cracked!!!', resp.text, resp.text)

class TestLengthLimit2WAF(TestBase):
    def setUp(self):
        super().setUp()
        self.blacklist = None
        self.setup_remote_waf("/lengthlimit2_waf")

    def test_waf(self):
        cracker = Cracker(self.subm, environment="flask")
        result = cracker.crack_eval_args()
        assert result is not None
        subm, will_print = result
        payload = "'fenjing'+'test'"
        self.assertTrue(will_print)
        resp = subm.submit(payload)
        assert resp is not None
        self.assertIn("fenjingtest", resp.text)


class TestReplacedWAFAvoid(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_remote_waf("/replace_waf")
        self.cracker_other_opts = {"replaced_keyword_strategy": "avoid"}


class TestReplacedWAFDoubleTapping(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_remote_waf("/replace_waf")
        self.cracker_other_opts = {"replaced_keyword_strategy": "doubletapping"}


class TestJinjaEnv(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_remote_waf("/jinja_env_waf")
        self.cracker_other_opts = {"environment": "jinja"}


class TestFix500(TestBase):
    def setUp(self):
        super().setUp()
        self.setup_remote_waf("/jinja_env_waf")
        self.cracker_other_opts = {"environment": "flask"}
