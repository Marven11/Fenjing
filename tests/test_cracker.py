# pylint: skip-file
# flake8: noqa

import sys

sys.path.append("..")

import unittest
import fenjing
from typing import Union
from fenjing.cracker import Cracker
from fenjing.submitter import BaseSubmitter, HTTPResponse
from fenjing import const
import jinja2
import logging


class FakeSubmitter(BaseSubmitter):
    def __init__(self, waf, callback=None):
        super().__init__(callback)
        self.waf = waf

    def submit_raw(self, raw_payload: str) -> Union[HTTPResponse, None]:
        if not self.waf(raw_payload):
            return HTTPResponse(200, "Nope")
        try:
            result = jinja2.Template(source=raw_payload).render()
            return HTTPResponse(200, result)
        except Exception:
            return HTTPResponse(500, "Internal Server Error")


class CrackerTestBase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.blacklist = ["."]
        self.subm = FakeSubmitter(
            lambda x: all(w not in x for w in self.blacklist)
        )

    def test_waf(self):
        cracker = Cracker(self.subm)
        full_payload_gen = cracker.crack()
        self.assertIsNotNone(full_payload_gen)
        payload, _ = full_payload_gen.generate(
            const.OS_POPEN_READ,
            "echo 'cracked! @m wr!tIng s()th' " + self.__class__.__name__,
        )
        self.assertIsNotNone(payload)
        resp = self.subm.submit(payload)
        self.assertIn("cracked! @m wr!tIng s()th", resp.text)


class CrackerTestHard(CrackerTestBase):
    def setUp(self):
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
            # "os",
            # "import",
            # "x",
            # "url",
            # "globals",
            # "cycler",
            "[",
            '"',
            "'",
            "_",
            ".",
            "+",
            "~",
            "{{",
        ]
        self.subm = FakeSubmitter(
            lambda x: all(w not in x for w in self.blacklist)
        )


class CrackerTestWeird(CrackerTestBase):
    def setUp(self):
        super().setUp()
        self.blacklist = [
            "[",
            '"',
            "'",
            "_",
            ".",
            "+",
            "~",
            "{{",
        ]
        self.subm = FakeSubmitter(
            lambda s: any(w in s for w in "facklimama")
            or all(w not in s for w in self.blacklist)
        )
