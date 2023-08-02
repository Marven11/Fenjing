# pylint: skip-file
# flake8: noqa

import sys

sys.path.append("..")
import unittest
import logging
import os
import subprocess

from typing import Union
import click

import fenjing
from fenjing import const, cli

VULUNSERVER_ADDR = os.environ["VULUNSERVER_ADDR"]


class TestCLI(unittest.TestCase):
    def crack_test(self, params):
        ctx = click.Context(cli.crack)
        ctx.params = {
            param.name: param.default
            for param in cli.crack.get_params(ctx)
            if param.name != "help"
        }
        ctx.params.update(params)
        cli.crack.invoke(ctx)

    def test_crack_basic(self):
        for uri in [
            "",
            "/static_waf",
            "/dynamic_waf",
            "/weird_waf",
            "/lengthlimit1_waf"
        ]:
            self.crack_test(
                {
                    "url": VULUNSERVER_ADDR + uri,
                    "method": "GET",
                    "inputs": "name",
                    "exec_cmd": "ls /",
                    "interval": 0.002
                }
            )


    def test_crack_notexist(self):
        try:
            self.crack_test(
                {
                    "url": VULUNSERVER_ADDR + "/notexist",
                    "method": "GET",
                    "inputs": "name",
                    "exec_cmd": "ls /",
                    "interval": 0.01,
                    "detect_mode": "fast" 
                }
            )
        except cli.RunFailed:
            return
        else:
            assert False


    def test_crack_nonrespond(self):
        try:
            self.crack_test(
                {
                    "url": VULUNSERVER_ADDR + "/nonrespond",
                    "method": "GET",
                    "inputs": "name",
                    "exec_cmd": "ls /",
                    "interval": 0.01,
                    "detect_mode": "fast" 
                }
            )
        except cli.RunFailed:
            return
        else:
            assert False

    def test_crack_fast(self):
        self.crack_test(
            {
                "url": VULUNSERVER_ADDR + "/static_waf",
                "method": "GET",
                "inputs": "name",
                "exec_cmd": "ls /",
                "interval": 0.01,
                "detect_mode": "fast" 
            }
        )

    def test_crack_eval_args(self):
        self.crack_test(
            {
                "url": VULUNSERVER_ADDR + "/lengthlimit2_waf",
                "method": "GET",
                "inputs": "name",
                "exec_cmd": "ls /",
                "interval": 0.01,
                "eval_args_payload": True
            }
        )
