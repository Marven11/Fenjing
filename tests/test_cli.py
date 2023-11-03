# pylint: skip-file
# flake8: noqa

import logging
import sys

sys.path.append("..")
import unittest
import os

import click

from fenjing import cli, waf_func_gen

SLEEP_INTERVAL = float(os.environ.get("SLEEP_INTERVAL", 0.01))
VULUNSERVER_ADDR = os.environ["VULUNSERVER_ADDR"]
waf_func_gen.logger.setLevel(logging.ERROR)

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

    def crack_path_test(self, params):
        ctx = click.Context(cli.crack_path)
        ctx.params = {
            param.name: param.default
            for param in cli.crack_path.get_params(ctx)
            if param.name != "help"
        }
        ctx.params.update(params)
        cli.crack_path.invoke(ctx)

    def get_config_test(self, params):
        ctx = click.Context(cli.get_config)
        ctx.params = {
            param.name: param.default
            for param in cli.get_config.get_params(ctx)
            if param.name != "help"
        }
        ctx.params.update(params)
        cli.get_config.invoke(ctx)

    def scan_test(self, params):
        ctx = click.Context(cli.scan)
        ctx.params = {
            param.name: param.default
            for param in cli.scan.get_params(ctx)
            if param.name != "help"
        }
        ctx.params.update(params)
        cli.scan.invoke(ctx)

    def test_crack_basic(self):
        for uri in [
            "",
            "/static_waf",
            "/dynamic_waf",
            "/weird_waf",
            "/lengthlimit1_waf",
        ]:
            self.crack_test(
                {
                    "url": VULUNSERVER_ADDR + uri,
                    "method": "GET",
                    "inputs": "name",
                    "exec_cmd": "ls /",
                    "interval": SLEEP_INTERVAL,
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
                    "interval": SLEEP_INTERVAL,
                    "detect_mode": "fast",
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
                    "interval": SLEEP_INTERVAL,
                    "detect_mode": "fast",
                }
            )
        except cli.RunFailed:
            return
        else:
            assert False

    def test_crack_ua(self):
        self.crack_test(
            {
                "url": VULUNSERVER_ADDR + "/verifyheader",
                "method": "GET",
                "inputs": "name",
                "exec_cmd": "ls /",
                "interval": SLEEP_INTERVAL,
                "user_agent": "114514",
                "header": ["Custom-Key: 114514"],
                "cookies": "data=114514; ",
            }
        )

    def test_crack_fast(self):
        self.crack_test(
            {
                "url": VULUNSERVER_ADDR + "/static_waf",
                "method": "GET",
                "inputs": "name",
                "exec_cmd": "ls /",
                "interval": SLEEP_INTERVAL,
                "detect_mode": "fast",
            }
        )

    def test_crack_eval_args(self):
        self.crack_test(
            {
                "url": VULUNSERVER_ADDR + "/lengthlimit2_waf",
                "method": "GET",
                "inputs": "name",
                "exec_cmd": "ls /",
                "interval": SLEEP_INTERVAL,
                "eval_args_payload": True,
                "environment": "flask"
            }
        )

    def test_crack_tamperer(self):
        self.crack_test(
            {
                "url": VULUNSERVER_ADDR + "/reversed_waf",
                "method": "GET",
                "inputs": "name",
                "exec_cmd": "ls /",
                "interval": SLEEP_INTERVAL,
                "tamper_cmd": "rev",
            }
        )

    def test_crack_path_basic(self):
        self.crack_path_test(
            {
                "url": VULUNSERVER_ADDR + "/crackpath/",
                "interval": SLEEP_INTERVAL,
                "exec_cmd": "ls /",
            }
        )

    def test_crack_path_tamperer(self):
        self.crack_path_test(
            {
                "url": VULUNSERVER_ADDR + "/crackpath/",
                "interval": SLEEP_INTERVAL,
                "exec_cmd": "ls /",
                "tamper_cmd": "cat"
            }
        )

    def test_crack_path_extra(self):
        self.crack_path_test(
            {
                "url": VULUNSERVER_ADDR + "/crackpath-extra/",
                "interval": SLEEP_INTERVAL,
                "extra_params": "debug=1",
                "exec_cmd": "ls /",
            }
        )

    def test_get_config_basic(self):
        self.get_config_test(
            {
                "url": VULUNSERVER_ADDR,
                "method": "GET",
                "inputs": "name",
                "interval": SLEEP_INTERVAL,
            }
        )

    def test_get_config_fast(self):
        self.get_config_test(
            {
                "url": VULUNSERVER_ADDR,
                "method": "GET",
                "inputs": "name",
                "interval": SLEEP_INTERVAL,
                "detect_mode": "fast",
            }
        )

    def test_scan_basic(self):
        self.scan_test(
            {
                "url": VULUNSERVER_ADDR,
                "interval": SLEEP_INTERVAL,
                "exec_cmd": "ls /",
            }
        )

    def test_scan_burstparam(self):
        self.scan_test(
            {
                "url": VULUNSERVER_ADDR + "/scan_burstkeywords",
                "interval": SLEEP_INTERVAL,
                "exec_cmd": "ls /",
            }
        )

    def test_scan_nonrespond(self):
        try:
            self.scan_test(
                {
                    "url": VULUNSERVER_ADDR + "/nonrespond",
                    "interval": SLEEP_INTERVAL,
                    "exec_cmd": "ls /",
                }
            )
        except cli.RunFailed:
            pass
        else:
            assert False

    def test_scan_tamperer(self):
        self.scan_test(
            {
                "url": VULUNSERVER_ADDR + "/reversed_waf",
                "interval": SLEEP_INTERVAL,
                "exec_cmd": "ls /",
                "tamper_cmd": "rev"
            }
        )
