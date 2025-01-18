import sys  # noqa

sys.path.append("..")  # noqa

import unittest
import fenjing
import string


from fenjing.payload_gen import PayloadGenerator, expression_gens
from fenjing.wordlist import CHAR_PATTERNS
from fenjing import const
import logging

from jinja2 import Template, TemplateError

fenjing.payload_gen.logger.setLevel(logging.ERROR)


def get_payload_gen(blacklist, context):
    def waf_func(x):
        return all(word not in x for word in blacklist)

    return PayloadGenerator(
        waf_func,
        context,
        options=fenjing.Options(python_version=fenjing.const.PythonVersion.PYTHON3),
    )


class PayloadGenTestsStringExpr(unittest.TestCase):
    def setUp(self):
        self.payload_gen = get_payload_gen([], {})
        self.target_strings = [
            "aaa",
            "114",
            "\\x61",
            "echo 123 | base64 -d",
            "!@#$%^&|;-_ ()[]{}",
            "print(114514)\n\n",
            "__globals__",
            "__114514__",
        ]
        for s in const.EXTRA_TARGETS:
            self.payload_gen.add_generated_expr(
                (const.STRING, s), self.payload_gen.generate_detailed(const.STRING, s)
            )

    def test_rules(self):
        for rule in expression_gens["string"]:
            for target_string in self.target_strings:
                target_list = rule({}, target_string)
                result = self.payload_gen.generate_by_list(target_list)
                if not result:
                    continue
                try:
                    render_result = Template("{{" + result[0] + "}}").render()
                except Exception as e:
                    raise ValueError(
                        f"{rule.__name__} failed generating {target_string!r} {result[0]=}"
                    ) from e
                self.assertIn(
                    target_string,
                    render_result,
                    f"{rule.__name__} failed generating {target_string!r} "
                    + f"{result[0]=} {render_result=}",
                )


class PositiveIntegers(unittest.TestCase):
    def setUp(self):
        self.payload_gen = get_payload_gen([], {})

    def test_rules(self):
        for rule in expression_gens["positive_integer"]:
            for target_integer in range(0, 150):
                target_list = rule({}, target_integer)
                result = self.payload_gen.generate_by_list(target_list)
                if not result:
                    continue
                try:
                    render_result = Template("{{" + result[0] + "}}").render()
                except Exception as e:
                    raise ValueError(
                        f"{rule.__name__} failed generating {target_integer!r} {result[0]=} {target_list=}"
                    ) from e
                self.assertIn(
                    str(target_integer),
                    render_result,
                    f"{rule.__name__} failed generating {target_integer!r} {result[0]=} {target_list=}",
                )


class PayloadGenTestsStringPiecesExpr(unittest.TestCase):
    def setUp(self):
        self.payload_gen = get_payload_gen([], {})

    def test_many_format_c(self):
        for rule in expression_gens["string_many_format_c"]:
            target_list = rule({}, 3)
            result = self.payload_gen.generate_by_list(target_list)
            if not result:
                continue
            try:
                render_result = Template("{{" + result[0] + "}}").render()
            except Exception as e:
                raise ValueError(
                    f"{rule} failed generating string_many_format_c"
                ) from e
            self.assertIn("{:c}" * 3, render_result)

    def test_many_percent_lower_c(self):
        for rule in expression_gens["string_many_percent_lower_c"]:
            target_list = rule({}, 3)
            result = self.payload_gen.generate_by_list(target_list)
            if not result:
                continue
            try:
                render_result = Template("{{" + result[0] + "}}").render()
            except Exception as e:
                raise ValueError(
                    f"{rule} failed generating string_many_percent_lower_c"
                ) from e
            self.assertIn("%c" * 3, render_result)

    def test_percent(self):
        for rule in expression_gens["string_percent"]:
            target_list = rule({})
            result = self.payload_gen.generate_by_list(target_list)
            if not result:
                continue
            try:
                render_result = Template("{{" + result[0] + "}}").render()
            except Exception as e:
                raise ValueError(f"{rule} failed generating string_percent") from e
            self.assertIn("%", render_result)

    def test_lower_c(self):
        for rule in expression_gens["string_lower_c"]:
            target_list = rule({})
            result = self.payload_gen.generate_by_list(target_list)
            if not result:
                continue
            try:
                render_result = Template("{{" + result[0] + "}}").render()
            except Exception as e:
                raise ValueError(f"{rule} failed generating string_percent") from e
            self.assertIn("c", render_result)


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
        self.context_payload = (
            "{%set l=1%}{%set e=3%}{%set lo=10%}{%set loo=100%}{%set eoo=300%}"
        )
        self.payload_gen = get_payload_gen([], self.context)

    def target_test(self, target):
        gen_type = target[0]
        for gen_func in expression_gens[gen_type]:
            try:
                target_list = gen_func(self.context, *target[1:])
            except Exception as e:
                raise RuntimeError(
                    f"Generate failed for rule {gen_func.__name__}"
                ) from e
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
            (const.VARIABLE_OF, "%c"),
            (const.ZERO,),
            (const.INTEGER, 11),
            (const.INTEGER, 123),
            (const.PLUS, (const.INTEGER, 98), (const.INTEGER, 37)),
            (const.MULTIPLY, (const.INTEGER, 3), (const.INTEGER, 37)),
            (const.MULTIPLY, (const.STRING, "a"), (const.INTEGER, 11)),
            (const.STRING_PERCENT,),
            (const.STRING_LOWERC,),
            (const.STRING_PERCENT_LOWER_C,),
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
        for target_string in strings:
            self.assertIsNotNone(self.payload_gen.generate(const.STRING, target_string))

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
        for target_string in strings:
            self.assertIsNotNone(self.payload_gen.generate(const.STRING, target_string))

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
            (const.STRING_PERCENT,),
            (const.STRING_LOWERC,),
            (const.INTEGER, 11),
            (const.STRING, "a"),
            (const.STRING_PERCENT_LOWER_C,),
            (const.STRING_MANY_PERCENT_LOWER_C, 11),
            (const.STRING, "ls /;"),
        ]
        for target in targets:
            result = self.payload_gen.generate(target[0], *target[1:])
            self.assertIsNotNone(result, repr(target))

    def test_string(self):
        test_strings = [
            string.digits,
            string.ascii_lowercase,
            "__dunder__",
            "__import__('os').popen('echo test_command/$(ls / | base64 -w)').read()",
        ]
        for target_string in test_strings:
            self.assertIsNotNone(
                self.payload_gen.generate(const.STRING, target_string), target_string
            )

    def test_os_popen_read(self):
        self.assertIsNotNone(
            self.payload_gen.generate(const.OS_POPEN_READ, "echo fen  jing;")
        )


class WordlistTest(unittest.TestCase):
    def test_char_patterns(self):
        for pattern, indexes in CHAR_PATTERNS.items():
            for i, c in indexes.items():
                expr = pattern.replace("INDEX", str(i))
                payload = "{%if (EXPR)==VALUE%}yes{%endif%}".replace(
                    "EXPR", expr
                ).replace("VALUE", repr(c))
                result = Template(payload).render()
                assert "yes" in result, f"Test {pattern!r} at {i} failed, {result=}"
