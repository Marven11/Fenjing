import sys  # noqa

sys.path.append("..")  # noqa

import unittest
import logging
import os

import requests

import fenjing
from fenjing.context_vars import const_exprs, const_exprs_py3

from jinja2 import Template

VULUNSERVER_ADDR = os.environ.get("VULUNSERVER_ADDR", "http://127.0.0.1:5000")

fenjing.payload_gen.logger.setLevel(logging.ERROR)


class ContextVarsTests(unittest.TestCase):
    def test_const_exprs(self):
        exprs = {**const_exprs, **const_exprs_py3}
        for k, v in exprs.items():
            payload = "{%if (EXPR)==(VALUE)%}yes{%endif%}".replace("EXPR", k).replace(
                "VALUE", repr(v)
            )
            result = Template(payload).render()
            assert "yes" in result, f"Test Failed for {k!r}"
