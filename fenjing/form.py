from urllib.parse import urlparse, urlunparse
from typing import Iterable
import random
import logging
import string

from bs4 import BeautifulSoup

logger = logging.getLogger("utils.form")

def Form(*, action: str, inputs: Iterable, method: str = "POST"):
    """
    the form we use
    """
    method = method.upper()
    if not action.startswith("/"):
        action = "/" + action
    assert method in ["GET", "POST"]
    return {
        "action": action,
        "method": method,
        "inputs": set(inputs)
    }


def parse_forms(url, html):
    """
    get forms from a html of a url
    """
    parsed_url = urlparse(url)
    uri = parsed_url[3]

    if isinstance(html, str):
        bs = BeautifulSoup(html, "html.parser")
    elif isinstance(html, BeautifulSoup):
        bs = html
    else:
        raise NotImplemented(f"Unsupported Type: type(html)={type(html)}")

    details = []
    for form_element in bs.select("form"):
        form = Form(
            action=form_element.attrs.get("action", uri),
            method=form_element.attrs.get("method", "POST").upper(),
            inputs=[
                element.attrs["name"]
                for element in form_element.select("input")
                if "name" in element.attrs
            ]
        )
        details.append(form)
    return details


def random_fill(form):
    """
    randomli fill the form
    """
    return {
        k: "".join(random.choices(string.ascii_lowercase, k=8))
        for k in form["inputs"]
    }


def fill_form(url, form, form_inputs = None, random_fill_other = True):
    """
    fill the form and return keyword arguments for the requests module
    """
    if random_fill_other:
        fill = random_fill(form)
        if form_inputs is not None:
            fill.update(form_inputs)
    else:
        fill = form_inputs
    return {
        "url": urlunparse(urlparse(url)._replace(path=form["action"])),
        "method": form["method"],
        ("data" if form["method"] == "POST" else "params"): fill
    }
