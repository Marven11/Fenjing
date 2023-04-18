

from .requester import Requester
from .form import parse_forms

from bs4 import BeautifulSoup


def parse_urls(html):
    if isinstance(html, str):
        bs = BeautifulSoup(html, "html.parser")
    elif isinstance(html, BeautifulSoup):
        bs = html
    else:
        raise NotImplemented(f"Unsupported Type: type(html)={type(html)}")

    return [element.attrs["href"] for element in bs.select("a") if "href" in element]


def yield_form(requester, start_url):
    targets = [start_url, ]
    visited = set()
    while targets:
        target_url, *targets = targets
        if target_url in visited:
            continue
        visited.add(target_url)
        resp = requester.request(method="GET", url=target_url)
        html = BeautifulSoup(resp.text, "html.parser")
        forms = parse_forms(target_url, html)
        yield target_url, forms
        targets += parse_urls(html)
