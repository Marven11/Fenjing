import logging
from typing import Union
from .form import parse_forms

from bs4 import BeautifulSoup

logger = logging.getLogger("scan_url")


def parse_urls(html: Union[str, BeautifulSoup]) -> list:
    """从html中解析出所有的链接

    Args:
        html (str|BeautifulSoup): HTML

    Returns:
        List[str]: 所有链接
    """
    if isinstance(html, str):
        bs = BeautifulSoup(html, "html.parser")
    elif isinstance(html, BeautifulSoup):
        bs = html

    return [element.attrs["href"] for element in bs.select("a") if "href" in element]


def yield_form(requester, start_url):
    found = False
    targets = [start_url, ]
    visited = set()
    while targets:
        target_url = targets.pop(0)
        if target_url in visited:
            continue
        visited.add(target_url)

        resp = requester.request(method="GET", url=target_url)
        html = BeautifulSoup(resp.text, "html.parser")
        forms = parse_forms(target_url, html)

        if forms:
            yield target_url, forms
            found = True
        targets += parse_urls(html)
    if not found:
        logger.warning("Exit without finding <form> element")
