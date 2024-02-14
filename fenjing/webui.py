"""webui后台的实现"""

import logging
import threading
import uuid

from urllib.parse import urlparse
from typing import Union

from flask import Flask, render_template, request, jsonify

from .const import (
    DetectMode,
    ReplacedKeywordStrategy,
    TemplateEnvironment,
    CALLBACK_GENERATE_FULLPAYLOAD,
    CALLBACK_GENERATE_PAYLOAD,
    CALLBACK_PREPARE_FULLPAYLOADGEN,
    CALLBACK_SUBMIT,
    CALLBACK_TEST_FORM_INPUT,
    APICODE_OK,
    APICODE_WRONG_INPUT,
    DEFAULT_USER_AGENT,
    OS_POPEN_READ,
)
from .cracker import Cracker
from .options import Options
from .form import get_form, Form
from .full_payload_gen import FullPayloadGen
from .requester import HTTPRequester
from .submitter import Submitter, FormSubmitter


logger = logging.getLogger("webui")
app = Flask(__name__)
tasks = {}


class CallBackLogger:
    """利用callback收集信息并以日志的形式保存的类"""

    def __init__(self, flash_messages, messages):
        self.flash_messages = flash_messages
        self.messages = messages

    def callback_prepare_fullpayloadgen(self, data):
        """收集FullPayloadGen准备好后的信息"""
        self.messages.append("上下文payload测试完毕。")
        if data["context"]:
            context_repr = ", ".join(
                f"{k}={repr(v)}" for k, v in data["context"].items()
            )
            self.messages.append(f"以下是在上下文中的值：{context_repr}")
        else:
            self.messages.append("没有上下文payload可以通过waf。。。")
        if not data["will_print"]:
            self.messages.append("生成的payload将不会具有回显。")

    def callback_generate_fullpayload(self, data):
        """收集FullPayloadGen生成payload的结果"""
        payload = (
            data["payload"]
            if len(data["payload"]) < 30
            else data["payload"][:30] + "..."
        )
        self.messages.append(f"分析完毕，为{data['gen_type']}生成payload: {payload}")
        if not data["will_print"]:
            self.messages.append("payload将不会产生回显")

    def callback_generate_payload(self, data):
        """收集PayloadGen生成payload的中间结果"""
        payload_repr = data["payload"]
        if len(payload_repr) > 100:
            payload_repr = payload_repr[:100] + "..."
        req = f"{data['gen_type']}({', '.join(repr(arg) for arg in data['args'])})"
        self.flash_messages.append(f"请求{req}对应的payload可以是{payload_repr}")

    def callback_submit(self, data):
        """收集表单的提交结果"""
        if data.get("type", "form"):
            self.flash_messages.append(
                f"提交表单完成，返回值为{data['response'].status_code}，输入为{data['inputs']}，表单为{data['form']}"
            )
        else:
            self.flash_messages.append(
                f"提交payload完成，返回值为{data['response'].status_code}，提交payload为{data['payload']}"
            )

    def callback_test_form_input(self, data):
        """收集测试表单的结果"""
        if not data["ok"]:
            return
        testsuccess_msg = (
            "payload测试成功！" if data["test_success"] else "payload测试失败。"
        )
        will_print_msg = "其会产生回显。" if data["will_print"] else "其不会产生回显。"
        self.messages.append(testsuccess_msg + will_print_msg)

    def __call__(self, callback_type, data):
        def default_handler(_):
            return logger.warning("callback_type=%s not found", callback_type)

        return {
            CALLBACK_PREPARE_FULLPAYLOADGEN: self.callback_prepare_fullpayloadgen,
            CALLBACK_GENERATE_FULLPAYLOAD: self.callback_generate_fullpayload,
            CALLBACK_GENERATE_PAYLOAD: self.callback_generate_payload,
            CALLBACK_SUBMIT: self.callback_submit,
            CALLBACK_TEST_FORM_INPUT: self.callback_test_form_input,
        }.get(callback_type, default_handler)(data)


class CrackTaskThread(threading.Thread):
    """crack任务的线程，由webui调用并实际承载攻击任务"""

    def __init__(self, taskid, url, form: Form, interval: float, options: Options):
        super().__init__()
        self.success = False
        self.taskid = taskid
        self.form = form
        self.url = url
        self.options = options
        self.flash_messages = []
        self.messages = []
        self.callback = CallBackLogger(self.flash_messages, self.messages)
        self.submitter: Union[Submitter, None] = None
        self.full_payload_gen: Union[FullPayloadGen, None] = None
        self.cracker: Union[Cracker, None]
        self.requester = HTTPRequester(interval=interval, user_agent=DEFAULT_USER_AGENT)

    def run(self):
        for input_field in self.form["inputs"]:
            self.messages.append(f"开始分析表单项{input_field}")
            self.submitter = FormSubmitter(
                self.url,
                self.form,
                input_field,
                self.requester,
                self.callback,
            )
            self.cracker = Cracker(
                self.submitter,
                self.callback,
                options=self.options,
            )
            if not self.cracker.has_respond():
                continue
            self.full_payload_gen = self.cracker.crack()
            if self.full_payload_gen:
                self.messages.append("WAF已绕过，现在可以执行Shell指令了")
                self.success = True
                break
            continue
        if not self.success:
            self.messages.append("WAF绕过失败")


class InteractiveTaskThread(threading.Thread):
    """表单攻击成功后，为给定shell指令生成payload的线程"""

    def __init__(
        self,
        taskid: str,
        submitter: Submitter,
        full_payload_gen: FullPayloadGen,
        cmd: str,
    ):
        super().__init__()
        self.taskid = taskid
        self.submitter = submitter
        self.full_payload_gen = full_payload_gen
        self.cmd = cmd

        self.flash_messages = []
        self.messages = []
        self.callback = CallBackLogger(self.flash_messages, self.messages)

        self.submitter.callback = self.callback
        self.full_payload_gen.callback = self.callback

    def run(self):
        self.messages.append("开始生成payload")
        payload, will_print = self.full_payload_gen.generate(OS_POPEN_READ, self.cmd)
        if not payload:
            self.messages.append("payload生成失败")
            return
        if not will_print:
            self.messages.append("此payload不会产生回显")
        resp = self.submitter.submit(payload)
        assert resp is not None
        self.messages.append("提交payload的回显如下：")
        self.messages.append(resp.text)


def create_crack_task(url, method, inputs, action, interval, options):
    """创建对应的攻击任务（一个线程）"""
    assert url != "" and inputs != "", "wrong param"
    form = get_form(
        action=action or urlparse(url).path,
        method=method,
        inputs=inputs.split(","),
    )
    taskid = uuid.uuid4().hex
    task = CrackTaskThread(taskid, url, form, interval=float(interval), options=options)
    task.daemon = True
    task.start()
    tasks[taskid] = task
    return taskid


def create_interactive_id(cmd, last_task):
    """根据给定的指令生成一个任务进行攻击"""
    assert cmd != "", "wrong param"
    submitter, full_payload_gen = (
        last_task.submitter,
        last_task.full_payload_gen,
    )
    taskid = uuid.uuid4().hex
    task = InteractiveTaskThread(taskid, submitter, full_payload_gen, cmd)
    task.daemon = True
    task.start()
    tasks[taskid] = task
    return taskid


@app.route("/")
def index():
    """渲染主页"""
    return render_template("index.html")


@app.route(
    "/createTask",
    methods=["POST"],
)
def create_task():
    """创建攻击任务"""
    task_type = request.form.get("type", None)
    if task_type not in ["crack", "interactive"]:
        logging.info(request.form)
        return jsonify(
            {
                "code": APICODE_WRONG_INPUT,
                "message": f"unknown type {request.form.get('type', None)}",
            }
        )
    if task_type == "crack":
        # response variable is used here because pylint don't like too many returns,
        # and i think code logic here is clear enough.
        if request.form["url"] == "" or request.form["inputs"] == "":
            response = jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": "URL and inputs should not be empty, but you provide "
                    + f"url={request.form['url']} and inputs={request.form['inputs']}",
                }
            )
        else:
            options = Options()
            if request.form.get("detect_mode", None):
                options.detect_mode = DetectMode(request.form.get("detect_mode", None))
            if request.form.get("environment", None):
                options.environment = TemplateEnvironment(
                    request.form.get("environment", None)
                )
            if request.form.get("replaced_keyword_strategy", None):
                options.replaced_keyword_strategy = ReplacedKeywordStrategy(
                    request.form.get("replaced_keyword_strategy", None)
                )
            taskid = create_crack_task(
                request.form["url"],
                request.form["method"],
                request.form["inputs"],
                request.form["action"],
                interval=request.form["interval"],
                options=options,
            )
            response = jsonify({"code": APICODE_OK, "taskid": taskid})
        return response
    if task_type == "interactive":
        cmd, last_task_id = (
            request.form["cmd"],
            request.form["last_task_id"],
        )
        last_task = tasks.get(last_task_id, None)
        if cmd == "":
            response = jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": "cmd should not be empty",
                }
            )
        elif not isinstance(last_task, CrackTaskThread):
            response = jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": f"last_task_id not found: {last_task_id}",
                }
            )
        elif not last_task.success:
            response = jsonify(
                {
                    "code": APICODE_WRONG_INPUT,
                    "message": f"specified task failed: {last_task_id}",
                }
            )
        else:
            taskid = create_interactive_id(cmd, last_task)
            response = jsonify({"code": APICODE_OK, "taskid": taskid})
        return response
    assert False, "This line should not be run, check code."


@app.route(
    "/watchTask",
    methods=[
        "POST",
    ],
)
def watch_task():
    """异步获取任务（一个线程）的运行状态"""
    if "taskid" not in request.form:
        return jsonify({"code": APICODE_WRONG_INPUT, "message": "taskid not provided"})
    if request.form["taskid"] not in tasks:
        return jsonify(
            {
                "code": APICODE_WRONG_INPUT,
                "message": f"task not found: {request.form['taskid']}",
            }
        )
    task: Union[CrackTaskThread, InteractiveTaskThread] = tasks[request.form["taskid"]]
    if isinstance(task, CrackTaskThread):
        return jsonify(
            {
                "code": APICODE_OK,
                "taskid": task.taskid,
                "done": not task.is_alive(),
                "messages": task.messages,
                "flash_messages": task.flash_messages,
                "success": task.success,
            }
        )
    if isinstance(task, InteractiveTaskThread):
        return jsonify(
            {
                "code": APICODE_OK,
                "taskid": task.taskid,
                "done": not task.is_alive(),
                "messages": task.messages,
                "flash_messages": task.flash_messages,
            }
        )
    assert False, "This line should not be run, check code."


def main(host="127.0.0.1", port=11451):
    """启动webui服务器"""
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
