# pylint: skip-file
# flake8: noqa

import sys

sys.path.insert(0, "..")

import time
import threading
import unittest
import os
import requests
from fenjing import webui, const

WEBUI_URL = "http://127.0.0.1:11451"
VULUNSERVER_URL = os.environ.get("VULUNSERVER_ADDR", "http://127.0.0.1:5000")

t = threading.Thread(target=webui.main, kwargs={"open_browser": False})
t.daemon = True
t.start()
time.sleep(0.5)


class TestWebui(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def test_index(self):
        resp = requests.get(WEBUI_URL)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("<!DOCTYPE html>", resp.text)

    def test_detect_mode_field_name(self):
        resp = requests.get(WEBUI_URL)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('name="detect_mode"', resp.text)
        self.assertNotIn('name="detect-mode"', resp.text)
        self.assertIn('name="waf_keywords"', resp.text)
        self.assertIn('name="extra_params"', resp.text)
        self.assertIn('name="extra_data"', resp.text)

    def test_parse_options(self):
        options = webui.parse_options(
            {
                "detect_mode": "fast",
                "environment": "jinja2",
                "replaced_keyword_strategy": "doubletapping",
                "detect_waf_keywords": "fast",
                "waf_keywords": "hacker!!!!, flag\nanother",
            }
        )
        self.assertEqual(options.detect_mode, const.DetectMode.FAST)
        self.assertEqual(options.environment, const.TemplateEnvironment.JINJA2)
        self.assertEqual(
            options.replaced_keyword_strategy,
            const.ReplacedKeywordStrategy.DOUBLETAPPING,
        )
        self.assertEqual(options.detect_waf_keywords, const.DetectWafKeywords.FAST)
        self.assertEqual(options.waf_keywords, ("hacker!!!!", "flag", "another"))

    def test_crack_task_extra_params(self):
        task = webui.CrackTaskThread(
            url=VULUNSERVER_URL,
            form={"action": "/", "method": "GET", "inputs": {"name"}},
            interval=0.0,
            options=webui.Options(),
            extra_params_querystr="submit=submit&a=1",
            extra_data_querystr="b=2",
        )
        self.assertEqual(
            task.requester.extra_params, {"submit": ["submit"], "a": ["1"]}
        )
        self.assertEqual(task.requester.extra_data, {"b": ["2"]})

    def wait_for_task(self, task_id, task_type, max_time=60):
        start_time = time.perf_counter()
        while True:
            time.sleep(0.2)
            resp = requests.post(
                WEBUI_URL + "/watchTask",
                data={
                    "taskid": task_id,
                },
            )
            resp_data = resp.json()
            self.assertEqual(resp_data["code"], const.APICODE_OK)
            if resp_data["done"]:
                if task_type == "crack":
                    self.assertTrue(resp_data["success"])
                break
            self.assertLessEqual(time.perf_counter() - start_time, max_time)

    def general_task_test(self, request_data):
        resp = requests.post(WEBUI_URL + "/createTask", data=request_data)
        resp_data = resp.json()
        self.assertEqual(resp_data["code"], const.APICODE_OK)
        task_id = resp_data["taskid"]
        self.wait_for_task(task_id, "crack")

        resp = requests.post(
            WEBUI_URL + "/createTask",
            data={
                "type": "interactive",
                "last_task_id": task_id,
                "cmd": "echo test  webui",
            },
        )
        resp_data = resp.json()
        self.assertEqual(resp_data["code"], const.APICODE_OK)
        task_id = resp_data["taskid"]
        self.wait_for_task(task_id, "interact")

        resp = requests.post(
            WEBUI_URL + "/watchTask",
            data={
                "taskid": task_id,
            },
        )
        resp_data = resp.json()
        self.assertEqual(resp_data["code"], const.APICODE_OK)
        messages = resp_data["messages"]

        is_cmd_executed = any("test webui" in msg for msg in messages)
        self.assertTrue(is_cmd_executed)

    def test_crack(self):
        self.general_task_test(
            {
                "type": "crack",
                "url": VULUNSERVER_URL,
                "inputs": "name",
                "method": "GET",
                "action": "/",
                "interval": "0.02",
            }
        )

    def test_scan(self):
        self.general_task_test(
            {
                "type": "scan",
                "url": VULUNSERVER_URL,
                "interval": "0.02",
            }
        )

    def test_crack_path(self):
        self.general_task_test(
            {
                "type": "crack-path",
                "url": VULUNSERVER_URL + "/crackpath/",
                "interval": "0.02",
            }
        )

    def test_crack_json(self):
        self.general_task_test(
            {
                "type": "crack-json",
                "url": VULUNSERVER_URL + "/crackjson",
                "json_data": '{"name": "admin", "age": 24, "msg": "test"}',
                "key": "msg",
                "method": "POST",
                "interval": "0.02",
            }
        )
