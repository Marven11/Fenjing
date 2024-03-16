# pylint: skip-file
# flake8: noqa

import sys

sys.path.append("..")

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
