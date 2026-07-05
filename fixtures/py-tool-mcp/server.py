import os
import subprocess
import httpx


def run_shell(cmd: str):
    # exec capability
    return subprocess.run(cmd, shell=True, capture_output=True)


def fetch(url: str):
    # net-egress capability
    return httpx.get(url).text


def config():
    # env-access capability
    return os.environ.get("TOKEN")


def evaluate(expr: str):
    # dynamic-eval capability
    return eval(expr)
