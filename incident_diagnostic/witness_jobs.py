"""被调度的业务函数与"真实世界"副作用标记。

SIDE_EFFECTS 模拟函数在 Redis 之外留下的痕迹（扣款/发信/写库），
事故取证时对应业务侧的对账记录。时间戳取 time.time()——
实验中它被替换为可控时钟，生产上即真实时钟。
"""

import time

SIDE_EFFECTS: list = []


def charge_customer(token: str) -> str:
    SIDE_EFFECTS.append(('charge_customer', token, time.time()))
    return f'charged:{token}'
