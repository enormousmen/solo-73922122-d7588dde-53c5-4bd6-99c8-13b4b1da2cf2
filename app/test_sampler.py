"""留样引擎与网页接口的单元测试 / 关键场景集成测试。"""
import base64
import json
import socket
import time

import pytest

from app import create_app, UdpReceiver
from sampler import (
    COLLECT_TIMEOUT_S,
    SLOT_BUDGET,
    WINDOW_CAP,
    SamplerEngine,
    parse_prefix,
)


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def make_engine():
    clock = FakeClock()
    return SamplerEngine(now_fn=clock), clock


def feed(engine, n, prefix=b"TLM1", src="127.0.0.1:5000", start=0):
    """连续喂 n 个包，返回它们的编号列表。"""
    seqs = []
    for i in range(start, start + n):
        seqs.append(engine.on_packet(prefix + bytes([i & 0xFF]), src))
    return seqs


# ---------- 编号与滚动窗口 ----------

def test_numbering_and_rolling_window():
    eng, _ = make_engine()
    seqs = feed(eng, WINDOW_CAP + 2)          # 130 个包
    assert seqs == list(range(1, WINDOW_CAP + 3))   # 从 1 起连续编号
    st = eng.status()
    assert st["received_total"] == WINDOW_CAP + 2
    assert st["window"]["size"] == WINDOW_CAP        # 只留最近 128 包
    assert st["window"]["oldest"] == 3               # 最旧的已被覆盖
    assert st["window"]["newest"] == WINDOW_CAP + 2


# ---------- 规则登记校验 ----------

def test_parse_prefix_ok():
    assert parse_prefix("deadbeef") == bytes.fromhex("deadbeef")
    assert parse_prefix(" DE AD be ef ") == bytes.fromhex("deadbeef")  # 空白容错
    assert parse_prefix("AA") == b"\xaa"


def test_parse_prefix_bad():
    for bad in (None, "", "   ", "abc", "zz", "00" * 65):
        with pytest.raises(ValueError):
            parse_prefix(bad)


def test_register_validation():
    eng, _ = make_engine()
    with pytest.raises(ValueError):
        eng.register_rule("aa", -1, 0)          # 前包数不能为负
    with pytest.raises(ValueError):
        eng.register_rule("aa", 0, -1)          # 后包数不能为负
    with pytest.raises(ValueError):
        eng.register_rule("aa", 100, 100)       # 合计超 128
    with pytest.raises(ValueError):
        eng.register_rule("xyz", 0, 0)          # 非法十六进制
    r = eng.register_rule("DEAD", 2, 3)
    assert r.prefix_hex == "dead" and r.before == 2 and r.after == 3


# ---------- 触发与收齐 ----------

def test_trigger_captures_hit_and_neighbors():
    eng, _ = make_engine()
    feed(eng, 5)                                 # #1..#5
    eng.register_rule("aa", before=2, after=2)
    hit = eng.on_packet(b"\xaa\xbb\xcc", "127.0.0.1:5001")   # #6 命中
    assert hit == 6
    (s,) = eng.list_samples()
    assert s["state"] == "COLLECTING"
    assert (s["start_seq"], s["hit_seq"], s["end_seq"]) == (4, 6, 8)
    assert s["collected"] == 3                   # 前段 2 包 + 命中包立即入样
    assert eng.status()["slots"]["used"] == 5    # 完整区间（含未到的 #7 #8）占额
    feed(eng, 2)                                 # #7 #8 到齐
    (s,) = eng.list_samples()
    assert s["state"] == "COMPLETE" and s["collected"] == 5


def test_rule_matches_only_packets_after_registration():
    eng, _ = make_engine()
    feed(eng, 3, prefix=b"\xaa")                 # 登记前的匹配包不算
    eng.register_rule("aa", 0, 0)
    assert eng.list_samples() == []
    feed(eng, 1, prefix=b"\xbb")                 # 不匹配不触发
    assert eng.list_samples() == []
    feed(eng, 1, prefix=b"\xaa")                 # 登记后首个匹配包触发
    (s,) = eng.list_samples()
    assert s["hit_seq"] == 5


def test_rule_is_one_shot():
    eng, _ = make_engine()
    eng.register_rule("aa", 0, 0)
    feed(eng, 3, prefix=b"\xaa")
    samples = eng.list_samples()
    assert len(samples) == 1                     # 只触发一次
    assert eng.list_rules()[0]["state"] == "TRIGGERED"


def test_zero_before_after_completes_immediately():
    eng, _ = make_engine()
    eng.register_rule("aa", 0, 0)
    feed(eng, 1, prefix=b"\xaa")
    (s,) = eng.list_samples()
    assert s["state"] == "COMPLETE" and s["total"] == 1


# ---------- 同包多规则：登记顺序受理 ----------

def test_same_packet_multiple_rules_in_registration_order():
    eng, _ = make_engine()
    eng.register_rule("aa", 0, 0)                # 先登记：区间 [h, h]
    eng.register_rule("aa", 1, 1)                # 后登记：区间 [h-1, h+1]
    feed(eng, 1)                                 # #1 普通包
    feed(eng, 1, prefix=b"\xaa")                 # #2 同包命中两条
    samples = eng.list_samples()
    assert len(samples) == 2
    # 按登记顺序受理：先登记的先建样本
    assert (samples[0]["total"], samples[1]["total"]) == (1, 3)
    # 区间 #2 与 #1..#3 重叠：重叠编号只占一个名额 -> 合计 3
    assert eng.status()["slots"]["used"] == 3
    feed(eng, 1)                                 # #3 到齐，第二条收齐
    a, b = eng.list_samples()
    assert a["state"] == b["state"] == "COMPLETE"
    # 两条样本共用命中包 #2 的载荷记录
    pa = [json.loads(x) for x in eng.sample_jsonl(a["id"]).splitlines()]
    pb = [json.loads(x) for x in eng.sample_jsonl(b["id"]).splitlines()]
    assert pa[0] == pb[1] and pa[0]["seq"] == 2


def test_quota_contention_same_packet_registration_order():
    eng, _ = make_engine()
    feed(eng, 64)                                # #1..#64
    eng.register_rule("aa", 64, 63)              # 先登记：区间 #1..#128 恰占满名额
    eng.register_rule("aa", 0, 64)               # 后登记：区间 #65..#129 需 1 个新名额 -> 超额
    feed(eng, 1, prefix=b"\xaa")                 # #65 同包命中两条，按登记顺序受理
    rules = eng.list_rules()
    assert rules[0]["state"] == "TRIGGERED"
    assert rules[1]["state"] == "FAILED"
    assert "超额" in rules[1]["error"]
    assert eng.status()["slots"]["used"] == SLOT_BUDGET  # 失败样本不占名额


# ---------- 触发失败：前段不足 ----------

def test_insufficient_leading_packets_fails():
    eng, _ = make_engine()
    feed(eng, 3)                                 # 窗口只有 #1..#3
    eng.register_rule("aa", before=5, after=0)   # 需要 5 个前包
    feed(eng, 1, prefix=b"\xaa")                 # #4 命中，前段 #−1..#3 不足
    (s,) = eng.list_samples()
    assert s["state"] == "FAILED" and "前段不足" in s["error"]
    assert eng.list_rules()[0]["state"] == "FAILED"
    assert eng.status()["slots"]["used"] == 0    # 未占名额


def test_leading_segment_boundary():
    # 命中包是窗口最新包，前段最多回看 127 包（窗口容量 128）：
    # before=127 且历史恰有 127 包 -> 边界成功
    eng, _ = make_engine()
    feed(eng, SLOT_BUDGET - 1)                   # #1..#127
    eng.register_rule("aa", before=SLOT_BUDGET - 1, after=0)
    feed(eng, 1, prefix=b"\xaa")                 # #128 命中，前段 #1..#127 正好够
    (s,) = eng.list_samples()
    assert s["state"] == "COMPLETE" and s["total"] == SLOT_BUDGET
    assert eng.status()["slots"]["used"] == SLOT_BUDGET


# ---------- 名额账本：重叠共用 / 超时作废 / 丢弃归还 ----------

def test_overlap_shares_slot_and_payload():
    eng, _ = make_engine()
    eng.register_rule("aa", 2, 0)                # 命中后区间 [h-2, h]
    eng.register_rule("aabb", 0, 2)              # 命中后区间 [h, h+2]
    feed(eng, 3)
    eng.on_packet(b"\xaa\xbb\xcc", "127.0.0.1:5000")  # #4 同时命中两条
    assert eng.status()["slots"]["used"] == 5    # 3+3-1（命中包重叠）
    feed(eng, 2)                                 # 后一条收齐
    a, b = eng.list_samples()
    assert a["state"] == b["state"] == "COMPLETE"
    # 共用载荷：两条样本的重叠编号记录完全相同
    pa = [json.loads(x) for x in eng.sample_jsonl(a["id"]).splitlines()]
    pb = [json.loads(x) for x in eng.sample_jsonl(b["id"]).splitlines()]
    assert [x["seq"] for x in pa] == [2, 3, 4]
    assert [x["seq"] for x in pb] == [4, 5, 6]
    assert pa[-1] == pb[0]


def test_timeout_expires_and_releases_exclusive_slots():
    eng, clock = make_engine()
    eng.register_rule("aa", 0, 3)
    feed(eng, 1, prefix=b"\xaa")                 # 触发，区间 #1..#4
    assert eng.status()["slots"]["used"] == 4
    clock.advance(COLLECT_TIMEOUT_S + 0.1)       # 5 秒内没收齐
    assert eng.expire_due() == 1
    (s,) = eng.list_samples()
    assert s["state"] == "EXPIRED"
    assert eng.status()["slots"]["used"] == 0    # 独占名额全部归还


def test_expiry_keeps_shared_slots():
    eng, clock = make_engine()
    eng.register_rule("aa", 0, 3)                # 区间 [h, h+3]
    eng.register_rule("aa", 0, 1)                # 区间 [h, h+1]，与前条重叠
    feed(eng, 1, prefix=b"\xaa")                 # 同包命中两条
    assert eng.status()["slots"]["used"] == 4
    clock.advance(COLLECT_TIMEOUT_S + 0.1)
    eng.expire_due()                             # 两条同时到期作废
    assert eng.status()["slots"]["used"] == 0
    # 再来一次：只作废其中一条（另一条已收齐）
    eng2, clock2 = make_engine()
    eng2.register_rule("aa", 0, 3)
    eng2.register_rule("aa", 0, 1)
    feed(eng2, 1, prefix=b"\xaa")
    feed(eng2, 2)                                # 后一条收齐（区间 #1..#2）
    clock2.advance(COLLECT_TIMEOUT_S + 0.1)
    eng2.expire_due()                            # 前一条（#1..#4）作废
    states = {s["state"] for s in eng2.list_samples()}
    assert states == {"EXPIRED", "COMPLETE"}
    # 只归还独占名额：#3 #4 释放，#1 #2 仍被收齐样本占用
    assert eng2.status()["slots"]["used"] == 2


def test_late_packet_does_not_count_after_deadline():
    eng, clock = make_engine()
    eng.register_rule("aa", 0, 1)                # 区间 [h, h+1]
    feed(eng, 1, prefix=b"\xaa")                 # 触发，等待 #2
    clock.advance(COLLECT_TIMEOUT_S + 0.1)       # 已过 5 秒收齐时限
    feed(eng, 1)                                 # 迟到的包不计入该样本
    (s,) = eng.list_samples()
    assert s["state"] == "EXPIRED"
    assert eng.status()["slots"]["used"] == 0


def test_discard_releases_only_exclusive_slots():
    eng, _ = make_engine()
    eng.register_rule("aa", 0, 2)                # 区间 [h, h+2]
    eng.register_rule("aa", 0, 1)                # 区间 [h, h+1]
    feed(eng, 1, prefix=b"\xaa")
    feed(eng, 2)                                 # 两条都收齐
    assert eng.status()["slots"]["used"] == 3
    a, b = eng.list_samples()
    eng.discard_sample(a["id"])                  # 丢弃区间更大的样本
    assert eng.status()["slots"]["used"] == 2    # 只归还其独占的 #h+2
    with pytest.raises(ValueError):
        eng.discard_sample(a["id"])              # 已丢弃，不能重复操作
    eng.discard_sample(b["id"])
    assert eng.status()["slots"]["used"] == 0


def test_completed_sample_holds_slots_until_discarded():
    eng, clock = make_engine()
    eng.register_rule("aa", 0, 1)
    feed(eng, 1, prefix=b"\xaa")
    feed(eng, 1)                                 # 收齐
    clock.advance(COLLECT_TIMEOUT_S * 3)
    eng.expire_due()                             # 收齐样本不作废
    (s,) = eng.list_samples()
    assert s["state"] == "COMPLETE"
    assert eng.status()["slots"]["used"] == 2    # 名额保留，供下载/核对


# ---------- 下载 ----------

def test_download_jsonl_format_and_order():
    eng, _ = make_engine()
    feed(eng, 5)
    eng.register_rule("aa", 2, 1)
    eng.on_packet(b"\xaa\x01", "10.0.0.9:7777")  # #6 命中，区间 #4..#7
    eng.on_packet(b"\xaa\x02", "10.0.0.9:7778")  # #7
    (s,) = eng.list_samples()
    assert s["state"] == "COMPLETE"
    lines = [json.loads(x) for x in eng.sample_jsonl(s["id"]).splitlines()]
    assert [x["seq"] for x in lines] == [4, 5, 6, 7]     # 按收包顺序
    hit = lines[2]
    assert hit["src"] == "10.0.0.9:7777"
    assert base64.b64decode(hit["payload_b64"]) == b"\xaa\x01"
    assert set(hit) == {"seq", "src", "payload_b64"}


def test_download_requires_complete():
    eng, _ = make_engine()
    eng.register_rule("aa", 0, 2)
    feed(eng, 1, prefix=b"\xaa")                 # 仍在收集
    (s,) = eng.list_samples()
    with pytest.raises(ValueError):
        eng.sample_jsonl(s["id"])
    with pytest.raises(KeyError):
        eng.sample_jsonl("不存在")


def test_completed_sample_survives_window_overwrite():
    eng, _ = make_engine()
    feed(eng, 1)                                 # #1 普通包
    eng.register_rule("aa", 1, 1)
    feed(eng, 1, prefix=b"\xaa")                 # #2 命中，区间 #1..#3
    feed(eng, 1)                                 # #3 到齐 -> 收齐
    feed(eng, WINDOW_CAP * 2)                    # 接收窗口被完全覆盖多轮
    total = 3 + WINDOW_CAP * 2
    st = eng.status()
    assert st["received_total"] == total
    assert st["window"]["oldest"] == total - WINDOW_CAP + 1  # 原样本包早已滚出
    (s,) = eng.list_samples()
    lines = eng.sample_jsonl(s["id"]).splitlines()
    assert len(lines) == 3                       # 收齐样本仍可完整下载
    assert json.loads(lines[0])["seq"] == 1


# ---------- 真实 UDP 接收线程 ----------

def test_udp_receiver_numbers_real_packets():
    eng, _ = make_engine()
    receiver = UdpReceiver(eng, "127.0.0.1", 0)  # 临时端口
    receiver.start()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(5):
            s.sendto(b"\xde\xad\xbe\xef" + bytes([i]), ("127.0.0.1", receiver.port))
        deadline = time.monotonic() + 5
        while eng.status()["received_total"] < 5 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert eng.status()["received_total"] == 5
        pkts = eng.recent_packets(5)
        assert [p["seq"] for p in pkts] == [5, 4, 3, 2, 1]
        assert pkts[0]["src"].startswith("127.0.0.1:")
    finally:
        receiver.stop()
        receiver.join(timeout=2)


# ---------- 网页接口端到端 ----------

@pytest.fixture()
def client():
    eng, _ = make_engine()
    app = create_app(eng)
    receiver = UdpReceiver(eng, "127.0.0.1", 0)
    receiver.start()
    app.udp_listen = (receiver.host, receiver.port)
    app.testing = True
    with app.test_client() as c:
        yield c, eng
    receiver.stop()
    receiver.join(timeout=2)


def test_http_register_and_validation(client):
    c, _ = client
    r = c.post("/api/rules", json={"prefix_hex": "deadbeef", "before": 2, "after": 2})
    assert r.status_code == 201 and r.get_json()["state"] == "ARMED"
    r = c.post("/api/rules", json={"prefix_hex": "xx", "before": 0, "after": 0})
    assert r.status_code == 400
    r = c.post("/api/rules", json={"prefix_hex": "aa", "before": 200, "after": 0})
    assert r.status_code == 400


def test_http_demo_triggers_sample_and_download(client):
    c, eng = client
    c.post("/api/rules", json={"prefix_hex": "deadbeef", "before": 2, "after": 2})
    r = c.post("/api/demo", json={"count": 12, "interval_ms": 1})
    assert r.status_code == 202
    # 等演示包到齐、样本收齐
    deadline = time.monotonic() + 5
    sample = None
    while time.monotonic() < deadline:
        samples = c.get("/api/samples").get_json()
        if samples and samples[0]["state"] == "COMPLETE":
            sample = samples[0]
            break
        time.sleep(0.05)
    assert sample is not None, "演示未在时限内触发并收齐样本"
    assert sample["total"] == 5
    # 下载 JSON Lines
    r = c.get(f"/api/samples/{sample['id']}/download")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/x-ndjson")
    lines = [json.loads(x) for x in r.get_data(as_text=True).splitlines()]
    assert len(lines) == 5
    assert [x["seq"] for x in lines] == list(range(sample["start_seq"], sample["end_seq"] + 1))
    payloads = [base64.b64decode(x["payload_b64"]) for x in lines]
    assert payloads[2].startswith(bytes.fromhex("deadbeef"))  # 命中包居中
    # 状态与窗口
    st = c.get("/api/status").get_json()
    assert st["slots"]["used"] == 5
    assert st["window"]["size"] == 12


def test_http_discard_and_errors(client):
    c, eng = client
    c.post("/api/rules", json={"prefix_hex": "aa", "before": 0, "after": 0})
    eng.on_packet(b"\xaa", "127.0.0.1:1")        # 直接喂包触发
    (sample,) = c.get("/api/samples").get_json()
    assert sample["state"] == "COMPLETE"
    r = c.delete(f"/api/samples/{sample['id']}")
    assert r.status_code == 200
    assert c.get("/api/status").get_json()["slots"]["used"] == 0
    r = c.delete(f"/api/samples/{sample['id']}")
    assert r.status_code == 409                  # 已丢弃
    r = c.get(f"/api/samples/{sample['id']}/download")
    assert r.status_code == 409                  # 丢弃后不可下载
    assert c.delete("/api/samples/不存在").status_code == 404
    assert c.delete("/api/rules/不存在").status_code == 404
