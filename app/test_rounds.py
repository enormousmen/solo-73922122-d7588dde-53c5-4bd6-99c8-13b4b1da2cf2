"""诊断引擎的单元测试与关键场景集成测试。"""
import time

import pytest

from rounds import Round, RoundConfig, RoundManager, make_verdict, parse_skip


# ---------- 纯逻辑 ----------

def test_parse_skip_mixed():
    assert parse_skip("10, 20,30-33") == {10, 20, 30, 31, 32, 33}
    assert parse_skip("") == set()
    assert parse_skip(None) == set()
    assert parse_skip([1, 2, 3]) == {1, 2, 3}
    assert parse_skip("5-3") == {3, 4, 5}  # 区间写反也能容错


def test_verdict_rules():
    assert "溢出" in make_verdict(5, 10)          # 计数>0 -> 本机队列溢出
    assert "未发现本机" in make_verdict(0, 10)     # 缺号但计数为0
    assert "完好" in make_verdict(0, 0)            # 无缺号无丢包
    assert "证据不足" in make_verdict(None, 10)    # 计数取不到


def test_config_validation():
    with pytest.raises(ValueError):
        RoundConfig.from_dict({"total": 0})
    with pytest.raises(ValueError):
        RoundConfig.from_dict({"payload": 99999})
    cfg = RoundConfig.from_dict({"total": 100, "skip": "5,6,9999"})
    assert cfg.skip == {5, 6}  # 超出编号空间的跳号被丢弃


# ---------- 集成（真实 UDP 收发，仅 Linux 语义下断言内核计数） ----------

def wait_done(r: Round, timeout=20.0) -> Round:
    deadline = time.monotonic() + timeout
    while r.state not in ("DONE", "ERROR") and time.monotonic() < deadline:
        time.sleep(0.05)
    assert r.state == "DONE", f"轮次未收尾: state={r.state} error={r.error}"
    return r


def test_clean_round_no_missing_no_drops():
    # 大接收缓冲：队列足以容纳整轮报文，不应出现本机溢出
    r = Round(RoundConfig(total=500, payload=256, grace_ms=500,
                          rcvbuf=1048576)).start()
    wait_done(r)
    assert r.missing_count == 0
    assert r.drops == 0
    assert "完好" in r.verdict


def test_sender_skip_gaps_without_local_overflow():
    skip = parse_skip("100-109")
    r = Round(RoundConfig(total=1000, payload=256, grace_ms=500,
                          rcvbuf=1048576, skip=skip)).start()
    wait_done(r)
    assert r.missing_count == len(skip)     # 缺号正好是跳号
    assert r.drops == 0                     # 本机无溢出
    assert "未发现本机" in r.verdict


def test_receiver_pause_causes_local_overflow():
    # 小接收缓冲 + 接收暂缓 + 大包快发：必然积压迫使内核丢包
    r = Round(RoundConfig(total=4000, payload=1000, rcvbuf=4096,
                          recv_pause_ms=600, grace_ms=500)).start()
    wait_done(r)
    assert r.drops is not None and r.drops > 0
    assert r.missing_count > 0
    assert "溢出" in r.verdict


def test_two_concurrent_rounds_counted_separately():
    mgr = RoundManager()
    a = mgr.start(RoundConfig(total=4000, payload=1000, rcvbuf=4096,
                              recv_pause_ms=600, grace_ms=500))   # 溢出轮
    b = mgr.start(RoundConfig(total=1000, payload=256, grace_ms=500,
                              rcvbuf=1048576,
                              skip=parse_skip("10-19")))          # 跳号轮
    wait_done(a)
    wait_done(b)
    assert a.port != b.port               # 各自独立套接字
    assert a.drops > 0                    # 溢出轮：计数>0
    assert b.drops == 0                   # 跳号轮：计数=0
    assert b.missing_count == 10
    assert "溢出" in a.verdict and "未发现本机" in b.verdict


def test_unreadable_counter_means_insufficient_evidence(monkeypatch):
    def boom(self):
        raise OSError("mocked: cannot read")
    monkeypatch.setattr(Round, "_read_kernel_drops", boom)
    r = Round(RoundConfig(total=200, payload=128, grace_ms=300)).start()
    wait_done(r)
    assert r.drops is None
    assert "证据不足" in r.verdict
