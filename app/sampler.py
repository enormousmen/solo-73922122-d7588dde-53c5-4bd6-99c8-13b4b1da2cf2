"""UDP 遥测报文特征留样引擎。

值班员在诊断页登记"十六进制载荷前缀 + 前后包数"。联调程序向本机独立
UDP 端口发包，引擎给实收包逐一编号（滚动窗口只保留最近 128 包，照常覆盖）。
登记后首个载荷以该前缀开头的包触发留样，样本 = 命中包及其紧邻的前后各
若干包（编号区间 [命中-前, 命中+后]）。

约定（与网页/接口行为一致）：

  - 触发时为完整区间预留名额，区间里还没到的包也立即占额；
    * 前段不足：需要的更早包已滚出接收窗口（或尚不存在）-> 本次触发报失败；
    * 名额超额：全部样本合计预留编号超过 128 -> 本次触发报失败；
  - 重叠编号只占一个名额、共用一份载荷（按编号存一份，引用计数）；
  - 同包命中多条规则时按登记顺序受理，每条规则只触发一次；
  - 触发后 5 秒没收齐 -> 作废；网页也可丢弃指定样本；
    作废/丢弃都只归还该样本独占的名额（仍被其他样本占用的编号保留）；
  - 收齐的样本可下载 JSON Lines：按收包顺序（编号升序）输出
    编号、源地址和 Base64 载荷。
"""
from __future__ import annotations

import base64
import json
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass

WINDOW_CAP = 128         # 滚动接收窗口容量（包）
SLOT_BUDGET = 128        # 全部样本合计可预留的编号上限（含还没到的包）
COLLECT_TIMEOUT_S = 5.0  # 触发后收齐时限（秒）
MAX_PREFIX_BYTES = 64    # 特征前缀最大字节数

# 规则状态
RULE_ARMED = "ARMED"            # 已登记，等待首个匹配包
RULE_TRIGGERED = "TRIGGERED"    # 已触发并受理（样本可能仍在收集）
RULE_FAILED = "FAILED"          # 已触发但受理失败（前段不足 / 名额超额）
RULE_CANCELLED = "CANCELLED"    # 尚未匹配即被网页撤销

# 样本状态
SAMPLE_COLLECTING = "COLLECTING"  # 已预留名额，等待后续包到齐
SAMPLE_COMPLETE = "COMPLETE"      # 已收齐，可下载
SAMPLE_FAILED = "FAILED"          # 触发即失败，未占名额
SAMPLE_EXPIRED = "EXPIRED"        # 5 秒未收齐，已作废
SAMPLE_DISCARDED = "DISCARDED"    # 网页手动丢弃


def _wall() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{int((t % 1) * 1000):03d}"


def parse_prefix(text) -> bytes:
    """把网页登记的十六进制前缀解析成字节串（允许空白分隔、大小写不限）。"""
    if text is None:
        raise ValueError("前缀不能为空")
    s = "".join(str(text).split())
    if not s:
        raise ValueError("前缀不能为空")
    if len(s) % 2:
        raise ValueError("十六进制前缀长度必须为偶数")
    try:
        raw = bytes.fromhex(s)
    except ValueError as e:
        raise ValueError(f"前缀不是合法十六进制: {e}") from e
    if not (1 <= len(raw) <= MAX_PREFIX_BYTES):
        raise ValueError(f"前缀长度须在 1..{MAX_PREFIX_BYTES} 字节之间")
    return raw


def _as_count(v, name: str) -> int:
    if isinstance(v, bool) or isinstance(v, float) and not float(v).is_integer():
        raise ValueError(f"{name} 须为整数")
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name} 须为整数") from None


@dataclass
class Packet:
    seq: int          # 实收编号（从 1 起，按到达顺序）
    src: str          # 源地址 "ip:port"
    data: bytes       # 载荷
    ts: float         # 到达时刻（monotonic）


@dataclass
class Rule:
    id: str
    prefix_hex: str
    prefix: bytes
    before: int       # 命中包之前要留的包数
    after: int        # 命中包之后要留的包数
    created_at: str
    state: str = RULE_ARMED
    sample_id: str | None = None
    error: str | None = None


@dataclass
class Sample:
    id: str
    rule_id: str
    prefix_hex: str
    hit_seq: int
    start_seq: int    # 区间起点 = 命中编号 - 前包数
    end_seq: int      # 区间终点 = 命中编号 + 后包数
    created_at: str
    created_mono: float
    deadline_mono: float
    state: str = SAMPLE_COLLECTING
    collected: int = 0
    completed_at: str | None = None
    finished_at: str | None = None
    error: str | None = None

    @property
    def total(self) -> int:
        return self.end_seq - self.start_seq + 1


class SamplerEngine:
    """留样引擎：编号、滚动窗口、规则受理、名额账本、样本生命周期。

    所有状态都由同一把锁保护，接收线程 / 清扫线程 / HTTP 线程可并发调用。
    now_fn 可注入假时钟便于测试。
    """

    def __init__(self, now_fn=time.monotonic):
        self._now = now_fn
        self._lock = threading.RLock()
        self._next_seq = 1
        self._window: deque[Packet] = deque(maxlen=WINDOW_CAP)
        self._rules: dict[str, Rule] = {}          # 插入序即登记顺序
        self._samples: dict[str, Sample] = {}
        self._slot_refs: dict[int, set[str]] = {}  # 编号 -> 占用它的样本 id 集
        self._payloads: dict[int, Packet] = {}     # 编号 -> 留样载荷（被预留才保存）

    # ---------------- 接收 ----------------

    def on_packet(self, data: bytes, src: str) -> int:
        """实收一个 UDP 包：编号、入窗、兑现预留、按登记顺序受理命中的规则。"""
        with self._lock:
            self.expire_due()  # 先结算到点样本：超过收齐时限的包不计入
            seq = self._next_seq
            self._next_seq += 1
            pkt = Packet(seq=seq, src=src, data=bytes(data), ts=self._now())
            self._window.append(pkt)  # 滚动窗口照常覆盖最旧的包

            # 该编号若已被在先样本预留：落留样存储（多样本共用同一份载荷）
            if seq in self._slot_refs:
                self._payloads[seq] = pkt
                for sid in tuple(self._slot_refs[seq]):
                    sample = self._samples[sid]
                    if sample.state == SAMPLE_COLLECTING:
                        sample.collected += 1
                        self._maybe_complete(sample)

            # 同包命中多条规则时按登记顺序受理；每条规则只触发一次
            for rule in self._rules.values():
                if rule.state == RULE_ARMED and pkt.data.startswith(rule.prefix):
                    self._trigger(rule, pkt)
            return seq

    # ---------------- 规则 ----------------

    def register_rule(self, prefix_hex, before, after) -> Rule:
        prefix = parse_prefix(prefix_hex)
        before = _as_count(before, "前包数")
        after = _as_count(after, "后包数")
        if not (0 <= before < SLOT_BUDGET):
            raise ValueError(f"前包数须在 0..{SLOT_BUDGET - 1} 之间")
        if not (0 <= after < SLOT_BUDGET):
            raise ValueError(f"后包数须在 0..{SLOT_BUDGET - 1} 之间")
        if before + 1 + after > SLOT_BUDGET:
            raise ValueError(f"前+命中+后合计不能超过 {SLOT_BUDGET} 包")
        with self._lock:
            rule = Rule(
                id=uuid.uuid4().hex[:8],
                prefix_hex=prefix.hex(),
                prefix=prefix,
                before=before,
                after=after,
                created_at=_wall(),
            )
            self._rules[rule.id] = rule
            return rule

    def cancel_rule(self, rule_id: str) -> Rule:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None:
                raise KeyError(rule_id)
            if rule.state != RULE_ARMED:
                raise ValueError(f"规则已{rule.state}，不能撤销")
            rule.state = RULE_CANCELLED
            return rule

    # ---------------- 触发与名额 ----------------

    def _trigger(self, rule: Rule, pkt: Packet) -> None:
        """命中包到达：为完整区间 [命中-前, 命中+后] 预留名额并建样本。"""
        hit = pkt.seq
        start, end = hit - rule.before, hit + rule.after
        now = self._now()
        sample = Sample(
            id=uuid.uuid4().hex[:8], rule_id=rule.id, prefix_hex=rule.prefix_hex,
            hit_seq=hit, start_seq=start, end_seq=end,
            created_at=_wall(), created_mono=now,
            deadline_mono=now + COLLECT_TIMEOUT_S,
        )
        self._samples[sample.id] = sample
        rule.sample_id = sample.id

        # 前段不足：需要的更早编号已滚出接收窗口（或尚不存在）
        oldest = self._window[0].seq
        if start < oldest:
            self._fail_trigger(rule, sample,
                               f"前段不足：需要编号 {start}..{hit - 1} 共 {rule.before} 包，"
                               f"接收窗口现存 {oldest}..{hit}")
            return

        # 名额超额：合计预留（含还没到的包）不得超预算；重叠编号不重复占额
        new_slots = [s for s in range(start, end + 1) if s not in self._slot_refs]
        if len(self._slot_refs) + len(new_slots) > SLOT_BUDGET:
            self._fail_trigger(rule, sample,
                               f"名额超额：本样本需新增 {len(new_slots)} 个编号，"
                               f"当前已预留 {len(self._slot_refs)}/{SLOT_BUDGET}")
            return

        # 受理：预留完整区间；窗口内已到的包（前段+命中包）立即拷贝进留样存储
        for s in range(start, end + 1):
            self._slot_refs.setdefault(s, set()).add(sample.id)
        for p in self._window:
            if start <= p.seq <= hit:
                self._payloads[p.seq] = p
                sample.collected += 1
        rule.state = RULE_TRIGGERED
        self._maybe_complete(sample)  # 后包数为 0 时立即收齐

    def _fail_trigger(self, rule: Rule, sample: Sample, error: str) -> None:
        sample.state = SAMPLE_FAILED
        sample.error = error
        sample.finished_at = _wall()
        rule.state = RULE_FAILED
        rule.error = error

    def _maybe_complete(self, sample: Sample) -> None:
        if sample.state == SAMPLE_COLLECTING and sample.collected >= sample.total:
            sample.state = SAMPLE_COMPLETE
            sample.completed_at = _wall()

    # ---------------- 样本生命周期 ----------------

    def expire_due(self) -> int:
        """把超过收齐时限仍未收齐的样本作废，返回本次作废数。"""
        with self._lock:
            now = self._now()
            n = 0
            for sample in self._samples.values():
                if sample.state == SAMPLE_COLLECTING and now >= sample.deadline_mono:
                    sample.state = SAMPLE_EXPIRED
                    sample.finished_at = _wall()
                    self._release(sample)
                    n += 1
            return n

    def discard_sample(self, sample_id: str) -> Sample:
        """网页丢弃指定样本（收集中或已收齐均可）。"""
        with self._lock:
            sample = self._samples.get(sample_id)
            if sample is None:
                raise KeyError(sample_id)
            if sample.state not in (SAMPLE_COLLECTING, SAMPLE_COMPLETE):
                raise ValueError(f"样本已是 {sample.state} 状态，无需丢弃")
            sample.state = SAMPLE_DISCARDED
            sample.finished_at = _wall()
            self._release(sample)
            return sample

    def _release(self, sample: Sample) -> None:
        """归还名额：只释放该样本独占的编号；仍被其他样本占用的编号保留。"""
        for s in range(sample.start_seq, sample.end_seq + 1):
            refs = self._slot_refs.get(s)
            if not refs:
                continue
            refs.discard(sample.id)
            if not refs:  # 没有任何样本再占用 -> 才真正归还名额并丢弃载荷
                del self._slot_refs[s]
                self._payloads.pop(s, None)

    # ---------------- 查询与导出 ----------------

    def status(self) -> dict:
        with self._lock:
            self.expire_due()
            states = {}
            for r in self._rules.values():
                states[r.state] = states.get(r.state, 0) + 1
            sstates = {}
            for s in self._samples.values():
                sstates[s.state] = sstates.get(s.state, 0) + 1
            return {
                "received_total": self._next_seq - 1,
                "next_seq": self._next_seq,
                "window": {
                    "cap": WINDOW_CAP,
                    "size": len(self._window),
                    "oldest": self._window[0].seq if self._window else None,
                    "newest": self._window[-1].seq if self._window else None,
                },
                "slots": {"budget": SLOT_BUDGET, "used": len(self._slot_refs)},
                "rules": states,
                "samples": sstates,
                "collect_timeout_s": COLLECT_TIMEOUT_S,
            }

    def list_rules(self) -> list[dict]:
        with self._lock:
            self.expire_due()
            return [self._rule_dict(r) for r in self._rules.values()]

    def list_samples(self) -> list[dict]:
        with self._lock:
            self.expire_due()
            return [self._sample_dict(s) for s in self._samples.values()]

    def recent_packets(self, limit: int = 30) -> list[dict]:
        with self._lock:
            pkts = list(self._window)[-limit:][::-1]  # 新的在前
            return [{
                "seq": p.seq,
                "src": p.src,
                "len": len(p.data),
                "hex": p.data[:24].hex(),
                "truncated": len(p.data) > 24,
            } for p in pkts]

    def sample_jsonl(self, sample_id: str) -> str:
        """收齐样本的 JSON Lines：按收包顺序（编号升序）逐行输出。"""
        with self._lock:
            sample = self._samples.get(sample_id)
            if sample is None:
                raise KeyError(sample_id)
            if sample.state != SAMPLE_COMPLETE:
                raise ValueError(f"样本未收齐（{sample.state}），不能下载")
            lines = []
            for s in range(sample.start_seq, sample.end_seq + 1):
                p = self._payloads[s]  # 收齐 => 区间内每个编号都有载荷
                lines.append(json.dumps({
                    "seq": p.seq,
                    "src": p.src,
                    "payload_b64": base64.b64encode(p.data).decode("ascii"),
                }, ensure_ascii=False))
            return "\n".join(lines) + "\n"

    # ---------------- 内部展示 ----------------

    @staticmethod
    def _rule_dict(r: Rule) -> dict:
        return {
            "id": r.id,
            "prefix_hex": r.prefix_hex,
            "before": r.before,
            "after": r.after,
            "state": r.state,
            "sample_id": r.sample_id,
            "error": r.error,
            "created_at": r.created_at,
        }

    def _sample_dict(self, s: Sample) -> dict:
        remaining_ms = None
        if s.state == SAMPLE_COLLECTING:
            remaining_ms = max(0, int((s.deadline_mono - self._now()) * 1000))
        return {
            "id": s.id,
            "rule_id": s.rule_id,
            "prefix_hex": s.prefix_hex,
            "hit_seq": s.hit_seq,
            "start_seq": s.start_seq,
            "end_seq": s.end_seq,
            "total": s.total,
            "collected": s.collected,
            "state": s.state,
            "created_at": s.created_at,
            "completed_at": s.completed_at,
            "finished_at": s.finished_at,
            "remaining_ms": remaining_ms,
            "error": s.error,
            "downloadable": s.state == SAMPLE_COMPLETE,
        }
