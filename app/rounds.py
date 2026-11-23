"""UDP 遥测缺号诊断引擎。

每"一轮"使用一个独立的 UDP 接收套接字，因此多轮并发时统计天然互相独立：

  1. 接收套接字绑定 127.0.0.1 的临时端口，并按需调小 SO_RCVBUF；
  2. 本地发送线程按 0..total-1 的编号空间发包（可按配置跳号，模拟对端/链路丢包）；
  3. 接收线程收包并记录到达的编号（可按配置暂缓启动或每包延时，模拟业务积压）；
  4. 发送结束后留出 grace 收包时间，到期统计缺号；
  5. 读取"本轮接收套接字"的内核丢包计数（sk_drops：报文到达时本机接收队列
     已满而被丢弃的次数），按 建套接字基线 -> 收尾终值 求本轮增量。

计数来源说明：标准接口是 getsockopt(SO_RXQ_OVFL)，但实测目标内核
（Linux 7.0.0）该路径只返回开关状态而非计数值（开=1/关=0，灌包产生 2997
个丢包读数不变）；同一计数经 /proc/net/udp 的 drops 列暴露且随丢包递增，
故本工具以 /proc/net/udp 的 drops 列为准（同为内核 sk_drops，按套接字计）。

判定规则：
  - 计数 > 0            -> 本机 UDP 接收队列溢出；
  - 计数 == 0 但有缺号  -> 未发现本机溢出（缺号发生在对端或链路）；
  - 计数 == 0 且无缺号  -> 链路完好；
  - 计数读不到          -> 证据不足。
"""
from __future__ import annotations

import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field

MAGIC = b"TGD1"
_HEADER = struct.Struct("!4sII")  # magic, round_token, seq

MAX_TOTAL = 200_000      # 单轮编号空间上限
MAX_PAYLOAD = 1400       # 单包字节数上限（含头部）
MISSING_PREVIEW = 500    # 结果中保存的缺号明细条数上限

PROC_NET_UDP = "/proc/net/udp"


def read_proc_udp_drops(port: int, proc_path: str = PROC_NET_UDP) -> int:
    """读取指定本地端口 UDP 套接字的内核丢包计数（/proc/net/udp 的 drops 列）。

    该列即内核的 sk_drops：本机接收队列溢出导致丢包的累计次数（按套接字计）。
    读不到（非 Linux、无此列、找不到该套接字）时抛 OSError。
    """
    target = f":{port:04X}"
    with open(proc_path) as f:
        header = next(f)
        if "drops" not in header:
            raise OSError(f"{proc_path} 缺少 drops 列")
        for line in f:
            parts = line.split()
            if len(parts) >= 2 and parts[1].endswith(target):
                try:
                    return int(parts[-1])
                except ValueError as e:
                    raise OSError(f"无法解析 drops 列: {line.strip()!r}") from e
    raise OSError(f"{proc_path} 中找不到端口 {port} 的套接字")


def parse_skip(text) -> set[int]:
    """把 "10,20,30-40" 这样的字符串（或整数列表）解析成跳号集合。"""
    if text is None or text == "":
        return set()
    if isinstance(text, (list, tuple)):
        return {int(x) for x in text}
    out: set[int] = set()
    for part in str(text).replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            if hi - lo + 1 > MAX_TOTAL:
                raise ValueError(f"跳号区间过大: {part}")
            out.update(range(lo, hi + 1))
        else:
            out.add(int(part))
    return out


def make_verdict(drops: int | None, missing_count: int) -> str:
    """根据内核丢包计数与缺号数给出值班员可读的结论。"""
    if drops is None:
        return "证据不足：无法读取本轮接收套接字的内核丢包计数"
    if drops > 0:
        return f"本机 UDP 接收队列溢出：内核丢包计数={drops}"
    if missing_count > 0:
        return "存在缺号，但内核丢包计数为 0：未发现本机接收队列溢出"
    return "无缺号，内核丢包计数为 0：链路完好"


@dataclass
class RoundConfig:
    total: int = 2000                # 编号空间 0..total-1
    payload: int = 512               # 每包字节数（含头部）
    send_interval_ms: float = 0.0    # 发送间隔（节流）
    recv_delay_ms: float = 0.0       # 每收一包的处理耗时（模拟业务处理慢）
    recv_pause_ms: float = 0.0       # 接收端启动后暂缓收包的时长（制造积压）
    grace_ms: int = 800              # 发完后的收尾收包时间
    rcvbuf: int = 1048576            # SO_RCVBUF 请求值（调小更容易演示溢出）
    skip: set = field(default_factory=set)  # 发送端主动跳过的编号

    @classmethod
    def from_dict(cls, d: dict) -> "RoundConfig":
        try:
            cfg = cls(
                total=int(d.get("total", 2000)),
                payload=int(d.get("payload", 512)),
                send_interval_ms=float(d.get("send_interval_ms", 0)),
                recv_delay_ms=float(d.get("recv_delay_ms", 0)),
                recv_pause_ms=float(d.get("recv_pause_ms", 0)),
                grace_ms=int(d.get("grace_ms", 800)),
                rcvbuf=int(d.get("rcvbuf", 1048576)),
                skip=parse_skip(d.get("skip")),
            )
        except (TypeError, ValueError) as e:
            raise ValueError(f"参数格式错误: {e}") from e
        if not (1 <= cfg.total <= MAX_TOTAL):
            raise ValueError(f"total 须在 1..{MAX_TOTAL} 之间")
        if not (_HEADER.size <= cfg.payload <= MAX_PAYLOAD):
            raise ValueError(f"payload 须在 {_HEADER.size}..{MAX_PAYLOAD} 之间")
        if not (0 <= cfg.send_interval_ms <= 1000):
            raise ValueError("send_interval_ms 须在 0..1000 之间")
        if not (0 <= cfg.recv_delay_ms <= 1000):
            raise ValueError("recv_delay_ms 须在 0..1000 之间")
        if not (0 <= cfg.recv_pause_ms <= 60_000):
            raise ValueError("recv_pause_ms 须在 0..60000 之间")
        if not (100 <= cfg.grace_ms <= 60_000):
            raise ValueError("grace_ms 须在 100..60000 之间")
        if not (512 <= cfg.rcvbuf <= 64 * 1024 * 1024):
            raise ValueError("rcvbuf 须在 512..67108864 之间")
        cfg.skip = {s for s in cfg.skip if 0 <= s < cfg.total}
        return cfg


class Round:
    """一轮诊断：独立套接字、独立线程、独立计数。"""

    def __init__(self, cfg: RoundConfig):
        self.id = uuid.uuid4().hex[:8]
        self.cfg = cfg
        self.token = uuid.uuid4().int & 0xFFFFFFFF  # 报文令牌，过滤串台报文
        self.state = "RUNNING"      # RUNNING -> DRAINING -> DONE / ERROR
        self.created_ts = time.time()
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.finished_at = None
        self.port = None
        self.rcvbuf_effective = None
        self.sent = 0
        self.send_errors = 0
        self.received = 0
        self.missing_count = None
        self.missing_preview: list[int] = []
        self.drops: int | None = None
        self.verdict: str | None = None
        self.error: str | None = None
        self._bitmap = bytearray(cfg.total)
        self._drops_baseline: int | None = None
        self._lock = threading.Lock()
        self._send_done = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "Round":
        self._thread = threading.Thread(
            target=self._run, name=f"round-{self.id}", daemon=True)
        self._thread.start()
        return self

    # ---------------- 内部实现 ----------------

    def _make_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.cfg.rcvbuf)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.2)
        self.port = sock.getsockname()[1]
        # 内核实际生效值（Linux 会翻倍且有下限），展示给值班员参考
        self.rcvbuf_effective = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        # 基线读数：本轮计数 = 收尾终值 - 基线（正常应为 0，防御性处理）
        try:
            self._drops_baseline = self._read_kernel_drops()
        except OSError as e:
            self._drops_baseline = None
            self.error = f"读取内核丢包计数基线失败: {e}"
        return sock

    def _run(self):
        try:
            sock = self._make_socket()
        except OSError as e:
            self.state = "ERROR"
            self.error = f"创建接收套接字失败: {e}"
            self.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            return
        sender = threading.Thread(
            target=self._send_loop, args=(self.port,),
            name=f"send-{self.id}", daemon=True)
        sender.start()
        if self.cfg.recv_pause_ms > 0:
            # 接收暂缓：发送已经开始，本机不取包，让接收队列积压直至溢出
            time.sleep(self.cfg.recv_pause_ms / 1000)
        try:
            self._recv_loop(sock)
        finally:
            self._finalize(sock)

    def _send_loop(self, port: int):
        cfg = self.cfg
        filler = b"\x55" * (cfg.payload - _HEADER.size)
        interval = cfg.send_interval_ms / 1000
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            addr = ("127.0.0.1", port)
            for seq in range(cfg.total):
                if seq in cfg.skip:
                    continue  # 发送端跳号：模拟对端/链路侧造成的缺号
                pkt = _HEADER.pack(MAGIC, self.token, seq) + filler
                try:
                    s.sendto(pkt, addr)
                    self.sent += 1
                except OSError:
                    self.send_errors += 1
                if interval:
                    time.sleep(interval)
        finally:
            s.close()
            self._send_done.set()

    def _recv_loop(self, sock: socket.socket):
        grace = self.cfg.grace_ms / 1000
        # 兜底时限：发送总时长 + 暂缓 + 收尾 + 余量，防止异常时永久占用
        hard_cap = (time.monotonic() + self.cfg.recv_pause_ms / 1000
                    + self.cfg.total * self.cfg.send_interval_ms / 1000
                    + grace + 30)
        deadline = None
        while time.monotonic() < hard_cap:
            if deadline is None and self._send_done.is_set():
                # 发完了：从此时起留出 grace 收包时间，到期收尾
                deadline = time.monotonic() + grace
                self.state = "DRAINING"
            if deadline is not None and time.monotonic() >= deadline:
                return
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self._record(data)
            if self.cfg.recv_delay_ms > 0:
                time.sleep(self.cfg.recv_delay_ms / 1000)
        self.error = "接收循环超出兜底时限，强制收尾"

    def _record(self, data: bytes):
        if len(data) < _HEADER.size:
            return
        magic, token, seq = _HEADER.unpack_from(data)
        if magic != MAGIC or token != self.token or seq >= self.cfg.total:
            return
        with self._lock:
            if not self._bitmap[seq]:
                self._bitmap[seq] = 1
                self.received += 1

    def _read_kernel_drops(self) -> int:
        """读取本轮接收套接字的内核丢包计数（/proc/net/udp 的 drops 列）。"""
        return read_proc_udp_drops(self.port)

    def _finalize(self, sock: socket.socket):
        try:
            final = self._read_kernel_drops()
        except OSError as e:
            final = None
            note = f"读取内核丢包计数失败: {e}"
            self.error = f"{self.error}; {note}" if self.error else note
        finally:
            sock.close()
        if final is not None and self._drops_baseline is not None:
            self.drops = max(0, final - self._drops_baseline)
        else:
            self.drops = None  # 取不到收尾计数 -> 证据不足
        missing = [i for i in range(self.cfg.total) if not self._bitmap[i]]
        self.missing_count = len(missing)
        self.missing_preview = missing[:MISSING_PREVIEW]
        self.verdict = make_verdict(self.drops, self.missing_count)
        self.state = "DONE"
        self.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")

    # ---------------- 输出 ----------------

    def to_dict(self, detail: bool = False) -> dict:
        d = {
            "id": self.id,
            "state": self.state,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "port": self.port,
            "rcvbuf_effective": self.rcvbuf_effective,
            "params": {
                "total": self.cfg.total,
                "payload": self.cfg.payload,
                "send_interval_ms": self.cfg.send_interval_ms,
                "recv_delay_ms": self.cfg.recv_delay_ms,
                "recv_pause_ms": self.cfg.recv_pause_ms,
                "grace_ms": self.cfg.grace_ms,
                "rcvbuf": self.cfg.rcvbuf,
                "skip_count": len(self.cfg.skip),
            },
            "sent": self.sent,
            "send_errors": self.send_errors,
            "received": self.received,
            "missing_count": self.missing_count,
            "drops": self.drops,
            "verdict": self.verdict,
            "error": self.error,
        }
        if detail:
            d["missing_preview"] = self.missing_preview
            d["skip_preview"] = sorted(self.cfg.skip)[:MISSING_PREVIEW]
        return d


class RoundManager:
    """管理并发进行的多轮诊断。"""

    def __init__(self):
        self._rounds: dict[str, Round] = {}
        self._lock = threading.Lock()

    def start(self, cfg: RoundConfig) -> Round:
        r = Round(cfg).start()
        with self._lock:
            self._rounds[r.id] = r
        return r

    def list(self) -> list[Round]:
        with self._lock:
            rounds = list(self._rounds.values())
        return sorted(rounds, key=lambda r: r.created_ts, reverse=True)

    def get(self, rid: str) -> Round | None:
        with self._lock:
            return self._rounds.get(rid)

    def clear_finished(self) -> int:
        with self._lock:
            done = [k for k, v in self._rounds.items()
                    if v.state in ("DONE", "ERROR")]
            for k in done:
                del self._rounds[k]
        return len(done)
