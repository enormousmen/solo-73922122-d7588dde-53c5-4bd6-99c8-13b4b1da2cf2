"""Flask 诊断网页：UDP 遥测报文特征自动留样。

- 独立线程在本机 UDP 端口（默认 9999）监听实收包并逐一编号，
  滚动窗口保留最近 128 包；
- 网页登记"十六进制载荷前缀 + 前后包数"，登记后首个匹配包触发留样，
  样本 = 命中包及其紧邻的前后包；
- 触发后 5 秒没收齐即作废，网页也可丢弃指定样本；
- 收齐的样本可下载 JSON Lines（编号、源地址、Base64 载荷）；
- 网页可触发本机发包演示（含 DEADBEEF 开头的异常帧）。
"""
from __future__ import annotations

import os
import socket
import struct
import threading
import time

from flask import Flask, Response, jsonify, render_template, request

from sampler import (
    COLLECT_TIMEOUT_S,
    SLOT_BUDGET,
    WINDOW_CAP,
    SamplerEngine,
)

UDP_HOST = os.environ.get("UDP_HOST", "0.0.0.0")
UDP_PORT = int(os.environ.get("UDP_PORT", "9999"))
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))

DEMO_ANOMALY_PREFIX = "deadbeef"  # 演示报文中"异常帧"的载荷前缀


class UdpReceiver(threading.Thread):
    """本机 UDP 端口接收线程：实收包交给引擎编号。"""

    def __init__(self, engine: SamplerEngine, host: str, port: int):
        super().__init__(name="udp-receiver", daemon=True)
        self.engine = engine
        self._stopped = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.settimeout(0.2)
        self.host, self.port = self.sock.getsockname()

    def run(self):
        while not self._stopped.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.engine.on_packet(data, f"{addr[0]}:{addr[1]}")

    def stop(self):
        self._stopped.set()
        self.sock.close()


class Sweeper(threading.Thread):
    """收齐时限清扫：到点把仍未收齐的样本作废。"""

    def __init__(self, engine: SamplerEngine, period: float = 0.2):
        super().__init__(name="sample-sweeper", daemon=True)
        self.engine = engine
        self.period = period
        self._stopped = threading.Event()

    def run(self):
        while not self._stopped.wait(self.period):
            self.engine.expire_due()

    def stop(self):
        self._stopped.set()


def send_demo_burst(port: int, count: int = 40, interval_ms: float = 20.0) -> None:
    """本机发包演示：普通遥测帧中夹两帧 DEADBEEF 开头的"异常"帧。"""
    anomaly_at = {count // 3, (2 * count) // 3}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for i in range(count):
            if i in anomaly_at:
                payload = (bytes.fromhex(DEMO_ANOMALY_PREFIX)
                           + struct.pack("!IH", i, 0xE001) + b"ANOMALY"
                           + bytes([i & 0xFF]) * 8)
            else:
                payload = (b"TLM1" + struct.pack("!IHH", i, 1000 + i, 7)
                           + bytes([i & 0xFF]) * 16)
            s.sendto(payload, ("127.0.0.1", port))
            if interval_ms:
                time.sleep(interval_ms / 1000)
    finally:
        s.close()


def create_app(engine: SamplerEngine | None = None) -> Flask:
    app = Flask(__name__)
    app.engine = engine or SamplerEngine()  # type: ignore[attr-defined]
    app.udp_listen = None  # type: ignore[attr-defined]  # (host, port)，接收线程启动后填入

    def eng() -> SamplerEngine:
        return app.engine  # type: ignore[attr-defined]

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            window_cap=WINDOW_CAP,
            slot_budget=SLOT_BUDGET,
            collect_timeout_s=COLLECT_TIMEOUT_S,
            demo_prefix=DEMO_ANOMALY_PREFIX,
        )

    @app.get("/api/status")
    def status():
        st = eng().status()
        st["listen"] = app.udp_listen  # type: ignore[attr-defined]
        return jsonify(st)

    @app.get("/api/packets")
    def packets():
        try:
            limit = min(max(int(request.args.get("limit", 30)), 1), WINDOW_CAP)
        except (TypeError, ValueError):
            return jsonify({"error": "limit 须为整数"}), 400
        return jsonify(eng().recent_packets(limit))

    @app.post("/api/rules")
    def register_rule():
        data = request.get_json(silent=True) or {}
        try:
            rule = eng().register_rule(
                data.get("prefix_hex"), data.get("before", 0), data.get("after", 0))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify(eng()._rule_dict(rule)), 201

    @app.get("/api/rules")
    def list_rules():
        return jsonify(eng().list_rules())

    @app.delete("/api/rules/<rid>")
    def cancel_rule(rid):
        try:
            rule = eng().cancel_rule(rid)
        except KeyError:
            return jsonify({"error": "规则不存在"}), 404
        except ValueError as e:
            return jsonify({"error": str(e)}), 409
        return jsonify(eng()._rule_dict(rule))

    @app.get("/api/samples")
    def list_samples():
        return jsonify(eng().list_samples())

    @app.delete("/api/samples/<sid>")
    def discard_sample(sid):
        try:
            eng().discard_sample(sid)
        except KeyError:
            return jsonify({"error": "样本不存在"}), 404
        except ValueError as e:
            return jsonify({"error": str(e)}), 409
        return jsonify({"discarded": sid})

    @app.get("/api/samples/<sid>/download")
    def download_sample(sid):
        try:
            body = eng().sample_jsonl(sid)
        except KeyError:
            return jsonify({"error": "样本不存在"}), 404
        except ValueError as e:
            return jsonify({"error": str(e)}), 409
        return Response(
            body,
            mimetype="application/x-ndjson; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="sample-{sid}.jsonl"'},
        )

    @app.post("/api/demo")
    def demo():
        listen = app.udp_listen  # type: ignore[attr-defined]
        if not listen:
            return jsonify({"error": "UDP 接收线程未启动"}), 503
        data = request.get_json(silent=True) or {}
        try:
            count = int(data.get("count", 40))
            interval_ms = float(data.get("interval_ms", 20))
        except (TypeError, ValueError):
            return jsonify({"error": "count / interval_ms 格式错误"}), 400
        if not (1 <= count <= 500) or not (0 <= interval_ms <= 1000):
            return jsonify({"error": "count 须在 1..500，interval_ms 须在 0..1000"}), 400
        threading.Thread(
            target=send_demo_burst, args=(listen[1], count, interval_ms),
            name="demo-burst", daemon=True).start()
        return jsonify({
            "sent": count,
            "to": f"127.0.0.1:{listen[1]}",
            "anomaly_prefix": DEMO_ANOMALY_PREFIX,
        }), 202

    return app


app = create_app()


def main():
    receiver = UdpReceiver(app.engine, UDP_HOST, UDP_PORT)  # type: ignore[attr-defined]
    receiver.start()
    app.udp_listen = (receiver.host, receiver.port)  # type: ignore[attr-defined]
    Sweeper(app.engine).start()  # type: ignore[attr-defined]
    # threaded=True：接收/清扫在各自线程里跑，HTTP 请求互不阻塞
    app.run(host="0.0.0.0", port=HTTP_PORT, threaded=True)


if __name__ == "__main__":
    main()
