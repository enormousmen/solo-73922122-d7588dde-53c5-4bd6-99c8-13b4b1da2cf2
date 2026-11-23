"""Flask 诊断网页：UDP 遥测缺号与本机接收队列溢出判定。

每轮独立接收套接字；收尾时从 /proc/net/udp 的 drops 列读取该轮套接字的
内核丢包计数（sk_drops），与建套接字时的基线相减得到本轮计数。
"""
from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from rounds import RoundConfig, RoundManager, parse_skip

app = Flask(__name__)
manager = RoundManager()


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/rounds")
def start_round():
    data = request.get_json(silent=True) or {}
    try:
        cfg = RoundConfig.from_dict(data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    r = manager.start(cfg)
    return jsonify(r.to_dict()), 202


@app.get("/api/rounds")
def list_rounds():
    return jsonify([r.to_dict() for r in manager.list()])


@app.get("/api/rounds/<rid>")
def get_round(rid):
    r = manager.get(rid)
    if r is None:
        return jsonify({"error": "round not found"}), 404
    return jsonify(r.to_dict(detail=True))


@app.delete("/api/rounds")
def clear_rounds():
    return jsonify({"cleared": manager.clear_finished()})


@app.post("/api/demo")
def demo():
    """一键并发演示：两轮同时开跑，分别统计。

    - 暂缓轮：接收端暂缓收包 + 小接收缓冲 -> 本机队列积压溢出（计数 > 0）；
    - 跳号轮：发送端主动跳过一段编号     -> 有缺号但本机无溢出（计数 = 0）。
    """
    pause_round = manager.start(RoundConfig(
        total=4000, payload=1000, rcvbuf=4096,
        recv_pause_ms=600, grace_ms=800,
    ))
    skip_round = manager.start(RoundConfig(
        total=2000, payload=256, rcvbuf=1048576,
        skip=parse_skip("500-549"), grace_ms=800,
    ))
    return jsonify({
        "pause_round": pause_round.id,
        "skip_round": skip_round.id,
    }), 202


if __name__ == "__main__":
    # threaded=True：诊断轮在各自线程里跑，HTTP 请求互不阻塞
    app.run(host="0.0.0.0", port=8080, threaded=True)
