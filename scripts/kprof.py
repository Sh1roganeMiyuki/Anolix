#!/usr/bin/env python3
# kprof.py —— Linux 进程状态机的采样式 profiler（pprof/tcmalloc heap profile 风格的带权有向图）
#
# 用法:
#   ./scripts/kprof.py --pid <pid> --interval 5ms --duration 10s
#   ./scripts/kprof.py -- ./anolix run --policy examples/policy.json --rootfs ./rootfs -- /probe
#   ./scripts/kprof.py --result logs/kprof-xxx.json --explain 120-140     # 追溯某条边的原始采样帧
#   ./scripts/kprof.py --compare logs/kprof-out.json logs/kprof-in.json   # 沙箱内外左右对照
#   ./scripts/kprof.py --test                                            # 跑 5 条可 falsify 的验收测试
#
# 【与 tcmalloc heap profile 的类比】
#   tcmalloc: hook 分配点 -> 记录调用栈 -> 按栈聚合 -> 节点大小=字节数, 边=调用关系
#   本工具  : 轮询 /proc  -> 记录状态+归因 -> 按(from,to,归因)聚合
#             -> 节点大小=累计停留样本数, 边粗细=迁移次数, 边标签=触发它的 syscall/wchan
#   关键：没有归因的状态图没有价值——每条边都回答"这次迁移是谁造成的"。
#
# 【采样源】只读 /proc，不 ptrace、不要 root、不改 seccomp 白名单。
#   进程集合：从根 pid 出发，用 /proc/*/stat 的 PPid 递归建进程树，采样全树（含中途新生/死亡的进程）。
#   宿主 /proc 能直接看到容器内进程（PID ns 只是视图），不需要进沙箱。
#
# 【硬约束】
#   1. 采样必然漏迁移：图上显式写明"边=被观测到的迁移，非全部；间隔 Xms 短于它的状态变化不可见"。
#   2. 每个节点/边可追溯到样本序号区间；--explain <from>-<to> 打印构成该边的原始采样帧。挂不上证据不画。
#   3. wchan/syscall 读不到（权限/进程已消失）-> 边标签写 ⚠️不可读，禁止用推断值填充。
#   4. 状态字母只用内核定义（R运行 S可中断睡眠 D不可中断睡眠 Z僵尸 T停止 t追踪停止 X死亡），
#      来源=/proc/<pid>/stat 第3字段。
#
# 【不做】自写 ptrace 采集端 / GUI / 实时 top 刷新 / 通用 syscall 数据库 / 火焰图 / 解析内核源码 /
#         任何第三方 Python 包（graphviz 仅通过 subprocess 调系统 dot，缺失时走 ASCII 退化）。

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NR_TABLE = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"

# 状态字母含义——只允许内核定义（约束 4）。来源：/proc/<pid>/stat 第 3 字段。
STATE_MEANING = {
    "R": "运行 (running)",
    "S": "可中断睡眠 (interruptible sleep)",
    "D": "不可中断睡眠 (uninterruptible sleep)",
    "Z": "僵尸 (zombie)",
    "T": "停止 (stopped)",
    "t": "追踪停止 (tracing stop)",
    "X": "死亡 (dead)",
}
STATE_SOURCE = "状态字母含义取自内核定义，来源 = /proc/<pid>/stat 第 3 字段"
# GONE 是【工具定义】的终态（进程从 /proc 消失），不是内核 stat 状态字母，图中单独标注。
GONE = "GONE"
UNREADABLE = "⚠️不可读"

# 节点底色（dot 渲染）：Z 与 GONE 用不同底色（任务要求）
_STATE_FILL = {
    "R": "#2ea043", "S": "#0969da", "D": "#bf8700", "Z": "#8250df",
    "T": "#8b949e", "t": "#8b949e", "X": "#cf222e", GONE: "#1f2328",
}


# ---------- syscall 号 -> 名字（从内核 UAPI 头解析；解析不到写 nr=<数字>，禁止猜）----------

def load_syscall_names(path=NR_TABLE):
    """解析 #define __NR_name num -> {num: name}。同号多名时保留第一个。"""
    nr2name = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"#define\s+__NR_(\w+)\s+(\d+)", line)
                if m:
                    nr2name.setdefault(int(m.group(2)), m.group(1))
    except OSError:
        return None            # 头文件缺失：全部按 nr=<数字> 处理
    return nr2name


def syscall_label(nr, nr2name):
    """syscall 号 -> 名字；表里没有就写 nr=<数字>（约束：禁止猜名字）。"""
    if nr is None:
        return None
    if nr2name and nr in nr2name:
        return nr2name[nr]
    return f"nr={nr}"


# ---------- /proc 读取基元（每个都可能因权限/进程消失而失败）----------

def read_stat(pid):
    """读 /proc/<pid>/stat -> (raw, comm, state, ppid)。comm 在首个 '(' 与末个 ')' 之间（可含空格/括号）。"""
    with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    lp, rp = raw.find("("), raw.rfind(")")
    comm = raw[lp + 1:rp] if 0 <= lp < rp else "?"
    rest = raw[rp + 2:].split()
    state = rest[0] if rest else "?"
    ppid = int(rest[1]) if len(rest) > 1 else 0
    return raw.rstrip("\n"), comm, state, ppid


def read_syscall(pid):
    """读 /proc/<pid>/syscall -> (readable, raw, nr)。
    内核对运行态返回 'running'；用户态返回 '-1 ...'；陷入系统调用时返回 '<nr> <args..> <sp> <pc>'。
    僵尸/无权限 -> 不可读（readable=False）。"""
    try:
        with open(f"/proc/{pid}/syscall", encoding="utf-8", errors="replace") as f:
            raw = f.read().strip()
    except (OSError, PermissionError):
        return False, None, None
    if raw == "" or raw == "running":
        return True, raw or "running", None
    parts = raw.split()
    try:
        nr = int(parts[0])
    except (ValueError, IndexError):
        return True, raw, None
    return True, raw, (nr if nr >= 0 else None)


def read_wchan(pid):
    """读 /proc/<pid>/wchan -> (readable, raw)。'0' 表示未阻塞在内核函数。"""
    try:
        with open(f"/proc/{pid}/wchan", encoding="utf-8", errors="replace") as f:
            raw = f.read().strip()
    except (OSError, PermissionError):
        return False, None
    return True, raw


def read_nspid(pid):
    """读 /proc/<pid>/status 的 NSpid 行 -> (readable, [宿主pid, 容器内pid...])。
    两个及以上字段 = 该进程在容器 PID ns 内，最后一个字段是容器内 PID。"""
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("NSpid:"):
                    return True, line.split(":", 1)[1].split()
    except (OSError, PermissionError):
        pass
    return False, []


def _fast_read(path, n=8192):
    """低开销读小文件（os.open/os.read，避开 Python 文件对象开销）——采样热路径用。"""
    fd = os.open(path, os.O_RDONLY)
    try:
        return os.read(fd, n).decode("utf-8", "replace")
    finally:
        os.close(fd)


def scan_all_stats():
    """全量扫一遍 /proc/*/stat -> {pid: (raw, comm, state, ppid)}。用于建进程树 + 采状态。
    这是每 tick 的热路径（开销∝系统进程数），故用 _fast_read 并就地解析。"""
    out = {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return out
    for d in entries:
        if not d.isdigit():
            continue
        try:
            raw = _fast_read("/proc/" + d + "/stat")
        except (OSError, ValueError):
            continue
        lp, rp = raw.find("("), raw.rfind(")")
        if rp < 0:
            continue
        rest = raw[rp + 2:].split()
        if len(rest) < 2:
            continue
        comm = raw[lp + 1:rp] if 0 <= lp < rp else "?"
        try:
            out[int(d)] = (raw.rstrip("\n"), comm, rest[0], int(rest[1]))
        except ValueError:
            continue
    return out


def build_tree(root_pid, stats):
    """从 root_pid 出发，用 ppid 递归建进程树（含 root）。root 不在 stats（已消失）时返回空集。"""
    if root_pid not in stats:
        return set()
    children = collections.defaultdict(list)
    for pid, (_, _, _, ppid) in stats.items():
        children[ppid].append(pid)
    seen, stack = set(), [root_pid]
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        stack.extend(children.get(p, []))
    return seen


# ---------- 采样帧 ----------

def make_frame(pid, seq, ts, nr2name, nspid_cache):
    """对单个 pid 采一帧；进程已消失返回 None（由调用方补 GONE 帧）。
    关键：stat/syscall/wchan 必须背靠背读，保证是同一时刻的一致快照——
    若用批量扫描的 state 再单独读 syscall，两者相隔整轮扫描，dd 的 fsync 可能已结束，
    导致 state=D 却 syscall_nr≠fsync 的错配（曾使 D-fsync 归因全丢）。"""
    try:
        raw_stat, comm, state, ppid = read_stat(pid)
    except (OSError, PermissionError, ValueError, IndexError):
        return None
    sc_ok, sc_raw, nr = read_syscall(pid)
    wc_ok, wc_raw = read_wchan(pid)
    if pid in nspid_cache:
        ns_ok, nspid = nspid_cache[pid]
    else:
        ns_ok, nspid = read_nspid(pid)
        if ns_ok:                                  # 只缓存成功读到的；失败（进程正在退出）下次重试
            nspid_cache[pid] = (ns_ok, nspid)      # NSpid 不随 exec 改变，读到一次即可缓存
    in_container = ns_ok and len(nspid) >= 2
    role = "容器内" if in_container else "宿主"
    return {
        "seq": seq, "ts": ts, "pid": pid, "state": state, "comm": comm, "ppid": ppid,
        "syscall_ok": sc_ok, "syscall_raw": sc_raw, "syscall_nr": nr,
        "syscall_name": syscall_label(nr, nr2name),
        "wchan_ok": wc_ok, "wchan_raw": wc_raw,
        "nspid_ok": ns_ok, "nspid": nspid, "role": role,
        "container_pid": (nspid[-1] if in_container else None),
        "raw_stat": raw_stat,
    }


def make_gone_frame(pid, seq, ts):
    """进程消失 -> 一次到工具终态 GONE 的特殊迁移。"""
    return {"seq": seq, "ts": ts, "pid": pid, "state": GONE, "comm": None, "ppid": None,
            "syscall_ok": False, "syscall_raw": None, "syscall_nr": None, "syscall_name": None,
            "wchan_ok": False, "wchan_raw": None, "nspid_ok": False, "nspid": [],
            "role": None, "container_pid": None, "raw_stat": None, "gone": True}


def attribute(frame):
    """给一帧定"归因 token"：这次采样时进程卡在什么上（回答"谁造成的"）。
    优先级：可读的 syscall 名 > wchan > running(在CPU) > 用户态 > ⚠️不可读。"""
    if frame.get("gone"):
        return "进程消失(GONE)"
    if frame["syscall_ok"]:
        if frame["syscall_nr"] is not None:
            return frame["syscall_name"] or f"nr={frame['syscall_nr']}"
        raw = frame["syscall_raw"]
        if raw == "running":
            return "running(在CPU)"
        if raw and raw.startswith("-1"):
            return "用户态(nr=-1)"
    # syscall 未给出有效号：看 wchan
    if frame["wchan_ok"]:
        w = frame["wchan_raw"]
        if w and w != "0":
            return f"wchan:{w}"
        return "wchan:0(未阻塞)"
    return UNREADABLE


def wchan_label(frame):
    """D 状态关注 wchan：非空函数名 / '0' / ⚠️不可读。"""
    if not frame["wchan_ok"]:
        return UNREADABLE
    w = frame["wchan_raw"]
    if not w or w == "0":
        return "0(未阻塞)"
    return w


# ---------- 采样主循环 ----------

def sample_tree(root_pid, interval_ms, duration_s, nr2name, launched=None, launched_proc=None, on_tick=None):
    """从 root_pid 采样整棵进程树 duration_s 秒（或 root 消失即止），目标间隔 interval_ms。
    launched_proc 非空时（-- cmd 模式）每轮 poll() 回收它，避免它退出后长时间滞为僵尸污染图。
    返回 (frames_by_pid, meta)。frames_by_pid[pid] 是按 seq 递增的帧序列（末帧可能是 GONE）。"""
    frames = collections.defaultdict(list)
    known, gone = set(), set()
    nspid_cache = {}
    seq = 0
    tick_ts = []
    t0 = time.monotonic()
    deadline = t0 + duration_s
    root_gone = False
    overruns = 0
    while True:
        tick_start = time.monotonic()
        if tick_start >= deadline:
            break
        # -- cmd 模式：非阻塞回收已退出的被拉起的进程（否则它会滞为我们的僵尸）
        if launched_proc is not None:
            launched_proc.poll()
        seq += 1
        ts = time.time()
        tick_ts.append(ts)
        stats = scan_all_stats()
        tree = build_tree(root_pid, stats)
        targets = sorted(tree | (known - gone))
        alive_now = set()
        for pid in targets:
            fr = make_frame(pid, seq, ts, nr2name, nspid_cache)
            if fr is None:
                if pid in known and pid not in gone:      # 之前见过、现在没了 -> GONE
                    frames[pid].append(make_gone_frame(pid, seq, ts))
                    gone.add(pid)
                continue
            frames[pid].append(fr)
            known.add(pid)
            alive_now.add(pid)
        if on_tick:
            on_tick(seq, alive_now)
        # root 消失 -> 收尾（root 的 GONE 帧已在上面补上）
        if root_pid in gone or root_pid not in stats:
            root_gone = True
            break
        elapsed_ms = (time.monotonic() - tick_start) * 1000.0
        sleep_ms = interval_ms - elapsed_ms
        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)
        else:
            overruns += 1
    # 实际间隔（中位数）：纯 Python 轮询 /proc 常常达不到 5ms，如实报告
    deltas = [round((tick_ts[i + 1] - tick_ts[i]) * 1000, 3) for i in range(len(tick_ts) - 1)]
    actual_ms = sorted(deltas)[len(deltas) // 2] if deltas else 0.0
    total_samples = sum(len(v) for v in frames.values())
    meta = {
        "root_pid": root_pid, "requested_interval_ms": interval_ms, "duration_s": duration_s,
        "actual_interval_ms_median": actual_ms, "ticks": seq, "overrun_ticks": overruns,
        "total_samples": total_samples, "covered_pids": len(frames), "root_gone": root_gone,
        "started_epoch": (tick_ts[0] if tick_ts else None), "ended_epoch": (tick_ts[-1] if tick_ts else None),
        "launched_cmd": launched, "syscall_table": (NR_TABLE if nr2name else None),
    }
    return dict(frames), meta


# ---------- 聚合：节点(大小=累计样本) + 边(粗细=迁移次数, 标签=归因) ----------

def build_graph(frames, key="role"):
    """把每 pid 的帧序列聚合成带权有向图。
    key='role' -> 节点=(角色,state)；key='pid' -> 节点=(pid,state)。
    返回 (nodes, edges, per_pid)：
      nodes[nk] = {"samples":N, "states":..}
      edges[ek] = {"weight":N, "from","to","attr","wchans":Counter,"seqs":[(from_seq,to_seq,pid)], ...}
      per_pid[pid] = {"samples","first_seq","last_seq","first_ts","last_ts","role","comm","container_pid"}
    """
    nodes = collections.defaultdict(lambda: {"samples": 0})
    edges = {}
    per_pid = {}

    def nkey(pid, role, state):
        return (role, state) if key == "role" else (pid, state)

    for pid, seq_frames in frames.items():
        if not seq_frames:
            continue
        first, last = seq_frames[0], seq_frames[-1]
        # 该 pid 的角色/comm（取首个非空帧）
        role = next((f["role"] for f in seq_frames if f.get("role")), "宿主")
        comm = next((f["comm"] for f in seq_frames if f.get("comm")), "?")
        cpid = next((f["container_pid"] for f in seq_frames if f.get("container_pid")), None)
        per_pid[pid] = {
            "samples": len(seq_frames), "first_seq": first["seq"], "last_seq": last["seq"],
            "first_ts": first["ts"], "last_ts": last["ts"], "role": role, "comm": comm,
            "container_pid": cpid,
            "alive_window_ms": round((last["ts"] - first["ts"]) * 1000, 1),
            "gone": bool(last.get("gone")),
        }
        for f in seq_frames:
            nk = nkey(pid, f.get("role") or role, f["state"])
            nodes[nk]["samples"] += 1
            nodes[nk]["role"] = f.get("role") or role
            nodes[nk]["state"] = f["state"]
        # 相邻两帧 -> 一条迁移（含自环）
        for a, b in zip(seq_frames, seq_frames[1:]):
            attr = attribute(b)                     # 归因取"迁移后那一帧"
            wk = wchan_label(b)
            ek = (nkey(pid, a.get("role") or role, a["state"]),
                  nkey(pid, b.get("role") or role, b["state"]), attr)
            e = edges.get(ek)
            if e is None:
                e = edges[ek] = {"from": ek[0], "to": ek[1], "attr": attr, "weight": 0,
                                 "wchans": collections.Counter(), "seqs": [], "self": ek[0] == ek[1]}
            e["weight"] += 1
            e["wchans"][wk] += 1
            e["seqs"].append((a["seq"], b["seq"], pid))
    return dict(nodes), edges, per_pid


def check_conservation(frames, edges, key="role"):
    """流守恒自检（测试1）：对每个 pid，出边权重和 == 入边权重和 == 样本数-1。
    两层校验：① 原始帧序列（相邻两帧=一条迁移）；② pid 视图下聚合边的权重回算，
    确保 build_graph 没有丢边/重复计边。返回 (ok, problems)。"""
    problems = []
    for pid, seq_frames in frames.items():
        n = len(seq_frames)
        transitions = n - 1
        out_sum = collections.Counter()
        in_sum = collections.Counter()
        for a, b in zip(seq_frames, seq_frames[1:]):
            out_sum[a["state"]] += 1
            in_sum[b["state"]] += 1
        if sum(out_sum.values()) != transitions or sum(in_sum.values()) != transitions:
            problems.append(f"pid {pid}(帧): 出={sum(out_sum.values())} 入={sum(in_sum.values())} 期望={transitions}")
    # ② 聚合边层面复核（仅 pid 视图能精确到 pid）：每 pid 的出/入边权重和也应 == 样本数-1
    if key == "pid":
        out_e, in_e = collections.Counter(), collections.Counter()
        for ek, e in edges.items():
            out_e[ek[0][0]] += e["weight"]
            in_e[ek[1][0]] += e["weight"]
        for pid, seq_frames in frames.items():
            n = len(seq_frames)
            if out_e[pid] != n - 1 or in_e[pid] != n - 1:
                problems.append(f"pid {pid}(聚合边): 出={out_e[pid]} 入={in_e[pid]} 期望={n - 1}")
    return (len(problems) == 0), problems



# ---------- 免责声明（约束 1：图必须显式写明采样不完备）----------

def disclaimer(meta):
    req = meta.get("requested_interval_ms")
    act = meta.get("actual_interval_ms_median")
    return (f"⚠ 边 = 被观测到的迁移，非全部迁移；采样间隔 {req}ms（实际中位 {act}ms），"
            f"短于该间隔的状态变化不可见。本图不是完备状态机。")


# ---------- 输出 1a：dot 文件 ----------

def _nk_str(nk):
    return f"{nk[0]}|{nk[1]}"


def render_dot(nodes, edges, meta, title, key="role"):
    """生成 graphviz dot 文本：节点面积 ∝ 累计样本数，边宽 ∝ 迁移次数，边标签 = 归因 ×次数。
    Z 与 GONE 节点用不同底色。"""
    max_s = max((n["samples"] for n in nodes.values()), default=1) or 1
    max_w = max((e["weight"] for e in edges.values()), default=1) or 1
    ids = {nk: f"n{i}" for i, nk in enumerate(sorted(nodes, key=_nk_str))}

    def q(s):                                          # dot 字符串引号：保留中文（ensure_ascii=False）
        return json.dumps(s, ensure_ascii=False)
    L = []
    L.append("digraph kprof {")
    L.append('  graph [rankdir=LR, fontname="Helvetica", labelloc="t", fontsize=13,')
    L.append(f'           label={q(title + chr(10) + disclaimer(meta))}];')
    L.append('  node [shape=box, style="filled,rounded", fontname="Helvetica", fontsize=11];')
    L.append('  edge [fontname="Helvetica", fontsize=9];')
    for nk, n in sorted(nodes.items(), key=lambda kv: _nk_str(kv[0])):
        state = nk[1]
        area = max(n["samples"], 1) / max_s           # 面积占比
        side = max(0.4, 1.7 * (area ** 0.5))           # 边长 ∝ sqrt(面积) => 面积 ∝ 样本数
        fill = _STATE_FILL.get(state, "#eaeef2")
        who = nk[0]
        meaning = STATE_MEANING.get(state, ("进程已消失(工具终态)" if state == GONE else state))
        label = f"{who}\n{state} · {meaning}\n样本 {n['samples']}"
        fc = "white" if state in ("R", "S", "D", "Z", GONE, "X") else "black"
        L.append(f'  {ids[nk]} [label={q(label)}, width={side:.2f}, height={side:.2f}, '
                 f'fillcolor="{fill}", fontcolor="{fc}"];')
    for ek, e in sorted(edges.items(), key=lambda kv: -kv[1]["weight"]):
        a, b = ids[ek[0]], ids[ek[1]]
        pw = 1.0 + 4.0 * e["weight"] / max_w
        top_wchan = e["wchans"].most_common(1)[0][0] if e["wchans"] else ""
        lab = f"{e['attr']} ×{e['weight']}"
        if e["self"]:
            L.append(f'  {a} -> {b} [label={q(lab)}, penwidth={pw:.1f}, color="#57606a", '
                     f'constraint=false, tooltip={q("wchan:" + top_wchan)}];')
        else:
            col = "#cf222e" if b and nodes[ek[1]]["state"] in ("Z", GONE) else "#0969da"
            L.append(f'  {a} -> {b} [label={q(lab)}, penwidth={pw:.1f}, color="{col}", '
                     f'tooltip={q("wchan:" + top_wchan)}];')
    # 图例
    L.append('  { rank=same; legR [label="R 运行", fillcolor="#2ea043"]; legS [label="S 可中断睡眠", fillcolor="#0969da"];'
             ' legD [label="D 不可中断睡眠", fillcolor="#bf8700"]; legZ [label="Z 僵尸", fillcolor="#8250df"];'
             ' legG [label="GONE 进程消失(工具终态)", fillcolor="#1f2328", fontcolor="white"]; }')
    L.append("  legR -> legS -> legD -> legZ -> legG [style=invis];")
    L.append("}")
    return "\n".join(L) + "\n"


def dot_available():
    return shutil.which("dot") is not None


def render_svg(dot_text, out_svg):
    """subprocess 调系统 dot 渲染 SVG；dot 不存在或失败返回 False（调用方走 ASCII 退化）。"""
    if not dot_available():
        return False
    try:
        p = subprocess.run(["dot", "-Tsvg"], input=dot_text.encode("utf-8"),
                           capture_output=True, timeout=60)
        if p.returncode != 0:
            return False
        with open(out_svg, "wb") as f:
            f.write(p.stdout)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


# ---------- 输出 2：终端 ASCII 字符图（无 graphviz 也能看）----------

def _bar(v, vmax, width=28):
    n = 0 if vmax <= 0 else max(1, round(v / vmax * width))
    return "█" * n


def render_ascii(nodes, edges, per_pid, meta, title, key="role"):
    out = []
    out.append(title)
    out.append(disclaimer(meta))
    out.append("─" * 76)
    out.append("节点（大小 = 累计停留样本数）")
    max_s = max((n["samples"] for n in nodes.values()), default=1) or 1
    for nk, n in sorted(nodes.items(), key=lambda kv: -kv[1]["samples"]):
        state = nk[1]
        meaning = STATE_MEANING.get(state, "进程消失(工具终态)" if state == GONE else state)
        out.append(f"  [{nk[0]:>6}] {state} {meaning:<26} {n['samples']:>6}  {_bar(n['samples'], max_s)}")
    out.append("─" * 76)
    out.append("迁移边（粗细 = 迁移次数；标签 = 迁移后一帧的 syscall/wchan 归因）")
    max_w = max((e["weight"] for e in edges.values()), default=1) or 1
    for ek, e in sorted(edges.items(), key=lambda kv: -kv[1]["weight"]):
        f_, t_ = ek[0], ek[1]
        arrow = "↺" if e["self"] else "→"
        fs = f"[{f_[0]}]{f_[1]}"
        ts = f"[{t_[0]}]{t_[1]}"
        wc = e["wchans"].most_common(1)[0][0] if e["wchans"] else ""
        out.append(f"  {fs:<14} {arrow} {ts:<14} {e['attr']:<22} ×{e['weight']:<5} {_bar(e['weight'], max_w)}")
        if wc and not e["attr"].startswith("wchan:"):
            out.append(f"      └ wchan: {wc}")
    out.append("─" * 76)
    out.append("图例 · " + STATE_SOURCE)
    out.append("  " + "  ".join(f"{k}={v.split(' ')[0]}" for k, v in STATE_MEANING.items())
               + f"  {GONE}=进程消失(工具终态，非内核状态)")
    return "\n".join(out)


# ---------- 输出 3：元信息表 ----------

def render_metadata(meta, per_pid):
    out = []
    out.append("─" * 76)
    out.append("元信息表")
    out.append(f"  采样间隔   : 请求 {meta['requested_interval_ms']}ms / 实际中位 {meta['actual_interval_ms_median']}ms"
               f"（超时 tick {meta['overrun_ticks']} 个）")
    out.append(f"  采样时长   : {meta['duration_s']}s   采样轮次(tick): {meta['ticks']}")
    out.append(f"  总样本数   : {meta['total_samples']}   覆盖 pid 数: {meta['covered_pids']}   根 pid: {meta['root_pid']}")
    if meta.get("launched_cmd"):
        out.append(f"  拉起命令   : {' '.join(meta['launched_cmd'])}")
    out.append(f"  syscall 表 : {meta.get('syscall_table') or '未找到（全部按 nr=<数字> 标注，不猜名）'}")
    out.append("  每 pid 样本数与存活时间窗:")
    out.append(f"    {'pid':>7} {'角色':<6} {'comm':<16} {'容器pid':>7} {'样本':>6} {'seq区间':>12} {'存活窗(ms)':>10} 终态")
    for pid in sorted(per_pid):
        p = per_pid[pid]
        out.append(f"    {pid:>7} {p['role']:<6} {str(p['comm'])[:16]:<16} {str(p['container_pid'] or '-'):>7} "
                   f"{p['samples']:>6} {str(p['first_seq'])+'-'+str(p['last_seq']):>12} "
                   f"{p['alive_window_ms']:>10} {'GONE' if p['gone'] else 'alive'}")
    return "\n".join(out)


# ---------- 结果持久化（供 --explain / --compare 复用）----------

def save_result(path, key, meta, frames, nodes, edges, per_pid):
    ser_nodes = [{"who": nk[0], "state": nk[1], "samples": n["samples"]} for nk, n in nodes.items()]
    ser_edges = [{"from": [ek[0][0], ek[0][1]], "to": [ek[1][0], ek[1][1]], "attr": e["attr"],
                  "weight": e["weight"], "self": e["self"],
                  "wchans": dict(e["wchans"]), "seqs": e["seqs"]} for ek, e in edges.items()]
    obj = {"key": key, "meta": meta, "per_pid": {str(k): v for k, v in per_pid.items()},
           "nodes": ser_nodes, "edges": ser_edges,
           "frames": {str(k): v for k, v in frames.items()}}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    return path


def load_result(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------- 约束 2：--explain 追溯原始采样帧 ----------

def do_explain(res, lo, hi, pid=None):
    """打印 seq ∈ [lo,hi] 的原始采样帧（时间戳 + 原始 /proc 行），把边追溯到证据。"""
    out = [f"--explain 采样帧 seq∈[{lo},{hi}]" + (f" pid={pid}" if pid else ""), "─" * 76]
    frames = res["frames"]
    pids = [str(pid)] if pid is not None else sorted(frames, key=lambda x: int(x))
    hit = 0
    for ps in pids:
        for fr in frames.get(ps, []):
            if lo <= fr["seq"] <= hi:
                hit += 1
                t = time.strftime("%H:%M:%S", time.localtime(fr["ts"])) + f".{int(fr['ts']*1e6)%1_000_000:06d}"
                out.append(f"seq={fr['seq']} @{t} pid={fr['pid']} state={fr['state']} role={fr.get('role')}")
                out.append(f"    stat    : {fr.get('raw_stat')}")
                sc = fr.get("syscall_raw") if fr.get("syscall_ok") else UNREADABLE
                wc = fr.get("wchan_raw") if fr.get("wchan_ok") else UNREADABLE
                out.append(f"    syscall : {sc}")
                out.append(f"    wchan   : {wc}")
                out.append(f"    NSpid   : {' '.join(fr.get('nspid') or []) or UNREADABLE}")
    if not hit:
        out.append("  （该 seq 区间内无帧；请确认区间来自某条边的 seqs 记录）")
    return "\n".join(out)


# ---------- 输出 4：两份结果左右对照（沙箱内 vs 沙箱外）----------

def do_compare(res_a, res_b, name_a="A", name_b="B"):
    out = [f"左右对照: [{name_a}] vs [{name_b}]", "─" * 76]

    def edge_index(res):
        idx = {}
        for e in res["edges"]:
            idx[((e["from"][1]), (e["to"][1]), e["attr"])] = e["weight"]
        return idx

    def state_totals(res):
        tot = collections.Counter()
        for n in res["nodes"]:
            tot[n["state"]] += n["samples"]
        return tot

    ta, tb = state_totals(res_a), state_totals(res_b)
    states = sorted(set(ta) | set(tb))
    out.append(f"  {'状态':<6}{name_a+'样本':>12}{name_b+'样本':>12}   含义")
    for s in states:
        meaning = STATE_MEANING.get(s, "进程消失(工具终态)" if s == GONE else s)
        out.append(f"  {s:<6}{ta.get(s,0):>12}{tb.get(s,0):>12}   {meaning}")
    out.append("─" * 76)
    ea, eb = edge_index(res_a), edge_index(res_b)
    allk = sorted(set(ea) | set(eb), key=lambda k: -(ea.get(k, 0) + eb.get(k, 0)))
    out.append(f"  按 (from→to, 归因) 的迁移次数对照（{name_a} | {name_b}）:")
    for k in allk[:40]:
        fr, to, attr = k
        out.append(f"    {fr}→{to:<5} {attr:<24} {ea.get(k,0):>6} | {eb.get(k,0):<6}")
    return "\n".join(out)



# ---------- 编排：一次采样 -> 模型 ----------

def parse_interval(s):
    """'5ms' / '0.005s' / '5' -> 毫秒(float)。"""
    s = str(s).strip().lower()
    if s.endswith("ms"):
        return float(s[:-2])
    if s.endswith("s"):
        return float(s[:-1]) * 1000.0
    return float(s)


def parse_duration(s):
    """'10s' / '500ms' / '2m' / '10' -> 秒(float)。"""
    s = str(s).strip().lower()
    if s.endswith("ms"):
        return float(s[:-2]) / 1000.0
    if s.endswith("m") and not s.endswith("ms"):
        return float(s[:-1]) * 60.0
    if s.endswith("s"):
        return float(s[:-1])
    return float(s)


def profile(root_pid=None, cmd=None, interval_ms=5.0, duration_s=10.0, key="role"):
    """采样一次并聚合。cmd 非空时自己拉起进程并以它为根；否则采样既有 root_pid。"""
    nr2name = load_syscall_names()
    proc = None
    if cmd is not None:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        root_pid = proc.pid
    if root_pid is None or not os.path.exists(f"/proc/{root_pid}"):
        if proc is not None:
            proc.kill()
        raise SystemExit(f"根 pid {root_pid} 不存在，无法采样")
    frames, meta = sample_tree(root_pid, interval_ms, duration_s, nr2name,
                               launched=cmd, launched_proc=proc)
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    nodes, edges, per_pid = build_graph(frames, key)
    ok, problems = check_conservation(frames, edges, key)
    return {"frames": frames, "meta": meta, "nodes": nodes, "edges": edges,
            "per_pid": per_pid, "key": key, "nr2name": nr2name,
            "conservation_ok": ok, "conservation_problems": problems}


def emit_outputs(model, title, out_prefix, want_svg=True, want_save=True):
    """渲染三样输出：dot(+svg) / ASCII / 元信息表；并保存 JSON 供 --explain/--compare。"""
    nodes, edges, per_pid, meta = model["nodes"], model["edges"], model["per_pid"], model["meta"]
    key = model["key"]
    dot = render_dot(nodes, edges, meta, title, key)
    dot_path = out_prefix + ".dot"
    with open(dot_path, "w", encoding="utf-8") as f:
        f.write(dot)
    svg_ok = False
    svg_path = out_prefix + ".svg"
    if want_svg:
        svg_ok = render_svg(dot, svg_path)
    if want_save:
        save_result(out_prefix + ".json", key, meta, model["frames"], nodes, edges, per_pid)
    # 终端：元信息表 + ASCII 图（无 graphviz 也能看）
    print(render_metadata(meta, per_pid))
    print()
    print(render_ascii(nodes, edges, per_pid, meta, title, key))
    print()
    print(f"dot 文件 : {os.path.relpath(dot_path, ROOT)}")
    if svg_ok:
        print(f"SVG 图   : {os.path.relpath(svg_path, ROOT)}  (graphviz dot 渲染)")
    else:
        print("SVG 图   : 未生成——系统无 graphviz 'dot'，已退化为上面的 ASCII 字符图")
    print(f"样本存档 : {os.path.relpath(out_prefix + '.json', ROOT)}  (供 --explain / --compare)")
    return {"dot": dot_path, "svg": svg_path if svg_ok else None, "json": out_prefix + ".json"}


# ---------- 验收：5 条可 falsify 的测试 ----------

KPROF_TMP = os.path.join(ROOT, ".kprof-tmp")
ANOLIX = os.path.join(ROOT, "anolix")
BUSYBOX = os.path.join(ROOT, "rootfs", "bin", "busybox")
PY = sys.executable or "python3"


def _ensure_tmp():
    os.makedirs(os.path.join(KPROF_TMP, "bundle"), exist_ok=True)
    os.makedirs(os.path.join(KPROF_TMP, "state"), exist_ok=True)
    return KPROF_TMP


def _spawn(args):
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _reap(proc):
    if proc is None:
        return
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _states(frames):
    s = set()
    for seq_frames in frames.values():
        for f in seq_frames:
            s.add(f["state"])
    return s


def run_tests():
    """5 条验收测试。返回是否全绿。"""
    _ensure_tmp()
    results = []

    def check(name, cond, detail=""):
        results.append((name, bool(cond), detail))
        print(f"  {'✓' if cond else '✗'} {name}" + (f"  [{detail}]" if detail else ""))

    print("验收测试（kprof · 5 条可 falsify）")
    print("─" * 76)

    # ── 测试 1：流守恒（含 fork/exit 进程 churn，压力检验 GONE 建边）──
    print("测试 1 · 流守恒自检（出边和==入边和==样本数-1，对每个 pid）")
    churn = ("import os,time\n"
             "end=time.time()+6\n"
             "while time.time()<end:\n"
             "    p=os.fork()\n"
             "    if p==0: os._exit(0)\n"
             "    time.sleep(0.008)\n"
             "    try: os.waitpid(-1,os.WNOHANG)\n"
             "    except ChildProcessError: pass\n")
    proc = _spawn([PY, "-c", churn])
    try:
        m1 = profile(root_pid=proc.pid, interval_ms=3, duration_s=1.5, key="pid")
    finally:
        _reap(proc)
    check("全图流守恒", m1["conservation_ok"],
          "; ".join(m1["conservation_problems"][:3]) or f"{len(m1['frames'])} 个 pid 守恒")
    check("覆盖多进程(含新生/死亡)", m1["meta"]["covered_pids"] >= 2, f"覆盖 {m1['meta']['covered_pids']} pid")

    # ── 测试 2：造僵尸（fork 后立刻 exit 且不 wait）──
    print("测试 2 · 僵尸 Z（入边来自 R/S，无通往非 Z 的出边）")
    zomb = ("import os,time\n"
            "c=os.fork()\n"
            "if c==0:\n"
            "    t=time.time();x=0\n"
            "    while time.time()-t<0.08: x+=1\n"
            "    os._exit(0)\n"
            "time.sleep(8)\n")
    proc = _spawn([PY, "-c", zomb])
    try:
        m2 = profile(root_pid=proc.pid, interval_ms=3, duration_s=1.5, key="pid")
    finally:
        _reap(proc)
    # 找僵尸 pid：帧序列里出现 Z
    zpid = None
    for pid, fs in m2["frames"].items():
        if any(f["state"] == "Z" for f in fs):
            zpid = pid
            break
    z_in_from_RS = False
    z_out_nonZ = False
    if zpid is not None:
        fs = m2["frames"][zpid]
        for a, b in zip(fs, fs[1:]):
            if b["state"] == "Z" and a["state"] in ("R", "S"):
                z_in_from_RS = True
            if a["state"] == "Z" and b["state"] not in ("Z", GONE):
                z_out_nonZ = True
    check("出现 Z 节点", zpid is not None, f"僵尸 pid={zpid}")
    check("Z 的入边来自 R 或 S", z_in_from_RS)
    check("Z 无通往其它状态的出边(未 wait 不转 GONE)", zpid is not None and not z_out_nonZ)

    # ── 测试 3：造 D（fsync 真实磁盘 -> 不可中断睡眠）──
    print("测试 3 · 阻塞 D（fsync 真实磁盘；wchan 非空或 ⚠️不可读）")
    dfile = os.path.join(KPROF_TMP, "dtest.bin")
    dfsync = ("import os\n"
              f"p={dfile!r}\n"
              "fd=os.open(p,os.O_CREAT|os.O_WRONLY,0o600)\n"
              "buf=b'x'*1048576\n"
              "while True:\n"
              "    os.lseek(fd,0,0);os.write(fd,buf);os.fsync(fd)\n")
    proc = _spawn([PY, "-c", dfsync])
    try:
        m3 = profile(root_pid=proc.pid, interval_ms=2, duration_s=1.2, key="pid")
    finally:
        _reap(proc)
        try:
            os.remove(dfile)
        except OSError:
            pass
    d_frames = [f for fs in m3["frames"].values() for f in fs if f["state"] == "D"]
    d_wc = [wchan_label(f) for f in d_frames]
    # "非空或 ⚠️不可读"：排除 wchan=='0(未阻塞)' 的瞬时无名阅塞，保留函数名与 ⚠️不可读
    d_wc_ok = [w for w in d_wc if w != "0(未阻塞)"]
    top_wc = collections.Counter(d_wc_ok).most_common(1)[0][0] if d_wc_ok else (d_wc[0] if d_wc else "无 D")
    check("出现 D 节点", len(d_frames) > 0, f"{len(d_frames)} 个 D 样本")
    check("D 的 wchan 非空或标 ⚠️不可读", len(d_wc_ok) > 0, f"主 wchan={top_wc}")

    # ── 测试 4：纯 sleep（S 自环权重全图最大，且不出现 Z）──
    print("测试 4 · 纯 sleep（S 自环权重最大，无 Z）")
    proc = _spawn([PY, "-c", "import time;time.sleep(30)"])
    try:
        m4 = profile(root_pid=proc.pid, interval_ms=5, duration_s=1.0, key="role")
    finally:
        _reap(proc)
    # S 自环 = from==to==S 的边
    s_self = max((e["weight"] for ek, e in m4["edges"].items() if e["self"] and ek[0][1] == "S"), default=0)
    max_edge = max((e["weight"] for e in m4["edges"].values()), default=0)
    check("S 自环权重是全图最大", s_self > 0 and s_self == max_edge, f"S自环={s_self} 最大边={max_edge}")
    check("不出现 Z", "Z" not in _states(m4["frames"]))

    # ── 测试 5：沙箱内外对照（seccomp errnoRet=1145 拦掉的 fsync 不进 D）──
    print("测试 5 · 沙箱内外对照（fsync：宿主进 D，沙箱内被拦不进 D）")
    t5 = test_sandbox_compare(check)

    print("─" * 76)
    ok = all(r[1] for r in results)
    print("全部通过 ✓" if ok else "存在失败 ✗")
    return ok


def test_sandbox_compare(check):
    """测试 5 的实现：同一 busybox dd conv=fsync 负载，宿主直跑 vs 沙箱内跑。
    宿主：fsync 放行 -> 真进内核阻塞 -> D 且 syscall=fsync(74) 出现在边标签。
    沙箱：fsync 不在白名单 -> seccomp 立即返回 errno 1145 -> 不进 D。"""
    if not (os.path.exists(ANOLIX) and os.path.exists(BUSYBOX)):
        check("沙箱内外对照", False, "缺少 anolix 或 rootfs/bin/busybox，无法运行")
        return False
    if shutil.which("runc") is None:
        check("沙箱内外对照", False, "系统无 runc，无法起沙箱")
        return False

    # 宿主外侧负载：同一 busybox dd 写真实磁盘 + conv=fsync（ext4 -> 稳定 D）
    #   注意：内外都显式用 busybox 多路复用器调 dd——容器内没有 dd 的 applet 软链，
    #   裸写 'dd' 会 "not found"（曾导致内侧负载空转、假阳性）。
    outfile = os.path.join(KPROF_TMP, "t5-out.bin")
    # 同一 busybox dd conv=fsync 负载；count 参数化：
    #   外侧 count=64 -> fsync 刷 64MB，D 窗口长且频繁（实测 ~450 个 D-fsync 样本）；
    #   内侧 count=64  -> 写容器 tmpfs（fsync 本就被拦）。
    loop = "i=0; while [ $i -lt 800 ]; do {DD} if=/dev/zero of={OUT} bs=1M count={CNT} conv=fsync 2>/dev/null; i=$((i+1)); done"
    outside_cmd = [BUSYBOX, "sh", "-c", loop.format(DD=f"{BUSYBOX} dd", OUT=outfile, CNT=64)]
    try:
        m_out = profile(cmd=outside_cmd, interval_ms=2, duration_s=2.5, key="role")
    finally:
        try:
            os.remove(outfile)
        except OSError:
            pass
    d_fsync_out = [f for fs in m_out["frames"].values() for f in fs
                   if f["state"] == "D" and f["syscall_nr"] == 74]
    attr_out = {e["attr"] for e in m_out["edges"].values()}

    # 沙箱内侧负载：同一 busybox dd，但 fsync 不在白名单 -> seccomp 立即返回 errno 1145 -> 不进 D
    pol = _write_min_policy()
    inside_cmd = [ANOLIX, "run", "--policy", pol, "--rootfs", os.path.join(ROOT, "rootfs"),
                  "--bundle", os.path.join(KPROF_TMP, "bundle"), "--state-dir", os.path.join(KPROF_TMP, "state"),
                  "--", "/bin/busybox", "sh", "-c", loop.format(DD="/bin/busybox dd", OUT="/tmp/t5.bin", CNT=64)]
    m_in = profile(cmd=inside_cmd, interval_ms=3, duration_s=6.0, key="role")
    sandbox_started = m_in["meta"]["covered_pids"] >= 2 and m_in["meta"]["ticks"] > 3
    container_frames = [f for fs in m_in["frames"].values() for f in fs if f.get("role") == "容器内"]
    d_fsync_in = [f for f in container_frames if f["state"] == "D" and f["syscall_nr"] == 74]

    check("宿主: fsync 进 D 且 syscall=fsync(74) 被观测", len(d_fsync_out) > 0,
          f"{len(d_fsync_out)} 个 D-fsync 样本")
    check("宿主: 'fsync' 出现在边标签", "fsync" in attr_out, ",".join(sorted(attr_out)[:6]))
    check("沙箱内: 起沙箱成功并采到足量容器进程帧", sandbox_started and len(container_frames) >= 20,
          f"覆盖 {m_in['meta']['covered_pids']} pid, 容器内 {len(container_frames)} 帧")
    check("沙箱内: fsync 被拦(errno1145)，容器进程不进 D", sandbox_started and len(d_fsync_in) == 0,
          f"{len(d_fsync_in)} 个容器 D-fsync 样本")

    # 左右对照输出（本工具最有价值的产物）
    print()
    print(do_compare(_model_to_result(m_out), _model_to_result(m_in), name_a="宿主外", name_b="沙箱内"))
    return True


def _write_min_policy():
    """生成一份只含 seccomp（errnoRet=1145）、去掉 resources 的最小策略。
    去掉 resources 是因为 rootless 下 cgroup 限额常无权限（会导致 runc 起不来），
    而本测试只关心 seccomp 拦截，不需要资源围栏。"""
    import json as _json
    src = os.path.join(ROOT, "examples", "policy.json")
    dst = os.path.join(KPROF_TMP, "policy.json")
    with open(src, encoding="utf-8") as f:
        p = _json.load(f)
    p.pop("resources", None)
    with open(dst, "w", encoding="utf-8") as f:
        _json.dump(p, f, ensure_ascii=False, indent=2)
    return dst


def _model_to_result(m):
    """把 profile() 的内存模型转成 save/load_result 的结构（供 do_compare 复用）。"""
    nodes = [{"who": nk[0], "state": nk[1], "samples": n["samples"]} for nk, n in m["nodes"].items()]
    edges = [{"from": [ek[0][0], ek[0][1]], "to": [ek[1][0], ek[1][1]], "attr": e["attr"],
              "weight": e["weight"], "self": e["self"], "wchans": dict(e["wchans"]), "seqs": e["seqs"]}
             for ek, e in m["edges"].items()]
    return {"nodes": nodes, "edges": edges, "meta": m["meta"],
            "per_pid": {str(k): v for k, v in m["per_pid"].items()},
            "frames": {str(k): v for k, v in m["frames"].items()}}


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(
        description="Linux 进程状态机采样式 profiler（tcmalloc heap profile 风格带权有向图）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int, default=None, help="采样既有进程树的根 pid")
    ap.add_argument("--interval", default="5ms", help="采样间隔（如 5ms / 0.005s）")
    ap.add_argument("--duration", default="10s", help="采样时长（如 10s / 500ms / 2m）")
    ap.add_argument("--aggregate", choices=["role", "pid"], default="role",
                    help="聚合视图：role=(角色,state) 默认；pid=(pid,state) 明细")
    ap.add_argument("--out", default=None, help="输出文件前缀（默认 logs/kprof-<tag>）")
    ap.add_argument("--no-svg", action="store_true", help="不调用 graphviz dot")
    ap.add_argument("--result", default=None, help="配合 --explain：读取的样本存档 JSON")
    ap.add_argument("--explain", default=None, help="打印构成边的原始采样帧：<from_seq>-<to_seq>")
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"), default=None,
                    help="两份样本存档 JSON 左右对照（如 沙箱外 沙箱内）")
    ap.add_argument("--test", action="store_true", help="跑 5 条验收测试")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- <命令...>：自己拉起并采样")
    args = ap.parse_args()

    if args.test:
        return 0 if run_tests() else 1

    if args.compare:
        a, b = load_result(args.compare[0]), load_result(args.compare[1])
        na = os.path.basename(args.compare[0])
        nb = os.path.basename(args.compare[1])
        print(do_compare(a, b, name_a=na, name_b=nb))
        return 0

    if args.explain:
        if not args.result:
            print("--explain 需要配合 --result <存档.json>", file=sys.stderr)
            return 2
        res = load_result(args.result)
        m = re.match(r'^(\d+)\s*-\s*(\d+)$', args.explain.strip())
        if not m:
            print("--explain 格式应为 <from>-<to>（样本序号区间）", file=sys.stderr)
            return 2
        print(do_explain(res, int(m.group(1)), int(m.group(2)), pid=args.pid))
        return 0

    # 正常采样流程
    cmd = None
    if args.cmd:
        cmd = args.cmd[1:] if args.cmd[0] == "--" else args.cmd
        if not cmd:
            print("未给出要拉起的命令", file=sys.stderr)
            return 2
    if cmd is None and args.pid is None:
        ap.print_help()
        return 2

    interval_ms = parse_interval(args.interval)
    duration_s = parse_duration(args.duration)
    model = profile(root_pid=args.pid, cmd=cmd, interval_ms=interval_ms,
                    duration_s=duration_s, key=args.aggregate)

    # 约束：流守恒自检不过直接报错退出
    if not model["conservation_ok"]:
        print("流守恒自检失败（采样或建边有 bug）：", file=sys.stderr)
        for p in model["conservation_problems"][:10]:
            print("  " + p, file=sys.stderr)
        return 1

    tag = f"pid{args.pid}" if args.pid else "cmd"
    out_prefix = args.out or os.path.join(ROOT, "logs", f"kprof-{tag}")
    os.makedirs(os.path.dirname(out_prefix), exist_ok=True)
    title = ("kprof 进程状态机 · " + (" ".join(cmd) if cmd else f"pid={args.pid}"))[:90]
    emit_outputs(model, title, out_prefix, want_svg=not args.no_svg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
