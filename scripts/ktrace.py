#!/usr/bin/env python3
# ktrace.py —— 把已有的 strace 日志推导成"沙箱生命周期状态机"
#
# 用法:
#   ./scripts/ktrace.py                      # 分析 trace.log，打印三样输出并生成 SVG
#   ./scripts/ktrace.py trace-bare.log       # 分析另一份日志（裸 pid 格式）
#   ./scripts/ktrace.py --out logs/x.html trace.log
#   ./scripts/ktrace.py --test               # 跑 4 条验收单元测试（针对 trace.log）
#
# 【定位】纯解释器：不自己 ptrace、不采新数据，只读仓库根目录已有的 strace 日志。
#   Python 3 + 标准库，零新依赖。渲染复用 scripts/skscope.py 的 SVG 类（import，不另写画图代码）。
#
# 【输入格式】两份日志行首不同，都要支持，统一归一化为 (lineno, pid, timestamp, text)：
#   A) [pid 216260] 11:21:52.022723 seccomp(...)   —— trace.log（10647 行这种）
#   B) 318340 17:02:50.897151 seccomp(...)         —— trace-bare.log（裸 pid，无方括号）
#   C) 11:21:51.550444 execve("./anolix", ...)     —— trace.log 有 233 行无 pid 前缀
#      规则：无前缀 = 根 tracee（最初被追踪的进程，即 anolix 主线程）。
#      根 tracee 的真实 pid 从它自报的 gettid()/getpid() 反推（trace.log L69: gettid()=216235）。
#
# 【必须处理的坑】
#   1) <unfinished ...> / <... resumed> 拼接：按 (pid, syscall名) LIFO 配对成一条完整调用。
#      不拼接会把被中断的调用误判成失败，从而长出不存在的迁移边。
#      注意：真正的 seccomp 装载行本身就带 <unfinished ...> 结尾，返回值 = 0 在后续 resumed 行。
#      另有 strace 多进程并发写导致的物理折行（"strace: Process N attached" 注入行中），
#      需把非行首碎片回接到上一条未完成记录。
#   2) libseccomp 自检噪音：seccomp(SET_MODE_FILTER, <flags>, NULL) = -1 EFAULT 是库能力探测，不是装载。
#      装载判据必须同时满足：含 "len=" 且返回 0。
#
# 【三条硬约束】
#   1) 每个状态、每条迁移边必须挂 trace 行号 + 原始那一行文本；挂不上就不许画（不得伪造行号）。
#   2) 规则未命中必须显式输出 "⚠️ 未观测到"，禁止静默跳过、禁止用推断值补白。
#   3) 所有耗时标注为"受扰时间"（ptrace 会拖慢被追踪进程），不得呈现为真实性能基线。

import argparse
import os
import re
import sys

# ── 复用 skscope.py 的 SVG 类与绘图基元（不另写一套画图代码）──────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import skscope                                   # noqa: E402
from skscope import SVG, esc, FONT, _arrow, _wrap  # noqa: E402
from skscope import GREEN, RED, GRAY, PURPLE, BLUE, AMBER, YELLOW  # noqa: E402

ROOT = os.path.dirname(_HERE)

# ---------- 常量：行首格式、命名空间 flag、角色名、状态名 ----------

RE_PID = re.compile(r'^\[pid (\d+)\]\s+(\d{2}:\d{2}:\d{2}\.\d{6})\s+(.*)$')   # A) [pid N] TS text
RE_BARE = re.compile(r'^(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d{6})\s+(.*)$')          # B) PID TS text
RE_ROOT = re.compile(r'^(\d{2}:\d{2}:\d{2}\.\d{6})\s+(.*)$')                  # C) TS text（根 tracee）
RE_STRACE_MSG = re.compile(r'^strace:\s+Process \d+ attached')                # strace 自身消息（丢弃）
RE_SELF_PID = re.compile(r'(?:gettid|getpid|set_tid_address)\(.*?=\s*(\d+)')  # 根 tracee 自报 pid

# CLONE_NEW* 命名空间 flag（S1->S2 计数用）；CLONE_NEWUSER 单列（S0->S1）
NS_FLAGS = ("CLONE_NEWUSER", "CLONE_NEWNS", "CLONE_NEWTIME", "CLONE_NEWCGROUP",
            "CLONE_NEWUTS", "CLONE_NEWIPC", "CLONE_NEWPID", "CLONE_NEWNET")

# 角色名（与验收口径一致：容器 payload 进程即"容器 init"）
ROLE_ANOLIX = "anolix"
ROLE_RUNC_RUN = "runc run"
ROLE_RUNC_INIT = "runc init"
ROLE_CONTAINER = "容器 init"
ROLE_OTHER = "其他"

# 状态机 S0..S7 的名称与一句话释义
STATES = [
    ("S0", "宿主态",       "被追踪起点：anolix 在宿主上，尚无隔离"),
    ("S1", "用户 ns",      "unshare(CLONE_NEWUSER)：拿到新用户命名空间"),
    ("S2", "其余 ns",      "unshare(其余 CLONE_NEW*)：mnt/pid/net/... 一次切入"),
    ("S3", "挂载",         "mount(MS_REC|MS_SLAVE) 起，构建容器根文件系统"),
    ("S4", "NNP",          "prctl(PR_SET_NO_NEW_PRIVS,1)：装 seccomp 的前置开关"),
    ("S5", "装载",         "seccomp(SET_MODE_FILTER,len=..)=0：BPF 过滤器入内核"),
    ("S6", "换人",         "execve(payload)：过滤器跨 execve 保留，新程序带锁出生"),
    ("S7", "退出",         "+++ exited with：payload 进程退出，命名空间引用归零"),
]

# 迁移边规则表（逐条匹配调用流；每条边记录命中的行号与原文）
EDGES = [
    ("S0->S1", "用户ns",  "unshare(CLONE_NEWUSER)"),
    ("S1->S2", "其余ns",  "unshare(CLONE_NEW(NS|TIME|CGROUP|UTS|IPC|PID|NET)...)"),
    ("S2->S3", "挂载",    "mount(...MS_REC|MS_SLAVE)"),
    ("S3->S4", "NNP",     "prctl(PR_SET_NO_NEW_PRIVS, 1)"),
    ("S4->S5", "装载",    "seccomp(...SET_MODE_FILTER...len=...) = 0"),
    ("S5->S6", "换人",    "execve(\"<payload>\")"),
    ("S6->S7", "退出",    "+++ exited with"),
]


def ts_to_us(ts):
    """'HH:MM:SS.ffffff' -> 自当日 0 点起的微秒数（用于算受扰耗时）。"""
    h, m, rest = ts.split(":")
    s, us = rest.split(".")
    return ((int(h) * 60 + int(m)) * 60 + int(s)) * 1_000_000 + int(us)


def _is_complete(text):
    """判断一条记录的文本是否已"写完"（决定后续碎片行是否回接）。
    完整 = 以 <unfinished ...> 结尾 / 是退出·信号标记 / 以 ") = 返回值" 或 "= 数字/?" 收尾。
    注意：args 内部的 '='（如 flags=CLONE_..）不算返回值，故要求 ')' 紧邻 '=' 或行尾是纯数字。"""
    t = text.rstrip()
    if t.endswith("<unfinished ...>"):
        return True
    if "+++ exited with" in t or t.startswith("--- "):
        return True
    if re.search(r'\)\s*=\s*\S', t):          # syscall(...) = ret
        return True
    if re.search(r'=\s*-?\d+\s*$', t):        # 以 = 数字 结尾
        return True
    if re.search(r'=\s*\?\s*$', t):           # = ?（被信号打断，返回值未知）
        return True
    return False


# ---------- Stage 1：归一化（三种行首 + 折行回接）----------


def parse_records(path):
    """读物理行 -> 归一化记录列表 [{lineno,end_lineno,pid,ts,text,raw}]。
    同时反推根 tracee 的真实 pid（从无前缀行的 gettid/getpid 自报）。
    返回 (records, root_pid, stats)。"""
    records = []
    root_pid = None
    open_rec = None                      # 当前可能被碎片回接的记录
    stats = {"total": 0, "pid": 0, "bare": 0, "root": 0, "frag": 0, "msg": 0, "noise": 0}
    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            raw = line.rstrip("\n")
            stats["total"] += 1
            pid = ts = text = None
            m = RE_PID.match(raw)
            if m:
                pid, ts, text = int(m.group(1)), m.group(2), m.group(3)
                stats["pid"] += 1
            else:
                m = RE_BARE.match(raw)
                if m:
                    pid, ts, text = int(m.group(1)), m.group(2), m.group(3)
                    stats["bare"] += 1
                else:
                    m = RE_ROOT.match(raw)
                    if m:
                        pid, ts, text = "ROOT", m.group(1), m.group(2)
                        stats["root"] += 1
            if pid is not None:
                open_rec = {"lineno": lineno, "end_lineno": lineno, "pid": pid,
                            "ts": ts, "text": text, "raw": raw}
                records.append(open_rec)
                if pid == "ROOT" and root_pid is None:
                    gm = RE_SELF_PID.match(text)
                    if gm:
                        root_pid = int(gm.group(1))
            else:
                # 非行首：strace 消息 / 折行碎片 / 程序输出噪音
                if RE_STRACE_MSG.match(raw.strip()):
                    stats["msg"] += 1
                    continue
                stats["frag"] += 1
                if open_rec is not None and not _is_complete(open_rec["text"]):
                    # 折行碎片：回接到上一条未完成记录（含被注入的 strace 消息尾巴）
                    open_rec["text"] += " " + raw.strip()
                    open_rec["end_lineno"] = lineno
                else:
                    stats["noise"] += 1   # 上一条已完整 -> 这是程序 stdout 噪音，丢弃
    # 归一化根 tracee 的 pid：无前缀 = 根 tracee = anolix 主线程
    for r in records:
        if r["pid"] == "ROOT":
            r["pid"] = root_pid if root_pid is not None else "root"
    return records, root_pid, stats


# ---------- Stage 2：<unfinished>/<resumed> LIFO 配对 ----------


def syscall_name(text):
    """取调用名：'seccomp(...' -> 'seccomp'；退出/信号标记 -> None。"""
    m = re.match(r'\s*([A-Za-z_]\w*)\(', text)
    return m.group(1) if m else None


def pair_calls(records):
    """按 (pid, syscall) LIFO 配对，产出逻辑调用列表。
    每条 call: {lineno,end_lineno,pid,ts,syscall,args,ret,full,raw,resumed_raw,resumed_lineno,kind}
      kind ∈ {single(整行), entry(unfinished 未配/已配), orphan(孤立 resumed), exit(+++ exited), signal}
    entry 配到 resumed 后：args=入参、ret=返回值尾、full=args+ret，行号取 entry 行、end_lineno 取 resumed 行。"""
    calls = []
    pending = {}                          # (pid, syscall) -> [entry, ...]（栈，LIFO）
    for r in records:
        text, pid = r["text"], r["pid"]
        base = {"lineno": r["lineno"], "end_lineno": r["end_lineno"], "pid": pid,
                "ts": r["ts"], "raw": r["raw"], "resumed_raw": None, "resumed_lineno": None}
        mres = re.match(r'\s*<\.\.\.\s+(\w+)\s+resumed>(.*)$', text, re.S)
        if text.rstrip().endswith("<unfinished ...>"):
            sc = syscall_name(text)
            args = text[:text.rfind("<unfinished ...>")].rstrip()
            c = dict(base, syscall=sc, args=args, ret=None, full=None, kind="entry")
            pending.setdefault((pid, sc), []).append(c)
            calls.append(c)
        elif mres:
            sc, tail = mres.group(1), mres.group(2)
            stack = pending.get((pid, sc))
            if stack:
                e = stack.pop()           # LIFO 配对：把返回值补回到最近的同名 entry
                e["ret"] = tail
                e["resumed_raw"] = r["raw"]
                e["resumed_lineno"] = r["lineno"]
                e["end_lineno"] = r["lineno"]
                e["full"] = e["args"] + " " + tail
            else:
                calls.append(dict(base, syscall=sc, args="", ret=tail, full=text, kind="orphan"))
        elif "+++ exited with" in text:
            calls.append(dict(base, syscall=None, args=text, ret=text, full=text, kind="exit"))
        elif text.startswith("--- "):
            calls.append(dict(base, syscall=None, args=text, ret=text, full=text, kind="signal"))
        else:
            sc = syscall_name(text)
            calls.append(dict(base, syscall=sc, args=text, ret=text, full=text, kind="single"))
    for c in calls:
        if c["full"] is None:
            c["full"] = c["args"] + (" " + c["ret"] if c["ret"] else "")
    return calls


def ret_is_zero(call):
    """返回值是否为 0（用于装载判据）。看 ret 尾部 '= 0'。"""
    tail = (call.get("ret") or "").strip()
    return re.search(r'=\s*0\s*$', tail) is not None


def ret_int(call):
    """取返回值的整数（clone/fork 的子 pid、getpid 等）；失败返回 None。"""
    tail = (call.get("ret") or call.get("full") or "").strip()
    m = re.search(r'=\s*(-?\d+)\s*$', tail)
    return int(m.group(1)) if m else None


# ---------- Stage 3：角色归因（pid + execve + 进程树继承）----------


def _execve_path_argv(call):
    """从 execve 调用抽取 (path, argv_str)。"""
    m = re.match(r'\s*execve\(\s*"([^"]*)"(?:\s*,\s*\[(.*?)\])?', call["full"], re.S)
    if not m:
        return None, ""
    return m.group(1), (m.group(2) or "")


def classify_execve(path, argv):
    """按提示词规则表把一次 execve 归类为角色。"""
    if path is None:
        return ROLE_OTHER
    base = path.rsplit("/", 1)[-1]
    if path == "./anolix" or base == "anolix":
        return ROLE_ANOLIX
    if base == "runc" and '"run"' in argv:
        return ROLE_RUNC_RUN
    if re.match(r'/proc/self/fd/\d+$', path) and '"init"' in argv:
        return ROLE_RUNC_INIT                                 # runc init（自重新执行）
    if path in ("/probe", "/bin/busybox") or base in ("probe", "busybox"):
        return ROLE_CONTAINER                                 # 容器 payload = 容器 init
    return ROLE_OTHER


def build_roles(calls, root_pid):
    """构建进程树 + 归因每个 pid 的角色。
    返回 dict：
      parents[child]=creator_pid           （来自 clone/fork/vfork 的返回值）
      execves[pid]=[(lineno,path,argv,role)] （按行号序）
      span[pid]=(first_lineno,last_lineno)
      role[pid]=最终角色, crit[pid]=判据文本, changed[pid]=是否 execve 换过人"""
    parents, execves, span = {}, {}, {}
    for c in calls:
        pid = c["pid"]
        if isinstance(pid, int):
            lo, hi = span.get(pid, (c["lineno"], c["end_lineno"]))
            span[pid] = (min(lo, c["lineno"]), max(hi, c["end_lineno"]))
        if c["syscall"] in ("clone", "fork", "vfork", "clone3"):
            child = ret_int(c)
            if child is not None and child > 0:
                parents.setdefault(child, pid)
        elif c["syscall"] == "execve":
            path, argv = _execve_path_argv(c)
            execves.setdefault(pid, []).append((c["lineno"], path, argv, classify_execve(path, argv)))

    role, crit, changed = {}, {}, {}

    def role_of(pid, seen=None):
        if pid in role:
            return role[pid]
        seen = seen or set()
        if pid in seen:                       # 防御：进程树成环
            role[pid] = ROLE_OTHER
            crit[pid] = "归因成环，判为其他"
            return ROLE_OTHER
        seen.add(pid)
        evs = execves.get(pid)
        if evs:
            lineno, path, argv, r = evs[-1]   # 取最后一次 execve = 该 pid 的最终身份
            role[pid] = r
            crit[pid] = f'L{lineno} execve("{path}"' + (f", [{argv}]" if argv else "") + ")"
            changed[pid] = len(evs) >= 1
            return r
        if pid in parents:
            pr = role_of(parents[pid], seen)
            role[pid] = pr
            crit[pid] = f"无自身 execve，继承自父 pid {parents[pid]}（{pr}）"
            changed[pid] = False
            return pr
        if root_pid is not None and pid == root_pid:
            role[pid] = ROLE_ANOLIX
            crit[pid] = "根 tracee（无前缀行 = anolix 主线程）"
            changed[pid] = False
            return ROLE_ANOLIX
        role[pid] = ROLE_OTHER
        # 诚实判据：日志里找不到创建它的 clone 返回值。常见于容器 ns 内进程——
        # clone 返回的是容器内 pid，而行首 [pid N] 是宿主 pid，双身份不对齐（不做推断补白）。
        crit[pid] = "无自身 execve；日志未对齐到创建它的 clone（疑似容器 ns 内进程，宿主/容器双 PID）"
        changed[pid] = False
        return ROLE_OTHER

    # 只对"有日志记录（span）"的 pid 下结论：clone 返回的容器 ns 内 pid（如 2、3…）
    # 在行首从未作为 [pid N] 出现，属幽灵身份，不纳入归因表（避免无据补白）。
    for pid in list(span):
        role_of(pid)
    return {"parents": parents, "execves": execves, "span": span,
            "role": role, "crit": crit, "changed": changed, "root_pid": root_pid}


# ---------- Stage 4：迁移边匹配（规则表逐条命中，记录行号+原文）----------


def _ns_flags(text):
    """抽取一条 unshare 里的 CLONE_NEW* flag 列表。"""
    return [f for f in NS_FLAGS if f in text]


def match_edges(calls, roles):
    """按规则表在调用流上单调匹配 S0->S1 .. S6->S7。
    返回 (edges, extra)：edges 是每条边的 dict（含 matched/lineno/raw/pid/sig）；
    extra 存放 mount 跨度、ns 计数、len 值等附加观测。"""
    ordered = sorted(calls, key=lambda c: c["lineno"])
    edges = []
    floor = 0                                 # 单调约束：下一条边的行号下界
    extra = {"mount_last": None, "mount_count": 0, "ns_flags": [], "ns_count": 0,
             "load_len": None, "unshare_pid": None, "load_pid": None, "payload_pid": None,
             "exit_code": None}

    def find(pred, lo):
        for c in ordered:
            if c["lineno"] >= lo and pred(c):
                return c
        return None

    def mk(eid, name, rule, call, sig, note=""):
        if call is None:
            return {"id": eid, "name": name, "rule": rule, "matched": False,
                    "lineno": None, "raw": None, "pid": None, "sig": sig, "note": note}
        return {"id": eid, "name": name, "rule": rule, "matched": True,
                "lineno": call["lineno"], "end_lineno": call["end_lineno"],
                "raw": call["raw"], "resumed_raw": call.get("resumed_raw"),
                "pid": call["pid"], "ts": call["ts"], "sig": sig, "note": note}

    # S0->S1：unshare(CLONE_NEWUSER)
    c = find(lambda x: x["syscall"] == "unshare" and "CLONE_NEWUSER" in x["args"], floor)
    edges.append(mk("S0->S1", "用户ns", EDGES[0][2], c, "unshare(CLONE_NEWUSER)"))
    if c:
        floor = c["lineno"] + 1
        extra["unshare_pid"] = c["pid"]

    # S1->S2：unshare(其余 CLONE_NEW*)，记录实际 ns 个数与 flags
    def is_other_ns(x):
        if x["syscall"] != "unshare":
            return False
        fl = [f for f in _ns_flags(x["args"]) if f != "CLONE_NEWUSER"]
        return len(fl) > 0
    c2 = find(is_other_ns, floor)
    if c2:
        fl = [f for f in _ns_flags(c2["args"]) if f != "CLONE_NEWUSER"]
        extra["ns_flags"] = fl
        extra["ns_count"] = len(fl)
        if extra["unshare_pid"] is None:
            extra["unshare_pid"] = c2["pid"]
        sig = f"unshare({len(fl)}×CLONE_NEW*)"
        e = mk("S1->S2", "其余ns", EDGES[1][2], c2, sig, note="ns=" + "|".join(x.replace("CLONE_NEW", "") for x in fl))
        edges.append(e)
        floor = c2["lineno"] + 1
    else:
        edges.append(mk("S1->S2", "其余ns", EDGES[1][2], None, "unshare(其余 CLONE_NEW*)"))

    # S2->S3：mount(...MS_REC|MS_SLAVE) 起，到最后一个 mount 止
    mounts = [x for x in ordered if x["syscall"] == "mount" and x["lineno"] >= floor]
    cm = next((x for x in mounts if "MS_REC" in x["args"] and "MS_SLAVE" in x["args"]), None)
    if cm:
        allm = [x for x in ordered if x["syscall"] == "mount"]
        extra["mount_count"] = len(allm)
        extra["mount_last"] = allm[-1] if allm else None
        note = f"共 {len(allm)} 次 mount，止于 L{allm[-1]['lineno']}" if allm else ""
        edges.append(mk("S2->S3", "挂载", EDGES[2][2], cm, "mount(MS_REC|MS_SLAVE)", note=note))
        floor = cm["lineno"] + 1
    else:
        edges.append(mk("S2->S3", "挂载", EDGES[2][2], None, "mount(MS_REC|MS_SLAVE)"))

    # S3->S4：prctl(PR_SET_NO_NEW_PRIVS, 1)
    c = find(lambda x: x["syscall"] == "prctl" and re.search(r'PR_SET_NO_NEW_PRIVS,\s*1', x["args"]), floor)
    edges.append(mk("S3->S4", "NNP", EDGES[3][2], c, "prctl(PR_SET_NO_NEW_PRIVS,1)"))
    if c:
        floor = c["lineno"] + 1

    # S4->S5：seccomp(...SET_MODE_FILTER...len=...) = 0（必须 len= 且返回 0，排除 EFAULT 自检）
    def is_load(x):
        return (x["syscall"] == "seccomp" and "SET_MODE_FILTER" in x["args"]
                and "len=" in x["args"] and ret_is_zero(x))
    c = find(is_load, floor)
    if c:
        m = re.search(r'len=(\d+)', c["args"])
        extra["load_len"] = int(m.group(1)) if m else None
        extra["load_pid"] = c["pid"]
        edges.append(mk("S4->S5", "装载", EDGES[4][2], c, f"seccomp(SET_MODE_FILTER,len={extra['load_len']})=0"))
        floor = c["lineno"] + 1
    else:
        edges.append(mk("S4->S5", "装载", EDGES[4][2], None, "seccomp(SET_MODE_FILTER,len=..)=0"))

    # S5->S6：execve("<payload>")（角色=容器 init 的 execve）
    def is_payload_exec(x):
        if x["syscall"] != "execve":
            return False
        path, argv = _execve_path_argv(x)
        return classify_execve(path, argv) == ROLE_CONTAINER
    c = find(lambda x: is_payload_exec(x) and x["lineno"] >= floor, 0)
    if c:
        extra["payload_pid"] = c["pid"]
        path, _ = _execve_path_argv(c)
        edges.append(mk("S5->S6", "换人", EDGES[5][2], c, f'execve("{path}")'))
        floor = c["lineno"] + 1
    else:
        edges.append(mk("S5->S6", "换人", EDGES[5][2], None, 'execve("<payload>")'))

    # S6->S7：payload 进程的 +++ exited with
    ppid = extra["payload_pid"]
    def is_exit(x):
        return x["kind"] == "exit" and (ppid is None or x["pid"] == ppid) and x["lineno"] >= floor
    c = find(is_exit, floor)
    if c is None:                                # 退化：payload pid 未知时取任意首个满足行号下界的退出
        c = find(lambda x: x["kind"] == "exit" and x["lineno"] >= floor, floor)
    if c:
        m = re.search(r'exited with (\d+)', c["full"])
        extra["exit_code"] = int(m.group(1)) if m else None
        edges.append(mk("S6->S7", "退出", EDGES[6][2], c, f"+++ exited with {extra['exit_code']}"))
    else:
        edges.append(mk("S6->S7", "退出", EDGES[6][2], None, "+++ exited with"))

    return edges, extra


# ---------- 分段时间（受扰时间）----------


def compute_segments(calls, roles):
    """三段受扰时间 + 到容器 init 的总时长。
    边界时间戳：T0=anolix execve, T1=runc run execve, T2=payload execve, T3=最后一个 +++ exited。"""
    def first_exec_ts(role):
        for pid, evs in roles["execves"].items():
            for lineno, path, argv, r in evs:
                if r == role:
                    for c in calls:
                        if c["lineno"] == lineno:
                            return c["ts"], lineno, path
        return None, None, None

    t0, l0, p0 = first_exec_ts(ROLE_ANOLIX)
    t1, l1, p1 = first_exec_ts(ROLE_RUNC_RUN)
    t2, l2, p2 = first_exec_ts(ROLE_CONTAINER)
    exits = [c for c in calls if c["kind"] == "exit"]
    t3 = max((c["ts"] for c in exits), key=ts_to_us) if exits else None
    l3 = max(exits, key=lambda c: ts_to_us(c["ts"]))["lineno"] if exits else None

    def ms(a, b):
        if a is None or b is None:
            return None
        return (ts_to_us(b) - ts_to_us(a)) / 1000.0

    return {
        "T0": (t0, l0, p0), "T1": (t1, l1, p1), "T2": (t2, l2, p2), "T3": (t3, l3),
        "anolix_ms": ms(t0, t1),      # anolix 自身：起点 -> runc run 起来
        "runc_ms": ms(t1, t2),        # runc 段：runc run -> payload execve
        "payload_ms": ms(t2, t3),     # 探针+收尾：payload execve -> 最后退出
        "to_init_ms": ms(t0, t2),     # 到容器 init：起点 -> payload execve
    }


# ---------- 诊断 / ⚠️ 列表 ----------


def build_notes(edges, extra):
    """产出诊断列表：未命中的边 -> "⚠️ 未观测到"；跨进程/异常观测 -> "⚠️ 注意"。
    trace-bare.log 预期至少含：S0->S1 未命中、len=120、ns 含 CLONE_NEWTIME 共 7 个、unshare 与装载 pid 不同。"""
    notes = []
    for e in edges:
        if not e["matched"]:
            notes.append(("warn", f'未观测到 {e["id"]} {e["name"]}（规则：{e["rule"]}）——本日志无命中该规则的调用'))
    if extra["ns_count"]:
        has_time = "CLONE_NEWTIME" in extra["ns_flags"]
        fl = "|".join(extra["ns_flags"])
        notes.append(("warn", f'S1->S2 其余 ns 命中 {extra["ns_count"]} 个 CLONE_NEW*：{fl}'
                              + ("（含 CLONE_NEWTIME）" if has_time else "（不含 CLONE_NEWTIME）")))
    if extra["load_len"] is not None:
        notes.append(("warn", f'S4->S5 装载 seccomp len={extra["load_len"]}（BPF 指令条数，随策略而变）'))
    upid, lpid = extra["unshare_pid"], extra["load_pid"]
    if upid is not None and lpid is not None and upid != lpid:
        notes.append(("warn", f'命名空间 unshare 由 pid {upid} 执行，seccomp 装载由 pid {lpid} 执行——不是同一进程'))
    return notes


# ---------- 汇总模型 ----------


def analyze(path):
    """跑完整流水线，返回一个模型 dict（供文本报告 / SVG / 测试复用）。"""
    records, root_pid, stats = parse_records(path)
    calls = pair_calls(records)
    roles = build_roles(calls, root_pid)
    edges, extra = match_edges(calls, roles)
    segments = compute_segments(calls, roles)
    notes = build_notes(edges, extra)
    # openat 路径含 hpage_pmd_size 的逻辑调用（Go 运行时启动特征，验收用）
    hpage = [c for c in calls if c["syscall"] == "openat" and "hpage_pmd_size" in c["full"]]
    # 所有满足装载判据的 seccomp（应唯一）
    loads = [c for c in calls if c["syscall"] == "seccomp" and "SET_MODE_FILTER" in c["args"]
             and "len=" in c["args"] and ret_is_zero(c)]
    return {"path": path, "records": records, "calls": calls, "roles": roles,
            "edges": edges, "extra": extra, "segments": segments, "notes": notes,
            "stats": stats, "root_pid": root_pid, "hpage": hpage, "loads": loads}



# ---------- 输出① ②：文本报告（角色表 / 分段时间 / 边表 / ⚠️ 列表）----------

def _ms(v):
    return "未观测到" if v is None else f"{v:.1f} ms（≈{round(v)} ms）"


def print_text_report(m):
    roles, seg, edges, extra, notes = m["roles"], m["segments"], m["edges"], m["extra"], m["notes"]
    st = m["stats"]
    name = os.path.basename(m["path"])
    print("=" * 78)
    print(f"ktrace · 沙箱生命周期状态机（纯解释器，不 ptrace）  日志: {name}")
    print(f"  归一化: 共 {st['total']} 行 -> [pid] {st['pid']} · 裸pid {st['bare']} · 无前缀(根) {st['root']}"
          f" · 折行碎片 {st['frag']} · strace消息 {st['msg']} · 程序输出噪音 {st['noise']}")
    print(f"  根 tracee pid = {m['root_pid']}（无前缀行归属）  逻辑调用 = {len(m['calls'])} 条（已完成 unfinished/resumed 拼接）")
    print("  ⚠ 所有耗时均为『受扰时间』：ptrace 会显著拖慢被追踪进程，不得当作真实性能基线。")
    print("=" * 78)

    # ① 角色归因表
    print("\n① 角色归因表（pid -> 角色 -> 起止行号 -> 判据）")
    print("-" * 78)
    print(f"  {'pid':>8}  {'角色':<10}  {'起止行号':<16}  判据（哪条 execve / 继承）")
    for pid in sorted(p for p in roles["role"] if isinstance(p, int)):
        span = roles["span"].get(pid)
        rg = f"L{span[0]}-L{span[1]}" if span else "-"
        mark = "*" if roles["changed"].get(pid) else " "
        print(f"  {pid:>8}  {roles['role'][pid]:<10} {mark}{rg:<15}  {roles['crit'][pid]}")
    print("  （* = 该 pid 曾 execve 换过人；角色取最后一次 execve 的身份）")

    # ② 分段时间
    print("\n② 分段时间（受扰时间，非真实性能基线）")
    print("-" * 78)
    (t0, l0, p0), (t1, l1, p1), (t2, l2, p2), (t3, l3) = seg["T0"], seg["T1"], seg["T2"], seg["T3"]

    def bnd(ts, ln, path):
        return f"L{ln} {ts}" + (f' execve("{path}")' if path else " +++ exited") if ln else "未观测到"
    print(f"  边界 T0 起点(anolix)   : {bnd(t0, l0, p0)}")
    print(f"  边界 T1 runc run 起来  : {bnd(t1, l1, p1)}")
    print(f"  边界 T2 payload execve : {bnd(t2, l2, p2)}")
    print(f"  边界 T3 最后退出       : {bnd(t3, l3, None)}")
    print(f"  ── anolix 自身 (T0→T1) : {_ms(seg['anolix_ms'])}")
    print(f"  ── runc 段    (T1→T2) : {_ms(seg['runc_ms'])}")
    print(f"  ── 探针+收尾  (T2→T3) : {_ms(seg['payload_ms'])}")
    print(f"  ── 到容器 init (T0→T2): {_ms(seg['to_init_ms'])}")

    # 迁移边表（每条边挂行号 + 原文，满足硬约束 1）
    print("\n③ L3 状态机迁移边（命中行号 + 原始那一行文本）")
    print("-" * 78)
    for e in edges:
        if e["matched"]:
            print(f"  ✓ {e['id']} {e['name']:<5} pid {e['pid']}  L{e['lineno']}  {e['sig']}")
            print(f"      原文: {e['raw'].strip()}")
            if e.get("resumed_raw"):
                print(f"      拼接: {e['resumed_raw'].strip()}   (resumed 行 L{e['end_lineno']})")
            if e.get("note"):
                print(f"      备注: {e['note']}")
        else:
            print(f"  ⚠️ 未观测到 {e['id']} {e['name']}（规则：{e['rule']}）")

    # ⚠️ 诊断 / 未观测列表（原样打印）
    print("\n④ ⚠️ 诊断 / 未观测项（原样打印）")
    print("-" * 78)
    if not notes:
        print("  （无）")
    for lvl, txt in notes:
        print(f"  ⚠️ {txt}")
    print()


# ---------- 输出③：L3 状态机 SVG（复用 skscope.SVG）----------

_STATE_COLOR = [GRAY, GREEN, GREEN, BLUE, RED, RED, BLUE, PURPLE]


def _draw_header(svg, y, m):
    svg.text(50, y, "Anolix 沙箱生命周期状态机（L3）", 25, "#1f2328", weight="bold")
    svg.text(50, y + 24, f"数据源：{os.path.basename(m['path'])}（strace 日志解释器，不 ptrace、不采新数据）"
             f" · 根 tracee pid={m['root_pid']} · 逻辑调用 {len(m['calls'])} 条", 12, "#57606a")
    svg.text(50, y + 44, "⚠ 全部耗时为『受扰时间』：ptrace 拖慢被追踪进程，非真实性能基线；"
             "每条边/状态均挂真实行号，未命中者显式标 ⚠️ 未观测到（灰虚线），绝无推断补白。", 12, "#bf8700")
    return y + 62


def _draw_role_table(svg, y, m):
    roles = m["roles"]
    pids = sorted(p for p in roles["role"] if isinstance(p, int))
    svg.text(50, y, "① 角色归因表　pid → 角色 → 起止行号 → 判据", 17, "#1f2328", weight="bold")
    y += 16
    colx = [60, 170, 300, 470]
    svg.rect(50, y, 1080, 24, "#f6f8fa", rx=4)
    for x, h in zip(colx, ("pid", "角色", "起止行号", "判据（哪条 execve / 继承）")):
        svg.text(x, y + 16, h, 12, "#57606a", weight="bold")
    y += 24
    for pid in pids:
        span = roles["span"].get(pid)
        rg = f"L{span[0]}–L{span[1]}" if span else "-"
        rolecolor = {"anolix": BLUE, "runc run": AMBER, "runc init": GREEN,
                     "容器 init": RED}.get(roles["role"][pid], GRAY)
        if roles["changed"].get(pid):
            svg.rect(50, y, 1080, 20, "#fff8e1", rx=3)   # 换过人的 pid 高亮
        svg.text(colx[0], y + 14, str(pid), 12, "#1f2328", family="monospace")
        svg.text(colx[1], y + 14, roles["role"][pid], 12, rolecolor, weight="bold")
        svg.text(colx[2], y + 14, rg + ("  *换人" if roles["changed"].get(pid) else ""),
                 11, "#57606a", family="monospace")
        svg.text(colx[3], y + 14, esc(roles["crit"][pid])[:78], 11, "#57606a",
                 title=roles["crit"][pid])
        y += 20
    return y + 16


def _draw_segments(svg, y, m):
    seg = m["segments"]
    svg.text(50, y, "② 分段时间（受扰时间 · 非真实性能基线）", 17, "#1f2328", weight="bold")
    y += 10
    rows = [("anolix 自身", "T0→T1", seg["anolix_ms"], BLUE),
            ("runc 段", "T1→T2", seg["runc_ms"], AMBER),
            ("探针+收尾", "T2→T3", seg["payload_ms"], RED),
            ("到容器 init", "T0→T2", seg["to_init_ms"], PURPLE)]
    maxms = max((r[2] for r in rows if r[2] is not None), default=1) or 1
    bx, bw = 300, 560
    for label, span, ms, col in rows:
        y += 30
        svg.text(60, y, label, 13, "#1f2328", weight="bold")
        svg.text(180, y, span, 11, "#8b949e", family="monospace")
        if ms is None:
            svg.text(bx, y, "⚠️ 未观测到", 12, RED)
            continue
        w = max(4, bw * ms / maxms)
        svg.rect(bx, y - 12, w, 16, col, rx=3, op=0.85,
                 title=f"{label} 受扰耗时 {ms:.1f} ms（ptrace 拖慢，非真实基线）")
        svg.text(bx + w + 10, y, f"{ms:.1f} ms（≈{round(ms)}）", 12, "#1f2328", family="monospace")
    (t0, l0, _), (t1, l1, _), (t2, l2, _), (t3, l3) = seg["T0"], seg["T1"], seg["T2"], seg["T3"]
    y += 26
    svg.text(60, y, f"边界时刻：T0={t0}(L{l0}) · T1={t1}(L{l1}) · T2={t2}(L{l2}) · T3={t3}(L{l3})",
             11, "#57606a", family="monospace")
    return y + 24


def _draw_fsm(svg, y, m):
    """L3 状态机：竖向时间轴。节点=状态（挂进入它的边行号），边=迁移（标注 syscall 签名+行号）。
    命中=彩色实线；未命中=灰色虚线 + ⚠️ 未观测到。"""
    svg.text(50, y, "③ L3 状态机　节点=状态，边=迁移（标注触发它的 syscall 签名与行号）", 17, "#1f2328", weight="bold")
    y += 12
    bx, bw, bh, pitch = 60, 360, 58, 104
    edges = m["edges"]
    # S0 的证据 = trace 起点（第一条记录）
    first = m["records"][0] if m["records"] else None
    for i, (sid, title, desc) in enumerate(STATES):
        top = y + i * pitch
        col = _STATE_COLOR[i]
        # 进入本状态的边（S0 用起点）
        if i == 0:
            ev_ln = first["lineno"] if first else None
            ev_raw = first["raw"] if first else None
            ev_txt = f"起点 L{ev_ln}（trace 第一行）" if ev_ln else "起点"
        else:
            e = edges[i - 1]
            ev_ln = e["lineno"] if e["matched"] else None
            ev_raw = e["raw"] if e["matched"] else None
            ev_txt = f"进入证据 L{ev_ln}" if ev_ln else "⚠️ 未观测到进入证据"
        tip = f"{sid} {title}\n{desc}\n{ev_txt}" + (f"\n原文: {ev_raw.strip()}" if ev_raw else "")
        svg.rect(bx, top, bw, bh, "#ffffff", col, rx=10, sw=2, title=tip)
        svg.rect(bx, top, 6, bh, col, rx=3)
        svg.text(bx + 16, top + 22, f"{sid} · {title}", 14, "#1f2328", weight="bold")
        svg.text(bx + 16, top + 40, esc(desc)[:46], 11, "#57606a", title=desc)
        svg.text(bx + bw - 12, top + 22, ev_txt, 10, GRAY if ev_ln or i == 0 else RED,
                 anchor="end", family="monospace", weight="normal" if (ev_ln or i == 0) else "bold")
        # 迁移边：从本状态底部到下一状态顶部
        if i < len(STATES) - 1:
            e = edges[i]
            ax = bx + bw // 2
            ay1, ay2 = top + bh + 2, top + pitch - 2
            if e["matched"]:
                _arrow(svg, ax, ay1, ax, ay2, col=col)
                lx = bx + bw + 24
                svg.text(lx, ay1 + 16, e["sig"], 12, col, weight="bold",
                         title=(e["raw"].strip() + ("\n" + e["resumed_raw"].strip() if e.get("resumed_raw") else "")))
                svg.text(lx, ay1 + 32, f"L{e['lineno']} · pid {e['pid']} · {e['id']}", 10, "#57606a", family="monospace")
                svg.text(lx, ay1 + 46, esc(e["raw"].strip())[:70], 9, "#8b949e", family="monospace",
                         title=e["raw"].strip())
                if e.get("note"):
                    svg.text(lx + 470, ay1 + 16, esc(e["note"])[:40], 10, "#8b949e", title=e["note"])
            else:
                # 未命中：灰色虚线箭头 + ⚠️（不伪造行号/原文）
                svg.line(ax, ay1, ax, ay2 - 9, "#c8ccd2", 2, dash="5,4")
                svg.poly(f"{ax},{ay2} {ax-4.5},{ay2-9} {ax+4.5},{ay2-9}", "#c8ccd2")
                lx = bx + bw + 24
                svg.text(lx, ay1 + 20, f"⚠️ 未观测到 {e['id']}", 12, RED, weight="bold")
                svg.text(lx, ay1 + 36, f"规则：{esc(e['rule'])}", 10, "#8b949e", title=e["rule"])
    return y + len(STATES) * pitch + 8


def _draw_notes(svg, y, m):
    svg.text(50, y, "④ ⚠️ 诊断 / 未观测项（原样）", 17, "#1f2328", weight="bold")
    y += 8
    if not m["notes"]:
        svg.text(60, y + 16, "（无）", 12, "#57606a")
        return y + 34
    for lvl, txt in m["notes"]:
        y += 22
        for j, ln in enumerate(_wrap("⚠️ " + txt, 118)[:2]):
            svg.text(60, y + j * 16, esc(ln), 12, "#bf8700")
        y += 16 * (min(2, len(_wrap("⚠️ " + txt, 118))) - 1)
    return y + 20


def render_svg(m):
    svg = SVG(1180, 100)
    svg.rect(0, 0, 1180, 5200, "#ffffff", rx=0)   # 背景（高度随后裁剪）
    y = 44
    y = _draw_header(svg, y, m) + 18
    y = _draw_role_table(svg, y, m) + 16
    y = _draw_segments(svg, y, m) + 16
    y = _draw_fsm(svg, y, m) + 16
    y = _draw_notes(svg, y, m) + 20
    svg.h = int(y)
    return svg.render()


def write_svg_html(m, out):
    css = ("<style>" + "body{margin:0;background:#eef1f5;}"
           ".wrap{max-width:1220px;margin:24px auto;background:#fff;"
           "box-shadow:0 2px 24px rgba(27,31,36,.12);border-radius:10px;overflow:hidden;}"
           f".wrap svg{{display:block;width:100%;height:auto;font-family:{FONT};}}"
           "svg text{user-select:none;}" + "</style>")
    page = ("<!doctype html><html lang='zh'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>ktrace · 沙箱生命周期状态机</title>" + css + "</head>"
            "<body><div class='wrap'>" + render_svg(m) + "</div></body></html>")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)
    return out


# ---------- 验收：4 条单元测试（跑 trace.log 必须全绿）----------

def run_tests():
    path = os.path.join(ROOT, "trace.log")
    if not os.path.exists(path):
        print(f"✗ 找不到 {path}")
        return False
    m = analyze(path)
    roles, seg, extra = m["roles"], m["segments"], m["extra"]
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  {'✓' if cond else '✗'} {name}" + (f"  [{detail}]" if detail else ""))
        ok = ok and cond

    print("验收单元测试（trace.log）")
    print("-" * 78)

    # 测试 1：归因表重现
    print("测试 1 · 归因表重现")
    anolix_ok = all(roles["role"].get(p) == ROLE_ANOLIX for p in range(216235, 216244))
    check("pid 216235-216243 = anolix", anolix_ok,
          ",".join(str(p) for p in range(216235, 216244) if roles["role"].get(p) != ROLE_ANOLIX) or "全部命中")
    check("pid 216245 = runc run", roles["role"].get(216245) == ROLE_RUNC_RUN, str(roles["role"].get(216245)))
    check("pid 216258/216259 = runc init 相关",
          roles["role"].get(216258) == ROLE_RUNC_INIT and roles["role"].get(216259) == ROLE_RUNC_INIT,
          f"216258={roles['role'].get(216258)} 216259={roles['role'].get(216259)}")
    check("pid 216260 = 容器 init", roles["role"].get(216260) == ROLE_CONTAINER, str(roles["role"].get(216260)))

    # 测试 2：分段重现（±1ms）
    print("测试 2 · 分段时间重现（受扰时间，±1ms）")
    for label, key, want in (("anolix 自身", "anolix_ms", 42), ("runc 段", "runc_ms", 441),
                             ("探针+收尾", "payload_ms", 63), ("到容器 init", "to_init_ms", 483)):
        v = seg[key]
        check(f"{label} ≈ {want}ms", v is not None and abs(v - want) <= 1.0,
              f"实测 {v:.3f}ms" if v is not None else "未观测到")

    # 测试 3：装载点唯一命中 L9596 且 len=159；EFAULT 自检不算装载
    print("测试 3 · 装载点唯一性")
    loads = m["loads"]
    check("装载判据(len= 且 =0)全局唯一命中 1 次", len(loads) == 1, f"命中 {len(loads)} 次")
    check("装载点 = L9596", len(loads) == 1 and loads[0]["lineno"] == 9596,
          str([c["lineno"] for c in loads]))
    check("装载 len = 159", extra["load_len"] == 159, str(extra["load_len"]))
    e45 = next(e for e in m["edges"] if e["id"] == "S4->S5")
    check("S4->S5 边命中 L9596", e45["matched"] and e45["lineno"] == 9596, str(e45["lineno"]))
    selfcheck = [c for c in m["calls"] if c["syscall"] == "seccomp" and 1317 <= c["lineno"] <= 1339]
    in_load = [c for c in loads if 1317 <= c["lineno"] <= 1339]
    check("L1317-1339 EFAULT 自检存在但一条都不算装载",
          len(selfcheck) > 0 and len(in_load) == 0, f"自检 {len(selfcheck)} 条，误判 {len(in_load)} 条")

    # 测试 4：openat 路径含 hpage_pmd_size 恰好 4 次
    print("测试 4 · openat hpage_pmd_size 计数")
    check("恰好出现 4 次", len(m["hpage"]) == 4, f"实测 {len(m['hpage'])} 次 行号={[c['lineno'] for c in m['hpage']]}")

    print("-" * 78)
    print("全部通过 ✓" if ok else "存在失败 ✗")
    return ok


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="把 strace 日志推导成沙箱生命周期状态机（纯解释器）")
    ap.add_argument("logfile", nargs="?", default=os.path.join(ROOT, "trace.log"),
                    help="strace 日志路径（默认 trace.log）")
    ap.add_argument("--out", default=None, help="SVG HTML 输出路径（默认 logs/ktrace-<名>.html）")
    ap.add_argument("--test", action="store_true", help="跑 4 条验收单元测试（针对 trace.log）")
    ap.add_argument("--no-svg", action="store_true", help="只打印文本报告，不生成 SVG")
    args = ap.parse_args()

    if args.test:
        return 0 if run_tests() else 1

    if not os.path.exists(args.logfile):
        print(f"找不到日志文件: {args.logfile}", file=sys.stderr)
        return 2

    m = analyze(args.logfile)
    print_text_report(m)

    if not args.no_svg:
        stem = os.path.splitext(os.path.basename(args.logfile))[0]
        out = args.out or os.path.join(ROOT, "logs", f"ktrace-{stem}.html")
        write_svg_html(m, out)
        rel = os.path.relpath(out, ROOT)
        print(f"已生成 SVG: {rel}")
        print(f"查看:      explorer.exe {rel}    （WSL 互操作，用 Windows 浏览器打开）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
