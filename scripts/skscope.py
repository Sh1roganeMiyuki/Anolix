#!/usr/bin/env python3
# skscope.py —— 沙箱解剖图生成器（真 SVG，浏览器查看）
#
# 用法:
#   ./scripts/skscope.py                 # 生成 logs/sandbox-view.html 并打印打开命令
#   ./scripts/skscope.py --policy examples/policy.json --out logs/sandbox-view.html
#
# 每次运行 = 做一次真实操作（启动一个沙箱 -> 抓 /proc 现场 -> 清理），
# 生成一个可交互 HTML（页眉导读 + 五幅图）：
#   A. 策略地图：syscall 号码空间的三色分区（白名单直方图 / 可盖章 / >M 伪造）+ 放大镜 inset + 先预测后揭晓
#   B. 运行时解剖：宿主 vs 容器 init 的 /proc 快照对照（namespace inode 连线 + 悬停释义）
#   C. 进程模型：真实 PPid 链（容器边界 + 双 PID 身份牌）
#   D. 地址空间：分段/聚类轴（消除线性映射塌缩）+ 此刻调用栈快照
#   E. 沙箱状态机：S0→S5 可步进（状态 + 迁移 + 真实 /proc 证据）——“状态模型”的本体
#
# 交互（内嵌 JS，无需服务器）：悬停看释义 · 图 A 点按钮做预测并揭晓 · 图 E 上一步/下一步/自动播放。
# 数据全部来自真实运行：策略文件、内核头文件、/proc/<pid>/{status,ns,cgroup,maps,syscall}。
# 不含任何模拟值；图上凡是"看起来是数字"的，都能在 /proc 里查到。

import argparse
import html
import json
import math
import os
import re
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANOLIX = os.path.join(ROOT, "anolix")
ROOTFS = os.path.join(ROOT, "rootfs")
PROBE = os.path.join(ROOTFS, "probe")
NR_TABLE = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"

# ---------- 数据采集 ----------


def load_nr_table():
    name2nr, nr2name = {}, {}
    with open(NR_TABLE, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"#define\s+__NR_(\w+)\s+(\d+)", line)
            if m:
                name2nr[m.group(1)] = int(m.group(2))
                nr2name.setdefault(int(m.group(2)), m.group(1))
    return name2nr, nr2name


def read_proc(pid):
    """采集一个进程的内核状态快照（全部来自 /proc，真实值）。"""
    snap = {"pid": pid}
    with open(f"/proc/{pid}/status", encoding="utf-8") as f:
        for line in f:
            k, _, v = line.partition(":")
            snap[k.strip()] = v.strip()
    snap["ns"] = {}
    for name in sorted(os.listdir(f"/proc/{pid}/ns")):
        snap["ns"][name] = os.readlink(f"/proc/{pid}/ns/{name}")
    with open(f"/proc/{pid}/cgroup", encoding="utf-8") as f:
        snap["cgroup_path"] = f.read().strip()
    return snap


def read_chain(pid, max_depth=6):
    """从容器 init 沿 PPid 往上爬：得到宿主侧真实进程链（进程模型图的骨架）。"""
    chain, cur = [], pid
    for _ in range(max_depth):
        try:
            snap = {}
            with open(f"/proc/{cur}/status", encoding="utf-8") as f:
                for line in f:
                    k, _, v = line.partition(":")
                    snap[k.strip()] = v.strip()
            snap["pid"] = cur
            chain.append(snap)
            if cur == 1:
                break
            cur = int(snap.get("PPid", "0"))
            if cur <= 0:
                break
        except (OSError, ValueError):
            break
    chain.reverse()
    return chain


def read_maps(pid):
    """解析 /proc/<pid>/maps -> [{start, end, perms, name}]（真实地址区间）。"""
    out = []
    try:
        with open(f"/proc/{pid}/maps", encoding="utf-8") as f:
            for line in f:
                m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+\S+\s+\S+\s*(.*)", line)
                if m:
                    out.append({"start": int(m.group(1), 16), "end": int(m.group(2), 16),
                                "perms": m.group(3), "name": m.group(4).strip()})
    except OSError:
        pass
    return out


def read_syscall(pid):
    """读 /proc/<pid>/syscall：此刻的调用号 + rsp/pc（进程在用户态时返回 None）。"""
    try:
        with open(f"/proc/{pid}/syscall", encoding="utf-8") as f:
            parts = f.read().split()
        if not parts or not parts[0].isdigit():
            return None
        return {"nr": int(parts[0]), "sp": int(parts[-2], 16), "pc": int(parts[-1], 16)}
    except (OSError, ValueError):
        return None


def read_kernel_stack(pid):
    """读 /proc/<pid>/stack（内核栈符号；无权限时返回 None）。"""
    try:
        with open(f"/proc/{pid}/stack", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        return lines or None
    except OSError:
        return None


def find_probe_pid(timeout=8.0):
    """扫描 /proc/*/comm，找到容器 init 在宿主侧的 PID。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/comm", encoding="utf-8") as f:
                    if f.read().strip() == "probe":
                        return int(entry)
            except (OSError, IOError):
                continue
        time.sleep(0.2)
    return None


def run_sandbox_and_capture(policy_path):
    """启动一个真实沙箱，抓容器 init 的一整套现场（proc/进程链/地址空间/调用栈），然后干净地清理。"""
    cmd = [ANOLIX, "run", "--rootfs", ROOTFS]
    if policy_path:
        cmd += ["--policy", policy_path]
    cmd += ["--", "/probe", "hold", "300"]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        pid = find_probe_pid()
        if pid is None:
            return None, "启动后 8 秒内没找到容器 init（probe）进程"
        data = {
            "proc": read_proc(pid),       # status/ns/cgroup 快照
            "chain": read_chain(pid),     # 宿主侧进程链（进程模型）
            "maps": read_maps(pid),       # 地址空间（家底图）
            "cur": read_syscall(pid),     # 此刻的 syscall + rsp/pc（调用栈）
            "kstack": read_kernel_stack(pid),  # 内核栈符号
        }
        return data, None
    finally:
        # 清理：SIGTERM 给 anolix（它会转发并回收容器），兜底 SIGKILL。
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------- SVG 基元 ----------


def esc(s):
    return html.escape(str(s))


def _xattrs(rid=None, cls=None, onclick=None):
    """拼装可选的交互/定位属性（id / class / onclick）。"""
    a = ""
    if rid:
        a += f' id="{rid}"'
    if cls:
        a += f' class="{cls}"'
    if onclick:
        a += f' onclick="{onclick}" style="cursor:pointer"'
    return a


class SVG:
    """极小的 SVG 生成器。所有基元都支持 id/class/title/onclick，
    以便在浏览器里做悬停提示（title）与点击交互（onclick + JS）。"""

    def __init__(self, w, h):
        self.w, self.h = w, h
        self.parts = []

    def add(self, s):
        self.parts.append(s)

    def _emit(self, tag, attrs, rid, cls, onclick, title, selfclose_ok=True):
        extra = _xattrs(rid, cls, onclick)
        if title:
            self.add(f'<{tag} {attrs}{extra}><title>{esc(title)}</title></{tag}>')
        elif selfclose_ok and not extra:
            self.add(f'<{tag} {attrs}/>')
        else:
            self.add(f'<{tag} {attrs}{extra}></{tag}>')

    def gopen(self, rid=None, cls=None, onclick=None, title=None):
        extra = _xattrs(rid, cls, onclick)
        t = f'<title>{esc(title)}</title>' if title else ""
        self.add(f'<g{extra}>{t}')

    def gclose(self):
        self.add('</g>')

    def rect(self, x, y, w, h, fill, stroke="none", rx=10, sw=1, dash=None, op=1,
             rid=None, cls=None, onclick=None, title=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        attrs = (f'x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}" opacity="{op}"{d}')
        self._emit('rect', attrs, rid, cls, onclick, title)

    def text(self, x, y, s, size=14, fill="#1f2328", anchor="start", weight="normal", family=None,
             rid=None, cls=None, onclick=None, title=None):
        fam = f' font-family="{family}"' if family else ""
        attrs = (f'x="{x}" y="{y}" font-size="{size}" fill="{fill}" '
                 f'text-anchor="{anchor}" font-weight="{weight}"{fam}')
        # 文本内容不能自闭合，单独处理
        extra = _xattrs(rid, cls, onclick)
        t = f'<title>{esc(title)}</title>' if title else ""
        self.add(f'<text {attrs}{extra}>{t}{esc(s)}</text>')

    def line(self, x1, y1, x2, y2, stroke, sw=1, dash=None,
             rid=None, cls=None, onclick=None, title=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        attrs = f'x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="{sw}"{d}'
        self._emit('line', attrs, rid, cls, onclick, title)

    def circle(self, cx, cy, r, fill, stroke="none", sw=1,
               rid=None, cls=None, onclick=None, title=None):
        attrs = f'cx="{cx}" cy="{cy}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"'
        self._emit('circle', attrs, rid, cls, onclick, title)

    def poly(self, points, fill, stroke="none", sw=1,
             rid=None, cls=None, onclick=None, title=None):
        attrs = f'points="{points}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"'
        self._emit('polygon', attrs, rid, cls, onclick, title)

    def render(self):
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" '
                f'width="{self.w}" height="{self.h}">\n' + "\n".join(self.parts) + "\n</svg>")


FONT = "'Microsoft YaHei','Noto Sans CJK SC',system-ui,sans-serif"
GREEN, YELLOW, RED, GRAY, PURPLE = "#2ea043", "#d4a72c", "#cf222e", "#8b949e", "#8250df"
BLUE, AMBER, LIGHT = "#0969da", "#bf8700", "#eaeef2"


def human_bytes(n):
    """字节数 -> 人话（用于地址空间空洞/区间大小标注）。"""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            return (f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}")
        n /= 1024
    return f"{n:.1f}PB"


# ---------- 图 A：策略地图 ----------


def pick_examples(allowed_set, m_max, nr2name, max_nr):
    """为“先预测后揭晓”选三个有代表性的真实 syscall（各命中一档）。"""
    allow_nr = next((n for n in (0, 1, 39, 3, 11) if n in allowed_set),
                    (min(allowed_set) if allowed_set else 0))
    policy_nr = next((n for n in range(0, m_max + 1) if n not in allowed_set and n in nr2name), None)
    fake_nr = next((n for n in range(m_max + 1, max_nr + 8) if n in nr2name), m_max + 1)
    out = [(allow_nr, nr2name.get(allow_nr, "?"))]
    if policy_nr is not None:
        out.append((policy_nr, nr2name.get(policy_nr, "?")))
    out.append((fake_nr, nr2name.get(fake_nr, "?")))
    return out


def draw_policy_map(svg, y0, policy, nr2name, max_nr=470):
    """图 A：策略地图。白名单改为按号段分箱的直方图（避免竖条糊成一团），
    再用一个放大镜 inset 把窄窄的 >M 伪造区拉宽，最后配一组先预测后揭晓小题。"""
    errno_ret = policy["errnoRet"]
    allowed = policy["allowed"]
    allowed_set = set(allowed)
    m_max = max(allowed) if allowed else 0

    x0, x1 = 70, 1130
    bw = x1 - x0
    h = 70
    binw = 10

    def px(nr):
        return x0 + bw * nr / max_nr

    svg.text(x0, y0 - 34, "图 A · 策略地图：你的策略把 syscall 号码空间切成了三块", 17, "#1f2328", weight="bold")
    svg.text(x0, y0 - 14, f"策略: errnoRet={errno_ret} · 白名单 {len(allowed)} 条 · M={m_max}（最大放行号）· 号码空间 0–{max_nr}", 12, "#57606a")

    # 背景三色带：≤M 黄（可盖章区） / >M 红（伪造区）
    svg.rect(x0, y0, px(m_max) - x0, h, "#fff8e1", rx=0)
    svg.rect(px(m_max), y0, x1 - px(m_max), h, "#ffebe9", rx=0)

    # 白名单直方图：按 binw 号段聚合，柱高 ∝ 该段放行个数（消除竖条重叠）
    nb = max_nr // binw + 1
    counts = [0] * nb
    members = [[] for _ in range(nb)]
    for nr in allowed:
        b = min(nr // binw, nb - 1)
        counts[b] += 1
        members[b].append(nr2name.get(nr, str(nr)))
    cmax = max(counts) if counts else 1
    base = y0 + h - 6
    maxh = h - 18
    for b in range(nb):
        if counts[b] == 0:
            continue
        bx0, bx1 = px(b * binw), px(min((b + 1) * binw, max_nr))
        bh = max(4, counts[b] / cmax * maxh)
        lo, hi = b * binw, min((b + 1) * binw - 1, max_nr)
        tip = f"号段 {lo}–{hi}：放行 {counts[b]} 个 / 共 {hi - lo + 1} 号\n" + "、".join(members[b])
        svg.rect(bx0 + 0.6, base - bh, max(bx1 - bx0 - 1.2, 1.6), bh, GREEN, rx=1, op=0.85, title=tip)

    # 边框 + M 分界线
    svg.rect(x0, y0, bw, h, "none", "#d0d7de", rx=0)
    svg.line(px(m_max), y0 - 8, px(m_max), y0 + h + 8, RED, 2, dash="5,4")
    svg.text(px(m_max) + 6, y0 - 12, f"M = {m_max}", 13, RED, weight="bold")

    # 端点与刻度
    for nr in range(0, max_nr + 1, 50):
        svg.line(px(nr), y0 + h, px(nr), y0 + h + 5, "#8b949e")
        svg.text(px(nr), y0 + h + 20, str(nr), 11, "#57606a", anchor="middle")

    # 三色带读法（图例式）
    lg = y0 + h + 40
    for dx, col, lab in ((0, GREEN, f"绿柱 = 白名单放行（{len(allowed)} 条，柱高=该号段个数）"),
                         (370, "#d4a72c", "黄底 = ≤M 未放行 → 盖章 errnoRet"),
                         (700, RED, "红底 = >M → 一律伪造 ENOSYS(38)")):
        svg.rect(x0 + dx, lg - 10, 14, 14, col, rx=2)
        svg.text(x0 + dx + 20, lg + 2, lab, 12, "#57606a")

    # ── 放大镜 inset：把 M 附近的尾巴拉宽，红区才看得清 ──
    lo = max(0, m_max - 25)
    inset_y = lg + 34
    inset_h = 46

    def ipx(nr):
        return x0 + bw * (nr - lo) / (max_nr - lo)

    svg.text(x0, inset_y - 12, f"🔍 放大镜 · M 附近（{lo}–{max_nr}）：红区其实只有 {max_nr - m_max} 档，却是最反直觉的一块", 12, "#57606a", weight="bold")
    # 在主条上框出“被放大的区段”（避免长斜引线穿过图例）
    svg.rect(px(lo), y0 - 4, px(max_nr) - px(lo), h + 8, "none", BLUE, rx=3, sw=1.5, dash="4,3",
             title=f"这一段（{lo}–{max_nr}）已放大到下方")
    svg.rect(x0, inset_y, ipx(m_max) - x0, inset_h, "#fff8e1", rx=0)
    svg.rect(ipx(m_max), inset_y, x1 - ipx(m_max), inset_h, "#ffebe9", rx=0)
    for nr in allowed:
        if nr >= lo:
            svg.line(ipx(nr), inset_y + 4, ipx(nr), inset_y + inset_h - 4, GREEN, 3,
                     title=f"{nr} {nr2name.get(nr, '')}（放行）")
    svg.rect(x0, inset_y, bw, inset_h, "none", "#d0d7de", rx=0)
    svg.line(ipx(m_max), inset_y - 6, ipx(m_max), inset_y + inset_h + 6, RED, 2, dash="5,4")
    svg.text(ipx(m_max) - 6, inset_y - 8, f"M={m_max}", 12, RED, anchor="end", weight="bold")
    for nr in range(lo - lo % 10, max_nr + 1, 10):
        if nr < lo:
            continue
        svg.line(ipx(nr), inset_y + inset_h, ipx(nr), inset_y + inset_h + 4, "#8b949e")
        svg.text(ipx(nr), inset_y + inset_h + 16, str(nr), 10, "#57606a", anchor="middle")
    svg.text((ipx(m_max) + x1) / 2, inset_y + inset_h / 2 + 4, "> M → 伪造 ENOSYS(38)", 12, RED, anchor="middle", weight="bold",
             title="libseccomp 内建：超界号码一律返回 38，改 errnoRet 无效")

    # ── 先预测后揭晓：三道小题（点击按钮 → JS 对照真实路线） ──
    qy = inset_y + inset_h + 46
    svg.text(x0, qy, "先预测后揭晓：这三个真实 syscall 在沙箱里各走哪一档？先点你的猜测，再对答案", 13, "#1f2328", weight="bold")
    examples = pick_examples(allowed_set, m_max, nr2name, max_nr)
    btns = (("allow", "放行", 90), ("policy", f"策略章 errno={errno_ret}", 168), ("fake", "伪造 ENOSYS(38)", 150))
    for i, (nr, nm) in enumerate(examples):
        ry = qy + 22 + i * 34
        svg.rect(x0, ry - 15, bw, 30, "#ffffff", "#eaeef2", rx=8)
        svg.text(x0 + 14, ry + 5, f"/sysc {nr}", 13, "#1f2328", family="monospace", weight="bold")
        svg.text(x0 + 108, ry + 5, f"({nm})", 12, "#57606a")
        bx = x0 + 230
        for k, lab, wbtn in btns:
            svg.rect(bx, ry - 13, wbtn, 26, "#f6f8fa", "#d0d7de", rx=6,
                     rid=f"qbtn{i}_{k}", onclick=f"skGuess({i},{nr},'{k}')", title="点它做出你的预测")
            svg.text(bx + wbtn / 2, ry + 5, lab, 12, "#1f2328", anchor="middle",
                     onclick=f"skGuess({i},{nr},'{k}')")
            bx += wbtn + 10
        svg.text(bx + 10, ry + 5, "？", 13, "#8b949e", rid=f"qlbl{i}")

    return qy + 22 + len(examples) * 34 + 14


# ---------- 图 B：运行时解剖 ----------


def ns_short(v):
    m = re.search(r"\[(\d+)\]", v)
    return m.group(1) if m else v


def cap_short(v):
    return ("0x" + v[:4] + "…" + v[-4:]) if len(v) > 10 else v


# 字段悬停释义（把 /proc 术语翻译成初学者听得懂的话 + 一致比喻）
FIELD_HINT = {
    "进程": "宿主侧看到的 PID 与进程名",
    "pid ns": "PID 命名空间的 inode 号——同一本‘户口册’则号相同",
    "mnt ns": "挂载命名空间 inode——‘账本身份证’，号不同=两本账",
    "net ns": "网络命名空间 inode——网卡/路由/端口表是否独立",
    "ipc ns": "IPC 命名空间 inode——信号量/共享内存是否独立",
    "uts ns": "UTS 命名空间 inode——hostname/domainname 是否独立",
    "cgroup ns": "cgroup 命名空间 inode——cgroup 根视图是否独立",
    "user ns": "用户命名空间 inode——UID/GID 映射是否独立",
    "cgroup": "所属 cgroup 路径（资源账本的落点）",
    "Seccomp": "0=未装载（无系统调用过滤）；2=过滤器已装载（每次 syscall 过安检站）",
    "NoNewPrivs": "1=禁止通过 execve/setuid 提权（装 seccomp 的前置开关）",
    "CapEff": "有效能力位掩码；满值≈root 全权，0=普通进程无特权",
}

# 进程状态字母（/proc/<pid>/status 的 State）释义
STATE_HINT = {
    "R": "R = running/runnable，正在跑或在就绪队列等 CPU",
    "S": "S = 可中断睡眠，在等一个事件（如 epoll 等 fd 就绪）",
    "D": "D = 不可中断睡眠，通常卡在磁盘/内核 IO",
    "Z": "Z = 僵尸，已退出但父进程尚未 wait 收尸",
    "T": "T = 已停止（被 SIGSTOP/调试器暂停）",
}


def draw_anatomy(svg, y0, host, cont, nr2name):
    w_total = 1060
    x0 = 70
    card_w, gap = 430, 60
    lx = x0
    rx = x0 + card_w + gap
    line_h = 44
    pad = 24

    svg.text(x0, y0 - 18, "图 B · 运行时解剖：宿主进程 vs 容器 init（同一时刻的真实 /proc 快照）", 17, "#1f2328", weight="bold")

    # 行定义：(标签, 取值函数)
    rows = [
        ("进程", lambda s: f"PID={s['pid']}  {s.get('Name', '?')}"),
        ("pid ns", lambda s: ns_short(s["ns"].get("pid", "?"))),
        ("mnt ns", lambda s: ns_short(s["ns"].get("mnt", "?"))),
        ("net ns", lambda s: ns_short(s["ns"].get("net", "?"))),
        ("ipc ns", lambda s: ns_short(s["ns"].get("ipc", "?"))),
        ("uts ns", lambda s: ns_short(s["ns"].get("uts", "?"))),
        ("cgroup ns", lambda s: ns_short(s["ns"].get("cgroup", "?"))),
        ("user ns", lambda s: ns_short(s["ns"].get("user", "?"))),
        ("cgroup", lambda s: s["cgroup_path"].split("::")[-1].split("/")[-1][:38]),
        ("Seccomp", lambda s: s.get("Seccomp", "?") + (" （过滤器已装载）" if s.get("Seccomp") == "2" else " （未装载）")),
        ("NoNewPrivs", lambda s: s.get("NoNewPrivs", "?")),
        ("CapEff", lambda s: cap_short(s.get("CapEff", "?"))),
    ]
    card_h = pad * 2 + line_h * len(rows)

    for side, x, snap, title, tc in (
        ("host", lx, host, "宿主（本例为生成器自身进程）", "#57606a"),
        ("cont", rx, cont, "容器 init（沙箱内）", "#1a7f37"),
    ):
        svg.rect(x, y0, card_w, card_h, "#ffffff", "#d0d7de", rx=14)
        svg.rect(x, y0, card_w, 44, "#f6f8fa", rx=14)
        svg.rect(x, y0 + 30, card_w, 14, "#f6f8fa", rx=0)
        svg.text(x + pad, y0 + 28, title, 14, tc, weight="bold")

    # 中间连线：namespace 隔离对照
    mid_x = lx + card_w + gap / 2
    for i, (label, fn) in enumerate(rows):
        cy = y0 + 44 + pad + line_h * i + line_h / 2 - 6
        for x, snap in ((lx, host), (rx, cont)):
            svg.line(x + pad, cy + 14, x + card_w - pad, cy + 14, "#eaeef2", 1)
            svg.text(x + pad, cy - 2, label, 12, "#8b949e", title=FIELD_HINT.get(label))
            val = fn(snap)
            danger = side_bad(label, snap)
            svg.text(x + pad + 96, cy - 2, val, 13,
                     RED if danger else "#1f2328", weight="bold" if label in ("Seccomp", "NoNewPrivs", "CapEff") else "normal",
                     title=FIELD_HINT.get(label))
        # ns 行画隔离连线
        if label.endswith("ns"):
            hv, cv = host["ns"].get(label[:-3].strip()), cont["ns"].get(label[:-3].strip())
            if hv is not None and cv is not None:
                same = hv == cv
                color = GRAY if same else GREEN
                svg.line(lx + card_w, cy - 2, rx, cy - 2, color, 2 if not same else 1, dash=None if not same else "4,4")
                tag = "共享" if same else "隔离"
                svg.text(mid_x, cy - 8, tag, 12, color, anchor="middle", weight="bold")

    # 底部注脚
    svg.text(x0, y0 + card_h + 30,
             "读法：同一进程树里，灰虚线=与宿主同一个 namespace（共享）；绿实线=独立 namespace（inode 不同，隔离）。"
             "把每个 ns 想成一本‘账本’，inode 号就是账本身份证——号不同即两本账。", 12, "#57606a")
    svg.text(x0, y0 + card_h + 50,
             "想亲手验证拦截：另开终端跑 ./scripts/kstate.py <syscall号>（它会起沙箱、先预判路线、再实测对照）。", 12, "#57606a")
    return y0 + card_h + 62


def side_bad(label, snap):
    """给'危险/无防护的默认值'标红：Seccomp=0（无过滤）、CapEff 满值（root 全权）。"""
    if label == "Seccomp":
        return snap.get("Seccomp") == "0"
    if label == "CapEff":
        try:
            # 置位能力多于 20 个 ≈ 接近 root 全权，视为危险默认值
            return bin(int(snap.get("CapEff", "0"), 16)).count("1") > 20
        except ValueError:
            return False
    return False


# ---------- 图 C：进程模型（真实 PPid 链） ----------


def draw_process_model(svg, y0, chain):
    """进程模型图：你敲下命令后真实产生的进程链（数据=宿主侧 PPid 实测）。"""
    svg.text(70, y0 - 18, "图 C · 进程模型：你敲命令后的真实进程链（宿主侧 PPid 实测）", 17, "#1f2328", weight="bold")
    chain = chain[-5:]  # 只展示最靠近容器 init 的 5 环
    if not chain:
        svg.text(70, y0 + 40, "（容器已退出，链不可见）", 14, "#57606a")
        return y0 + 60

    node_w, node_h, gapx = 184, 112, 50
    x = (1200 - (len(chain) * node_w + (len(chain) - 1) * gapx)) / 2

    def in_container(s):
        return len(s.get("NSpid", "").split()) >= 2

    for i, s in enumerate(chain):
        cont_here = in_container(s)
        nspid_all = s.get("NSpid", "").split()
        node_tip = (f"{s.get('Name', '?')}｜宿主 PID {s['pid']}"
                    + (f"｜容器内 PID {nspid_all[-1]}" if len(nspid_all) >= 2 else "")
                    + f"｜状态 {s.get('State', '?').strip()}")
        svg.rect(x, y0, node_w, node_h, "#ffffff", GREEN if cont_here else "#d0d7de",
                 rx=12, sw=2 if cont_here else 1, title=node_tip)
        svg.text(x + 16, y0 + 30, s.get("Name", "?"), 16, "#1f2328", weight="bold")
        svg.text(x + 16, y0 + 54, f"宿主 PID {s['pid']}", 12, "#57606a")
        nspid = s.get("NSpid", "").split()
        if len(nspid) >= 2:
            svg.text(x + 16, y0 + 76, f"容器内 PID {nspid[-1]}", 13, GREEN, weight="bold")
        else:
            svg.text(x + 16, y0 + 76, "（单层 PID 视图）", 12, "#8b949e")
        st = (s.get("State", "?") + " ")[0]
        svg.text(x + 16, y0 + 98, f"状态 {st}", 12, "#57606a", title=STATE_HINT.get(st, "进程状态字母"))

        if i < len(chain) - 1:
            ax0, ax1, ay = x + node_w + 6, x + node_w + gapx - 6, y0 + node_h / 2
            svg.line(ax0, ay, ax1 - 8, ay, "#8b949e", 2)
            svg.add(f'<polygon points="{ax1},{ay} {ax1-9},{ay-4.5} {ax1-9},{ay+4.5}" fill="#8b949e"/>')
            svg.text((ax0 + ax1) / 2, ay - 10, "fork/exec", 11, "#8b949e", anchor="middle")
            # 容器边界：目标节点首次拥有“容器内 PID”时，画一道红线
            if in_container(chain[i + 1]) and not in_container(s):
                bx = (ax0 + ax1) / 2
                svg.line(bx, y0 - 30, bx, y0 + node_h + 34, RED, 2, dash="6,5")
                svg.text(bx, y0 - 38, "容器边界（clone 进新命名空间）", 12, RED, anchor="middle", weight="bold")
        x += node_w + gapx

    svg.text(70, y0 + node_h + 56,
             "读法：绿色框 = 容器内的进程——同一个 task_struct 挂着两副 PID 身份牌（宿主侧一个、容器内一个）；"
             "红虚线 = 世界切换点。", 12, "#57606a")
    svg.text(70, y0 + node_h + 76,
             "状态字母（悬停节点可看释义）：R=在跑/可跑 · S=可中断睡眠（等事件，如 epoll） · D=不可中断睡眠 · Z=僵尸 · T=已停", 12, "#8b949e")
    return y0 + node_h + 90


# ---------- 图 D：地址空间与调用栈（真实 maps + syscall） ----------


def addr_color(m):
    """根据 perms/name 给地址区间分类上色，返回 (颜色, 类别名)。"""
    nm, p = m["name"], m["perms"]
    if nm == "[stack]":
        return GREEN, "用户栈"
    if nm == "[heap]":
        return AMBER, "堆(brk)"
    if nm in ("[vvar]", "[vvar_vclock]", "[vdso]"):
        return PURPLE, "vDSO/vvar"
    if p.startswith("---"):
        return "#d8dee4", "保留/守护页(未提交)"
    if "x" in p:
        return BLUE, "代码段 r-x"
    if "w" in p:
        return "#54aeff" if not nm else AMBER, ("匿名 rw(堆/goroutine 栈)" if not nm else "数据段 rw")
    return GRAY, "只读数据 r--"


def cluster_maps(maps, gap_threshold=1 << 24):
    """按地址邻近度聚簇：相邻区间空洞 ≤ gap_threshold 则归为一簇（降序返回，高地址在前）。"""
    clusters = []
    for m in sorted(maps, key=lambda x: x["start"]):
        if clusters and m["start"] - clusters[-1]["hi"] <= gap_threshold:
            c = clusters[-1]
            c["maps"].append(m)
            c["hi"] = max(c["hi"], m["end"])
        else:
            clusters.append({"lo": m["start"], "hi": m["end"], "maps": [m]})
    clusters.reverse()  # 高地址在前（画在顶部）
    for c in clusters:
        c["maps"].sort(key=lambda x: x["start"], reverse=True)
    return clusters


def cluster_label(cm):
    """给一个地址簇起个初学者看得懂的名字。"""
    names = {m["name"] for m in cm["maps"]}
    if "[stack]" in names:
        return "用户栈 [stack]", "函数调用/局部变量的领地，向下生长"
    if names & {"[vdso]", "[vvar]", "[vvar_vclock]"}:
        return "mmap 区 · 匿名映射 + vDSO/vvar", "goroutine 栈、运行时保留区；vDSO=内核放的用户态只读页"
    if any(m["name"].startswith("/") for m in cm["maps"]):
        binname = next(m["name"] for m in cm["maps"] if m["name"].startswith("/"))
        return f"程序映像 {binname}", "代码段(r-x) + 只读数据(r--) + 数据段(rw)"
    return "堆竞技场 / 匿名 mmap", "runtime 管理的堆与保留地址（大段 ---p 未提交）"


def draw_address_space(svg, y0, maps, cur, kstack, nr2name):
    """地址空间家底图（分段/聚类轴，消除塔缩）+ 此刻调用栈快照。
    数据=真实 /proc/<pid>/maps 与 syscall；空洞与区间大小都是实测值。"""
    svg.text(70, y0 - 18, "图 D · 地址空间与调用栈：进程的家底全图（真实 /proc/<pid>/maps）", 17, "#1f2328", weight="bold")
    svg.text(70, y0 + 4, "轴是“分段”的：真实地址空间稀疏而空洞巨大，按线性比例会把所有区间压成薄片——这里把空洞折叠，保留真实大小标注", 12, "#8b949e")
    if not maps:
        svg.text(90, y0 + 60, "（maps 不可读）", 14, "#57606a")
        return y0 + 80

    bar_x, bar_w = 90, 130
    y_top, y_bot = y0 + 60, y0 + 600
    clusters = cluster_maps(maps)
    nc = len(clusters)
    gap_h = 28
    avail = (y_bot - y_top) - max(nc - 1, 0) * gap_h
    minh = 46
    weights = [max(2, len(c["maps"])) for c in clusters]
    wsum = sum(weights)
    heights = [max(minh, avail * w / wsum) for w in weights]
    over = sum(heights) - avail
    if over > 0:
        shrink = [i for i, hh in enumerate(heights) if hh > minh]
        tot = sum(heights[i] - minh for i in shrink)
        if tot > 0:
            for i in shrink:
                heights[i] -= over * (heights[i] - minh) / tot

    svg.text(bar_x + bar_w / 2, y_top - 12, "高地址 ↑", 11, "#8b949e", anchor="middle")
    cy = y_top
    band_of = []  # 记录每簇的 (by0, by1) 供 rsp 定位
    for idx, cm in enumerate(clusters):
        bh = heights[idx]
        by0, by1 = cy, cy + bh
        band_of.append((cm, by0, by1))
        # 簇内逐段（高度 ∵ log(size)，避免小区间消失）
        ws = [max(1.0, math.log10(max(m["end"] - m["start"], 1) + 1)) for m in cm["maps"]]
        wtot = sum(ws)
        sy = by0
        for m, w in zip(cm["maps"], ws):
            sh = max(2, bh * w / wtot)
            col, cat = addr_color(m)
            tip = (f"{m['name'] or '(匿名)'}  {m['perms']}\n"
                   f"0x{m['start']:x}–0x{m['end']:x}  {human_bytes(m['end'] - m['start'])}\n{cat}")
            svg.rect(bar_x, sy, bar_w, sh, col, rx=1, title=tip)
            sy += sh
        svg.rect(bar_x, by0, bar_w, bh, "none", "#d0d7de", rx=3)
        # 右侧标注
        title, note = cluster_label(cm)
        committed = sum(m["end"] - m["start"] for m in cm["maps"] if not m["perms"].startswith("---"))
        tx = bar_x + bar_w + 26
        svg.text(tx, by0 + 18, title, 13, "#1f2328", weight="bold")
        svg.text(tx, by0 + 36, f"0x{cm['lo']:x} – 0x{cm['hi']:x}　{len(cm['maps'])} 段　已提交 ≈{human_bytes(committed)}", 11, "#57606a", family="monospace")
        svg.text(tx, by0 + 54, note, 11, "#8b949e")
        cy = by1
        # 簇间空洞断裂标记
        if idx < nc - 1:
            nxt = clusters[idx + 1]
            gap = cm["lo"] - nxt["hi"]
            gy = cy + gap_h / 2
            svg.line(bar_x, gy, bar_x + bar_w, gy, "#d0d7de", 1, dash="4,3")
            svg.text(bar_x + bar_w / 2, gy - 4, "⋯", 14, "#8b949e", anchor="middle")
            svg.text(bar_x + bar_w + 26, gy + 4, f"⬆⬇ 地址空洞 ≈ {human_bytes(gap)}（未映射，被折叠）", 11, "#8b949e")
            cy += gap_h
    svg.text(bar_x + bar_w / 2, y_bot + 20, "低地址 ↓", 11, "#8b949e", anchor="middle")

    # rsp 游标：指向包含它的簇（通常就是用户栈）
    if cur and cur.get("sp"):
        for cm, by0, by1 in band_of:
            if cm["lo"] <= cur["sp"] <= cm["hi"]:
                ym = (by0 + by1) / 2
                svg.line(bar_x - 12, ym, bar_x - 2, ym, RED, 1.5, dash="4,3")
                svg.poly(f"{bar_x-2},{ym} {bar_x-9},{ym-4} {bar_x-9},{ym+4}", RED)
                svg.text(bar_x - 16, ym + 4, "当前rsp", 11, RED, anchor="end",
                         title=f"当前 rsp = 0x{cur['sp']:x}（落在用户栈里）")
                break

    # 类别色图例
    legend = []
    seen = set()
    for m in maps:
        col, cat = addr_color(m)
        if cat not in seen:
            seen.add(cat)
            legend.append((col, cat))
    lx = bar_x
    ly = y_bot + 40
    for col, cat in legend:
        svg.rect(lx, ly - 9, 12, 12, col, rx=2)
        svg.text(lx + 17, ly + 1, cat, 11, "#57606a")
        lx += 30 + 12 * len(cat)
        if lx > 560:
            lx = bar_x
            ly += 20

    # 右侧：此刻调用栈快照卡
    cx, cw2 = 660, 470
    card_h = 340
    svg.rect(cx, y_top, cw2, card_h, "#ffffff", "#d0d7de", rx=14)
    svg.rect(cx, y_top, cw2, 40, "#f6f8fa", rx=14)
    svg.rect(cx, y_top + 26, cw2, 14, "#f6f8fa", rx=0)
    svg.text(cx + 20, y_top + 26, "此刻快照：进程正在内核里做什么", 15, "#1f2328", weight="bold")
    yy = y_top + 66
    if cur:
        svg.text(cx + 20, yy, f"系统调用: nr={cur['nr']}（{nr2name.get(cur['nr'], '?')}）", 13, "#1f2328",
                 title="进程此刻陷在内核里执行的那个 syscall")
        yy += 22
        svg.text(cx + 20, yy, f"rsp=0x{cur['sp']:x}   rip=0x{cur['pc']:x}", 12, "#57606a", family="monospace")
        yy += 30
    else:
        svg.text(cx + 20, yy, "（此刻在用户态运行，未陷入内核）", 13, "#57606a")
        yy += 30
    svg.text(cx + 20, yy, "内核栈（真实符号，/proc/<pid>/stack）：", 13, "#1f2328")
    yy += 22
    if kstack:
        for line in kstack[:7]:
            svg.text(cx + 20, yy, line[:74], 11, "#57606a", family="monospace")
            yy += 17
    else:
        svg.text(cx + 20, yy, "（不可读——需要 root/CAP_SYS_ADMIN 权限）", 12, "#8b949e")
        yy += 17
    svg.text(cx + 20, y_top + card_h - 16, "提示：重跑本脚本会重新采集一帧，多跑几次能看到 rsp/syscall 变化", 11, "#8b949e")

    return max(y_bot + 40 + (ly - (y_bot + 40)) + 24, y_top + card_h + 20)


# ---------- 页眉导读 + 图 E：可步进状态机 ----------


def _wrap(s, units):
    """按显示宽度折行（CJK 算 2 列），用于框内文本。"""
    out, line, w = [], "", 0
    for ch in s:
        cw = 2 if ord(ch) > 0x2E7F else 1
        if w + cw > units:
            out.append(line)
            line, w = "", 0
        line += ch
        w += cw
    if line:
        out.append(line)
    return out


def _arrow(svg, x1, y1, x2, y2, label=None, col="#8b949e"):
    """画一个带箭头的迁移边，可带边标签（触发条件）。"""
    svg.line(x1, y1, x2, y2, col, 2)
    ang = math.atan2(y2 - y1, x2 - x1)
    L = 9
    p1 = (x2 - L * math.cos(ang - 0.42), y2 - L * math.sin(ang - 0.42))
    p2 = (x2 - L * math.cos(ang + 0.42), y2 - L * math.sin(ang + 0.42))
    svg.poly(f"{x2:.1f},{y2:.1f} {p1[0]:.1f},{p1[1]:.1f} {p2[0]:.1f},{p2[1]:.1f}", col)
    if label:
        svg.text((x1 + x2) / 2, (y1 + y2) / 2 - 8, label, 11, col, anchor="middle", weight="bold")


def draw_header(svg, y0, cont, n_iso, n_ns):
    """页眉导读：说清数据来源、三层认知、以及可交互点。返回底部 y。"""
    svg.text(70, y0, "Anolix 沙箱解剖图", 26, "#1f2328", weight="bold")
    svg.text(70, y0 + 26,
             "每张图的数字都来自一次真实运行：策略文件 + 内核头文件 + /proc/<pid>/{status,ns,cgroup,maps,syscall}。凡看起来是数字的，都能在 /proc 里查到。",
             12, "#57606a")
    svg.text(70, y0 + 48,
             "三层认知：符号层（图 A・syscall 号码与策略）→ 现场层（图 B/C/D・真实 /proc 快照）→ 机制层（图 E・状态机模型）。",
             12, "#0969da")
    svg.text(70, y0 + 70,
             "🖱 悬停看释义 · 🔘 图 A 点按钮做预测并揭晓 · ⏯ 图 E 可逐步播放沙箱一生（本次：隔离 "
             f"{n_iso}/{n_ns} 个 namespace・Seccomp={cont.get('Seccomp')}・NoNewPrivs={cont.get('NoNewPrivs')}）",
             12, "#8b949e")
    return y0 + 84


def draw_state_machine(svg, y0, host, cont, policy, data, nr2name):
    """图 E：把一次沙箱运行画成可步进的状态机 S0→S5（状态 + 迁移 + 真实证据）。
    这是‘状态模型’的本体：图 B/C/D 只是其中某一帧的快照。"""
    errno_ret = policy["errnoRet"]
    m_max = max(policy["allowed"]) if policy["allowed"] else 0
    mnt_h = ns_short(host["ns"].get("mnt", "?"))
    mnt_c = ns_short(cont["ns"].get("mnt", "?"))
    n_iso = sum(1 for k in cont["ns"] if host["ns"].get(k) != cont["ns"].get(k))
    n_ns = len(cont["ns"])
    cur = data.get("cur")
    cur_txt = f"nr={cur['nr']} ({nr2name.get(cur['nr'], '?')})" if cur else "此刻在用户态"
    binname = next((m["name"] for m in data.get("maps", []) if m["name"].startswith("/")), "/probe")

    svg.text(70, y0 - 18, "图 E · 沙箱状态机：一次运行真实经历的状态迁移（可步进）", 17, "#1f2328", weight="bold")

    states = [
        {"title": "宿主态", "hc": GRAY,
         "desc": "anolix/runc 在宿主上，和大家共用宿主的 namespace，没有 seccomp。",
         "ev": [f"Seccomp={host.get('Seccomp')}（未装载）", f"NoNewPrivs={host.get('NoNewPrivs')}", f"mnt ns={mnt_h}"],
         "edge": "clone(CLONE_NEW*)"},
        {"title": "世界切换", "hc": GREEN,
         "desc": "runc clone 出子进程，一次切进新的 pid/mnt/net/ipc/uts/cgroup/user 命名空间。",
         "ev": [f"隔离 {n_iso}/{n_ns} 个 namespace", f"mnt ns={mnt_c}", "进程链出现「容器内 PID 1」"],
         "edge": "prctl + seccomp"},
        {"title": "上锁（装 seccomp）", "hc": RED,
         "desc": "先置 NoNewPrivs=1，再把 BPF 过滤器装进内核——单向棘轮：装上不可卸、只增不减。",
         "ev": [f"Seccomp={cont.get('Seccomp')}（2=filter）", f"NoNewPrivs={cont.get('NoNewPrivs')}", f"CapEff={cap_short(cont.get('CapEff', '?'))}"],
         "edge": "execve(payload)"},
        {"title": "execve 拉起 payload", "hc": BLUE,
         "desc": "exec 目标程序；过滤器跨越 execve 保留，新程序一出生就带着锁。",
         "ev": [f"Name={cont.get('Name')}", f"映像={binname}", f"宿主 PID={cont.get('pid')} / 容器内 PID=1"],
         "edge": "运行，发起 syscall"},
        {"title": "运行/安检态", "hc": AMBER,
         "desc": "每次 syscall 过安检站，三档裁决：白名单放行 / ≤M 盖章 errnoRet / >M 伪造 ENOSYS。",
         "ev": [f"此刻 {cur_txt}", f"errnoRet={errno_ret} · M={m_max}", "对照见图 A / kstate.py"],
         "edge": "exit / 被信号终止"},
        {"title": "退出/析构", "hc": PURPLE,
         "desc": "进程退出，namespace 引用归零→账本析构；宿主磁盘上的目录/文件毫发无损。",
         "ev": ["引用计数归零才回收", "孤儿/ns fd 会钉住账本（泄漏）", "本脚本采集完即 SIGTERM 回收"],
         "edge": None},
    ]

    bw, bh = 340, 160
    cols = [70, 455, 840]
    row1 = y0 + 40
    row2 = row1 + bh + 74
    # 蛇形布局：S0 S1 S2 （首行左→右）；S3 S4 S5（次行右→左）
    pos = [(cols[0], row1), (cols[1], row1), (cols[2], row1),
           (cols[2], row2), (cols[1], row2), (cols[0], row2)]

    for i, st in enumerate(states):
        x, y = pos[i]
        svg.rect(x, y, bw, bh, "#ffffff", "#d0d7de", rx=12, sw=1, rid=f"stbox{i}",
                 title=st["desc"] + "\n证据：" + " ; ".join(st["ev"]))
        svg.rect(x, y, 6, bh, st["hc"], rx=3)
        svg.text(x + 16, y + 24, f"S{i} · {st['title']}", 14, "#1f2328", weight="bold")
        dy = y + 46
        for ln in _wrap(st["desc"], 46)[:3]:
            svg.text(x + 16, dy, ln, 11, "#57606a")
            dy += 15
        svg.text(x + 16, y + 98, "证据 · 真实 /proc：", 10, "#8b949e", weight="bold")
        ey = y + 113
        for e in st["ev"]:
            svg.text(x + 16, ey, e[:44], 10, "#1a7f37", family="monospace")
            ey += 14
        # “当前”徽章（初始隐藏，JS 根据步进显示）
        svg.add(f'<g id="stmark{i}" opacity="0">')
        svg.rect(x + bw - 60, y + 7, 52, 20, "#0969da", rx=10)
        svg.text(x + bw - 34, y + 21, "当前", 11, "#ffffff", anchor="middle", weight="bold")
        svg.add('</g>')
        # 高亮环（初始隐藏，JS 步进时点亮当前状态）
        svg.rect(x - 2, y - 2, bw + 4, bh + 4, "none", "#0969da", rx=13, sw=3, op=0, rid=f"string{i}")

    # 迁移边（带触发标签）
    ay1 = row1 + bh / 2
    ay2 = row2 + bh / 2
    _arrow(svg, cols[0] + bw + 4, ay1, cols[1] - 4, ay1, states[0]["edge"])
    _arrow(svg, cols[1] + bw + 4, ay1, cols[2] - 4, ay1, states[1]["edge"])
    _arrow(svg, cols[2] + bw / 2, row1 + bh + 4, cols[2] + bw / 2, row2 - 4, states[2]["edge"])
    _arrow(svg, cols[2] - 4, ay2, cols[1] + bw + 4, ay2, states[3]["edge"])
    _arrow(svg, cols[1] - 4, ay2, cols[0] + bw + 4, ay2, states[4]["edge"])

    # 控件（SVG 原生按钮 + onclick）
    btn_y = y0 - 24
    bx = 748
    for lab, oc in (("◀ 上一步", "skStep(-1)"), ("下一步 ▶", "skStep(1)"),
                    ("⏵ 自动播放", "skAuto()"), ("↺ 重置", "skReset()")):
        wbtn = 96
        svg.rect(bx, btn_y - 16, wbtn, 26, "#f6f8fa", "#d0d7de", rx=6, onclick=oc, title="点击控制状态机步进")
        svg.text(bx + wbtn / 2, btn_y + 2, lab, 12, "#1f2328", anchor="middle", onclick=oc)
        bx += wbtn + 8

    svg.text(70, row2 + bh + 30,
             "读法：每个框 = 一个状态（附真实 /proc 证据）；箭头 = 迁移，标签 = 触发该迁移的动作。点“下一步”逐步看沙箱一生。", 12, "#57606a")
    return row2 + bh + 46


# ---------- 主流程 ----------


def main():
    ap = argparse.ArgumentParser(description="沙箱解剖图生成器（真 SVG）")
    ap.add_argument("--policy", default=os.path.join(ROOT, "examples", "policy.json"))
    ap.add_argument("--out", default=os.path.join(ROOT, "logs", "sandbox-view.html"))
    args = ap.parse_args()

    for f, tip in ((ANOLIX, "anolix 二进制（先 go build -o anolix ./cmd/anolix）"),
                   (PROBE, "rootfs/probe（先 ./scripts/mkrootfs.sh）")):
        if not os.path.exists(f):
            print(f"缺少 {tip}", file=sys.stderr)
            return 2

    # 数据 1：策略
    with open(args.policy, encoding="utf-8") as f:
        cfg = json.load(f)
    sec = cfg.get("seccomp", {})
    name2nr, nr2name = load_nr_table()
    allowed = sorted(name2nr[n] for n in sec.get("allowedSyscalls", []) if n in name2nr)
    policy = {"errnoRet": sec.get("errnoRet", 1), "allowed": allowed}

    # 数据 2：真实沙箱快照（起沙箱 -> 抓一整套现场 -> 清理）
    print("启动沙箱并采集 /proc 现场 …")
    data, err = run_sandbox_and_capture(args.policy)
    if err:
        print(f"采集失败: {err}", file=sys.stderr)
        return 1
    cont = data["proc"]
    host = read_proc(os.getpid())
    n_iso = sum(1 for k in host["ns"] if host["ns"].get(k) != cont["ns"].get(k))
    n_ns = len(cont["ns"])
    errno_ret = policy["errnoRet"]
    m_max = max(allowed) if allowed else 0

    # 画图（页眉 + 五张：策略地图 / 运行时解剖 / 进程模型 / 地址空间 / 状态机）
    # 顺序布局：每张图返回自己的底部 y，下一张接着画，最后回填总高
    svg = SVG(1200, 100)
    svg.rect(0, 0, 1200, 4600, "#ffffff", rx=0)  # 背景（高度随后按实际裁剪）
    y = 56
    y = draw_header(svg, y, cont, n_iso, n_ns) + 64
    y = draw_policy_map(svg, y, policy, nr2name) + 60
    y = draw_anatomy(svg, y, host, cont, nr2name) + 60
    y = draw_process_model(svg, y, data["chain"]) + 60
    y = draw_address_space(svg, y, data["maps"], data["cur"], data["kstack"], nr2name) + 60
    y = draw_state_machine(svg, y, host, cont, policy, data, nr2name) + 30
    svg.h = int(y)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    css = ("<style>"
           "body{margin:0;background:#eef1f5;}"
           ".wrap{max-width:1240px;margin:24px auto;background:#fff;"
           "box-shadow:0 2px 24px rgba(27,31,36,.12);border-radius:10px;overflow:hidden;}"
           f".wrap svg{{display:block;width:100%;height:auto;font-family:{FONT};}}"
           "svg text{-webkit-user-select:none;user-select:none;}"
           "svg [onclick]:hover{filter:brightness(.95);}"
           "</style>")
    js = (
        "<script>"
        f"var SK_ALLOWED=new Set({json.dumps(sorted(set(allowed)))});"
        f"var SK_M={m_max},SK_ERRNO={errno_ret},SK_NSTATES=6,skCur=0,skTimer=null;"
        "function skRoute(nr){if(SK_ALLOWED.has(nr))return 'allow';if(nr<=SK_M)return 'policy';return 'fake';}"
        "function skRender(){for(var i=0;i<SK_NSTATES;i++){var a=(i===skCur)?'1':'0';"
        "var r=document.getElementById('string'+i),m=document.getElementById('stmark'+i);"
        "if(r)r.setAttribute('opacity',a);if(m)m.setAttribute('opacity',a);}}"
        "function skStop(){if(skTimer){clearInterval(skTimer);skTimer=null;}}"
        "function skStep(d){skStop();skCur=(skCur+d+SK_NSTATES)%SK_NSTATES;skRender();}"
        "function skReset(){skStop();skCur=0;skRender();}"
        "function skAuto(){if(skTimer){skStop();return;}"
        "skTimer=setInterval(function(){skCur=(skCur+1)%SK_NSTATES;skRender();},1700);}"
        "function skGuess(qi,nr,guess){var ans=skRoute(nr),ok=(guess===ans);"
        "var nm={allow:'放行（内核真执行）',policy:'策略章 errno='+SK_ERRNO,fake:'伪造章 ENOSYS(38)'};"
        "var l=document.getElementById('qlbl'+qi);"
        "if(l){l.textContent=(ok?'✓ 猜对了！':'✗ 再想想～')+' 正确：'+nm[ans];"
        "l.setAttribute('fill',ok?'#1a7f37':'#cf222e');}"
        "['allow','policy','fake'].forEach(function(k){var b=document.getElementById('qbtn'+qi+'_'+k);"
        "if(!b)return;if(k===ans){b.setAttribute('fill','#2ea043');b.setAttribute('stroke','#1a7f37');}"
        "else if(k===guess){b.setAttribute('fill','#ffebe9');b.setAttribute('stroke','#cf222e');}"
        "else{b.setAttribute('fill','#f6f8fa');b.setAttribute('stroke','#d0d7de');}});}"
        "window.addEventListener('load',skReset);"
        "</script>")
    page = ("<!doctype html><html lang='zh'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Anolix 沙箱解剖图</title>" + css + "</head>"
            "<body><div class='wrap'>" + svg.render() + "</div>" + js + "</body></html>")
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(page)

    rel = os.path.relpath(args.out, ROOT)
    print(f"已生成: {rel}")
    print(f"查看:   explorer.exe {rel}    （WSL 互操作，用 Windows 浏览器打开）")
    print(f"容器快照: 隔离 {sum(1 for k in host['ns'] if host['ns'].get(k) != cont['ns'].get(k))}/{len(cont['ns'])} 个 namespace"
          f" · Seccomp={cont.get('Seccomp')} · NoNewPrivs={cont.get('NoNewPrivs')} · CapEff={cont.get('CapEff')}")
    if data["chain"]:
        print(f"进程链:   {' → '.join(s.get('Name', '?') for s in data['chain'][-4:])}")
    nr_now = data["cur"]["nr"] if data["cur"] else "（用户态）"
    print(f"地址空间: {len(data['maps'])} 个区间 · 此刻 syscall nr={nr_now}"
          f" · 内核栈{'可读' if data['kstack'] else '不可读（权限）'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())