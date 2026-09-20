#!/usr/bin/env python3
# kstate.py —— 内核对系统调用的"决策状态机"可视化探针
#
# 用法:
#   ./scripts/kstate.py 41 2 1 0        # 每次操作 = 给一个 syscall 号码（+参数）
#   ./scripts/kstate.py 9999
#   ./scripts/kstate.py 440 0 0 0 0 0 --policy examples/policy.json
#
# 每次运行做三件事：
#   1) 解析策略文件，算出 errnoRet 与"放行名单最大号 M"
#   2) 画出内核对本号码的决策状态机（三档路径），高亮本次预判路径
#   3) 真实跑两次（宿主直跑 / 沙箱内跑），把实测值与预判对照
#
# 【源】号码<->名字表来自内核 UAPI 头文件（内核固定）：
#   /usr/include/x86_64-linux-gnu/asm/unistd_64.h
# 【源】errnoRet 与放行名单来自策略文件（本项目自定义）

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS = os.path.join(ROOT, "rootfs", "sysc")          # 宿主机侧的 sysc 探针
ANOLIX = os.path.join(ROOT, "anolix")               # 本项目 CLI
ROOTFS = os.path.join(ROOT, "rootfs")               # 容器根目录
NR_TABLE = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"

COLOR = sys.stdout.isatty()


def c(text, code):
    """ANSI 上色；非终端环境自动退化为纯文本。"""
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def swidth(s):
    """字符串显示宽度（中日韩全角字符按 2 列算，用于框线对齐）。"""
    w = 0
    for ch in s:
        w += 2 if ord(ch) > 0x2E7F else 1
    return w


def pad(s, width):
    """按显示宽度补齐到 width 列；超宽时截断并以 "." 标记（保证框线对齐）。"""
    if swidth(s) <= width:
        return s + " " * (width - swidth(s))
    out, wsum = "", 0
    for ch in s:
        cw = 2 if ord(ch) > 0x2E7F else 1
        if wsum + cw > width - 1:
            break
        out += ch
        wsum += cw
    return out + "." + " " * (width - wsum - 1)


def load_nr_table():
    """解析内核头文件: #define __NR_socket 41 -> {'socket': 41} 及反查表。"""
    name2nr, nr2name = {}, {}
    try:
        with open(NR_TABLE, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"#define\s+__NR_(\w+)\s+(\d+)", line)
                if m:
                    name2nr[m.group(1)] = int(m.group(2))
                    nr2name.setdefault(int(m.group(2)), m.group(1))
    except FileNotFoundError:
        print(f"警告: 找不到内核号码表 {NR_TABLE}，名字解析将缺失", file=sys.stderr)
    return name2nr, nr2name


def load_policy(path):
    """读策略文件，返回 (errnoRet, 名单号码集合, M, 名单名字)。"""
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    sec = cfg.get("seccomp", {})
    errno_ret = sec.get("errnoRet", 1)
    names = sec.get("allowedSyscalls", [])
    name2nr, _ = load_nr_table()
    nums = sorted(name2nr[n] for n in names if n in name2nr)
    unknown = [n for n in names if n not in name2nr]
    if unknown:
        print(f"警告: 名单中 {len(unknown)} 个名字不在内核表中: {unknown[:5]}", file=sys.stderr)
    m_max = max(nums) if nums else 0
    return errno_ret, set(nums), m_max, names


def run_sysc(cmd):
    """执行探针，解析输出 -> ('ok', 返回值) 或 ('errno', 数字) 或 ('fail', 原文)。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return ("fail", str(e))
    out = (p.stdout or "") + (p.stderr or "")
    m = re.search(r"errno=(\d+)", out)
    if m:
        return ("errno", int(m.group(1)))
    m = re.search(r"成功: 返回值=(-?\d+)", out)
    if m:
        return ("ok", int(m.group(1)))
    return ("fail", out.strip().splitlines()[-1] if out.strip() else "(无输出)")


def draw_machine(nr, name, errno_ret, m_max, route):
    """画决策状态机，高亮本次路径。route ∈ {allow, policy, fake}"""
    w = 40  # 框内宽度（显示列）
    hl = {"allow": "32;1", "policy": "33;1", "fake": "31;1"}  # 绿/黄/红

    def ln(r, mark=None):
        """统一缩进：“▶ ”或“  ”前缀占 2 列，保证图形内部对齐。"""
        return c("▶ " + r, hl[mark]) if mark else "  " + r

    def block(text):
        """一个决策节点框：顶线 / 内容 / 底线（中线留给向下分支）。"""
        return [
            ln("┌" + "─" * (w + 2) + "┐"),
            ln("│ " + pad(text, w) + " │"),
            ln("└" + "─" * 16 + "┬" + "─" * 25 + "┘"),
        ]

    def arm(mark=None):
        """“否”分支臂：竖线 + 向下箭头。"""
        return [ln("                 │ 否", mark), ln("                 ▼", mark)]

    def exit_tail(text, mark):
        """节点右侧的“是”出口；命中时整段上色并标 ◀ 本次。"""
        if mark:
            return "── 是 ─▶ " + c(text + "   ◀ 本次", hl[mark])
        return "── 是 ─▶ " + text

    out = []
    out += block(f"① 内核入口 · 收单   nr={nr}" + (f" ({name})" if name else ""))
    out.append(ln("                 │ 交给 seccomp 过滤器（runc/libseccomp 生成）"))
    out.append(ln("                 ▼"))

    out += block("② nr ∈ 放行名单？")
    out[-2] += exit_tail("【放行】内核真执行 → 天然结果", "allow" if route == "allow" else None)
    # “否”分支：策略章/伪造章路线都会经过
    out += arm(route if route in ("policy", "fake") else None)

    out += block(f"③ nr ≤ M = {m_max}？")
    out[-2] += exit_tail(f"【策略章】errno = {errno_ret}", "policy" if route == "policy" else None)
    # “否”分支：只有伪造章路线经过
    out += arm("fake" if route == "fake" else None)

    leaf = "【伪造章】errno = 38 (ENOSYS)  ← libseccomp 内建，与 errnoRet 无关"
    out.append(ln("  " + leaf, "fake" if route == "fake" else None))
    return out


def describe(res):
    kind, val = res
    if kind == "errno":
        return f"errno={val}"
    if kind == "ok":
        return f"成功 返回值={val}"
    return f"无法判定: {val}"


def main():
    args = sys.argv[1:]
    policy_path = os.path.join(ROOT, "examples", "policy.json")
    if "--policy" in args:
        i = args.index("--policy")
        policy_path = args[i + 1]
        del args[i:i + 2]

    if not args:
        print(__doc__ or "用法: kstate.py <syscall号> [参数...] [--policy 文件]")
        return 2

    try:
        nr = int(args[0], 0)
    except ValueError:
        print(f"首个参数必须是号码: {args[0]!r}")
        return 2
    extra = args[1:]

    for f, what in ((SYS, "rootfs/sysc（先跑 ./scripts/mkrootfs.sh）"), (ANOLIX, "anolix（先 go build -o anolix ./cmd/anolix）")):
        if not os.path.exists(f):
            print(f"缺少 {what}", file=sys.stderr)
            return 2

    errno_ret, allowed, m_max, names = load_policy(policy_path)
    _, nr2name = load_nr_table()
    name = nr2name.get(nr, "")

    # 预判：这条号码在沙箱里会走哪一档
    if nr in allowed:
        route = "allow"
        reason = [f"{nr} ({name}) ∈ 名单?  是 → 放行"]
    elif nr <= m_max:
        route = "policy"
        reason = [f"{nr} ({name}) ∈ 名单?  否", f"{nr} ≤ M({m_max})?  是 → 策略章 errnoRet={errno_ret}"]
    else:
        route = "fake"
        reason = [f"{nr} ({name}) ∈ 名单?  否", f"{nr} ≤ M({m_max})?  否 → 伪造章 38"]

    # 实测：宿主直跑（无过滤器） + 沙箱内跑（有过滤器）
    host = run_sysc([SYS, str(nr)] + extra)
    sandbox = run_sysc([ANOLIX, "run", "--policy", policy_path, "--rootfs", ROOTFS, "/sysc", str(nr)] + extra)

    # ── 输出 ─────────────────────────────────────────────
    print()
    print(f"  本次操作 : /sysc {nr}" + (" " + " ".join(extra) if extra else "") + (f"    ({name})" if name else ""))
    print(f"  策    略 : {os.path.relpath(policy_path, ROOT)}   errnoRet={errno_ret} · 名单 {len(names)} 条 · M={m_max}")
    print()
    print("  ── 预判推理链 ─────────────────────────────")
    for r in reason:
        print("    " + r)
    print()
    print("  ── 决策状态机 ─────────────────────────────")
    for line in draw_machine(nr, name, errno_ret, m_max, route):
        print("  " + line)
    print()
    print("  ── 实测对照 ───────────────────────────────")
    print(f"    宿主（无过滤器）: {describe(host)}")
    print(f"    沙箱（有过滤器）: {describe(sandbox)}")

    # 一致性核对
    print()
    if route == "allow":
        if sandbox == ("errno", errno_ret):
            print(f"  ⚠ 名单内却被盖章 errnoRet={errno_ret}？检查名单解析或策略")
        else:
            print("  ✓ 名单内 → 放行，过滤器未参与（结果由内核天然决定；"
                  "getpid 之类的值可因命名空间而天然不同）")
    elif route == "policy":
        if sandbox == ("errno", errno_ret):
            print(f"  ✓ 命中策略章: 沙箱返回 {errno_ret} == errnoRet，与预判一致")
        else:
            print(f"  ⚠ 预判策略章 {errno_ret}，实测 {describe(sandbox)}——检查 M 的解析或名单")
    elif route == "fake":
        if sandbox == ("errno", 38):
            print("  ✓ 命中伪造章: 沙箱返回 38（与 errnoRet 无关，改它也没用）")
            if host == ("errno", 38):
                print("    注意: 宿主也是 38——本例两者数字相同但来源不同（内核真不支持 vs 伪造）")
        else:
            print(f"  ⚠ 预判伪造章 38，实测 {describe(sandbox)}")
    print("    提示: 宿主一列是'天然结果'——放行后沙箱应复现它；被拦时沙箱值是盖的章")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())