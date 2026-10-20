# 06_zygote 三围栏接入：cgroup / seccomp / rootfs

> 研究文档系列 06 ｜ 2026-10-20
> 项目：Anolix（轻量沙箱运行时核心，Go + runc）
> 环境：WSL2 Ubuntu / 内核 6.18 / Go 1.27；母体宿主直跑（非 runc 容器），sudo（root）
> 本文所有数字与输出均来自本机真实运行，无推断值；推导项标注【推导】，未完成项标注【待续】。

---

## 背景

05 篇把 worker 造出来了——有 6 间房（namespace）、能共享母体热内存，但**它还不是一个"完整沙箱"**：

- **没有资源围栏**（cgroup）：一个 worker 能吃垮宿主；
- **没有 syscall 围栏**（seccomp）：worker 能调 `reboot`/`bpf` 等任意危险调用；
- **没有独立根**（rootfs）：worker 能看见宿主整个文件系统。

本篇补这三件——沿用 05 篇的三段链方法，逐件走"**机制 → 落进代码 → 实测**"。

最关键的共性是一个词：**"出生就带"**。
namespace 用 `clone(CLONE_NEW*)` 出生就带（05 篇）；本篇 cgroup 用 `clone3(CLONE_INTO_CGROUP)` 出生就带；rootfs 用薄 init 在**装 seccomp 之前**换根。三者**都不是"事后补"**。

---

## 问题

| 待实证的问题 | 此前状态 |
| --- | --- |
| 给 worker 加 cgroup，怎么避免"先 clone 再迁移"的启动空窗？ | 无（只有"事后写 cgroup.procs"的纸面方案） |
| cgroup 的 `pids.max` 到底限什么？超了报什么？ | 无实测 |
| `memory.max` 写了就一定 OOM 吗？ | 无实测（02 篇标过"swap 未映射"的缺口） |
| seccomp 由谁装、什么时候装？漏一条会怎样？ | 01 篇有名单坑，未在 zygote 场景实测 |
| 任意 payload（busybox）怎么也被 rootfs + seccomp 覆盖？ | 无（worker 只会护自己） |

---

## 分析

### 装置与读法

在 05 篇三件套之上，新增两件：

| 二进制 / 脚本 | 角色 |
| --- | --- |
| `bin/worker-init` | **薄 init**：装 rootfs（`pivot_root`）+ 装 seccomp，再 `execve` payload |
| `bin/worker` | 增加攻击模式：`attack-oom` / `attack-pids` / `attack-syscall` |
| `scripts/zygote/{build,mother,verify,attack,rootfs}.sh` | 一键跑：编译 / 起母体 / 验装备 / 打攻击 / 演示 rootfs |

**读法**（贯穿三件）：

1. **"装备检查"（verify）≠ "执法生效"（attack）**：前者查"限额写没写对"，后者才去"撑爆它"，看限额咬不咬；
2. **worker 的 stdout 接母体**，所以证据都在母体日志里（`/tmp/zygote-mother.log`）；
3. seccomp 的"盖章"= 我们配的默认动作（`ERRNO(EPERM)`）。

### 实验一：cgroup —— 出生即在册，与"计数限什么"

- **机制**：母体**在 clone 之前** mkdir 叶子 cgroup + 写限额 + 拿目录 fd；`clone3(CLONE_INTO_CGROUP)` 把 fd 传进去 → worker **一出生就在叶子里**，没有"先 clone 再写 `cgroup.procs`"的空窗（#20）。
- **Go 落点**：`SysProcAttr.UseCgroupFD + CgroupFD` 底层就是 `clone3(CLONE_INTO_CGROUP)`。

**数据一（装备：叶子 + 限额）**：

```
cgroup.procs: 1250458          ← worker 的宿主 PID（出生即在册）
memory.max  : 268435456        ← 256MB
pids.max    : 200
cpu.max     : max 100000
```

**数据二（执法：`pids.max` 超了 → EAGAIN，且"194"是彩蛋）**：

```
[attack-pids] 第 194 个 fork 失败: fork/exec /bin/sleep: resource temporarily unavailable
```

> `pids.max` 数的是 **task（线程）**，不是"进程数"。
> worker 是 Go 程序，自带 ~6 条线程；**194 个子进程 + 其 ~6 线程 = 200** → 卡在第 194 个。

**数据三（执法：`memory.max=64MB`，worker touch 512MB —— 居然没死）**：

```
[attack-oom] 居然没死？touch 完了 512 MB —— memory.max 没生效？
```

查真相（三处证据）：

```
memory.swap.max = max          ← 子 cgroup 默认"不限换出"
/proc/swaps    → /dev/sdc 2GB  ← 系统有 swap
memory.stat    → pswpout 116020 ← swap 是活的
```

→ **`memory.max` 只限"常驻"**；超出部分被**换出**到 swap，常驻始终 ≤ 64MB → 内核没有 OOM 的理由。**内存炸弹静默退化成 thrashing。**

**修法**：把 `memory.swap.max` 也封上（默认 0）——`memory.max` 才是真硬上限。已加 `--cg-swap`（默认 0）。

### 实验二：seccomp —— 自己装，与"漏一条是静默的"

- **机制**：seccomp **由进程自己装**（母体代装会自缚 + 全员共享一份，#19 坑1），且**紧贴 execve**。本实现里 worker 一启动就先装。
- **名单来源**：`config.DefaultAllowedSyscalls`（Anolix 沙箱那份名单）。

**数据一（A/B 探针，对照教科书级）**：

```
A（装 seccomp）： sethostname → EPERM ✅   bpf → EPERM ✅   keyctl → EPERM ✅
B（noseccomp） ： sethostname → 0（成功！） bpf → 22(EINVAL) keyctl → 95(EOPNOTSUPP)
```

> B 那行 `sethostname → 0` 是铁证：worker 是 root、在自己的 UTS ns 里，**没 seccomp 时它真把主机名改了**——seccomp 是唯一挡住它的墙。

**数据二（"漏一条"活体：我自己漏抄了 4 条）**：

```
⚠️ 名单里 4 条没认出来（拼错=没写，#19 坑2）: [clock_getres clock_gettime clock_nanosleep getdents64]
```

这是"unknown 回吐"机制当场抓住的——我手写 x86-64 号码表时漏抄了这 4 条。**worker 当时没崩**，因为 Go 用 `futex` 睡觉、`clock_gettime` 走 **vDSO**（根本不过 seccomp）绕开了；**换个 payload 就会神秘挂**。

**seccomp 六坑**（详见小知识点 #26）：① 漏一条→静默神秘失败；② errno 撞衫（用哨兵值）；③ 名字拼错=静默忽略；④ 超界号伪 ENOSYS（libseccomp 特有）；⑤ 自缚/顺序；⑥ "只能筛号"是误解（能筛参数值、筛不了参数指向的内容）。

### 实验三：rootfs —— 薄 init 换根，与"任意 payload 覆盖"

- **难点**：母体 clone 之后**直接 execve 新程序**，Go 的 os/exec 不给"fork 与 exec 之间跑代码"的钩子 → 给了 mount ns 也**没地方 `pivot_root`** → 必须借道**薄 init**。
- **`worker-init` 顺序**：`MS_PRIVATE → bind rootfs → pivot_root → 挂 /proc、/dev → 装 seccomp → execve payload`。
  - rootfs 相关的 syscall 必须在**装 seccomp 之前**做完（否则自缚）；
  - 这顺带补了"seccomp 只护自己 worker"的缺口：**busybox 这类任意 payload 也被盖上了**。
- **安全闸**：`worker-init` 拒绝在非 PID-1（宿主）上运行，防单独跑 `pivot_root` 掉宿主根。

**数据一（换根成功）**：

```
worker-init: pivot_root 完成；seccomp 放行 113 条 syscall
ls / →  sh: ls: Operation not permitted        ← EPERM！被 seccomp 盖了
```

`pivot_root` 那步成了（进了新根），但 `ls`（busybox applet）**自己**某条 syscall 不在名单 → 盖 EPERM → **又是"漏一条"**。

**数据二（务实补 40 条后）**：

```
worker-init: pivot_root 完成；seccomp 放行 153 条 syscall
ls / →
bin
dev
probe
proc
rawfilter
sys
sysc
tmp
```

**worker 只看得见 rootfs 自己的内容**——宿主的 `/home`、`/etc`、`/usr`、宿主那套 `/bin` 全没了。**rootfs 隔离成立。**

> ⚠️ 诚实标：这次是**务实补法**（把"常见工具会用的 40 条"一次加上，113→153）。**它破坏了"最小白名单"**（#19 坑2）。严谨做法是 **strace 抓出那一两唯一缺失的、只补它**——【待续】。

---

## 数据对比

| 件 | 机制 | 关键数据 | 状态 |
| --- | --- | --- | --- |
| **cgroup** | per-worker 叶子 + `clone3(CLONE_INTO_CGROUP)` 出生即在册 | `pids` 超 → 第 194 个 fork `EAGAIN`；`memory.max=64MB` 被 swap 绕过 → 补 `memory.swap.max=0` | ✅ 已实测（执法 + 修复） |
| **seccomp** | worker 自装 + 探针 | A/B：A 全 `EPERM`、B `sethostname→0`；unknown 回吐抓住漏抄 4 条 | ✅ 已实测 |
| **rootfs** | 薄 init：`pivot_root` → seccomp → execve payload | `ls /` 只剩 `bin dev probe proc rawfilter sys sysc tmp` | ✅ 隔离成立；名单待收最小 |

---

## 结论与启示

### 1. 结论

1. **cgroup 能"出生即在册"**：`clone3(CLONE_INTO_CGROUP)` 消掉"先 clone 再迁移"的启动空窗；
2. **`pids.max` 限的是线程数**（实测：194 子进程 + ~6 线程 = 200）；
3. **`memory.max` 只限常驻**：有 swap 且 `swap.max` 不限时，炸弹退化成 thrashing——`memory.max + memory.swap.max` 才共同定义硬上限；
4. **seccomp 必须自己装、字体紧贴 execve**；探针 A/B 证明它是唯一挡住 root worker 危险 syscall 的墙；
5. **rootfs 靠薄 init**：`pivot_root` 换根后 worker 只看得到 rootfs，且 init 让**任意 payload** 也受 seccomp 覆盖。

### 2. 教训

- **"装备检查"≠"执法生效"**：`verify.sh` 说 `memory.max` 写对了 ✓，`attack.sh` 一撑却发现限额不咬——**只查配置永远查不出这种坑**；
- **"漏一条"是静默的**：漏 `clock_*` worker 没崩（Go 走了 vDSO/futex 绕开）；漏 `ls` 需要的那条才崩。**没崩 ≠ 没问题**；
- **务实补 vs 精确补**：把"常见 40 条"一次加上能立刻跑通，但**破坏了最小白名单**——正确姿势是 strace 抓唯一那条（#26 坑1）；
- **"出生就带"是贯穿三件的模式**：ns（clone flags）、cgroup（CLONE_INTO_CGROUP）、seccomp（init 装完再 execve）——**都不是事后补**；
- **`smaps` 的 `Shared`/`Private` 看 mapcount**（05 篇遗留的修正）：与映射标志无关，>1 才报 Shared。

---

## 下一步

| # | 项 | 目的 | 状态 |
| --- | --- | --- | --- |
| 1 | **seccomp 名单收最小** | strace 抓唯一缺失 syscall，把 153 收回 ~114 | 待执行 |
| 2 | **薄 init 收编 worker** | 让 `worker-init` 统一做 rootfs+seccomp，`worker` 只管负载（去掉双装判定） | 待执行 |
| 3 | **state.json 收养** | 让 runc `list/kill/delete` 管得到 worker | 待执行 |
| 4 | **延迟稳态数** | 脱 strace 取 p50/p95（带基准对照） | ✅ 已完成（见 07 篇） |
| 5 | 母体进 runc 容器 | 用 `zygote/spec.go` 对齐"母体是容器"的形态 | 装置已写，待跑 |

---

## 附录：命令

```bash
cd scripts/zygote
./build.sh              # 编译 zygote/spawn/worker/worker-init

./mother.sh up          # 起母体（--warm 64 --cgroup --cg-memory 256 ...）
./mother.sh log 40      # 看 worker 自打印（证据都在母体日志）

./verify.sh all         # 装备检查：ns / memfd / cgroup / seccomp
./attack.sh all         # 执法：OOM / pids 爆 / 危险 syscall
./rootfs.sh             # rootfs 演示：worker-init 换根

./mother.sh down        # 收工：杀母体 + 清 anolix-* 叶子
```

```bash
# 想看得更细：把母体套 strace（-f 跟到 worker）
sudo strace -f -tt -o /tmp/m.trace ./bin/zygote --socket /tmp/anolix-zygote.sock --warm 64
grep -E 'pivot_root|mount|EPERM' /tmp/m.trace
```

源码参照位置：

- `zygote/cgroup.go`（per-worker 叶子 + clone3 出生即在册 + swap 封顶）、`zygote/seccomp.go`（号码表 + 常见工具补充名单 + 过滤器构造/安装）
- `cmd/worker-init/main.go`（薄 init：`pivot_root` → seccomp → execve）、`cmd/worker/main.go`（负载 + 攻击模式）
- `scripts/zygote/*.sh`；架构见 `docs/zygote-design.md`；推理链见 `notes/小知识点.md` #22–#27