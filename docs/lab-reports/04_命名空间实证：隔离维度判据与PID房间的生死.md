# 04_命名空间实证：隔离维度的判据与 PID 房间的生死

> 研究文档系列 04 ｜ 2026-09-30
> 项目：Anolix（轻量沙箱运行时核心，Go + runc）
> 环境：WSL2 Ubuntu / 内核 6.18 / runc 1.3.4
> 本文所有数字与输出均来自本机真实运行，无推断值；推导项标注【推导】，未完成项标注【待续】。

---

## 背景

前三篇的取证角度：01 = **错误码**（seccomp 拦截的三种来源），02 = **读数**（cgroup 执法证据），03 = **时序**（strace 全链路）。

本篇补上第四块拼图：**视图**——隔离维度到底隔离了没有、怎么判、以及在"最坏情况"（强杀）下这套视图怎么被销毁。

与前几篇的呼应：03 篇记下了 `unshare(CLONE_NEWPID|…)` 那一行系统调用；本篇回答"那一行执行完之后，世界变成了什么样、怎么用眼睛验证"。

---

## 一、一条链：从一行代码到内核里的对象

```
spec.go   {Type: specs.PIDNamespace}                    ← 声明【项目自定义】
    │（launcher 序列化）
config.json  "namespaces":[{"type":"pid"}, …]           ← 说明书字段【行业固定】
    │（runc 读取后逐个调用）
unshare(CLONE_NEWPID|NEWNS|…)                            ← 内核动作【runc 实现】
    │
/proc/<pid>/ns/pid → pid:[4026532235]                   ← 内核对象的编号【内核固定】
    │
行为变化：容器内 pid=1、hostname=anolix、挂载不可见……    ← 现象
```

本节的意义：**"隔离生效"不是一句配置声明**，它在这条链的每一层都有可指认的落点。03 篇的 trace L4248/L4267 提供了第三层的原始记录。

---

## 二、判据实验 1：inode 对照法

### 2.1 方法

```bash
# 宿主（窗口 1）：
ls -l /proc/self/ns/
# 容器（窗口 2，先记住容器 init 的宿主 pid）：
ls -l /proc/<宿主pid>/ns/
```

**唯一判据：同名不同号 = 隔离；同名同号 = 共享。**

### 2.2 原始数据（rootless 运行 + 宿主 shell 对照）

| 维度 | 容器 | 宿主 shell | 判读 |
| --- | --- | --- | --- |
| cgroup | 4026532236 | 4026531835 | 隔离 |
| ipc | 4026532234 | 4026532208 | 隔离 |
| mnt | 4026532232 | 4026532219 | 隔离 |
| net | 4026532237 | 4026531833 | 隔离 |
| pid | 4026532235 | 4026532221 | 隔离 |
| uts | 4026532233 | 4026532220 | 隔离 |
| user | 4026532231 | 4026531837 | 隔离（rootless 追加的第 7 间房） |
| **time** | **4026531834** | **4026531834** | **未隔离（两边同号）** |
| pid_for_children | =pid | =pid | 别名视图，非第 8、9 间房 |
| time_for_children | =time | =time | 同上 |

### 2.3 三个结论

1. 与 `spec.go` 声明的 6 个 namespace 逐一对应，另加 rootless 的 user → **7 维隔离成立**；
2. **time 是初测时唯一没隔离的维度**：当时 spec 未声明 TimeNamespace，两边共享初始 time 视图。"知道哪一维没开"与"知道哪一维开了"同等重要（复测补上后见 2.4）；
3. `*_for_children` 是别名视图：显示"将来 fork 的子进程会进哪个 ns"。稳态下与本体相等；若某进程"已 unshare(CLONE_NEWPID) 但还没 fork"，会看到 `pid ≠ pid_for_children`（见第四章）。

### 2.4 复测（2026-10-04）：为 spec 加入 TimeNamespace 后

`spec.go` 的 namespaces 列表追加一行 `{Type: specs.TimeNamespace},` 并重编译后复测（rootless）：

| 维度 | 宿主 | 容器（初测） | 容器（复测） | 判读 |
| --- | --- | --- | --- | --- |
| time | 4026531834 | 4026531834（同号） | **4026532303（不同号）** | 隔离已生效 |
| 其余 7 维 | — | 均不同 | 均不同 | 无回归 |

- time inode 的号段与其他几个不同，只是**创建时机不同**（CLONE_NEWTIME 单独创建）；判据仍只看"是否与宿主相同"；
- **偏移默认是 0**：隔离已生效（inode 不同），但 `CLOCK_MONOTONIC`/`BOOTTIME` 的数值暂与宿主一致；要产生数值差异需另行写 offsets【内核固定】；
- 至此隔离维度 **8/8**（六个基础 + rootless 的 user + time）。

### 2.5 附带发现：宿主自己也在"房间里"

对照初始 ns 的典型值（cgroup=…835、user=…837、time=…834 等），宿主 shell 的 pid/mnt/ipc/uts/net inode 均非初始值 → 本机 WSL 的登录会话自身处于一层命名空间内。即观察到的实际层次为：**WSL 会话 ns → anolix 容器 ns**，嵌套隔离的一个现成样本【判读】。

---

## 三、判据实验 2：NSpid 双坐标

### 3.1 容器内读（单坐标）

```
$ /bin/busybox cat /proc/self/status | grep NSpid
NSpid:  1
```

单值不是错：`NSpid` 只显示"**procfs 挂载点所在 pid ns 往下**"的层级；容器的 /proc 由 runc 在容器 PID ns 内部挂载，起点即容器自己 → 只看到一个编号。【内核固定】

### 3.2 宿主侧读（双坐标）

```
$ grep NSpid /proc/1953744/status        # 1953744 = 容器 init 的宿主 pid
NSpid:  1953744  1
```

**两段数字**：宿主坐标 1953744 / 容器坐标 1。同一进程、两套坐标系——这就是"PID 房间"最直观的证据。

同卡片的其它两行：`Uid: 0`（rootful 运行）、`CapEff: 0000000000000000`（能力表已清空，去能力化的 root）。

> 阅读规则：**想看双坐标，必须从"房间外面"读**；容器内读自己永远是单坐标。

---

## 四、判据实验 3：`*_for_children` 中间态（本机实测）

### 4.1 两个前置陷阱（先踩后记）

**陷阱一：权限。** 创建 PID 房间需要 CAP_SYS_ADMIN；宿主普通用户直接跑会得到**内核真实 EPERM**（无 seccomp 参与）：

```
$ unshare --pid true
unshare: unshare failed: Operation not permitted
$ strace -e trace=unshare unshare --pid true
unshare(CLONE_NEWPID) = -1 EPERM (Operation not permitted)
```

对照：rootless 容器能建成，是因为 runc **先建 user 房间、再建其余房间**（03 篇 trace L4248 → L4267）——在新 user 房间里你就是 root（持有 CAP_SYS_ADMIN），后续 unshare 才被允许。本机实验用 `sudo` 等价复现这一步。

**陷阱二：`/proc/self` 指的是"读它的那个进程"，不是 shell。** `ls -l /proc/self/ns/…` 里的 self 是 `ls` 自己——它是 sh 的**子进程**，出生就在新房间里，所以它的 `pid` 与 `pid_for_children` 必然相等，会把中间态"藏起来"。要看 sh 自己，必须用 `/proc/$$`。

### 4.2 原始输出

**中间态**（不带 fork，看 sh 自己）：

```
$ sudo unshare --pid sh -c 'ls -l /proc/$$/ns/pid /proc/$$/ns/pid_for_children'
/proc/27250/ns/pid              -> 'pid:[4026532221]'
/proc/27250/ns/pid_for_children -> 'pid:[4026532232]'
```

**成为 1 号**（带 fork）：

```
$ sudo unshare --pid --fork sh -c 'ls -l /proc/self/ns/pid /proc/self/ns/pid_for_children'
/proc/self/ns/pid              -> 'pid:[4026532232]'
/proc/self/ns/pid_for_children -> 'pid:[4026532232]'
```

### 4.3 判读

- **中间态成立**：unshare 之后、fork 之前，`pid`（自己仍在的旧房间 4026532221）≠ `pid_for_children`（给孩子准备的新房间 4026532232）；
- 4026532221 与第二章表格中"宿主 shell 的 pid"完全一致——同一实验数据自洽；
- 一旦 fork，子进程"生"在新房间里，从它视角两行相等（4026532232）；多轮间同号属内核 inode 复用【判读】；
- 结论：**这正是 runc 必须"先 unshare 再 fork"的原因**——要让容器 init 成为新房间里的 1 号，只能"生"在房间里，不能"搬"进去。

---

## 五、PID 房间的生死学（本次实证）

### 5.1 装置（含一条装置教训）

```bash
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 300s -- \
  /bin/busybox sh -c '/bin/busybox sleep 300 & /bin/busybox sleep 300 & echo 子进程已起; wait'
```

装置教训：**非交互 shell 不会等后台任务**——脚本若以 `&` 结尾，sh 立即退出、容器即刻被回收，观测窗口为零。撑窗口靠在末尾用 `wait`（内建，不需要 fork）或前台 `sleep`。

### 5.2 观测 A：杀一个子进程 = 局部死亡

```
$ sudo kill -9 1955744        # 目标 = 一个 sleep 子进程
$ pgrep -af busybox
1955738 /bin/busybox sh -c …        ← init 仍在
1955744 [busybox] <defunct>         ← 僵尸：已死，等父亲收尸
1955745 /bin/busybox sleep 300      ← 另一个子进程仍在
```

终端侧同步出现一行 `Killed`——来源是容器里的 sh（**作业状态通报**，不是错误）。僵尸只存在一瞬：父亲正在 `wait`，很快收尸。【内核固定】

### 5.3 观测 B：杀 init = 内核清空整个房间

```
$ sudo kill -9 1955738        # 目标 = 容器 init（/bin/busybox sh -c 那行）
$ pgrep -af busybox
（空）
```

整棵树消亡：另一个 sleep 陪葬、僵尸一并被清。机制：**PID ns 的 init 死亡 → 内核清空该命名空间内所有进程**——不是"逐个去杀"，所以不会漏。【内核固定】

事后复查：无残留进程、无僵尸。

### 5.4 三种"上游死亡"的完整对照（三轮实验合集）

| 杀谁 | 结果 | 出处 |
| --- | --- | --- |
| kill anolix | 容器活（runc 与容器不受影响） | 早期实验 |
| kill sudo | anolix/runc 连带退出（pty 级联【推断】），**容器仍活**；init 的 PPid 变为 WSL 的 `/init`（subreaper 收养） | 本次 |
| kill 容器 init | **全树消亡**（本节 5.3） | 本次 |

一句话：**上游进程的死亡不连坐容器；容器的死亡由内核保证全树清空——两件事各归各管。**

---

## 六、排障陷阱（本轮踩到的）

1. **`pgrep -f` 是"整条命令行子串匹配"**：`sudo ./anolix run … /bin/busybox sh -c …` 这一行的参数里原样包含目标文字，会被一并命中；`head -1` 又恰好取到**最祖先**（sudo）→ 杀错对象。正确写法：**行首锚定** `pgrep -af '^/bin/busybox sh -c'`；
2. **`ps` 无参数只看本终端进程**：全局找人用 `pgrep -af` / `ps -ef`；
3. **runc 状态本按身份分家**：rootless = `--root /run/user/<uid>/anolix-runc`；rootful = runc 默认本（`/run/runc`）。用 sudo 跑却查用户本 → 永远"列表为空"；
4. **回收不是"发信号"的事**：僵尸的消失依赖父进程 `wait`；若父进程永不收尸，僵尸会堆积——这就是"容器里的 1 号必须会收尸"的原因。

### 插曲：容器内"裸名命令"为何失败（与白名单相关）

现象：`sh -c 'grep …'` 报 `Operation not permitted`；改为 `/bin/busybox grep …` 通过。

strace 定位（证据）：

```
stat("/usr/local/sbin/grep", …) = -1 EPERM (Operation not permitted)
stat("/usr/local/bin/grep",  …) = -1 EPERM
… （共 6 条，逐 PATH 目录）
```

两条原因叠加：
1. 裸名 → shell 沿 PATH 逐个"探头看"（legacy `stat` 系统调用）→ **`stat` 不在放行名单** → 每次探查都被盖章；
2. 默认策略 `errnoRet=1`（EPERM）→ 文案伪装成"权限问题"（01 篇教训的又一次现身）。

修复方向【待实现】：把 `stat` 加入两份名单；同族候选 `lstat`（busybox 的 `ls -l` 等会用到）待 `sysc 6` 实测确认。

---

## 七、结论与待续

### 7.1 结论

1. 隔离维度有唯一判据：**同名不同号 = 隔离**；并需排除两类干扰（`*_for_children` 别名、未声明的 time）；
2. 双坐标（宿主 pid / 容器 pid）可从宿主侧 NSpid 读到；容器内读永远是单坐标；
3. PID 房间的生死由内核一步裁决：**init 死 → 全房间清空**；杀子进程只是局部死亡 + 短暂僵尸；
4. "上游死"不连坐容器（anolix、sudo 两轮均已实证），三种结局对照见表 5.4；
5. `*_for_children` 中间态已实测：unshare 后未 fork 时 `pid ≠ pid_for_children`（旧房间 4026532221 / 新房间 4026532232）——这就是"runc 先 unshare 再 fork"的根据。

### 7.2 待续实验

| # | 实验 | 观测点 | 状态 |
| --- | --- | --- | --- |
| 1 | `*_for_children` 中间态（第四章） | unshare 后未 fork 的进程 | **已实证（第四章）** |
| 2 | time ns（未隔离维度的对照） | timens_offsets 与 CLOCK_MONOTONIC 偏移 | 待执行 |
| 3 | 禁嵌套：容器内 `unshare -u` / `sysc 272` | 预期 1145（名单未放行 unshare） | 待执行 |
| 4 | 名单补 `stat`（及候选 `lstat`） | 裸名命令恢复可用 | 待实现 |

---

## 附录：本篇用过的命令

```bash
# inode 对照
ls -l /proc/self/ns/
ls -l /proc/<容器init宿主pid>/ns/

# 双坐标
/bin/busybox cat /proc/self/status | grep NSpid      # 容器内（单坐标）
grep NSpid /proc/<容器init宿主pid>/status            # 宿主侧（双坐标）

# 生死实验（装置）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 300s -- \
  /bin/busybox sh -c '/bin/busybox sleep 300 & /bin/busybox sleep 300 & echo 子进程已起; wait'
# 正确的"选 init"与死亡验证
pgrep -af '^/bin/busybox sh -c'
sudo kill -9 <容器init宿主pid> && sleep 1 && pgrep -af busybox

# 中间态与"成为 1 号"（需 sudo；看 sh 自己要用 /proc/$$，不是 /proc/self）
sudo unshare --pid sh -c 'ls -l /proc/$$/ns/pid /proc/$$/ns/pid_for_children'
sudo unshare --pid --fork sh -c 'ls -l /proc/self/ns/pid /proc/self/ns/pid_for_children'
```