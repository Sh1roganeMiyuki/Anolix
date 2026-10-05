# 02_cgroup 资源围栏：三道限额的执法取证与 rootless 权限限制

> 研究文档系列 02 ｜ 2026-09-24
> 项目：Anolix（轻量沙箱运行时核心，Go + runc）
> 环境：WSL2 Ubuntu / 内核 6.18 / runc 1.3.4 / cgroup v2 统一层级
> 本文所有数字与输出均来自本机真实运行，无推断值；推导项标注【推导】，未完成项标注【待续】。

---

## 背景

01 篇完成了 seccomp 模块——约束沙箱"能做什么系统调用"。本篇是第二个模块：**cgroup 资源围栏**——约束沙箱"能用多少资源"（内存 / 进程数 / CPU）。

沿用同一套三段链方法：

```
【声明层】policy.json              —— 项目自定义
【翻译层】launcher → OCI spec      —— 项目自定义
【执法层】runc → 内核 cgroup v2    —— 内核固定
```

验证标准：每个限额都要在**内核接口文件里读到数字**，并在超限时观察到**执法行为**（fork 被拒 / OOM / CPU 节流）——只看配置不算数。

本篇记录五件事：模块接入、rootless 权限限制、memory / pids / CPU 三道围栏的执法取证。

---

## 问题

把 `resources` 接进 policy 之后，出现两类与预期不符的现象：

| 现象 | 与预期的偏差 |
| --- | --- |
| 非 root 运行、policy 带限额时容器直接起不来（`mkdir /sys/fs/cgroup/anolix-*: permission denied`） | 预期"rootless 自动启用、无需 sudo"，实际带限额就失败 |
| 同一条 fork 循环命令先后给出三种不同的失败文案（`No error information` / `can't open '/dev/null'` / `Resource temporarily unavailable`） | 预期"限额生效就只有一种失败"，实际三种 |

本篇要回答的是：权限限制的边界在哪、三种文案各出自哪一层、三道围栏各自的执法证据长什么样。

---

## 分析

### 实验一：模块接入（声明 → 映射 → 写入）

- **预期**：policy 的三个限额字段应一一映射到 OCI `LinuxResources`，并落到内核接口文件；bundle/config.json 可静态核对。

- **数据**：

  examples/policy.json 基线：

  ```json
  "resources": {
    "memoryLimitBytes": 67108864,
    "pidsLimit": 20,
    "cpuQuotaMicros": 20000,
    "cpuPeriodMicros": 100000
  }
  ```

  即：内存 64 MiB、进程数上限 20、CPU 每 100ms 允许 20ms（0.2 核）。

  校验逻辑（`config.Resources.Validate`）：数值下限、周期范围 [1ms, 1s]；周期未配置时回退默认 100ms。

  `launcher.applyResourceLimits` → OCI `LinuxResources` 映射：

  | policy 字段 | OCI 字段 | 内核接口文件 |
  | --- | --- | --- |
  | memoryLimitBytes | LinuxMemory.Limit | memory.max |
  | pidsLimit | LinuxPids.Limit | pids.max |
  | cpuQuotaMicros / cpuPeriodMicros | LinuxCPU.Quota / Period | cpu.max 左值 / 右值 |

- **结果**：映射链打通，单测覆盖（config / launcher 双侧）。【项目自定义】

- **附带故障 A：旧二进制 + 严格解析。** 用未重编译的二进制跑新 policy，解析层直接拒绝：

  ```
  unknown field "resources"
  ```

  原因：config 解析使用 `DisallowUnknownFields`，旧二进制不认识新增字段。重编译（`go build -o anolix ./cmd/anolix`）后通过。教训：解析层报错，先核对"跑的是哪份二进制"，再怀疑代码逻辑。

### 实验二：rootless 权限限制定位

- **预期**：若失败源于"没有可写的 cgroup 位置"，则应能在 runc 源码里找到对应的两分支逻辑，且换身份或换地块应能绕过。

- **数据一（原始报错）**：非 root 运行、policy 带限额：

  ```
  ERRO[0000] runc run failed: unable to start container process: unable to apply cgroup configuration:
  rootless needs no limits + no cgrouppath when no permission is granted for cgroups:
  mkdir /sys/fs/cgroup/anolix-d89938e9fb84: permission denied
  ```

- **数据二（源码级定位）**：runc 的 cgroup 建立走 cgroups 库 fs2 实现，建立失败时的 rootless 分支（摘录，关键分支）：

  ```go
  if createErr != nil {
      if config.Rootless && config.Path == "" {
          if !needAnyControllers(config.Resources) {
              return cgroups.ErrRootless                  // 无任何限额：容忍，容器照跑（无专属 cgroup）
          }
          return fmt.Errorf("rootless needs no limits + no cgrouppath ...")  // 有限额：硬报错
      }
      return createErr
  }
  ```

- **数据三（落点规则与环境事实）**：runc 未指定 cgroupsPath 时，

  ```
  目标路径 = cgroup2 挂载点 + dir(自身所在 cgroup) + 容器ID
  ```

  本机会话位于 `/init.scope`，`dir()` 后为 `/`，因此目标是 `/sys/fs/cgroup/anolix-<id>`（顶层）。【runc 实现】

  | 对象 | 观察值 |
  | --- | --- |
  | /sys/fs/cgroup（顶层） | dr-xr-xr-x root:root（555，不给普通用户写） |
  | 当前会话 cgroup | /init.scope |
  | 委派子树 | user@1000.service/app.slice，属主 sh1rogane，控制器含 cpu memory pids |

- **数据四（权限尝试：chmod 无效）**：

  | 尝试 | 结果 |
  | --- | --- |
  | 普通用户 `chmod -x /sys/fs/cgroup` | Operation not permitted（非属主；且方向也错——缺的是 w，不是去掉 x） |
  | `sudo chmod +w /sys/fs/cgroup` | 命令成功：555 → 755，但只加到属主位（umask 滤掉 group/other 的 w）；普通用户身份重跑依然 mkdir 被拒 |
  | 对照：`chmod o+w` 自己名下的 app.slice | 成功（0755→0757，随后已还原）——修改权限的前提是目录属主是自己 |

  （写本文时实测 /sys/fs/cgroup 已回到 dr-xr-xr-x；目录时间戳显示此后发生过重新挂载，早前的权限改动已复位。）

- **数据五（三条路线对照）**：

  | 路线 | 身份 | 落点 | 结果 |
  | --- | --- | --- | --- |
  | 普通 shell | sh1rogane | /sys/fs/cgroup/anolix-*（顶层） | mkdir 被拒（有限额时硬报错） |
  | sudo | root | 同上 | 容器正常启动，限额写入生效 |
  | systemd-run --user --scope | sh1rogane | app.slice/anolix-* | 已见可建 cgroup（早期实验）；限额读数【待续】 |

- **结果**：
  1. "以前能跑、现在报错"的分界不是改坏了代码，而是从"没有任何限额要求"变成"有要求"——**无要求时可静默跳过，有要求时没有可写的位置就拒绝启动**。【runc 实现】
  2. 普通用户身份在该环境下没有可写的位置来建容器 cgroup；runc 官方测试矩阵（tests/integration/cgroups.bats）覆盖了对应象限：无限制 + 无权限 → 跳过且成功；有限制 + 无权限 → 报错。行为属预期设计，不是本项目缺陷。
  3. 两个出口由此收敛：**换身份**（sudo，rootful——顶层对 root 可写；本篇后续全部执法实验均走此路线）或**换地块**（先进入委派子树，如 `systemd-run --user --scope`，在属自己的 cgroup 上开工）【待续】。

- **遗留：一次失败点漂移（待复核）。** 另一次非 root 运行，失败点不在 mkdir 而在更后面：

  ```
  failed to write <pid>: write /sys/fs/cgroup/anolix-5aeeb66be7fb/cgroup.procs: permission denied
  ```

  说明失败点会随 /sys/fs/cgroup 当时的权限状态变化（该次运行时的权限状态未完整记录，之后挂载已复位为 555）。【待复核：在固定环境下复现一次，确认失败点漂移的条件。】

### 实验三：pids 围栏——同一条命令的三种失败文案

- **预期**：限额写入生效后，fork 循环应在触到 `pids.max` 时以**内核资源错误**（EAGAIN）失败；其它文案都意味着还没走到 cgroup 这一层。

- **装置**：容器内 fork 循环，尝试开出 60 个后台进程（sudo 路线，限额真实写入）：

  ```bash
  sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 60s -- \
    /bin/busybox sh -c 'i=0; while [ $i -lt 60 ]; do /bin/busybox sleep 60 & i=$((i+1)); done; echo "fork 结束，活着等你看"; sleep 45'
  ```

  同一条命令在名单修复过程中先后跑出三种文案，逐一归因。

- **数据一（第一种文案：无名 errno，seccomp 层盖章）**：

  ```
  sh: can't fork: No error information
  ```

  `No error information` 是 libc 对**不认识的 errno 值**的兜底文案（musl 的写法；glibc 会写 `Unknown error <n>`）。内核定义的 errno 都有名字（EAGAIN、ENOMEM……），因此这个 errno 不是内核产生的——它是 policy 的 `errnoRet=1145`（01 篇的哨兵值）：**fork 在 syscall 入口就被 seccomp 的 defaultAction 盖章，内核的 pids 检查根本没执行到**。

  根因：放行名单里只有 `clone`/`clone3`，没有 `fork`(57)/`vfork`(58)。Go/glibc 的进程创建走 clone，而 busybox（musl 静态构建）的 fork 路径走 57/58 号——**名单按名字匹配，clone 的放行不覆盖 fork**。runc/libseccomp 对名单中无法识别的名字是静默忽略的，因此这个缺口没有任何报错提示。

  点验（补名单后）：`sysc 57` 由"盖章"变为"放行"，且输出出现父子两份（fork 的真实语义）：

  ```
  syscall 57 成功: 返回值=11
  syscall 57 成功: 返回值=0
  ```

- **数据二（第二种文案：/dev/null，open(2) 缺口）**：补上 fork/vfork 后重跑，文案变为：

  ```
  sh: can't open '/dev/null': No error information
  ```

  POSIX 规定后台作业的 stdin 必须改接 /dev/null（否则后台进程会抢终端输入），这一步发生在 fork 之后、exec 之前，动作是一次 `open("/dev/null")`。名单里有 `openat` 但没有 `open`，而 musl 的 `open()` 在 x86-64 上走的是 2 号系统调用——**openat 的放行不覆盖 open**，于是子进程在这一步被盖章后死亡。

  伴随的两个现场证据（/proc 采样）：

  | 对象 | 观察值 | 含义 |
  | --- | --- | --- |
  | 子进程 | State = Z（zombie），cmdline 为空 | 死在 exec 之前，且未被回收 |
  | 父 shell | State = R；`/proc/<pid>/syscall` 连续 20 次采样均为 `running` | 纯用户态忙循环，`wait` 从未被调用 |

  即"漏一条名单"的第三种死法：不报错、不退出，而是**挂死**。

- **数据三（第三种文案：EAGAIN，pids 围栏真正上手）**：补上 open 后重跑同一条命令：

  ```
  sh: can't fork: Resource temporarily unavailable
  ```

  `Resource temporarily unavailable` 是 **EAGAIN(11)** 的标准文案——有名字的错误，来自内核资源检查：`pids.current` 触到 `pids.max=20` 后，fork 在 clone 执行路径中被 pids 控制器拒绝。【内核固定】

  两个细节：

  - 输出只有一行错误、`echo "fork 结束"` 未打印：busybox ash 将 fork 失败视为不可恢复错误，脚本当场终止（失败点约在第 19~20 个子进程处【推导：pids.max=20 扣除 shell 自身】）；
  - 已创建的 sleep 子进程随容器 init 退出由 runc 一并清理，未在宿主残留。

- **结果**：同一条命令的三种文案完成归因——**无名 errno = seccomp 盖章；/dev/null 无名 errno = 白名单缺口（open）；EAGAIN = cgroup pids 围栏**。三层签名对照：

  | 观测到的错误 | 出自哪层 | 语义 |
  | --- | --- | --- |
  | 1145（libc 兜底文案，无名 errno） | seccomp defaultAction | syscall 入口被盖章（策略章，01 篇哨兵值） |
  | EAGAIN 11（Resource temporarily unavailable） | cgroup pids.max | 内核资源检查：允许 fork，但生不出来 |
  | ENOSYS 38（Function not implemented） | 真内核 / libseccomp 内建伪造 | 号码表外或内核不支持（01 篇发现一） |

  判据：**有名字的错误来自内核，无名字的错误来自策略层**。

### 实验四：memory 围栏——OOM kill 的 dmesg 判据

- **预期**：越过 `memory.max` 时应观察到 OOM kill，且击杀被约束在容器自己的 cgroup 内（不是宿主全局 OOM）；`anon-rss` 应贴近上限。

- **装置**：容器内持续分配匿名内存直到越过 `memory.max = 67108864`（64 MiB）；死因由宿主 `dmesg` 判定。

  > 装置备注（详见 03 篇）：指数装置（`x="$x$x$x$x"`）毫秒级越界、读数抓不到爬升过程；可观测版用"每步 +10MB、步间 sleep 1"的阶梯装置。

- **数据（两份 dmesg 样本）**：

  样本一（wall-clock 格式，`dmesg -T`）：

  ```text
  [Fri Sep 25 10:13:55 2026] busybox invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0
  [Fri Sep 25 10:13:55 2026] oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=anolix-7c480544055c,mems_allowed=0,oom_memcg=/anolix-7c480544055c,task_memcg=/anolix-7c480544055c,task=busybox,pid=5570,uid=0
  [Fri Sep 25 10:13:55 2026] Memory cgroup out of memory: Killed process 5570 (busybox) total-vm:79428kB, anon-rss:64908kB, file-rss:584kB, shmem-rss:0kB, UID:0 pgtables:180kB oom_score_adj:0
  ```

  样本二（另一轮复跑；raw 格式，时间戳为开机秒数）：

  ```text
  [97651.671100] oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=anolix-d2094fe02604,mems_allowed=0,oom_memcg=/anolix-d2094fe02604,task_memcg=/anolix-d2094fe02604,task=busybox,pid=12367,uid=0
  [97651.671117] Memory cgroup out of memory: Killed process 12367 (busybox) total-vm:99604kB, anon-rss:64940kB, file-rss:452kB, shmem-rss:0kB, UID:0 pgtables:180kB oom_score_adj:0
  ```

  两份样本对照：

  | 项 | 样本一 | 样本二 |
  | --- | --- | --- |
  | 容器 cgroup | anolix-7c480544055c | anolix-d2094fe02604 |
  | 被杀进程 | busybox（pid 5570） | busybox（pid 12367） |
  | total-vm | 79,428 kB（约 77.6 MB） | 99,604 kB（约 97.3 MB） |
  | anon-rss | 64,908 kB（约 63.4 MiB） | 64,940 kB（约 63.4 MiB） |
  | shmem-rss | 0 | 0 |

- **结果**：
  - **anon-rss 两次都贴住 64 MiB 上限（63.4 MiB）** → 击杀发生在"charge 越过 memory.max"的瞬间；
  - total-vm 差异（77.6 → 97.3 MB）反映被杀那一刻**在途分配规模不同**（realloc 的新缓冲 + 旧缓冲 + 壳子）【推导】——装置/步长可以不同，签名不变。

  字段判据：

  | 字段 | 读数特征 | 判读 |
  | --- | --- | --- |
  | `constraint=CONSTRAINT_MEMCG`；`oom_memcg` 与 `task_memcg` 相同 | 均为容器 cgroup | 击杀**被约束在容器自己的 cgroup 内**——不是宿主全局 OOM【内核固定】 |
  | `anon-rss` | 两次均 ≈ 63.4 MiB | 贴 64 MiB 上限被杀 |
  | `shmem-rss = 0` | — | 与"匿名内存炸弹"装置一致（非 tmpfs 路径） |
  | 时间戳格式 | `[Fri Sep 25 10:13:55 2026]` vs `[97651.671100]` | 前者是 `-T` 墙钟；后者是 raw 开机秒数，跨样本比较先确认格式 |

  三条小结：
  1. memory 围栏三段链闭环：声明（policy）→ 映射（`memory.max`）→ 执法（OOM kill，约束=memcg）；
  2. 已知缺口：`memory.swap.max` 未映射（默认 max）——有 swap 时超额可能被"换出消化"而不是击杀；裁决为【待实现】：内存围栏下强制 swap=0；
  3. 复现性：两份独立样本签名一致（constraint=memcg + anon-rss 贴上限）。

### 实验五：CPU 围栏——throttle 的读数

- **预期**：cpu.max 不产生错误输出，只能读计数器；若配额生效，`usage_usec` 应等于窗口长度 × 配额比例，且 `nr_throttled` 持续累加。

- **前置：为什么 CPU 围栏没有错误输出。** 三道围栏的执法方式不同，可观测签名也因此不同：

  | 围栏 | 执法方式 | 可观测签名 |
  | --- | --- | --- |
  | memory.max | OOM kill | dmesg：constraint=CONSTRAINT_MEMCG、anon-rss 贴 64 MiB 上限（实验四） |
  | pids.max | 拒绝新增 | fork 返回 EAGAIN（实验三） |
  | cpu.max | throttle：周期内配额用尽即冻结，下周期再放行 | **无任何错误输出**，只能读 cpu.stat |

  因此 CPU 围栏的取证不能等报错，必须主动布点读计数器。

- **装置**：容器内起两个纯用户态死循环（0 个系统调用，seccomp 不参与），前台 sleep 30 撑出观测窗口：

  ```bash
  sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 60s -- \
    /bin/busybox sh -c '
      echo "=== CPU 燃烧开始，持续 30 秒 ==="
      # 起 2 个死循环后台进程把核占满
      i=0; ( while :; do i=$((i+1)); done ) &
      j=0; ( while :; do j=$((j+1)); done ) &
      /bin/busybox sleep 30
      echo "=== 燃烧结束 ==="
    '
  ```

  第二终端在窗口内盯读数（cgroup 由 sudo 创建，但目录权限 755，读取无需 sudo）：

  ```bash
  c=$(ls -dt /sys/fs/cgroup/anolix-* | head -1)
  watch -n 1 "cat $c/cpu.stat"
  ```

  容器内输出：

  ```
  === CPU 燃烧开始，持续 30 秒 ===
  === 燃烧结束 ===
  ```

- **数据（原始读数）**：

  ```
  Every 1.0s: cat /sys/fs/cgroup/anolix-3aee011e67c6/cpu.stat          LAPTOP-BF0J00M9: Thu Sep 24 19:02:41 2026

  usage_usec  5965001
  user_usec  5949531
  system_usec  15470
  nice_usec  0
  nr_periods  297
  nr_throttled  297
  throttled_usec  53302860
  nr_bursts  0
  burst_usec  0
  ```

- **结果（数字自洽性核对）**：配置值 cpu.max = `20000 100000`（0.2 核，由 policy 映射写入）。【项目自定义 → 内核固定】

  | 核对项 | 计算 | 观察值 | 结论 |
  | --- | --- | --- | --- |
  | 窗口长度 | nr_periods 297 × 100ms = 29.7s | 燃烧窗口 30s | 周期配置真实生效 |
  | CPU 发放量 | 29.7s × 0.2 = 5.94s = 5,940,000µs | usage_usec = 5,965,001µs | 偏差 0.4%，配额真实生效 |
  | 限流频率 | — | nr_throttled = 297 = nr_periods | **每个周期都被限流**（需求持续超配额） |
  | 冻结总量【推导】 | 需求 2 核 × 29.7s = 59.4s，减去发放 5.94s = 53.46s | throttled_usec = 53,302,860µs | 偏差 0.3%；throttled_usec 为全部被冻任务的合计时间 |
  | 时间分布 | user_usec / usage_usec = 99.7% | system_usec 仅 15,470µs | 与"纯用户态循环"的装置设计一致 |

  五项读数互相咬合：配额（0.2 核）、周期（100ms）、限流频率（每周期）、冻结总量（需求−发放）全部对得上——**cpu.max 的执法行为完成实证**。CPU 围栏的签名是"读数"而不是"报错"：usage_usec 的斜率恒为配额比例、nr_throttled 持续累加。这与 06 讲义的模型一致——throttle 是"跑跑停停"，不是降频，也不是拒绝。【内核固定】

---

## 修复

| 问题 | 改动 / 出口 |
| --- | --- |
| 故障 A：`unknown field "resources"` | 重编译二进制（`abuild`）；解析层报错先核对跑的是哪份二进制 |
| rootless + 限额起不来 | 换身份（sudo，本篇后续执法实验均走此路线）或换地块（委派子树）；chmod 修不了（方向也不对） |
| 文案一：fork 被盖章 | 名单补 `fork` / `vfork` |
| 文案二：/dev/null 打不开 | 名单补 `open`（musl 走 2 号） |
| memory 的 swap 缺口 | 【待实现】`memory.swap.max = 0` 映射（policy 字段 + spec 映射 + 单测） |

## 数据对比

三道围栏的执法签名对照（本篇的核心产出）：

| 围栏 | 执法方式 | 证据形态 | 取证位置 |
| --- | --- | --- | --- |
| memory.max | OOM kill | dmesg：`constraint=CONSTRAINT_MEMCG`、`anon-rss` ≈ 63.4 MiB 贴上限 | 实验四（两份样本） |
| pids.max | 拒绝新增 | fork 返回 EAGAIN（`Resource temporarily unavailable`） | 实验三（第三种文案） |
| cpu.max | throttle 冻结 | cpu.stat 五项读数自洽（usage/nr_periods/nr_throttled/throttled_usec/user 占比） | 实验五 |

## 观测窗口约束（方法论）

cgroup 目录随容器生命周期存在与消失，"何时读"与"读什么"同等重要：

1. **目录生命周期**：容器退出 → cgroup 目录被清理 → 宿主机读不到（`ls: cannot access '/sys/fs/cgroup/anolix-*': No such file or directory`）。读数必须在存活窗口内完成；本篇 CPU 实验用前台 `sleep 30` 撑窗口；
2. **fork 失败会直接终止 shell**：循环触到 pids 上限后仅输出一行 `can't fork` 且容器随即退出——不能用"fork 出来的命令"撑窗口，要用**内建 wait**（不需要 fork）；
3. **后台 SIGTTIN**：命令尾挂 `&` 且 stdin 仍接终端时，容器进程组读终端会被 SIGTTIN 停住（Stopped (tty input)），残留 job 干扰后续。处理：`</dev/null` 或前台运行，残留用 `kill %N` 清理。

---

## 结论与启示

### 1. 阶段性结论

1. 三段链全部打通，**三道围栏均拿到第一手执法证据**：memory——OOM kill（dmesg constraint=CONSTRAINT_MEMCG、anon-rss 贴上限）；pids——fork 返回 EAGAIN；cpu——cpu.stat 读数五项自洽；
2. rootless + 有限额 + 无权限 = 硬报错；rootless + 无限额 = 静默跳过。分界条件：是否需要控制器。【runc 实现】
3. 权限限制的出口只有两条：**换身份**（sudo）或**换地块**（委派子树）；chmod 修不了（方向也不对）；
4. 同一条命令的三种失败文案证明：**错误文案本身就是分层判据**——无名 errno 指向策略层，有名字的错误指向内核层。

### 2. 教训

- **二进制版本是第一嫌疑**：解析层报错（unknown field）先查"跑的哪个二进制"；
- **"配置了" ≠ "生效了"**：限额证据是内核文件里的数字与执法行为（EAGAIN / OOM / 节流读数），不是 policy.json 里的声明；
- **白名单缺口有三种死法**：解析层报错（unknown field）、seccomp 盖章（无名 errno）、挂死（zombie + 用户态自旋）——同一条"漏一条"的根因，表现完全不同；且 runc 对名单中无法识别的名字静默忽略，拼写错误同样无声；
- **CPU 围栏不产生错误输出**：观测必须主动布点（cpu.stat），等报错会永远等不到；
- **实验装置要包含"读取窗口"**：cgroup 对象只在容器存活期存在，涉及存活时间的失败模式（fork 失败即退）要先想清楚撑窗口的手段。

---

## 下一步

| # | 实验 | 观测点 | 状态 |
| --- | --- | --- | --- |
| 1 | pids 三件套读数（窗口内读取，命令见附录） | pids.max / pids.current / pids.events | 待执行 |
| 2 | 内存超限 | dmesg "Memory cgroup out of memory"、constraint=CONSTRAINT_MEMCG | **已实证（实验四；两份样本）** |
| 3 | 委派子树对照（systemd-run --user --scope） | 容器 cgroup 落在 app.slice 下、三件套可读可写 | 待执行 |
| 4 | 失败点漂移复现（实验二遗留） | 固定环境复现一次 | 待复核 |
| 5 | 探针判据与 errnoRet 对齐 | probe 的 blocked() 只认 EPERM/ENOSYS，errnoRet=1145 下误报 fail | 待实现 |
| 6 | 第二批工具：内存炸弹 / CPU 忙循环专用探针 | 替代 busybox 的粗验证 | 未开始 |
| 7 | `memory.swap.max = 0` 映射（policy 字段 + spec 映射 + 单测） | 越界即击杀，不再被换出消化 | 待实现 |

---

## 附录：本模块使用过的关键命令

```bash
# 重编译（或 abuild，见 ~/.bash_aliases）
go build -o anolix ./cmd/anolix

# pids 实验（fork 循环，sudo 路线）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 60s -- \
  /bin/busybox sh -c 'i=0; while [ $i -lt 60 ]; do /bin/busybox sleep 60 & i=$((i+1)); done; sleep 45'

# pids 三件套（长窗口版：19 个子进程 + 内建 wait 撑窗口）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 120s -- \
  /bin/busybox sh -c 'i=0; while [ $i -lt 19 ]; do /bin/busybox sleep 60 & i=$((i+1)); done; echo "--- 窗口打开 ---"; wait'
# 第二终端（窗口内）：
c=$(sudo ls -dt /sys/fs/cgroup/anolix-* | head -1); sudo cat "$c"/pids.max "$c"/pids.current "$c"/pids.events

# CPU 实验（双燃烧进程 + sleep 30 撑窗口）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 60s -- \
  /bin/busybox sh -c 'i=0; ( while :; do i=$((i+1)); done ) & j=0; ( while :; do j=$((j+1)); done ) & /bin/busybox sleep 30'
# 第二终端（窗口内）：
c=$(ls -dt /sys/fs/cgroup/anolix-* | head -1); watch -n 1 "cat $c/cpu.stat"

# memory 实验（10MB 步进装置；applet 必须带 /bin/busybox 前缀）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 60s -- \
  /bin/busybox sh -c 's=""; i=1; while [ $i -le 15 ]; do chunk=$(/bin/busybox yes | /bin/busybox head -c 10000000); s="${s}${chunk}"; echo "[Step $i] 约 $((i*10)) MB"; i=$((i+1)); /bin/busybox sleep 1; done'
# 死因判定（raw 格式无 -T，时间戳为开机秒数）
sudo dmesg | grep -i -E 'CONSTRAINT_MEMCG|Memory cgroup out of memory'

# 名单点验（容器内按号码观测）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs -- /sysc 57   # fork：放行则输出父子两份
```

源码参照位置（本地缓存，已 gitignore）：

- `.tmpgm/github.com/opencontainers/cgroups@v0.0.4/`（fs2 实现：Apply 两分支、defaultpath 落点规则、CreateCgroupPath）
- `.tmprs/` 中 runc 1.3.4（tests/integration/cgroups.bats 四象限测试矩阵）
