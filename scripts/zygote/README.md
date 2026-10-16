# zygote 验证脚本集

改完代码不用记命令——跑这套脚本验证机制没坏。

## 文件

| 脚本 | 干什么 |
|---|---|
| `build.sh` | 编译 `bin/{zygote,spawn,worker}` |
| `mother.sh up\|down\|status\|log [N]` | 起/杀/查母体；`log` 看日志（worker 自打印都在这） |
| `verify.sh ns\|memfd\|cgroup\|seccomp\|all` | 四条探针，验四套机制 |

## 前置

- **sudo**：母体要 root（clone 带 `CLONE_NEW*` 需 `CAP_SYS_ADMIN`）。先 `sudo -v` 缓存一下，免得每条命令都问密码。
- 在**仓库根目录**跑（脚本会自己 `cd` 到根）。
- 第一次给脚本加执行位：`chmod +x scripts/zygote/*.sh`

## 典型流程

```bash
cd scripts/zygote

./build.sh            # 1. 编译
./mother.sh up        # 2. 起母体（后台；--warm 64 --cgroup ...）
./verify.sh all       # 3. 一把验四套
./mother.sh log 40    # 4. 看 worker 的自打印（smaps / seccomp 探针）
./mother.sh down      # 5. 收工（杀母体 + 清残留 cgroup 叶子 + socket）
```

## 每条探针验什么 / 期望

| 探针 | 验 | 期望 |
|---|---|---|
| `ns` | `NSpid` | **两字段**（宿主 PID + ns 内 PID=1） |
| `memfd` | `smaps` | `Shared_Dirty`≈全区；`Pss` 随并发摊薄（N 个→约 1/N） |
| `cgroup` | 叶子 cgroup | `cgroup.procs` 含 worker PID；`memory.max`/`pids.max` 是设的值 |
| `seccomp` | 探针 syscall | 装：`sethostname`→`EPERM` ✅；不装（`noseccomp`）：→成功 ❌ |

## 可调环境变量

`mother.sh up` 读这些（默认值见脚本头）：

| 变量 | 默认 | 含义 |
|---|---|---|
| `SOCK` | `/tmp/anolix-zygote.sock` | socket 路径 |
| `LOG` | `/tmp/zygote-mother.log` | 母体日志 |
| `WARM` | `64` | 共享 memfd 大小（MB） |
| `CGMEM` | `256` | worker 内存上限（MB）；调小可试 OOM |
| `CGPIDS` | `200` | worker 进程数上限 |
| `CGCPU` | `0` | worker CPU 配额百分比；0=不限 |

例：起一个"内存只给 32MB"的母体，再 spawn 一个吃内存的 worker 看 OOM：

```bash
CGMEM=32 ./mother.sh up
./verify.sh cgroup        # 看 memory.max=33554432
```

## 注意

- **worker 的自打印不在 `verify.sh` 的输出里**——worker 的 stdout 接的是母体，所以去 `./mother.sh log` 看。
- `mother.sh down` 会清 `/sys/fs/cgroup/anolix-*` 残留叶子；若有 worker 还没退，会提示"留"。
- 这些脚本是**验证探针**，不是攻击工具——它们 spawn 的是我们自己的 `bin/worker`。