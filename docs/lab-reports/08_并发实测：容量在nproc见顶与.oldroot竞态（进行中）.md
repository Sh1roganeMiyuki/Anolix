# 08_并发实测：容量在 nproc 见顶与 .oldroot 竞态（进行中）

> 状态：只写到“数据与现象”。归因、屏障、R 轮、优化都没做。
> 本文所有“为什么”都是假设，标了 ⚠️；能当结论的只有数字和 `.oldroot` 那一条闭环。

---

## 背景

07 把单次启动钉在了同一个终点：同权限完整档 15.0 / 4.40 = 3.4×。
但 zygote 的卖点不是“第一个快”，是“第 100 个还一样快”。

单次数据回答不了这个问题：

- 吞吐 = K / 窗口，不是单次延迟的倒数；
- 并发下每个请求的起点不同，没有共同时间轴就无法对账；
- 测量工具自己也会抢 CPU。

08 要回答三件事：

1. K 个同时 spawn，延迟、吞吐、CPU 怎么变？
2. 瓶颈是 CPU 吗？
3. 并发会不会暴露单次测不出的 bug？

---

## 实验设计

### 口径（三个旋钮）

- **起点**：每个客户端发请求前的 `CLOCK_MONOTONIC`（`SPAWN_META.dispatch_ns`）。
- **终点**：payload 第一条用户态指令（`PAYLOAD_META.abs_ns`，tprobe 一进 `main` 就取）。
- **窗口**：最早 dispatch → 最晚 abs。吞吐 = K / 窗口。
- **条件**：nproc=16；母体 `--warm 64 --cgroup --cg-memory 256 --cg-pids 200`；K=1/16/64；单轮。

### 三路打点，按 id 归并

| 行 | 产出方 | 用途 |
|---|---|---|
| `SPAWN_META` | spawn 客户端 | dispatch / 母体回包 |
| `ANOLIX_MOTHER` | 母体 | accept / cgroup 建完 / clone+exec 返回 |
| `PAYLOAD_META` | tprobe | 第一条指令的绝对时刻 + run id |
| `ANOLIX_REAP` | 母体收尸 | worker 的 utime+stime |

并发下日志顺序不可信，所以按 id 归并，不按行号。

### 为什么客户端不用 sudo

特权动作都在母体（clone、cgroup、mount），socket 是 0666。客户端提权只会引入
`sudo secure_path` 这个额外变量（07 的 PATH 税）。

### 为什么要 `ANOLIX_MOTHER`

没有它，只能看到“客户端回包”；而母体是在 `cmd.Start()` 成功后就回包，payload 还没跑。
K=16 时回包 p50 5.9ms，payload p50 16.1ms——两个终点差约 10ms。

### 工具与原始数据

`scripts/zygote/conc.sh`；原始数据落 `.bench-tmp/conc/<tag>/`（不入库）。
K=1/16/64 的 tag 见附录。

---

## 数据

### 主表（本机、单母体、单轮，load 0.13）

| K | p50(ms) | p95(ms) | 窗口(ms) | 起跑斜坡(ms) | 吞吐(spawn/s) | CPU(核/16) |
|---|---|---|---|---|---|---|
| 1 | 7.0 | 7.0 | 7.0 | 0 | — | 0.9 |
| 16 | 16.1 | 19.4 | 25.3 | 9.9 | 632 | 5.3 |
| 64 | 62.7 | 87.8 | 125.7 | 52.4 | 509 | 4.6 |

> K=1 的吞吐不填：1 个请求除以窗口没有意义（脚本会打 142/s）。

### 分段（p50 / p95，ms）

| K | socket+排队 | cgroup | clone+exec | rootfs+seccomp+exec |
|---|---|---|---|---|
| 1 | 0.30 / — | 0.26 / — | 0.88 / — | 5.59 / — |
| 16 | 1.1 / 9.5 | 0.46 / 1.0 | 3.2 / 13.2 | 7.7 / 15.1 |
| 64 | 5.6 / 58.7 | 2.8 / 57.0 | 9.8 / 38.1 | 9.4 / 59.3 |

⚠️ `rootfs+seccomp+exec` 的终点是母体记的 `clone_done`，而母体的记账会滞后于 worker 自己。
早前几轮出现过 tail 为负（payload 早于 clone_done）。正确边界应该用 worker-init 自己的
`init_start`（打点已有，脚本还没解析）。**这一列只能看趋势，不能当精确账。**

---

## 现象

### 现象 1：容量在 nproc 见顶

- 吞吐 632 → 509；每个 spawn 的平均成本 1.58 → 1.96ms。
- CPU 只用了 4.6 / 16 核。
- 四段 p95 都在 57–59ms。

⚠️ 假设（未归因）：不是 CPU 不够，是整条链在等——cgroup、Go 的 fork 路径、
worker 的 `mount` / `pivot_root`、调度，四者尚未分离。

### 现象 2：并发第一枪打中 .oldroot

K=64 首轮 **6/64** 失败，日志是：

```
worker-init: rootfs 设置失败: pivot_root 失败: no such file or directory
```

- **根因**：rootfs 是所有 worker 共享的同一个宿主目录；`.oldroot` 是里面的普通目录。
  A 换根后 `rmdir` 删的是共享目录项，B 在 `mkdir` 与 `pivot_root` 之间就找不到 put_old。
- **两种交错**：
  1. B 先 `pivot_root` → 目录成为挂载点 → A 的 `rmdir` 吃 `EBUSY` → B 成功。
  2. B `mkdir` → A `rmdir` → B `pivot_root` 找不到 put_old → `ENOENT` → 6/64。
- **修复 A（采用）**：只 `umount`，不 `rmdir`；`.oldroot` 常驻空目录。
  - 代价：payload 的 `/` 下多一个空目录；rootfs 必须可写或预建。
  - 放弃唯一目录名（崩溃留垃圾、需清理）；放弃每 worker 独立 rootfs（复制成本、违背共享初衷）。
  - 失效条件：rootfs 只读时 A 不成立，需预建 `.oldroot` 或改用唯一名。
- **验证**：修复前 6/64 ENOENT；修复后 3 次 K=64（含一次冷启动）**均 64/64**。
  仍属必要非充分证据。

> 这是 08 目前唯一的闭环：现象 → 根因 → 修复 → 复跑。

---

## 还没做的（下半篇）

- **屏障**：K 个请求同一时刻发出，把 52.4ms 的斜坡移出窗口。现在 509/s 是下限。
- **R 轮**：K=64 的 p50 三次是 44 / 93 / 63ms（冷启动、load、斜坡），单轮不可复现。
- **归因**：`--cgroup` on/off、1 个母体 vs 4 个母体、worker 侧 8 站拆分。
- **优化**：cgroup 池化、worker 侧 5.6ms、或多母体横向扩。
- **基线**：07 是 4 vCPU 时代；现在 nproc=16，K=1 已 7.0ms，旧绝对值不能直接比。

---

## 附录：复跑

```bash
./scripts/zygote/build.sh
CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe

sudo -v
./scripts/zygote/mother.sh down && ./scripts/zygote/mother.sh up

K=16 W=3 ./scripts/zygote/conc.sh
K=64 W=3 ./scripts/zygote/conc.sh
```

原始数据 tag（本机 `.bench-tmp/conc/`）：

- `k1-1792577948342307973`
- `k16-1792577949437528913`
- `k64-1792577950566294903`