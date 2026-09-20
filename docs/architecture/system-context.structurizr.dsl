# Anolix 当前态 C4 模型（Structurizr DSL）
# 生成方式：架构可视化插件 system-modeler（场景）+ c4model（C4 DSL 基础）
# 证据索引：system-model.evidence.md ｜ 解读：system-model.summary.md
# 预览：在 Qoder 中打开本文件，由插件 canvases/dsl 的 Structurizr DSL format viewer 渲染
workspace "Anolix 沙箱运行时" "当前态架构模型：把安全策略翻译成 OCI 配置并管理容器生命周期。" {
    !identifiers hierarchical

    model {
        developer = person "开发者 / 学习者" "运行沙箱命令、复现三世界对照实验、生成内核机制可视化。"

        anolix = softwareSystem "Anolix 沙箱运行时" "将 policy 翻译为 OCI 配置并管理容器生命周期；隔离机制由 runc 与 Linux 内核提供。" {
            cli = container "anolix CLI" "沙箱启动器：参数解析、策略加载、生成 OCI bundle、驱动 runc、透传退出码。" "Go（cmd/anolix）" {
                cliMain = component "CLI 入口" "flag 解析、policy 加载、信号处理（Ctrl+C/SIGTERM）、退出码透传。" "cmd/anolix/main.go"
                configPkg = component "config 包" "policy JSON 严格解析（拒绝未知字段）与取值校验。" "Go"
                launcherPkg = component "launcher 包" "OCI spec 生成（spec.go）、bundle 组装与容器生命周期（launcher.go）。" "Go"
            }

            group "沙箱内工具（rootfs 内容）" {
                probe = container "probe 探针" "容器内自检：PID/UTS 隔离、能力集清空、NoNewPrivileges、seccomp 拦截 socket/ptrace。" "Go 静态二进制"
                sysc = container "sysc 系统调用探针" "按号码直接发起系统调用观察放行/拦截；raw 模式读 rax 原值。" "Go + x86-64 汇编"
                rawfilter = container "rawfilter 原始过滤器实验" "手写经典 BPF 过滤器直接装入自身（不经 libseccomp），验证表外号码是否可见。" "Go"
            }

            labBuild = container "构建与实验脚本" "mkrootfs.sh 构建最小 rootfs；syscall-lab.sh 复现三世界对照实验。" "Bash"
            labVisual = container "可视化脚本（本地未入库）" "skscope.py 沙箱解剖图；kstate.py 内核决策状态机。" "Python"
        }

        runc = softwareSystem "runc（OCI 运行时）" "外部依赖：创建命名空间、装载 seccomp 过滤器、以容器 init 执行命令。" {
            tags "External"
        }
        kernel = softwareSystem "Linux 内核" "隔离机制提供者：namespaces、seccomp BPF、cgroups、设备过滤。" {
            tags "External"
        }

        # ---- 系统边界关系 ----
        developer -> anolix "anolix run [flags] -- <命令>"
        developer -> anolix.labBuild "运行实验脚本"
        developer -> anolix.labVisual "生成可视化 / 状态机图"

        # ---- 系统内关系 ----
        anolix.labBuild -> anolix.cli "三世界对照：经沙箱运行" "Bash"
        anolix.labBuild -> anolix.sysc "世界 1 对照：宿主直跑（无 seccomp）" "Bash"
        anolix.labBuild -> anolix.probe "构建：CGO_ENABLED=0 静态编译进 rootfs" "Go build"
        anolix.labVisual -> anolix.cli "启动真实沙箱抓取 /proc 现场" "Python"

        anolix.cli -> runc "exec：runc run --bundle <bundle> <id>" "CLI"
        anolix.cli.cliMain -> anolix.cli.configPkg "Load() / Default() 获取策略"
        anolix.cli.cliMain -> anolix.cli.launcherPkg "New() + Run(ctx) 驱动运行"
        anolix.cli.launcherPkg -> anolix.cli.configPkg "Validate() / Effective* 取值"
        anolix.cli.launcherPkg -> runc "exec runc run（BuildRuncArgs 组装参数）" "CLI"

        # ---- 外部依赖与沙箱内进程的边界 ----
        runc -> kernel "创建 namespaces / 装载 seccomp BPF / cgroup 设备规则" "syscalls"
        runc -> anolix.probe "以容器 init 执行 /probe"
        runc -> anolix.sysc "实验时以容器 init 执行 /sysc"

        anolix.probe -> kernel "自检：读 /proc、探测 socket/ptrace（预期被拦）"
        anolix.sysc -> kernel "按号码发起系统调用，观察放行/拦截"
        anolix.rawfilter -> kernel "PR_SET_NO_NEW_PRIVS + PR_SET_SECCOMP 装载过滤器"
    }

    views {
        systemContext anolix "SystemContext" "系统边界：开发者、Anolix、runc 与 Linux 内核。" {
            include *
            autoLayout lr
        }

        container anolix "Containers" "系统内可运行单元与工具（连同直接交互的外部系统）。" {
            include *
            autoLayout lr
        }

        component anolix.cli "CliComponents" "anolix CLI 内部包级组件。" {
            include *
            autoLayout lr
        }

        styles {
            element "Person" {
                shape person
                background #08427b
                color #ffffff
            }
            element "External" {
                background #999999
                color #ffffff
            }
        }
    }
}