# docs/architecture/ — Anolix 架构产物

由 Qoder「架构可视化」（architecture-visualization）插件生成：场景技能 `system-modeler`，格式基础 `c4model` + `graphviz`。
状态：**当前态（current）** 快照，采集日期 2026-09-20。

## 文件清单

| 文件 | 内容 | 用什么看 |
| --- | --- | --- |
| `system-context.structurizr.dsl` | C4 三视图：SystemContext / Containers / CliComponents | Qoder 打开 → 插件 Structurizr DSL viewer |
| `package-dependency.dot` | Go 包级依赖图（import 实线 / 运行时 exec 虚线） | Qoder 打开 → 插件 Graphviz DOT viewer |
| `architecture-model.json` | 结构化证据模型（节点/边 + sourceRefs + 置信度） | 任意编辑器；可用下方校验命令复核 |
| `system-model.evidence.md` | 证据索引 + 已知局限 + 验证任务 | Markdown |
| `system-model.summary.md` | 一页纸解读：边界、关键关系、下一步路由 | Markdown |

## 预览

在 Qoder 中直接打开 `.structurizr.dsl` 或 `.dot` 文件即可触发插件自带的格式查看器（Canvas）。
渲染结果是派生视图；**文件本身是唯一事实源**，若渲染异常请修正源文件而不是渲染产物。

## 更新方式（无确定性抽取器，按证据手工维护）

1. 代码变更后，按 `architecture-model.json` 中每条节点/边的 `sourceRefs` 逐条复核（引用行号为闭区间）。
2. 更新对应视图（DSL / DOT / JSON / 证据表），保持节点与边的**稳定 ID** 不变，便于 diff。
3. 未知项写入证据索引进「已知局限与验证任务」，不要平滑进图。

## 自检命令（本次已通过）

```bash
# 1) JSON 语法
python3 -m json.tool docs/architecture/architecture-model.json > /dev/null && echo "JSON OK"

# 2) DOT 语法（需 graphviz）
dot -Tsvg -o /tmp/pkg-dep.svg docs/architecture/package-dependency.dot && echo "DOT OK"

# 3) sourceRefs 逐条可解析（文件存在 + 行号在范围内）
python3 - <<'PY'
import json, re, pathlib
m = json.load(open('docs/architecture/architecture-model.json'))
root = pathlib.Path('.')
bad = []
for item in m['nodes'] + m['edges']:
    for ref in item.get('sourceRefs', []):
        path, _, span = ref.partition(':')
        f = root / path
        if not f.exists():
            bad.append(ref); continue
        if span and '-' in span:
            s, e = map(int, span.split('-'))
            n = len(f.read_text(errors='ignore').splitlines())
            if not (1 <= s <= e <= n):
                bad.append(ref)
print("sourceRefs OK" if not bad else f"BAD: {bad}")
PY
```