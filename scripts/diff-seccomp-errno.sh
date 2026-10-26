#!/usr/bin/env bash
# runc vs crun：seccomp errnoRet/action 组合合法性差分。
#
# 规范依据（runtime-spec config-linux.md）：
#   defaultErrnoRet / syscalls[].errnoRet 只对 SCMP_ACT_ERRNO、SCMP_ACT_TRACE
#   这类"支持 errno"的动作有效；动作不支持 errno 时，
#   "the runtime MUST print an error and fail."
#
# 四格（同一份 config.json 原样喂两家，只换运行时）：
#   valid         ALLOW 默认 + 一条 ERRNO 规则   合法 → 两家都该跑出 payload 输出
#   bad-default   ALLOW 默认 + defaultErrnoRet   非法 → 两家都该报错退出
#   bad-per       ALLOW 规则 + errnoRet          非法 → 同上（含一条合法规则，测"冗余"与否）
#   bad-per-only  只留那条非法 ALLOW 规则         最小化复现
#
# 判定：rc=0 且打出 payload 结果 = 接受了非法配置；rc≠0 + 报错 = 符合规范。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUNC="${RUNC:-/usr/sbin/runc}"
CRUN="${CRUN:-$ROOT/.tools/crun-root/usr/bin/crun}"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-$ROOT/.tools/crun-root/usr/lib/x86_64-linux-gnu}"

W="$ROOT/.bench-tmp/errno-allow"

run_one() { # $1=运行时路径 $2=标签 $3=bundle
  local rt="$1" tag="$2" bundle="$3" out rc first
  out=$("$rt" --root "$W/state-$tag" run --bundle "$bundle" "t-$tag" 2>&1)
  rc=$?
  first=$(printf '%s' "$out" | grep -v '^$' | head -1 | cut -c1-140)
  # runc 的报错带 logrus 前缀，剥掉时间戳只留 message
  first=$(printf '%s' "$first" | sed -E 's/^time="[^"]*" level=[a-z]+ msg="?//; s/"$//')
  printf '  %-4s rc=%-3s %s\n' "$(basename "$rt")" "$rc" "${first:-<无输出>}"
}

for tag in valid bad-default bad-per bad-per-only; do
  echo "=== $tag ==="
  printf '  config: %s\n' "$(python3 -c "import json;print(json.dumps(json.load(open('$W/$tag/config.json'))['linux']['seccomp']))")"
  run_one "$RUNC" "runc-$tag" "$W/$tag"
  run_one "$CRUN" "crun-$tag" "$W/$tag"
done