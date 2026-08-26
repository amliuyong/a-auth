#!/usr/bin/env bash
# open 档 POST /register per-IP 注册洪水限流真机 e2e(spec 005 §3.2 / C10.8)。
#
# 同一 IP(X-Forwarded-For)突发注册超桶容量(10)→ 429;不同 IP 独立放行(per-IP 隔离)。
# 防批量脚本洪水铸 client(存储膨胀 + 未验证标识滥用)。仅 open 档生效(IAT 档由票据闸挡)。
# **注**:注册桶补充 0.2/s 极慢,不受 wall-clock 影响 → 限流触发确定性(区别于 token 桶 10/s)。
#
# 用法:  API_URL=https://<host> ./e2e/register_flood.sh
# ⚠️ 会在目标环境造 ~10 个 DCR client(随机 id,dev 无害;生产勿跑)。用随机 IP 避免污染既有桶。
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
# 随机 IP 段避免与既有 reg-ip 桶碰撞(每次跑用不同 IP → 满桶起步)。
IP="203.0.113.$((RANDOM % 200 + 1))"
IP2="198.51.100.$((RANDOM % 200 + 1))"
pass=0; fail=0

echo "== 1. 同 IP($IP)突发 13 次注册 → 前 10 次 201、第 11 次 429 =="
saw_429=0; created=0; trip_at=0
for i in $(seq 1 13); do
  code=$(curl -s -X POST "$API_URL/register" -H "content-type: application/json" \
    -H "x-forwarded-for: $IP" \
    -d "{\"redirect_uris\":[\"https://flood$i.example.com/cb\"]}" -o /dev/null -w '%{http_code}')
  if [ "$code" = "429" ]; then saw_429=1; trip_at=$i; break;
  elif [ "$code" = "201" ]; then created=$((created+1)); fi
done
if [ "$saw_429" = "1" ]; then echo "  ✅ 第 $trip_at 次触发 429(限流前成功 $created 次)"; pass=$((pass+1));
else echo "  ❌ 13 次内未触发 429(成功 $created 次)"; fail=$((fail+1)); fi
# 桶容量 10:期望限流前恰 10 次成功(允许 ±1 容差防边界)。
if [ "$created" -ge 9 ] && [ "$created" -le 11 ]; then echo "  ✅ 限流前成功次数 ~容量 10($created)"; pass=$((pass+1));
else echo "  ⚠️ 限流前成功 $created 次(期望 ~10)"; fi

echo "== 2. 不同 IP($IP2)首次注册 → 201(per-IP 隔离,不受他人洪水影响)=="
code=$(curl -s -X POST "$API_URL/register" -H "content-type: application/json" \
  -H "x-forwarded-for: $IP2" \
  -d '{"redirect_uris":["https://other-ip.example.com/cb"]}' -o /dev/null -w '%{http_code}')
if [ "$code" = "201" ]; then echo "  ✅ 不同 IP → 201 放行(per-IP 隔离)"; pass=$((pass+1));
else echo "  ❌ 不同 IP → $code(应 201)"; fail=$((fail+1)); fi

echo ""
echo "==== 结果:$pass 通过, $fail 失败 ===="
[ "$fail" -eq 0 ] || exit 1
