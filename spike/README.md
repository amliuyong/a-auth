# P-1 薄纵切 spike —— KMS ES256 Sign(P0 开工 gate)

> DESIGN §10 line 776/783 定义的 **P0 开工 gate**:验证最薄端到端签名链的**正确性**与**性能输入**,据此拍板语言选型 / provisioned concurrency / 跨区分片阈值 / 重估 P0 工期。**非生产代码**,不进 workspace。

## 结论(2026-07-09,真机 us-east-1,profile default,configured AWS identity)

### ✅ Gate 通过

**密码学链正确性(spec 005 C10.3 DER↔JOSE 对真实 KMS 输出成立)**:

- 真实 KMS `Sign`(EcdsaSha256,EC_NIST_P256 CMK)返回 **71 字节 DER** 签名
- 经 `agent_auth_infra_core::signature::der_to_jose` 转成 **64 字节裸 r‖s**(JOSE ES256)
- 组装完整 JWT,导出 KMS 公钥(GetPublicKey,SPKI DER)
- **独立验签器 PyJWT/ES256(与签发方零共享代码)验签通过**;篡改签名被拒(验签器确在校验)
- → 第三方 RS 的标准 JOSE 验签器会接受我们的 token,DER→JOSE 转换无 off-by-one

**性能实测(Rust,Lambda arm64,provided.al2023)**:

> 数据来源:冷启动 / warm Duration 三项据 **CloudWatch Logs REPORT 行**(`Init Duration` / `Duration`,真机 invoke 后读出);KMS Sign 本身据 `kms-es256` bin 内的 30 次采样循环(代码可复现)。

| 指标 | 实测 | 来源 |
|---|---|---|
| 冷启动 Init Duration | median **98ms**(74–103ms,n=6) | CloudWatch Logs |
| 冷环境首请求 Duration | median 826ms —— **首次 KMS 调用的 TLS 建连一次性成本**(非稳态) | CloudWatch Logs |
| Warm Duration(含 KMS Sign) | median **7.5ms**,P95 7.7ms(n=6) | CloudWatch Logs |
| KMS Sign 本身(warm,本机直连) | P50 5.6ms / P99 6.1ms(n=30) | bin 采样循环(代码) |
| bootstrap 二进制大小 | 7.3 MB(release + lto + strip) | `ls` 产物 |

### 拍板(DESIGN §10 gate 决议)

1. **语言 = Rust**:冷启动 Init Duration ~98ms(远低于 Node 典型几百 ms~1s),**基本免 provisioned concurrency**(DESIGN §8 倾向被实测支持)。
2. **冷环境首请求的 ~800ms 来自首次 KMS TLS 建连**,不是 Sign 慢(warm 7.5ms 印证)。缓解项(留待 [b]/[c] 实现):Lambda `INIT` 阶段预热 KMS 连接(在 `main` 里先做一次 Sign 或建连,把建连成本移进 Init 而非首请求);或 SnapStart/预置并发按需。
3. **KMS Sign 延迟(warm P99 6.1ms)对 /token 热路径可接受**;并发闸按该区 Sign 配额设(C10.2)。
4. **工期**:密码学链与工具链(cargo-lambda + zig + arm64)一次跑通,无 Rust 生态阻塞;P0 纯逻辑已全部实现(224 UT)。真机 [b] CDK 编排 + [c] e2e 仍是主要剩余量。

## 目录

- `kms-es256/` — 本机直连 KMS 的签名链 + 延迟实测(Rust bin;`der_to_jose` 正确性 + Sign 延迟)。
- `kms-es256/verify.py` — 独立验签器(PyJWT + cryptography,gate 密码学判定)。
- `lambda-coldstart/` — Rust Lambda(arm64)冷启动 + 签发路径实测 handler。

## 复现 / 清理

```bash
# 前置:.env 有 AWS_PROFILE=default;zig 在 PATH(npm i -g @ziglang/cli);cargo-lambda 已装
# 1. 本机签名链 + Sign 延迟
cd spike/kms-es256 && AWS_PROFILE=default cargo run            # 创建 CMK,或 --reuse-key <id>
python3 verify.py                                                  # 独立验签

# 2. Lambda 冷启动(需 KMS key id 注入 env)
cd spike/lambda-coldstart && cargo lambda build --release --arm64
cargo lambda deploy --iam-role <role-arn> --binary-name bootstrap \
  --env-var SPIKE_ES256_KEY_ID=<key-id> spike-coldstart

# 3. 清理真机资源(spike 用完即删)
cd spike/kms-es256 && cargo run -- --cleanup <key-id>             # 计划删 CMK(7天等待期)
aws lambda delete-function --function-name spike-coldstart --profile default --region us-east-1
aws iam delete-role-policy --role-name agent-auth-spike-coldstart-role --policy-name kms-sign-spike --profile default
aws iam detach-role-policy --role-name agent-auth-spike-coldstart-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole --profile default
aws iam delete-role --role-name agent-auth-spike-coldstart-role --profile default
```

> 账号号 / key id 等敏感值走 `.env`(gitignored),不写进本文件或代码。
