#!/usr/bin/env bash
# 取当前 Admin break-glass credential(spec 030 #16):从 CloudFormation stack output
# `AdminSecretArn` 拿到 Secrets Manager ARN,再从 credential-set JSON 提取 current.secret。
# **不硬编码 secret-id / 账号号**(全从栈解析)。
#
# 用途:登入 /admin,或给 e2e/admin_console.sh 供 ADMIN_TOKEN。
#
# 用法:
#   ./e2e/get-admin-token.sh                      # 打印 token 明文(默认栈/区域/profile)
#   STACK=AgentAuthDev REGION=us-east-1 PROFILE=default ./e2e/get-admin-token.sh
#   ADMIN_TOKEN=$(./e2e/get-admin-token.sh)        # 供其它脚本复用
#
# 环境变量(均有默认):STACK、REGION、PROFILE。
# ⚠️ profile 默认走项目约定 default,**不** fallback 到环境里的 AWS_PROFILE(那可能是别的账号,
# 如 bedrock);要用别的 profile 请显式 `PROFILE=xxx`。
set -euo pipefail

STACK="${STACK:-AgentAuthDev}"
REGION="${REGION:-us-east-1}"
PROFILE="${PROFILE:-default}"

# 1) 从 stack output 取 AdminSecretArn(不写死 secret-id;栈是唯一真相源)。
if ! ARN=$(aws cloudformation describe-stacks \
  --stack-name "$STACK" --region "$REGION" --profile "$PROFILE" \
  --query "Stacks[0].Outputs[?OutputKey=='AdminSecretArn'].OutputValue | [0]" \
  --output text); then
  echo "❌ describe-stacks 失败(栈 $STACK / 区域 $REGION / profile $PROFILE)——检查 profile 与凭证。" >&2
  exit 1
fi

if [ -z "$ARN" ] || [ "$ARN" = "None" ]; then
  echo "❌ 栈 $STACK($REGION)无 AdminSecretArn output——请先 cdk deploy 更新栈(spec 025 加了该 output)。" >&2
  exit 1
fi

# 2) GetSecretValue 取当前值(仅输出到 stdout,不落文件/日志)。
aws secretsmanager get-secret-value \
  --secret-id "$ARN" --region "$REGION" --profile "$PROFILE" \
  --query SecretString --output text | jq -er '.current.secret'
