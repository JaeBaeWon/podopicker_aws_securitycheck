#!/bin/bash

set -euo pipefail

# ===== 설정 =====
BUCKET_NAME="${BUCKET_NAME:-podopicker-web-s3}"
CF_URL="${CF_URL:-https://www.podopicker.store}"
DIST_ID="${DIST_ID:-EKBBK4D1CTWHQ}"
ACCOUNT_ID="${ACCOUNT_ID:-639965457439}"
TEST_FILE="${TEST_FILE:-index.html}"

# 색상
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

FAILURES=()

log() { echo "[$(date '+%F %T')] $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; log "PASS: $1"; }
warn() { echo -e "${YELLOW}⚠️ $1${NC}"; log "WARN: $1"; }
error() { echo -e "${RED}❌ $1${NC}"; log "FAIL: $1"; FAILURES+=("$1"); }
info() { echo -e "${BLUE}ℹ️ $1${NC}"; log "INFO: $1"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}"; log "=== $1 ==="; }

check_dependencies() {
  header "필수 도구 확인"
  for tool in curl aws jq; do
    if ! command -v "$tool" &>/dev/null; then
      error "도구 누락: $tool"
      exit 1
    fi
  done
  success "모든 도구 확인 완료"
}

check_aws() {
  header "AWS 인증 확인"
  if ! aws sts get-caller-identity &>/dev/null; then
    error "AWS 인증 실패"
  fi
  success "AWS 인증 성공"
}

check_bucket() {
  header "S3 버킷 존재 여부"
  if ! aws s3api head-bucket --bucket "$BUCKET_NAME" 2>/dev/null; then
    error "버킷 존재하지 않거나 접근 불가"
    exit 1
  fi
  success "버킷 접근 가능"
}

test_s3_access() {
  header "S3 직접 접근 테스트"
  local endpoints=(
    "https://${BUCKET_NAME}.s3.amazonaws.com/${TEST_FILE}"
    "https://${BUCKET_NAME}.s3.ap-northeast-2.amazonaws.com/${TEST_FILE}"
    "https://s3.amazonaws.com/${BUCKET_NAME}/${TEST_FILE}"
  )
  for url in "${endpoints[@]}"; do
    local code=$(curl -s -o /dev/null -I -w "%{http_code}" "$url")
    if [ "$code" = "200" ]; then
      error "$url 접근 가능 (취약)"
    elif [[ "$code" = "403" || "$code" = "404" ]]; then
      success "$url 차단됨 ($code)"
    else
      warn "$url 응답 이상 ($code)"
    fi
  done
}

test_cf_access() {
  header "CloudFront 정상 접근 테스트"
  local url="${CF_URL}/${TEST_FILE}"
  local code=$(curl -s -o /dev/null -I -w "%{http_code}" "$url")
  if [ "$code" = "200" ]; then
    success "CloudFront 접근 성공 ($code)"
  else
    error "CloudFront 접근 실패 ($code)"
  fi
}

test_header_attacks() {
  header "헤더 조작 테스트"
  local headers=(
    "Referer: https://evil.com"
    "Origin: https://attacker.com"
    "User-Agent: Mozilla/5.0"
  )
  for h in "${headers[@]}"; do
    local result=$(curl -s -I "https://${BUCKET_NAME}.s3.amazonaws.com/${TEST_FILE}" -H "$h")
    if echo "$result" | grep -q "200 OK"; then
      error "[$h] 조작 접근 허용됨"
    else
      success "[$h] 조작 차단 성공"
    fi
  done
}

check_bucket_config() {
  header "S3 보안 설정 확인"
  if aws s3api get-bucket-website --bucket "$BUCKET_NAME" >/dev/null 2>&1; then
    error "정적 웹호스팅 활성화됨"
  else
    success "정적 웹호스팅 비활성화됨"
  fi

  local block=$(aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json)
  if echo "$block" | jq -e '.BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets' >/dev/null; then
    success "퍼블릭 차단 설정 완료"
  else
    error "퍼블릭 차단 설정 미흡"
  fi

  local policy=$(aws s3api get-bucket-policy --bucket "$BUCKET_NAME" --query 'Policy' --output text 2>/dev/null || echo "")
  local expect="arn:aws:cloudfront::${ACCOUNT_ID}:distribution/${DIST_ID}"
  if [[ "$policy" == *"$expect"* ]]; then
    success "OAC 연결 정책 존재"
  else
    error "OAC 정책 누락"
  fi
}

check_cf_config() {
  header "CloudFront 설정 확인"
  local dist=$(aws cloudfront get-distribution --id "$DIST_ID" --query 'Distribution.DistributionConfig' --output json)
  if [[ "$dist" == "{}" ]]; then
    error "CloudFront 배포 조회 실패"
    return
  fi
  local proto=$(echo "$dist" | jq -r '.DefaultCacheBehavior.ViewerProtocolPolicy')
  if [[ "$proto" =~ https ]]; then
    success "HTTPS 리디렉션 설정 완료 ($proto)"
  else
    error "HTTPS 설정 미흡 ($proto)"
  fi
}

summarize() {
  header "점검 요약"
  if [ ${#FAILURES[@]} -eq 0 ]; then
    success "✅ 모든 보안 항목 통과"
  else
    for f in "${FAILURES[@]}"; do
      echo -e "${RED}- $f${NC}"
    done
    exit 1
  fi
}

main() {
  header "🔐 S3 + CloudFront 보안 점검 시작"
  check_dependencies
  check_aws
  check_bucket
  test_s3_access
  test_cf_access
  test_header_attacks
  check_bucket_config
  check_cf_config
  summarize
}

main "$@"
