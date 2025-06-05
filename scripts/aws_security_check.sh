#!/bin/bash
set -euo pipefail

# ===== 설정 =====
BUCKET_NAME="${BUCKET_NAME:-podopicker-web-s3}"
CF_URL="${CF_URL:-https://www.podopicker.store}"
DIST_ID="${DIST_ID:-EKBBK4D1CTWHQ}"
ACCOUNT_ID="${ACCOUNT_ID:-639965457439}"
TEST_FILE="${TEST_FILE:-index.html}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
FAILURES=()
ERROR_MESSAGES=(); WARN_MESSAGES=(); SUCCESS_MESSAGES=()
ERROR_COUNT=0; WARN_COUNT=0; SUCCESS_COUNT=0

log()      { echo "[$(date '+%F %T')] $1"; }
success()  { echo -e "${GREEN}✅ $1${NC}"; log "PASS: $1"; SUCCESS_MESSAGES+=("$1"); SUCCESS_COUNT=$((SUCCESS_COUNT+1)); }
warn()     { echo -e "${YELLOW}⚠️ $1${NC}"; log "WARN: $1"; WARN_MESSAGES+=("$1"); WARN_COUNT=$((WARN_COUNT+1)); }
error()    { echo -e "${RED}❌ $1${NC}"; log "FAIL: $1"; ERROR_MESSAGES+=("$1"); ERROR_COUNT=$((ERROR_COUNT+1)); FAILURES+=("$1"); }
header()   { echo -e "\n${BLUE}=== $1 ===${NC}"; log "=== $1 ==="; }

check_dependencies() {
  header "필수 도구 확인"
  for tool in curl aws jq; do
    if ! command -v "$tool" &>/dev/null; then error "도구 누락: $tool"; fi
  done
  success "모든 도구 확인 완료"
}

check_aws() {
  header "AWS 인증 확인"
  aws sts get-caller-identity &>/dev/null && success "AWS 인증 성공" || error "AWS 인증 실패"
}

test_cf_access() {
  header "CloudFront 정상 접근 테스트"
  code=$(curl -s -o /dev/null -I -w "%{http_code}" "$CF_URL/$TEST_FILE")
  [ "$code" = "200" ] && success "CloudFront 접근 성공 ($code)" || error "CloudFront 접근 실패 ($code)"
}

check_cf_config() {
  header "CloudFront 설정 확인"
  dist=$(aws cloudfront get-distribution --id "$DIST_ID" --query 'Distribution.DistributionConfig' --output json)
  [[ "$dist" == "{}" ]] && error "CloudFront 배포 조회 실패" && return
  proto=$(echo "$dist" | jq -r '.DefaultCacheBehavior.ViewerProtocolPolicy')
  [[ "$proto" =~ https ]] && success "HTTPS 리디렉션 설정 완료 ($proto)" || error "HTTPS 설정 미흡 ($proto)"
}

check_bucket() {
  header "S3 버킷 접근 제한 여부 확인"
  aws s3api head-bucket --bucket "$BUCKET_NAME" &>/dev/null && \
    warn "❗ 버킷 직접 접근 가능" || success "S3 직접 접근 차단됨"
}

test_s3_access() {
  header "S3 직접 접근 테스트"
  local endpoints=(
    "https://${BUCKET_NAME}.s3.amazonaws.com/${TEST_FILE}"
    "https://${BUCKET_NAME}.s3.ap-northeast-2.amazonaws.com/${TEST_FILE}"
    "https://s3.amazonaws.com/${BUCKET_NAME}/${TEST_FILE}"
  )
  for url in "${endpoints[@]}"; do
    code=$(curl -s -o /dev/null -I -w "%{http_code}" "$url")
    case "$code" in
      200) error "$url 접근 가능 (취약)";;
      403|404) success "$url 차단됨 ($code)";;
      *) warn "$url 응답 이상 ($code)";;
    esac
  done
}

test_header_attacks() {
  header "헤더 조작 테스트"
  for h in "Referer: https://evil.com" "Origin: https://attacker.com" "User-Agent: Mozilla/5.0"; do
    result=$(curl -s -I "https://${BUCKET_NAME}.s3.amazonaws.com/${TEST_FILE}" -H "$h")
    echo "$result" | grep -q "200 OK" && error "[$h] 조작 접근 허용됨" || success "[$h] 조작 차단 성공"
  done
}

check_bucket_config() {
  header "S3 보안 설정 확인"
  aws s3api get-bucket-website --bucket "$BUCKET_NAME" &>/dev/null && error "정적 웹호스팅 활성화됨" || success "정적 웹호스팅 비활성화됨"
  block=$(aws s3api get-public-access-block --bucket "$BUCKET_NAME" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)
  if [ -z "$block" ] || [ "$block" = "null" ]; then
    warn "퍼블릭 차단 정보 없음 (권한 부족 가능)"
  elif echo "$block" | jq -e '.BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets' >/dev/null; then
    success "퍼블릭 차단 정책 설정됨"
  else
    warn "퍼블릭 차단 설정 일부 누락"
  fi
  policy=$(aws s3api get-bucket-policy --bucket "$BUCKET_NAME" --query 'Policy' --output text 2>/dev/null || echo "")
  [[ -z "$policy" ]] && error "버킷 정책 없음 (OAC 확인 불가)" && return
  expect_arn="arn:aws:cloudfront::${ACCOUNT_ID}:distribution/${DIST_ID}"
  echo "$policy" | jq -e --arg OAC_ARN "$expect_arn" 'fromjson | .Statement[] | select(.Principal.Service == "cloudfront.amazonaws.com") | select(.Action == "s3:GetObject") | select(.Condition.StringEquals."AWS:SourceArn" == $OAC_ARN)' >/dev/null \
    && success "OAC 정책 존재" || error "OAC 정책 누락/불일치"
}

check_eks_config() {
  header "EKS 보안 설정 확인"
  for cluster in $(aws eks list-clusters --query 'clusters' --output text); do
    endpoint=$(aws eks describe-cluster --name "$cluster" --query 'cluster.resourcesVpcConfig.endpointPublicAccess' --output text)
    [[ "$endpoint" == "false" ]] && success "$cluster: 퍼블릭 엔드포인트 비활성화" || error "$cluster: 퍼블릭 엔드포인트 활성화"
    oidc=$(aws eks describe-cluster --name "$cluster" --query 'cluster.identity.oidc.issuer' --output text)
    [[ "$oidc" == "https://"* ]] && success "$cluster: OIDC 연결됨" || warn "$cluster: OIDC 미연결"
    logging=$(aws eks describe-cluster --name "$cluster" --query 'cluster.logging.clusterLogging[?enabled==`true`].types' --output text)
    echo "$logging" | grep -q "audit" && success "$cluster: Audit 로그 활성화" || warn "$cluster: Audit 로그 비활성화"
  done
}

check_ec2_config() {
  header "EC2 보안 설정 확인"
  pub_count=$(aws ec2 describe-instances --query 'Reservations[].Instances[].PublicIpAddress' --output text | wc -w)
  [ "$pub_count" -gt 0 ] && warn "퍼블릭 IP EC2 수: $pub_count" || success "퍼블릭 IP 없음"
  ssh_open=$(aws ec2 describe-security-groups --query 'SecurityGroups[].IpPermissions[]' | jq '[.[] | select(.FromPort == 22 and .IpRanges[].CidrIp == "0.0.0.0/0")] | length')
  [ "$ssh_open" -gt 0 ] && error "SSH 포트 전체 개방됨" || success "SSH 제한 설정 완료"
  unenc=$(aws ec2 describe-volumes --query 'Volumes[] | [?Encrypted==`false`]' --output json | jq length)
  [ "$unenc" -gt 0 ] && error "암호화 안된 볼륨: $unenc" || success "모든 EBS 암호화됨"
  def_enc=$(aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault' --output text)
  [[ "$def_enc" == "true" ]] && success "EBS 기본 암호화 설정됨" || warn "EBS 기본 암호화 미설정"
}

check_alb_config() {
  header "ALB 보안 설정 확인"
  albs=$(aws elbv2 describe-load-balancers --query 'LoadBalancers[?Type==`application`]' --output json)
  echo "$albs" | jq -c '.[]' | while read -r alb; do
    name=$(echo "$alb" | jq -r '.LoadBalancerName')
    arn=$(echo "$alb" | jq -r '.LoadBalancerArn')
    https=$(aws elbv2 describe-listeners --load-balancer-arn "$arn" --output json | jq '[.Listeners[] | select(.Protocol=="HTTPS")] | length')
    [ "$https" -gt 0 ] && success "$name: HTTPS 리스너 있음" || error "$name: HTTPS 리스너 없음"
    waf=$(aws wafv2 get-web-acl-for-resource --resource-arn "$arn" --region ap-northeast-2 2>/dev/null || true)
    echo "$waf" | jq -e '.WebACL.Name' &>/dev/null && success "$name: WAF 연결됨" || warn "$name: WAF 미연결"
  done
}

check_iam_config() {
  header "IAM 보안 설정 확인"
  mfa=$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text)
  [ "$mfa" -eq 1 ] && success "루트 MFA 설정됨" || error "루트 MFA 미설정"
  policy=$(aws iam get-account-password-policy --output json 2>/dev/null || true)
  echo "$policy" | jq -e '.PasswordPolicy.MinimumPasswordLength' &>/dev/null && success "패스워드 정책 존재" || warn "패스워드 정책 없음"
}

check_account_s3_block() {
  header "계정 전체 S3 퍼블릭 차단 확인"
  config=$(aws s3control get-public-access-block --account-id "$ACCOUNT_ID" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)
  if [ -z "$config" ]; then warn "계정 수준 퍼블릭 차단 정책 없음"
  elif echo "$config" | jq -e '.BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets' >/dev/null; then
    success "계정 전체 S3 퍼블릭 차단 정책 설정됨"
  else warn "퍼블릭 차단 설정 일부 누락"; fi
}

summarize() {
  local file="daily_security_report.txt"
  > "$file"
  {
    echo "AWS Security Compliance Check Summary"
    echo "Scan Date: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo
    echo "== 결과 요약 =="
    echo "- 전체 검사 수: $((ERROR_COUNT + WARN_COUNT + SUCCESS_COUNT))"
    echo "- 실패: $ERROR_COUNT"
    echo "- 경고: $WARN_COUNT"
    echo "- 통과: $SUCCESS_COUNT"
    echo

    echo "== 중요 이슈 =="
    if [ "$ERROR_COUNT" -eq 0 ]; then echo "없음"; else for e in "${ERROR_MESSAGES[@]}"; do echo "- $e"; done; fi
    echo

    echo "== 경고 사항 =="
    if [ "$WARN_COUNT" -eq 0 ]; then echo "없음"; else for w in "${WARN_MESSAGES[@]}"; do echo "- $w"; done; fi
  } >> "$file"
  echo "📄 리포트 생성됨: $file"
}

send_slack_notification() {
  return
}

main() {
  check_dependencies
  check_aws
  test_cf_access
  check_cf_config
  check_bucket
  test_s3_access
  test_header_attacks
  check_bucket_config
  check_eks_config
  check_ec2_config
  check_alb_config
  check_iam_config
  check_account_s3_block

  summarize
  return 0
}

main "$@"
