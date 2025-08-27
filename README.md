# AWS Security Compliance Check (with GitHub Actions)

## 1. 기획 배경
- 팀 규모: **5인 소규모**, AWS 활용 경험 **low level**
- 한정된 예산 → **무료 서비스 최대한 활용** 필요
- 보안 운영 필요성: 침해 징후 탐지(Threat Detection)가 아닌  
  **구성 오류 및 정책 위반 여부 자동 확인**이 목표
- GitHub Actions를 CI/CD뿐 아니라 **보안 점검 자동화** 용도로 활용

---

## 2. 기본 구조
- **점검 대상**: S3, CloudFront, ALB, EKS, EC2, IAM, 계정 단위 설정
- **구성 요소**
  - Shell Script (`.sh`)
  - GitHub Actions Workflow (`.yml`)
- **출력**
  - CLI 컬러 로그
  - `daily_security_report.txt` (검사 결과 요약 리포트)

---

## 3. 버전 히스토리
### v1
- **S3 기본 정책 검토**
  - 정적 웹 호스팅 여부
  - Public Access Block 설정 여부
- GitHub Actions 내부 **Access Key/Secret Access Key 저장 방식** 사용

### v2
- 점검 범위 확장:  
  - **S3 + CloudFront → ALB, IAM, EC2, EKS까지 확대**
  - CloudFront OAC 정책 검증
  - EC2 퍼블릭 IP, SSH 개방, EBS 암호화 확인
  - ALB HTTPS 리스너, WAF 연결 상태
  - IAM 루트 MFA / 패스워드 정책
  - EKS 퍼블릭 엔드포인트 / OIDC / Audit 로그 활성화
- 결과 리포트 파일 자동 생성

---

## 4. 개선 방향성
- ⚠️ **권한 부족** → `s3 정책 없음` 으로 찍히는 이슈 개선 필요
- GitHub Actions 기반 자동화는 유용했으나,  
  장기적으로는 **AWS Native Service (Config, Security Hub)** 기반 재구성 고려
- Slack 알림 / 대시보드 연계 등 추가 개선 가능

---

## 5. 레퍼런스
- **Cisco CX Cloud**  
  - 정책 위반 및 보안 이벤트 발생 시 실시간 메일/문자 발송 경험  
  - 본 프로젝트 기획의 출발점
- **AWS Config & Security Hub**  
  - AWS 네이티브 보안 준수 점검 서비스  
  - Config Rules / CIS Benchmark 기반 정책 위반 탐지 가능  
  - 단, 리소스 및 평가 건수 기준으로 과금 발생 (비용 부담 → GitHub Actions 대체 선택)

---

## 6. 예시 화면
(추가 예정: 실행 화면 캡처, 리포트 예시)

---

## 7. 실행 방법
```bash
# 로컬 실행
chmod +x security_check.sh
./security_check.sh

# GitHub Actions는 .github/workflows/security_check.yml 참고
