#!/bin/sh
# c211-i108924 read-only enumeration probe.
# Prints only non-secret metadata (no credential values, no env dump).
exec 1>&2
echo "===== C211_I108924 PROBE BEGIN $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
echo "host=$(hostname) user=$(id -un) uid=$(id -u) cwd=$(pwd)"
echo "AWS_env_var_count=$(env | grep -c '^AWS_')"
echo "AWS_REGION=${AWS_REGION:-<unset>} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-<unset>} AWS_ROLE_ARN=${AWS_ROLE_ARN:-<unset>}"
for t in aws gcloud az curl wget jq base64 python3 openssl apk; do
  P=$(command -v "$t" 2>/dev/null); echo "TOOL $t = ${P:-MISSING}"
done
if ! command -v curl >/dev/null 2>&1; then
  echo "--- installing curl ---"
  apk add --no-cache curl >/dev/null 2>&1 || apk add --no-cache curl
fi
CURL=$(command -v curl || true)
echo "curl_path=${CURL:-MISSING}"
[ -n "$CURL" ] && "$CURL" --version 2>&1 | head -2
sig() {
  REGION="$1"; SVC="$2"; shift 2
  "$CURL" -sS --max-time 45 --aws-sigv4 "aws:amz:${REGION}:${SVC}" \
    --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
    -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" "$@"
  echo
}
echo "===== STS GetCallerIdentity ====="
STS_OUT=$(sig eu-central-1 sts 'https://sts.eu-central-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15')
echo "$STS_OUT"
echo "===== ServiceQuotas GetServiceQuota ec2 L-DB2E81BA (G/VT on-demand vCPUs) ====="
sig eu-central-1 servicequotas -H 'Content-Type: application/x-amz-json-1.1' -H 'X-Amz-Target: ServiceQuotasV20190624.GetServiceQuota' -d '{"ServiceCode":"ec2","QuotaCode":"L-DB2E81BA"}' 'https://servicequotas.eu-central-1.amazonaws.com/'
echo "===== ServiceQuotas GetServiceQuota ec2 L-3819A6DF (G/VT spot) ====="
sig eu-central-1 servicequotas -H 'Content-Type: application/x-amz-json-1.1' -H 'X-Amz-Target: ServiceQuotasV20190624.GetServiceQuota' -d '{"ServiceCode":"ec2","QuotaCode":"L-3819A6DF"}' 'https://servicequotas.eu-central-1.amazonaws.com/'
echo "===== ServiceQuotas GetServiceQuota ec2 L-417A185B (P on-demand vCPUs) ====="
sig eu-central-1 servicequotas -H 'Content-Type: application/x-amz-json-1.1' -H 'X-Amz-Target: ServiceQuotasV20190624.GetServiceQuota' -d '{"ServiceCode":"ec2","QuotaCode":"L-417A185B"}' 'https://servicequotas.eu-central-1.amazonaws.com/'
echo "===== EC2 DescribeInstances eu-central-1 ====="
sig eu-central-1 ec2 'https://ec2.eu-central-1.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15&MaxResults=20'
echo "===== EC2 DescribeRegions ====="
sig eu-central-1 ec2 'https://ec2.eu-central-1.amazonaws.com/?Action=DescribeRegions&Version=2016-11-15'
echo "===== ECR DescribeRepositories core_services/metric-metadata-service ====="
sig eu-central-1 ecr -H 'Content-Type: application/x-amz-json-1.1' -H 'X-Amz-Target: AmazonEC2ContainerRegistry_V20150921.DescribeRepositories' -d '{"repositoryNames":["core_services/metric-metadata-service"]}' 'https://ecr.eu-central-1.amazonaws.com/'
echo "===== gcloud / az ====="
if command -v gcloud >/dev/null 2>&1; then gcloud config list 2>&1; gcloud auth list 2>&1; else echo 'gcloud: not installed'; fi
if command -v az >/dev/null 2>&1; then az account show 2>&1; else echo 'az: not installed'; fi
echo "===== AWS CLI fallback if curl sigv4 failed ====="
case "$STS_OUT" in
  *Arn*) echo "curl-sigv4: OK" ;;
  *)
    echo "curl-sigv4 failed; installing aws-cli"
    apk add --no-cache aws-cli >/dev/null 2>&1 || apk add --no-cache aws-cli
    if command -v aws >/dev/null 2>&1; then
      echo "--- aws sts get-caller-identity ---"
      aws sts get-caller-identity --region eu-central-1 2>&1
      echo "--- aws service-quotas L-DB2E81BA ---"
      aws service-quotas get-service-quota --service-code ec2 --quota-code L-DB2E81BA --region eu-central-1 2>&1
      echo "--- aws service-quotas L-3819A6DF ---"
      aws service-quotas get-service-quota --service-code ec2 --quota-code L-3819A6DF --region eu-central-1 2>&1
      echo "--- aws service-quotas L-417A185B ---"
      aws service-quotas get-service-quota --service-code ec2 --quota-code L-417A185B --region eu-central-1 2>&1
      echo "--- aws ec2 describe-instances ---"
      aws ec2 describe-instances --region eu-central-1 --max-items 20 2>&1
    else
      echo "aws-cli install failed"
    fi
    ;;
esac
echo "===== EC2 DescribeInstanceTypeOfferings g4dn/g5/g6 eu-central-1 ====="
sig eu-central-1 ec2 'https://ec2.eu-central-1.amazonaws.com/?Action=DescribeInstanceTypeOfferings&Version=2016-11-15&LocationType=region&MaxResults=20&Filter.1.Name=instanceType&Filter.1.Value.1=g4dn.xlarge&Filter.1.Value.2=g5.xlarge&Filter.1.Value.3=g6.xlarge&Filter.1.Value.4=p3.2xlarge'
echo "===== EC2 RunInstances DryRun=true (creates nothing) ====="
sig eu-central-1 ec2 'https://ec2.eu-central-1.amazonaws.com/?Action=RunInstances&Version=2016-11-15&DryRun=true&ImageId=ami-0d6dd9e8265d48906&InstanceType=g4dn.xlarge&MinCount=1&MaxCount=1'
echo "===== C211_I108924 PROBE END ====="
