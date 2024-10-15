# kubernetes-security
A curated lab on how to secure kubernetes. It covers all the major areas of kubernetes security, including system hardening, protecting node metadata, verifying binaries, implementing pod-to-pod encryption, isolation techniques for multi-tenancy, understanding the supply chain, behavioral analytics for threat detection, attack investigation, and ensuring container immutability at runtime.
Certainly! Here's the complete, comprehensive Kubernetes Security Tutorial that aligns with the CKS certification syllabus:

## Comprehensive Kubernetes Security Tutorial (CKS-Aligned)

### Part 1: Threat Modeling for Kubernetes

Before implementing security measures, consider potential threats:

1. Container escape
2. Unauthorized access to the Kubernetes API
3. Compromised images in the supply chain
4. Network-based attacks between pods
5. Data exfiltration from volumes
6. Resource abuse
7. Host system compromise

Consider threat actors such as external attackers, internal attackers, malicious insiders, and inadvertent internal actors.

Use methodologies like STRIDE to systematically analyze threats in your Kubernetes environment.

### Part 2: Securing the Kubernetes Control Plane

#### 2.1 Enable Role-Based Access Control (RBAC)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
```

#### 2.2 Use Third-Party Authentication for API Server

Integrate with external identity providers using OpenID Connect (OIDC).

#### 2.3 Protect etcd with TLS and Firewall

Secure etcd communication:

```bash
etcd --cert-file=/path/to/server.crt --key-file=/path/to/server.key \
  --client-cert-auth --trusted-ca-file=/path/to/ca.crt
```

#### 2.4 Enable Audit Logging

Edit kube-apiserver configuration:

```yaml
--audit-log-path=/var/log/kubernetes/audit.log
--audit-log-maxage=30
--audit-log-maxbackup=10
--audit-log-maxsize=100
```

### Part 3: Securing Kubernetes Nodes

#### 3.1 Keep Kubernetes Version Up to Date

Regularly update Kubernetes:

```bash
kubeadm upgrade plan
kubeadm upgrade apply
```

#### 3.2 Isolate Kubernetes Nodes

Use network policies to restrict node access:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

#### 3.3 Secure kubelet

Configure kubelet securely:

```yaml
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
```

### Part 4: System Hardening

#### 4.1 Minimize Host OS Footprint

Reduce the attack surface by:

```bash
# Remove unnecessary packages
sudo apt purge <unnecessary-package>

# Disable unused services
sudo systemctl disable <unused-service>

# Use a minimal base image for nodes, e.g., Ubuntu Server Minimal or Container-Optimized OS
```

#### 4.2 Verify Platform Binaries

Before deploying Kubernetes components:

```bash
# Download Kubernetes binaries and checksums
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
curl -LO "https://dl.k8s.io/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl.sha256"

# Verify the binary
echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check
```

#### 4.3 Protect Node Metadata and Endpoints

Restrict access to the Kubernetes node's metadata:

```yaml
# Example NetworkPolicy to restrict access to metadata endpoint
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-metadata-access
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32  # AWS metadata endpoint
```

### Part 5: Minimize Microservice Vulnerabilities

#### 5.1 Use Pod Security Standards

Apply Pod Security Standards:

```yaml
apiVersion: pod-security.kubernetes.io/v1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  # ... other restrictions
```

#### 5.2 Implement Network Policies

Create network policies:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-specific-ingress
spec:
  podSelector:
    matchLabels:
      app: myapp
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: frontend
```

#### 5.3 Use Secrets Management

Create and use Kubernetes Secrets:

```bash
kubectl create secret generic my-secret --from-literal=key1=supersecret
```

Use secrets in pods:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
  - name: mycontainer
    image: myimage
    env:
      - name: SECRET_KEY
        valueFrom:
          secretKeyRef:
            name: my-secret
            key: key1
```

#### 5.4 Implement Pod-to-Pod Encryption Using Cilium

Install Cilium with encryption enabled:

```bash
helm install cilium cilium/cilium --version 1.9.1 \
   --namespace kube-system \
   --set encryption.enabled=true \
   --set encryption.nodeEncryption=false
```

Configure Cilium Network Policy to enforce encryption:

```yaml
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "encrypt-traffic"
spec:
  endpointSelector:
    matchLabels:
      app: myapp
  egress:
  - toEndpoints:
    - matchLabels:
        app: otherapp
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
  encrypt: true
```

#### 5.5 Isolation Techniques for Multi-tenancy

Implement namespace isolation:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-a
  labels:
    tenant: a

---

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-from-other-namespaces
  namespace: tenant-a
spec:
  podSelector:
    matchLabels:
  ingress:
  - from:
    - podSelector: {}
```

Use ResourceQuotas for resource isolation:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-resources
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 1Gi
    limits.cpu: "2"
    limits.memory: 2Gi
```

### Part 6: Supply Chain Security

#### 6.1 Minimize Base Image Footprint

Use minimal base images:

```dockerfile
FROM alpine:3.14
RUN apk add --no-cache python3
```

#### 6.2 Implement Image Scanning

Use tools like Trivy for image scanning:

```bash
trivy image myapp:latest
```

#### 6.3 Secure Your Supply Chain

Use Docker Content Trust for image signing:

```bash
export DOCKER_CONTENT_TRUST=1
docker push myregistry.azurecr.io/myimage:tag
```

#### 6.4 Understand Your Supply Chain

Implement Software Bill of Materials (SBOM):

```bash
# Generate SBOM using Syft
syft packages alpine:latest -o syft-json > alpine-sbom.json

# Analyze SBOM for vulnerabilities using Grype
grype sbom:./alpine-sbom.json
```

Set up a secure CI/CD pipeline:

```yaml
# Example GitLab CI/CD pipeline with security checks
stages:
  - build
  - test
  - scan
  - deploy

build:
  stage: build
  script:
    - docker build -t myapp:$CI_COMMIT_SHA .

test:
  stage: test
  script:
    - docker run myapp:$CI_COMMIT_SHA npm test

scan:
  stage: scan
  script:
    - trivy image myapp:$CI_COMMIT_SHA

deploy:
  stage: deploy
  script:
    - kubectl set image deployment/myapp myapp=myapp:$CI_COMMIT_SHA
```

### Part 7: Monitoring, Logging and Runtime Security

#### 7.1 Implement Runtime Security

Use tools like Falco for runtime security:

```yaml
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
  output: >
    A shell was spawned in a container with an attached terminal (user=%user.name %container.info shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: NOTICE
  tags: [container, shell, mitre_execution]
```

#### 7.2 Use Admission Controllers

Enable and configure admission controllers:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: "pod-policy.example.com"
webhooks:
- name: "pod-policy.example.com"
  rules:
  - apiGroups:   [""]
    apiVersions: ["v1"]
    operations:  ["CREATE"]
    resources:   ["pods"]
    scope:       "Namespaced"
  clientConfig:
    service:
      namespace: "example-namespace"
      name: "example-service"
    caBundle: "Ci0tLS0tQk...<base64-encoded CA bundle>...tLS0K"
```

#### 7.3 Regular Auditing and Compliance Checks

Use tools like kube-bench for CIS benchmark checks:

```bash
kube-bench run --targets master
```

#### 7.4 Behavioral Analytics for Threat Detection

Implement Falco for runtime behavioral analysis:

```yaml
# Example Falco rule
- rule: Suspicious mount activities
  desc: Detect suspicious mount activities
  condition: >
    spawned_process and proc.name in (mount, umount, mountpoint)
    and not proc.pname in (systemd, mount, umount)
  output: "Suspicious mount activity (user=%user.name command=%proc.cmdline)"
  priority: WARNING
```

#### 7.5 Investigate Attacks and Identify Bad Actors

Use audit logs and tools for investigation:

```bash
# Enable detailed auditing
sudo vi /etc/kubernetes/audit-policy.yaml

# Example audit policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse

# Analyze audit logs
kubectl logs kube-apiserver-minikube -n kube-system | jq 'select(.user.username != "system:addon-manager")'

# Use Sysdig Inspect for deep forensics
sysdig -w capture.scap
sysdig-inspect capture.scap
```

#### 7.6 Ensure Container Immutability at Runtime

Use security contexts to enforce read-only root filesystem:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: readonly-pod
spec:
  containers:
  - name: myapp
    image: myapp:latest
    securityContext:
      readOnlyRootFilesystem: true
```

Implement OPA Gatekeeper to enforce immutability:

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sContainerImmutability
metadata:
  name: container-immutability
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    allowedCapabilities: ["NET_BIND_SERVICE"]
    requiredDropCapabilities: ["ALL"]
    runAsNonRoot: true
    readOnlyRootFilesystem: true
```

### Sources
- Kubernetes Official Documentation - Security Concepts
- Kubernetes Official Documentation - Security Tutorials
- Wiz - Kubernetes Security Best Practices
- OWASP - Kubernetes Security Cheat Sheet
- Tigera - Kubernetes Security Guide
- Armosec - Kubernetes Security Best Practices + Checklist
