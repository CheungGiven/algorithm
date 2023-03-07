# Curricul （67% pass）
* Cluster Setup 10%
* Cluster Hardening 15%
* System Hardening 15%
* Minimize Microservice Vulnerabilities 20%
* Supply Chain Security 20% 
* Monitoring Logging and Runtime Security 20%


# 01. introduction
* 4c for cloud security
  - code, container, cluster, cloud
* Allowed
  - [Kubernetes Docs](https://kubernetes.io/docs/)
  - [Kubernetes GitHub](https://github.com/kubernetes/)
  - [Kubernetes Blog](https://kubernetes.io/blog)
  - [Trivy Docs](https://github.com/aquasecurity/trivy)
  - [Falco Docs](https://falco.org/docs/)
  - [AppArmor Docs](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)


# 02. Cloud Security Overview
* CNCF Projects
  - Graduated
  - Incubating
  - Snadbox
  - Archived
* Basic Principles
  - Assessment
    - 通过资产评估来决定优先级
  - Prevention
    - 最高性价比
    - 技术控制(Technical)，程序控制(Pococesses polices)，物理控制(Physical)
  - Detection
    - 最昂贵的
    - IDPS
    - 事件检测
      - 基于签名
      - 基于统计异常
      - 状态协议分析
    - Prometheus
  - Reaction
* Classes of Attack
* Security Principles
  - Defense in Depth
  - Least Privilege
  - Limiting the attack surface


# 1. Cluster Setup - 10%
* CA
  - [All You Need to Know About Certificates in Kubernetes](https://www.youtube.com/watch?v=gXz4cq3PKdg)
  - [PKI certificates and requirements](https://kubernetes.io/docs/setup/best-practices/certificates)
* NetworkPolicy $$$$
  - [Use Network security policies to restrict cluster level access](https://kubernetes.io/docs/concepts/services-networking/network-policies)
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: "pod-restriction"
    namespace: "dev-team"
  spec:
    podSelector:
      matchLabels:
        environment: products-service
    policyTypes:
    - Ingress
    ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            name: qa
    - from:
      - namespaceSelector:
          matchLabels:
        podSelector:
          matchLabels:
            environment: testing
  ```
  ```
  $ kubectl get po -A --show-labels
  ```

* Ingress
  - [Ingress objects with security control](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
* CIS benchmark
  - CIS(Center for Internet Security)
  - best practices for the secure configuratuon of a target system
  - Use Network security policies to restrict cluster level access
  - [Use CIS benchmark to review the security configuration of Kubernetes components](https://www.cisecurity.org/benchmark/kubernetes/)
  - [kube-bench](https://github.com/aquasecurity/kube-bench) $$$$
  - kube-bench run --targets master --check 1.2.20
  ```  
  # 修复 kube-apiserver 安全问题
  $ vi /etc/kubernetes/manifests/kube-apiserver
  #修改：
  --authorization-mode=Node,RBAC
  #添加
  --insecure-port=0
  #删除
  # --insecure-bind-address=0.0.0.0
  
  #修复 kubelet 安全问题
  $ vi /var/lib/kubelet/config.yaml
  # 将authentication.anonymous.enabled 设置为 false
  authentication:
    anonymous:
      enabled: false
  # authorization.mode 设置为 Webhook
  authorization:
    mode: Webhook
    
  # 修复 etcd 安全问题
  $ vi /etc/kubernetes/manifests/etcd.yaml
  # 修改为true：
  - --client-cert-auth=true
  
  # 以上修复完成后，重新加载配置文件并重启 kubelet
  
  $ systemctl daemon-reload
  $ systemctl restart kubelet
  ```
* GUI elements
  - https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/#accessing-the-dashboard-ui
* Node Metadata Protection
    ```
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: deny-only-cloud-metadata-access
    spec:
      podSelector: {}
      policyTypes:
      - Egress
      egress:
      - to:
        - ipBlock:
          cidr: 0.0.0.0/0
          except:
          - 169.254.169.254/32
    ```

* Verify Platform Binaries
    ```
    whereis kubelet
    sha512sum /usr/bin/kubelet
    sha512sum kubernetes/server/bin/kubelet
    ```

# 2. Cluster Hardening - 15%
## RABC $$$$
 - whitelisting
 - namespace: role
 - no namespace: cluster role
 - role is a set of permissions
 - 同一个role在不用namespace可以有不同权限
  ```
  $ kubectl -n namespace create role secrets-manager --verb=get --resource=secrets
  $ kubectl -n namespace create rolebinding secrets-manager --role=secrets-manager --user=tom -oyaml --dry-run
  $ kubectl -n namespace auth can-i get secrets --as tom
  $ kubectl create clusterrole -h # examples
  $ kubectl create rolebinding -h # examples
  ```

## Restrict API Acess
* Anonymous Access
  - Enabled by default
  - vim /etc/kubernetes/mainfests/kube-apiserver.yaml
  - --anonymous-auth=false
* Insecure Access
  - 1.20 insecure access is not longer possible
  - kube-apiserver --insecure-port=8080
* Apiserver Access
  - kubectl config view --raw
  - echo xxx | base64 -d
  - curl https://10.154.0.2:6553 --cacert ca --cert crt --key key
  - kube-apiserver --enable-admission-plugins=NodeRestriction
* Verify NodeRestriction

# 3. System Hardening - 15%
* Minimize host OS footprint
  - [seccomp](https://kubernetes.io/zh-cn/docs/tutorials/security/seccomp/)
* syscalls
  - https://www.youtube.com/watch?v=8g-NUUmCeGI
* AppArmor $$$$
  - https://www.youtube.com/watch?v=JFjXvIwAeVI
  ```yaml
  annotations:
    container.apparmor.security.beta.kubernetes.io/podx: localhost/nginx-profile-3
  ```
  ```
  aa-status
  apparmor_parser
  aa-genprof
  /etc/apparmor.d
  ```


# 4. Microservice Vulnerabilities - 20%
* [Container Runtime Landscape](https://www.youtube.com/watch?v=RyXL1zOa8Bw)
* [Gvisor](https://www.youtube.com/watch?v=kxUZ4lVFuVo)
* [Kata Containers](https://www.youtube.com/watch?v=4gmLXyMeYWI) $$$$
  ```
  apiVersion: node.k8s.io/v1
  kind: RuntimeClass
  metadata:
    name: gvisor
  handler: runsc
  ---
  apiVersion: v1
  kind: Pod
  metadata:
    labels:
      run: gvisor
    name: gvisor
  spec:
    runtimeClassName: gvisor
    containers:
      - image: nginx
        name: gvisor
        resources: {}
    dnsPolicy: ClusterFirst
    restartPolicy: Always
  ```

## mTLS $$$$

## Open Policy Agent
* Gatekeeper
```
kubectl create -f https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/course-content/opa/gatekeeper.yaml
```
https://play.openpolicyagent.org
https://github.com/BouweCeunen/gatekeeper-policies

# 5. Supply Chain Security
* Image footprint
  - https://docs.docker.com/develop/develop-images/dockerfile_best-practices
* Static Analysis
  - code => (analysis)commit => git => (analysis)build => (analysis)test => deploy => (PSP/OPA)k8s
* kubesec
* rego - policy Language
* Iamge Vulnerability Scan
  - https://cve.mitre.org
  - https://nvd.nist.gov
* Trivy $$$$
  - $ trivy image IMAGE_NAME:TAG | egrep -i "High|Critical"  
* Supply Chain
  - Tools => SoftwareDevelopment => Container => CICD => k8s cloud => Browser


# Monitoring, Logging and Runtime Security - 20%
* strace: show system call
  - /proc directory
* falco
  - [Syscall talk by Liz Rice](https://www.youtube.com/watch?v=8g-NUUmCeGI)
  ```
  vi /etc/falco/falco_rules.yaml
  ```
* immutable
  - StartUp Probe
  - Security Context
    - $ kubectl get po -n production frontent -o yaml | egrep "priv.*: true"  
    - $ kubectl get po -n production pod1 -o jsonpath={.spec.volumes} | jq
    - container.securityContext.readOnlyRootFilesystem
* Audit logs
  - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit
  ```yaml
  apiVersion: audit.k8s.io/v1 # This is required.
  kind: Policy
  # Don't generate audit events for all requests in RequestReceived stage.
  omitStages:
    - "RequestReceived"
  rules:
    - level: RequestResponse
      resources:
      - group: ""
        resources: ["namespaces"]
    - level: Request
      resources:
      - group: ""
        resources: ["pods"]
      namespaces: ["front-apps"]
    - level: Metadata
      resources:
      - group: ""
        resources: ["secrets", "configmaps"]
    - level: Metadata
      omitStages:
      - "RequestReceived"
  ```
  ```yaml
  - --audit-policy-file=/etc/kubernetes/logpolicy/sample-policy.yaml
  - --audit-log-path=/var/log/kubernetes/audit-logs.txt
  - --audit-log-maxage=10
  - --audit-log-maxbackup=2
  ```
  - $ systemctl restart kubelet  



# tips
/etc/kubernetes/manifests
/etc/kubernetes/manifests/kube-apiserver.yaml
/etc/kubernetes/manifests/kube-controller-manager.yaml
/etc/kubernetes/manifests/etcd.yaml
/var/lib/kubelet/config.yaml
/var/log/contailners
/etc/kubernetes/etcd.yaml
/var/log/kubernetes/audit.log

/etc/falco
/etc/falco/falco.yaml
/etc/falco/falco_rules.yaml
/etc/falco/falco_rules.local.yaml
/etc/falco/k8s_audit_rules.yaml
/etc/falco/rules.d
/etc/systemd/system/kubelet.service.d/10-kubeadm.conf

falco --help
apparmor_status --help
apparmor_parser --help
trivy --help
trivy image --help




# 真题
1.镜像扫描ImagePolicyWebhook
2. sysdig检测pod
3. RABC
4. AppArmor
5. PodSecurityPolicy
6. Network security policies
7. dockerfile检测及yaml文件问题
8. pod安全
  - $ kubectl get po -n production frontent -o yaml | egrep "priv.*: true"  
  - $ kubectl get po -n production pod1 -o jsonpath={.spec.volumes} | jq
9. 创建SA
10. trivy检测镜像安全
11. 创建secret
12. kube-bench
13. gVsior
14. 审计
15. 默认网络策略
16. falco 检测输出日志格式
  ```
  $ crictl ps | grep pod_name
  $ sysdig -l | grep time
  $ sysdig -M 30 -p "%evnt.time,%user.name,%proc.name"  --cri /run/containerd/containerd.sock container.name=tomcat123 >> /opt/KSR00101/incidents/summary
  $ sysdig-probe-loader
  ```

* AppArmor
* Network security policies
* secrets

* CIS
* TLS安全配置
  ```
  $ vi /etc/kubernetes/manifests/kube-apiserver.yaml
  - --tls-cipher-suites=TLS_AES_128_GCM_SHA256
  - --tls-min-version=VersionTLS13
  
  $ vi /etc/kubernetes/manifests/etcd.yaml
  - --cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  ```

* Verify Platform Binaries
 ```
 $ sha512sum kubernetes/server/bin/kubelet
 $ sha512sum /usr/bin/kubelet
 ```
* RuntimeClass gVisor
  ```
  apiVersion: node.k8s.io/v1
  kind: RuntimeClass
  metadata:
    name: untrusted 
  # The name of the corresponding CRI configuration
  handler: runc 
  ```
  ```
  spec:
    runtimeClassName: untrusted
  ```
  