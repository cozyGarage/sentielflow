# METADATA
# title: No Privileged Containers
# description: Prevents deployment of privileged containers in Kubernetes
# severity: critical

package sentinelflow.kubernetes

# Deny privileged containers
deny_privileged[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    
    msg := sprintf("Container '%s' is running in privileged mode", [container.name])
}

deny_privileged[msg] {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]
    container := input.spec.template.spec.containers[_]
    container.securityContext.privileged == true
    
    msg := sprintf("Container '%s' is running in privileged mode", [container.name])
}

# Deny containers running as root
deny_root[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.runAsNonRoot
    
    msg := sprintf("Container '%s' is not enforcing runAsNonRoot", [container.name])
}

deny_root[msg] {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    
    msg := sprintf("Container '%s' is not enforcing runAsNonRoot", [container.name])
}

# Deny privilege escalation
deny_priv_escalation[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    
    msg := sprintf("Container '%s' allows privilege escalation", [container.name])
}
