# METADATA
# title: No Privileged Containers
# description: Prevents deployment of privileged containers in Kubernetes (including init/ephemeral)
# severity: critical

package sentinelflow.kubernetes

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}

is_true(v) {
	v == true
}

is_true(v) {
	v == "true"
}

is_true(v) {
	v == 1
}

pod_containers[c] {
	input.kind == "Pod"
	c := input.spec.containers[_]
}

pod_containers[c] {
	input.kind == "Pod"
	c := input.spec.initContainers[_]
}

pod_containers[c] {
	input.kind == "Pod"
	c := input.spec.ephemeralContainers[_]
}

workload_pod_spec := input.spec.template.spec {
	workload_kinds[input.kind]
}

workload_pod_spec := input.spec.jobTemplate.spec.template.spec {
	input.kind == "CronJob"
}

workload_containers[c] {
	c := workload_pod_spec.containers[_]
}

workload_containers[c] {
	c := workload_pod_spec.initContainers[_]
}

workload_containers[c] {
	c := workload_pod_spec.ephemeralContainers[_]
}

container_defines_privileged(container) {
	_ = container.securityContext.privileged
}

container_privileged(container, pod_sc) {
	is_true(container.securityContext.privileged)
}

container_privileged(container, pod_sc) {
	not container_defines_privileged(container)
	is_true(pod_sc.privileged)
}

deny_privileged[msg] {
	input.kind == "Pod"
	container := pod_containers[_]
	pod_sc := object.get(input.spec, "securityContext", {})
	container_privileged(container, pod_sc)
	msg := sprintf("Container '%s' is running in privileged mode", [container.name])
}

deny_privileged[msg] {
	workload_kinds[input.kind]
	container := workload_containers[_]
	pod_sc := object.get(workload_pod_spec, "securityContext", {})
	container_privileged(container, pod_sc)
	msg := sprintf("Container '%s' is running in privileged mode", [container.name])
}

deny_privileged[msg] {
	input.kind == "CronJob"
	container := workload_containers[_]
	pod_sc := object.get(workload_pod_spec, "securityContext", {})
	container_privileged(container, pod_sc)
	msg := sprintf("Container '%s' is running in privileged mode", [container.name])
}

# Deny containers running as root
deny_root[msg] {
	input.kind == "Pod"
	container := pod_containers[_]
	not container.securityContext.runAsNonRoot
	msg := sprintf("Container '%s' is not enforcing runAsNonRoot", [container.name])
}

deny_root[msg] {
	workload_kinds[input.kind]
	input.kind != "Job"
	container := workload_containers[_]
	not container.securityContext.runAsNonRoot
	msg := sprintf("Container '%s' is not enforcing runAsNonRoot", [container.name])
}

# Deny privilege escalation
deny_priv_escalation[msg] {
	input.kind == "Pod"
	container := pod_containers[_]
	is_true(container.securityContext.allowPrivilegeEscalation)
	msg := sprintf("Container '%s' allows privilege escalation", [container.name])
}

deny_priv_escalation[msg] {
	workload_kinds[input.kind]
	container := workload_containers[_]
	is_true(container.securityContext.allowPrivilegeEscalation)
	msg := sprintf("Container '%s' allows privilege escalation", [container.name])
}
