# METADATA
# title: Require HTTPS
# description: Ensures all endpoints use HTTPS instead of HTTP
# severity: high

package sentinelflow.network

# Deny HTTP endpoints in Terraform
deny_http[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    resource.change.after.protocol == "HTTP"
    
    msg := sprintf("Load balancer listener '%s' uses HTTP instead of HTTPS", [resource.name])
}

deny_http[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_alb_listener"
    resource.change.after.protocol == "HTTP"
    
    msg := sprintf("ALB listener '%s' uses HTTP instead of HTTPS", [resource.name])
}

# Deny HTTP in Kubernetes Ingress
deny_http_ingress[msg] {
    input.kind == "Ingress"
    not input.spec.tls
    
    msg := "Ingress does not have TLS configuration"
}

deny_http_ingress[msg] {
    input.kind == "Ingress"
    rule := input.spec.rules[_]
    not rule.host
    
    msg := "Ingress rule does not specify a host for TLS"
}
