# METADATA
# title: IAM policy grants full administrative (wildcard) permissions
# description: >-
#   An IAM policy statement with Effect=Allow and Action="*" grants god-mode:
#   every action on the target resources. This violates least privilege and,
#   combined with Resource="*", is effectively account-admin. Scope actions to
#   the specific operations the principal needs.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege
# custom:
#   id: SS-AWS-IAM-001
#   avd_id: SS-AWS-IAM-001
#   provider: aws
#   service: iam
#   severity: HIGH
#   short_code: no-wildcard-admin-policy
#   recommended_action: "Replace Action = \"*\" with the specific actions the principal requires (least privilege)."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package user.aws.iam001

import rego.v1

# Trivy normalizes the IAM policy document to a JSON string at
# policy.document.value with Action/Resource always coerced to arrays. We
# unmarshal and flag any Allow statement whose Action set contains the bare "*"
# (full admin) — distinct from a scoped service wildcard like "s3:*".
#
# LIMITATION (static analysis): if the policy's jsonencode(...) references a
# resource Trivy can't resolve (e.g. Resource = [aws_s3_bucket.x.arn] where x is
# in another module or undefined), the evaluated document comes back empty
# (Statement: null) and this rule cannot see the wildcard. Trivy's own built-in
# cloud checks share this limit. A raw-HCL fallback (schema["terraform"], scan
# the policy attribute string) is a tracked follow-up in PLAN-iac-rules-engine.md.
deny contains res if {
	policy := input.aws.iam.policies[_]
	doc := json.unmarshal(policy.document.value)
	stmt := doc.Statement[_]
	stmt.Effect == "Allow"
	stmt.Action[_] == "*"
	res := result.new(
		"IAM policy grants full administrative permissions (Action = \"*\").",
		policy.document,
	)
}
