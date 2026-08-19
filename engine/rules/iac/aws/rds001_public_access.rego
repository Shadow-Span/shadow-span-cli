# METADATA
# title: RDS instance is publicly accessible
# description: >-
#   An RDS DB instance with publicly_accessible = true is reachable from the
#   public internet, exposing the database to credential-stuffing, brute-force
#   and direct-exploit attacks. Databases must live in private subnets and be
#   reached only through the VPC / a bastion.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html
# custom:
#   id: SS-AWS-RDS-001
#   avd_id: SS-AWS-RDS-001
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: no-public-db-access
#   recommended_action: "Set publicly_accessible = false on the aws_db_instance and place it in a private subnet."
#   input:
#     selector:
#       # TWO Trivy gotchas encoded here (both cost real debugging — see
#       # PLAN-iac-rules-engine.md "Trivy custom-check gotchas"):
#       #  1. Checks that read the cloud-adapted model (input.aws.*) MUST select
#       #     `type: cloud`. `type: terraform` is for raw-HCL checks reading
#       #     schema["terraform"]; used here it loads but NEVER evaluates.
#       #  2. Compliance/framework mappings do NOT go in this metadata block — a
#       #     nested `frameworks:` map silently breaks evaluation. They live in
#       #     the sidecar engine/rules/iac/mappings.json, keyed by rule id.
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
package user.aws.rds001

import rego.v1

deny contains res if {
	instance := input.aws.rds.instances[_]
	instance.publicaccess.value == true
	res := result.new(
		"RDS instance is publicly accessible (publicly_accessible = true).",
		instance.publicaccess,
	)
}
