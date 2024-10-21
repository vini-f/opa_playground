package okta.cloudsec.cloudsec_admin_roles
import input as tfplan
import future.keywords.in
import data.okta_utils as utils

deny[msg] {
    tfplan.resource_changes[r].type == "okta_app_group_assignment"
    utils.okta_group_create_update(r)
    acct_m := utils.check_accounts_cloudsec(r)
    count(acct_m) > 0
    msg = sprintf("Sensitive roles were detected in this change. Please reach out to for approvals. Roles: %v", [acct_m])
}

