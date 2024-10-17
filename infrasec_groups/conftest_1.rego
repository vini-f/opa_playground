package main
import input as tfplan
import future.keywords.in
import data.okta_utils as utils

cloudsec_groups = {
    "OKTA GROUP ID"
}

translate_name = {}

deny[msg] {
    tfplan.resource_changes[r].type == "okta_group_memberships"
    tfplan.resource_changes[r].change.actions[_] in {"update"}
    tfplan.resource_changes[r].change.after.group_id in cloudsec_groups
    msg = sprintf("Group %v has been modified. This requires CloudSec review, please reach out to channel.", [cloudsec_groups])
}