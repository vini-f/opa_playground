package okta.cloudsec.cloudsec_group_members
import input as tfplan
import future.keywords.in
import data.okta_utils as utils

cloudsec_groups = {
    "Admin Group 1",
    "Admin Group 2",
    "Admin Group 3",
    "Admin Group 4",
    "Admin Group 5"
}

group_id_to_name[id] = name {
    some r
    tfplan.resource_changes[r].type == "okta_group"
    id := tfplan.resource_changes[r].change.after.id
    name := tfplan.resource_changes[r].change.after.name
}

deny[msg] {
    tfplan.resource_changes[r].type == "okta_group_memberships"
    tfplan.resource_changes[r].change.actions[_] in {"update"}
    group_id := tfplan.resource_changes[r].change.after.group_id
    group_name := group_id_to_name[group_id]
    group_name in cloudsec_groups
    msg = sprintf("Group %v has been modified. This requires CloudSec review, please reach out to channel.", [group_name])
}