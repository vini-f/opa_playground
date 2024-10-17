package main
import input as tfplan
import future.keywords.in
import data.okta_utils as utils

cloudsec_groups = {
    "OKTA_GROUP_NAME_1",
    "OKTA_GROUP_NAME_2",
    "OKTA_GROUP_NAME_3",
    "OKTA_GROUP_NAME_4",
    "OKTA_GROUP_NAME_5"
}

group_id_to_name[id] = name {
    some r
    tfplan.resource_changes[r].type == "okta_group"
    id := tfplan.resource_changes[r].change.after.id
    name := tfplan.resource_changes[r].change.after.name
}

deny[msg] {
    tfplan.resource_changes[r].type == "okta_group_memberships"
    tfplan.resource_changes[r].change.actions[_] == "update"
    group_id := tfplan.resource_changes[r].change.after.group_id
    group_name := group_id_to_name[group_id]
    group_name in cloudsec_groups
    msg = sprintf("Group %v has been modified. This requires CloudSec review, please reach out to channel.", [group_name])
}