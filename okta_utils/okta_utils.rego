package okta_utils
import input as tfplan
import future.keywords.in

roles_to_be_detected = {
    "admin_1",
    "super_admin",
}

core_infra_accounts =  {
    "[critical-core-account]",
    "[really-critical-core-account]",
}

grab_diff(r) = diff {
    json_after_2 := json.unmarshal(tfplan.resource_changes[r].change.after.profile).samlRoles
    tfplan.resource_changes[r].change.before.profile
    json_before_2 := json.unmarshal(tfplan.resource_changes[r].change.before.profile).samlRoles
    diff := {x | x := json_after_2[_]} - {x | x := json_before_2[_]}
}

grab_diff(r) = diff {
    json_after_2 := json.unmarshal(tfplan.resource_changes[r].change.after.profile).samlRoles
    not tfplan.resource_changes[r].change.before.profile
    diff := {x | x := json_after_2[_]}
}

okta_group_create_update(r) = true {
    tfplan.resource_changes[r].change.after.app_id == "OKTA_APP_ID"
    tfplan.resource_changes[r].change.actions[_] in {"create", "update"}
}

check_accounts_coreinfra(r) = detected_roles {
    delta := grab_diff(r)
    matches := {y |
        x := core_infra_accounts[_]
        y := delta[_]
        contains(y, x)
    }
    detected_roles := {y |
        x := roles_to_be_detected[_]
        y := matches[_]
        contains(y, x)
    }
}

check_accounts_cloudsec(r) = detected_roles {
    delta := grab_diff(r)
    matches := {y |
        x := core_infra_accounts[_]
        y := delta[_]
        contains(y, x)
    }
    not_matched := delta - matches
    detected_roles := {y |
        x := roles_to_be_detected[_]
        y := not_matched[_]
        contains(y, x)
    }
}

is_not_no_op_and_read(action) = true {
    tfplan.resource_changes[r].change.actions[_] != {"no-op", "read"}
}