package okta.cloudsec.cloudsec_admin_roles

test_1_allow_for_approved_roles{
    count(deny) == 0 with input as {
       "resource_changes": [
        {
            "address": "module.app_group_assignment_aws.okta_app_group_assignment.app_assignment",
            "module_address": "module.app_group_assignment_aws",
            "mode": "managed",
            "type": "okta_app_group_assignment",
            "name": "app_assignment",
            "provider_name": "registry.terraform.io/okta/okta",
            "change": {
                "actions": [
                    "update"
                ],
                "before": {
                    "app_id": "APP_ID",
                    "group_id": "GROUP_ID",
                    "id": "GROUP_ID",
                    "priority": 55,
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_iam_admin\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_alert_manager\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_oriole_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_woodpecker_developer\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[zesty-prod] -- sso_readonly\"]}",
                    "retain_assignment": false,
                    "timeouts": {
                        "create": null,
                        "read": null,
                        "update": null
                    }
                },
                "after": {
                    "app_id": "APP_ID",
                    "group_id": "GROUP_ID",
                    "id": "GROUP_ID",
                    "priority": 55,
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_iam_admin\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_alert_manager\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_oriole_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_woodpecker_developer\",\"[org-account] -- sso_infrasec_engineer\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[org-account] -- sso_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[zesty-prod] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\"]}",
                    "retain_assignment": false,
                    "timeouts": {
                        "create": null,
                        "read": null,
                        "update": null
                    }
                },
                "after_unknown": {},
                "before_sensitive": {
                    "timeouts": {}
                },
                "after_sensitive": {
                    "timeouts": {}
                }
            }
        }
    ] 
    }
}

test_2_deny_for_not_approved_roles{
    count(deny) != 0 with input as {
       "resource_changes": [
        {
            "address": "module.app_group_assignment_aws.okta_app_group_assignment.app_assignment",
            "module_address": "module.app_group_assignment_aws",
            "mode": "managed",
            "type": "okta_app_group_assignment",
            "name": "app_assignment",
            "provider_name": "registry.terraform.io/okta/okta",
            "change": {
                "actions": [
                    "update"
                ],
                "before": {
                    "app_id": "APP_ID",
                    "group_id": "GROUP_ID",
                    "id": "GROUP_ID",
                    "priority": 55,
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_iam_admin\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_alert_manager\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_oriole_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_woodpecker_developer\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[zesty-prod] -- sso_readonly\"]}",
                    "retain_assignment": false,
                    "timeouts": {
                        "create": null,
                        "read": null,
                        "update": null
                    }
                },
                "after": {
                    "app_id": "APP_ID",
                    "group_id": "GROUP_ID",
                    "id": "GROUP_ID",
                    "priority": 55,
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_iam_admin\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_alert_manager\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_oriole_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_woodpecker_developer\",\"[org-account] -- sso_infrasec_engineer\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[zesty-prod] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\"]}",
                    "retain_assignment": false,
                    "timeouts": {
                        "create": null,
                        "read": null,
                        "update": null
                    }
                },
                "after_unknown": {},
                "before_sensitive": {
                    "timeouts": {}
                },
                "after_sensitive": {
                    "timeouts": {}
                }
            }
        }
    ] 
    }
}

test_3_allow_for_not_aws_app{
    count(deny) == 0 with input as {
       "resource_changes": [
        {
            "address": "module.app_group_assignment_aws.okta_app_group_assignment.app_assignment",
            "module_address": "module.app_group_assignment_aws",
            "mode": "managed",
            "type": "okta_app_group_assignment",
            "name": "app_assignment",
            "provider_name": "registry.terraform.io/okta/okta",
            "change": {
                "actions": [
                    "update"
                ],
                "before": {
                    "app_id": "APP_ID",
                    "group_id": "GROUP_ID",
                    "id": "GROUP_ID",
                    "priority": 55,
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_iam_admin\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_alert_manager\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_oriole_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_woodpecker_developer\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[zesty-prod] -- sso_readonly\"]}",
                    "retain_assignment": false,
                    "timeouts": {
                        "create": null,
                        "read": null,
                        "update": null
                    }
                },
                "after": {
                    "app_id": "APP_ID",
                    "group_id": "GROUP_ID",
                    "id": "GROUP_ID",
                    "priority": 55,
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_iam_admin\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_alert_manager\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_oriole_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_woodpecker_developer\",\"[org-account] -- sso_infrasec_engineer\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[org-account] -- sso_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[zesty-prod] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\"]}",
                    "retain_assignment": false,
                    "timeouts": {
                        "create": null,
                        "read": null,
                        "update": null
                    }
                },
                "after_unknown": {},
                "before_sensitive": {
                    "timeouts": {}
                },
                "after_sensitive": {
                    "timeouts": {}
                }
            }
        }
    ] 
    }
}

test_4_allow_for_coreinfra_account{
    count(deny) == 0 with input as {
       "resource_changes": [
        {
            "address": "module.app_group_assignment_aws.okta_app_group_assignment.app_assignment",
            "module_address": "module.app_group_assignment_aws",
            "mode": "managed",
            "type": "okta_app_group_assignment",
            "name": "app_assignment",
            "provider_name": "registry.terraform.io/okta/okta",
            "change": {
                "actions": [
                    "update"
                ],
                "before": {
                    "app_id": "APP_ID",
                    "group_id": "GROUP_ID",
                    "id": "GROUP_ID",
                    "priority": 55,
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_iam_admin\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_alert_manager\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_oriole_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_woodpecker_developer\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[zesty-prod] -- sso_readonly\"]}",
                    "retain_assignment": false,
                    "timeouts": {
                        "create": null,
                        "read": null,
                        "update": null
                    }
                },
                "after": {
                    "app_id": "APP_ID",
                    "group_id": "GROUP_ID",
                    "id": "GROUP_ID",
                    "priority": 55,
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_iam_admin\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_security_engineer\",\"[org-account] -- sso_infrasec_engineer\",\"[org-account] -- sso_snowy_engineer\",\"[org-account] -- sso_alert_manager\",\"[org-account] -- sso_cloudsec_stats_engineer\",\"[org-account] -- sso_oriole_engineer\",\"[org-account] -- sso_redstart_engineer\",\"[org-account] -- sso_woodpecker_developer\",\"[org-account] -- sso_infrasec_engineer\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[zesty-prod] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_readonly\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_admin\",\"[org-account] -- sso_readonly\"]}",
                    "retain_assignment": false,
                    "timeouts": {
                        "create": null,
                        "read": null,
                        "update": null
                    }
                },
                "after_unknown": {},
                "before_sensitive": {
                    "timeouts": {}
                },
                "after_sensitive": {
                    "timeouts": {}
                }
            }
        }
    ] 
    }
}