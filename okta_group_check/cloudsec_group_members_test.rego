package okta.cloudsec.cloudsec_group_members

test_1_deny_for_okta_group_memberships{
    count(deny) != 0 with input as {
        "resource_changes":
        [
            {
                "address": "module.app_group_assignment_aws.okta_app_group_assignment.app_assignment",
                "module_address": "module.app_group_assignment_aws",
                "mode": "managed",
                "type": "okta_app_group_assignment",
                "name": "app_assignment",
                "provider_name": "registry.terraform.io/okta/okta",
                "change":
                {
                    "actions":
                    [
                        "no-op"
                    ],
                    "before":
                    {
                        "app_id": "APP_ID",
                        "group_id": "GROUP_ID_1",
                        "id": "GROUP_ID_1",
                        "priority": 104,
                        "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[[org-account]] -- sso_admin\",\"[[org-account]] -- sso_security_admin\"]}",
                        "retain_assignment": false,
                        "timeouts": null
                    },
                    "after":
                    {
                        "app_id": "APP_ID",
                        "group_id": "GROUP_ID_1",
                        "id": "GROUP_ID_1",
                        "priority": 104,
                        "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[[org-account]] -- sso_admin\",\"[[org-account]] -- sso_security_admin\"]}",
                        "retain_assignment": false,
                        "timeouts": null
                    },
                    "after_unknown":
                    {},
                    "before_sensitive":
                    {},
                    "after_sensitive":
                    {}
                }
            },
            {
                "address": "module.okta_group.okta_group.group",
                "module_address": "module.okta_group",
                "mode": "managed",
                "type": "okta_group",
                "name": "group",
                "provider_name": "registry.terraform.io/okta/okta",
                "change":
                {
                    "actions":
                    [
                        "no-op"
                    ],
                    "before":
                    {
                        "custom_profile_attributes": "{}",
                        "description": "Users with elevated access in tf_account_secinfra",
                        "id": "GROUP_ID_1",
                        "name": "TF-SG - SecInfra Admins",
                        "skip_users": false,
                        "users":
                        []
                    },
                    "after":
                    {
                        "custom_profile_attributes": "{}",
                        "description": "Users with elevated access in tf_account_secinfra",
                        "id": "GROUP_ID_1",
                        "name": "TF-SG - SecInfra Admins",
                        "skip_users": false,
                        "users":
                        []
                    },
                    "after_unknown":
                    {},
                    "before_sensitive":
                    {
                        "users":
                        []
                    },
                    "after_sensitive":
                    {
                        "users":
                        []
                    }
                }
            },
            {
                "address": "module.okta_group.okta_group_memberships.group",
                "module_address": "module.okta_group",
                "mode": "managed",
                "type": "okta_group_memberships",
                "name": "group",
                "provider_name": "registry.terraform.io/okta/okta",
                "change":
                {
                    "actions":
                    [
                        "update"
                    ],
                    "before":
                    {
                        "group_id": "GROUP_ID_1",
                        "id": "GROUP_ID_1",
                        "track_all_users": false,
                        "users":
                        [
                            "00ujy93u3jacnLSGL0x7",
                            "00ukrysxqh17fjs4W0x7",
                            "00uqjm75qhBiGQmer0x7",
                            "00uu3wzzrtvzgVJ4Z0x7"
                        ]
                    },
                    "after":
                    {
                        "group_id": "GROUP_ID_1",
                        "id": "GROUP_ID_1",
                        "track_all_users": false,
                        "users":
                        [
                            "00ujy93u3jacnLSGL0x7",
                            "00ukrysxqh17fjs4W0x7",
                            "00uqjm75qhBiGQmer0x7",
                            "00uu3wzzrtvzgVJ4Z0x7",
                            "00uu3x2ur3zJJQK950x7"
                        ]
                    },
                    "after_unknown":
                    {},
                    "before_sensitive":
                    {
                        "users":
                        [
                            false,
                            false,
                            false,
                            false
                        ]
                    },
                    "after_sensitive":
                    {
                        "users":
                        [
                            false,
                            false,
                            false,
                            false,
                            false
                        ]
                    }
                }
            }
        ]
    }
}

test_2_allow_for_okta_group_memberships{
    count(deny) == 0 with input as {
        "resource_changes":
        [
            {
                "address": "module.app_group_assignment_aws.okta_app_group_assignment.app_assignment",
                "module_address": "module.app_group_assignment_aws",
                "mode": "managed",
                "type": "okta_app_group_assignment",
                "name": "app_assignment",
                "provider_name": "registry.terraform.io/okta/okta",
                "change":
                {
                    "actions":
                    [
                        "no-op"
                    ],
                    "before":
                    {
                        "app_id": "APP_ID",
                        "group_id": "GROUP_ID_2",
                        "id": "GROUP_ID_2",
                        "priority": 104,
                        "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[[org-account]] -- sso_admin\",\"[[org-account]] -- sso_security_admin\"]}",
                        "retain_assignment": false,
                        "timeouts": null
                    },
                    "after":
                    {
                        "app_id": "APP_ID",
                        "group_id": "GROUP_ID_2",
                        "id": "GROUP_ID_2",
                        "priority": 104,
                        "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[[org-account]] -- sso_admin\",\"[[org-account]] -- sso_security_admin\"]}",
                        "retain_assignment": false,
                        "timeouts": null
                    },
                    "after_unknown":
                    {},
                    "before_sensitive":
                    {},
                    "after_sensitive":
                    {}
                }
            },
            {
                "address": "module.okta_group.okta_group.group",
                "module_address": "module.okta_group",
                "mode": "managed",
                "type": "okta_group",
                "name": "group",
                "provider_name": "registry.terraform.io/okta/okta",
                "change":
                {
                    "actions":
                    [
                        "no-op"
                    ],
                    "before":
                    {
                        "custom_profile_attributes": "{}",
                        "description": "Users with elevated access in tf_account_secinfra",
                        "id": "GROUP_ID_2",
                        "name": "TF-SG - infrasec_one_off",
                        "skip_users": false,
                        "users":
                        []
                    },
                    "after":
                    {
                        "custom_profile_attributes": "{}",
                        "description": "Users with elevated access in tf_account_secinfra",
                        "id": "GROUP_ID_2",
                        "name": "TF-SG - infrasec_one_off",
                        "skip_users": false,
                        "users":
                        []
                    },
                    "after_unknown":
                    {},
                    "before_sensitive":
                    {
                        "users":
                        []
                    },
                    "after_sensitive":
                    {
                        "users":
                        []
                    }
                }
            },
            {
                "address": "module.okta_group.okta_group_memberships.group",
                "module_address": "module.okta_group",
                "mode": "managed",
                "type": "okta_group_memberships",
                "name": "group",
                "provider_name": "registry.terraform.io/okta/okta",
                "change":
                {
                    "actions":
                    [
                        "update"
                    ],
                    "before":
                    {
                        "group_id": "GROUP_ID_2",
                        "id": "GROUP_ID_2",
                        "track_all_users": false,
                        "users":
                        [
                            "00ujy93u3jacnLSGL0x7",
                            "00ukrysxqh17fjs4W0x7",
                            "00uqjm75qhBiGQmer0x7",
                            "00uu3wzzrtvzgVJ4Z0x7"
                        ]
                    },
                    "after":
                    {
                        "group_id": "GROUP_ID_2",
                        "id": "GROUP_ID_2",
                        "track_all_users": false,
                        "users":
                        [
                            "00ujy93u3jacnLSGL0x7",
                            "00ukrysxqh17fjs4W0x7",
                            "00uqjm75qhBiGQmer0x7",
                            "00uu3wzzrtvzgVJ4Z0x7",
                            "00uu3x2ur3zJJQK950x7"
                        ]
                    },
                    "after_unknown":
                    {},
                    "before_sensitive":
                    {
                        "users":
                        [
                            false,
                            false,
                            false,
                            false
                        ]
                    },
                    "after_sensitive":
                    {
                        "users":
                        [
                            false,
                            false,
                            false,
                            false,
                            false
                        ]
                    }
                }
            }
        ]
    }
}

test_3_deny_for_okta_group_memberships{
    count(deny) != 0 with input as {
        "resource_changes":
        [
            {
                "address": "module.app_group_assignment_aws.okta_app_group_assignment.app_assignment",
                "module_address": "module.app_group_assignment_aws",
                "mode": "managed",
                "type": "okta_app_group_assignment",
                "name": "app_assignment",
                "provider_name": "registry.terraform.io/okta/okta",
                "change":
                {
                    "actions":
                    [
                        "no-op"
                    ],
                    "before":
                    {
                        "app_id": "APP_ID",
                        "group_id": "GROUP_ID_3",
                        "id": "GROUP_ID_3",
                        "priority": 104,
                        "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[[org-account]] -- sso_admin\",\"[[org-account]] -- sso_security_admin\"]}",
                        "retain_assignment": false,
                        "timeouts": null
                    },
                    "after":
                    {
                        "app_id": "APP_ID",
                        "group_id": "GROUP_ID_3",
                        "id": "GROUP_ID_3",
                        "priority": 104,
                        "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[[org-account]] -- sso_admin\",\"[[org-account]] -- sso_security_admin\"]}",
                        "retain_assignment": false,
                        "timeouts": null
                    },
                    "after_unknown":
                    {},
                    "before_sensitive":
                    {},
                    "after_sensitive":
                    {}
                }
            },
            {
                "address": "module.okta_group.okta_group.group",
                "module_address": "module.okta_group",
                "mode": "managed",
                "type": "okta_group",
                "name": "group",
                "provider_name": "registry.terraform.io/okta/okta",
                "change":
                {
                    "actions":
                    [
                        "no-op"
                    ],
                    "before":
                    {
                        "custom_profile_attributes": "{}",
                        "description": "Users with elevated access in tf_account_secinfra",
                        "id": "GROUP_ID_3",
                        "name": "TF-SG - AWS Central Admins",
                        "skip_users": false,
                        "users":
                        []
                    },
                    "after":
                    {
                        "custom_profile_attributes": "{}",
                        "description": "Users with elevated access in tf_account_secinfra",
                        "id": "GROUP_ID_3",
                        "name": "TF-SG - AWS Central Admins",
                        "skip_users": false,
                        "users":
                        []
                    },
                    "after_unknown":
                    {},
                    "before_sensitive":
                    {
                        "users":
                        []
                    },
                    "after_sensitive":
                    {
                        "users":
                        []
                    }
                }
            },
            {
                "address": "module.okta_group.okta_group_memberships.group",
                "module_address": "module.okta_group",
                "mode": "managed",
                "type": "okta_group_memberships",
                "name": "group",
                "provider_name": "registry.terraform.io/okta/okta",
                "change":
                {
                    "actions":
                    [
                        "update"
                    ],
                    "before":
                    {
                        "group_id": "GROUP_ID_3",
                        "id": "GROUP_ID_3",
                        "track_all_users": false,
                        "users":
                        [
                            "00ujy93u3jacnLSGL0x7",
                            "00ukrysxqh17fjs4W0x7",
                            "00uqjm75qhBiGQmer0x7",
                            "00uu3wzzrtvzgVJ4Z0x7"
                        ]
                    },
                    "after":
                    {
                        "group_id": "GROUP_ID_3",
                        "id": "GROUP_ID_3",
                        "track_all_users": false,
                        "users":
                        [
                            "00ujy93u3jacnLSGL0x7",
                            "00ukrysxqh17fjs4W0x7",
                            "00uqjm75qhBiGQmer0x7",
                            "00uu3wzzrtvzgVJ4Z0x7",
                            "00uu3x2ur3zJJQK950x7"
                        ]
                    },
                    "after_unknown":
                    {},
                    "before_sensitive":
                    {
                        "users":
                        [
                            false,
                            false,
                            false,
                            false
                        ]
                    },
                    "after_sensitive":
                    {
                        "users":
                        [
                            false,
                            false,
                            false,
                            false,
                            false
                        ]
                    }
                }
            }
        ]
    }
}