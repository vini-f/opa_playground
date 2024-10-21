package okta.cloudsec.cloudsec_saml_app

test_1_allow_for_okta_app_group_assignment{
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
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_admin\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_admin\",\"[org_account] -- sso_cloudsec_stats_engineer\",\"[org_account] -- sso_iam_admin\",\"[org_account] -- sso_redstart_engineer\",\"[org_account] -- sso_snowy_engineer\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_security_engineer\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_security_engineer\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_alert_manager\",\"[org_account] -- sso_cloudsec_stats_engineer\",\"[org_account] -- sso_infrasec_engineer\",\"[org_account] -- sso_oriole_engineer\",\"[org_account] -- sso_redstart_engineer\",\"[org_account] -- sso_snowy_engineer\",\"[org_account] -- sso_woodpecker_developer\",\"[org_account] -- sso_admin\",\"[org_account] -- sso_infrasec_engineer\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[zesty-prod] -- sso_readonly\"]}",
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
                    "profile": "{\"role\":\"[secinfra-gateway] -- sso_sandbox\",\"samlRoles\":[\"[org_account] -- sso_readonly\",\"[org_account] -- sso_admin\",\"[org_account] -- sso_iam_admin\",\"[org_account] -- sso_snowy_engineer\",\"[org_account] -- sso_cloudsec_stats_engineer\",\"[org_account] -- sso_redstart_engineer\",\"[org_account] -- sso_security_engineer\",\"[org_account] -- sso_security_engineer\",\"[org_account] -- sso_infrasec_engineer\",\"[org_account] -- sso_snowy_engineer\",\"[org_account] -- sso_alert_manager\",\"[org_account] -- sso_cloudsec_stats_engineer\",\"[org_account] -- sso_oriole_engineer\",\"[org_account] -- sso_redstart_engineer\",\"[org_account] -- sso_woodpecker_developer\",\"[org_account] -- sso_infrasec_engineer\",\"[org_account] -- sso_infrasec_engineer\",\"[secinfra-dev] -- sso_admin\",\"[org_account] -- sso_admin\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[zesty-prod] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_readonly\",\"[org_account] -- sso_admin\",\"[org_account] -- sso_admin\",\"[org_account] -- sso_readonly\"]}",
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

test_2_deny_for_okta_saml_app{
    count(deny) != 0 with input as {
        "resource_changes": [
        {
            "address": "okta_app_saml.app",
            "mode": "managed",
            "type": "okta_app_saml",
            "name": "app",
            "provider_name": "registry.terraform.io/okta/okta",
            "change": {
            "actions": [
                "create"
            ],
            "before": null,
            "after": {
                "accessibility_error_redirect_url": null,
                "accessibility_login_redirect_url": null,
                "accessibility_self_service": false,
                "acs_endpoints": null,
                "admin_note": null,
                "app_links_json": null,
                "app_settings_json": null,
                "assertion_signed": true,
                "attribute_statements": [
                {
                    "filter_type": null,
                    "filter_value": null,
                    "name": "email",
                    "namespace": "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
                    "type": "EXPRESSION",
                    "values": [
                    "${user.email}"
                    ]
                },
                {
                    "filter_type": null,
                    "filter_value": null,
                    "name": "name",
                    "namespace": "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
                    "type": "EXPRESSION",
                    "values": [
                    "${user.displayName}"
                    ]
                },
                {
                    "filter_type": null,
                    "filter_value": null,
                    "name": "username",
                    "namespace": "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
                    "type": "EXPRESSION",
                    "values": [
                    "${user.userName}"
                    ]
                }
                ],
                "audience": "https://console.anyscale.com/",
                "authentication_policy": null,
                "authn_context_class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                "auto_submit_toolbar": false,
                "default_relay_state": null,
                "destination": "https://console.anyscale.com/api/v2/organizations/org_abc/saml_acs",
                "digest_algorithm": "SHA256",
                "enduser_note": null,
                "groups": null,
                "hide_ios": true,
                "hide_web": false,
                "honor_force_authn": true,
                "idp_issuer": null,
                "implicit_assignment": null,
                "inline_hook_id": null,
                "key_name": null,
                "key_years_valid": null,
                "label": "Anyscale",
                "logo": null,
                "preconfigured_app": null,
                "recipient": "https://console.anyscale.com/api/v2/organizations/org_abc/saml_acs",
                "request_compressed": null,
                "response_signed": true,
                "saml_signed_request_enabled": false,
                "saml_version": "2.0",
                "signature_algorithm": "RSA_SHA256",
                "single_logout_certificate": null,
                "single_logout_issuer": null,
                "single_logout_url": null,
                "skip_groups": true,
                "skip_users": true,
                "sp_issuer": null,
                "sso_url": "https://console.anyscale.com/api/v2/organizations/org_abc/saml_acs",
                "status": "ACTIVE",
                "subject_name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "subject_name_id_template": "${user.userName}",
                "timeouts": null,
                "user_name_template": "${source.email}",
                "user_name_template_push_status": null,
                "user_name_template_suffix": null,
                "user_name_template_type": "BUILT_IN",
                "users": []
            },
            "after_unknown": {
                "attribute_statements": [
                {
                    "values": [
                    false
                    ]
                },
                {
                    "values": [
                    false
                    ]
                },
                {
                    "values": [
                    false
                    ]
                }
                ],
                "certificate": true,
                "embed_url": true,
                "entity_key": true,
                "entity_url": true,
                "features": true,
                "http_post_binding": true,
                "http_redirect_binding": true,
                "id": true,
                "key_id": true,
                "keys": true,
                "logo_url": true,
                "metadata": true,
                "metadata_url": true,
                "name": true,
                "sign_on_mode": true,
                "users": []
            },
            "before_sensitive": false,
            "after_sensitive": {
                "attribute_statements": [
                {
                    "values": [
                    false
                    ]
                },
                {
                    "values": [
                    false
                    ]
                },
                {
                    "values": [
                    false
                    ]
                }
                ],
                "features": [],
                "keys": [],
                "users": []
            }
            }
        }
    ]
    }
}

test_3_allow_for_okta_group_rule{
    count(deny) == 0 with input as {
            "resource_changes": [
            {
                "address": "okta_group_rule.tf_sg_aviator_users",
                "mode": "managed",
                "type": "okta_group_rule",
                "name": "tf_sg_aviator_users",
                "provider_name": "registry.terraform.io/okta/okta",
                "change": {
                "actions": [
                    "update"
                ],
                "before": {
                    "expression_type": "urn:okta:expression:1.0",
                    "expression_value": "isMemberOfAnyGroup(\"00gyrnahmildrAFyM0x7\",\"00gw18nd5ayVdpkFe0x7\",\"00goxavfgeCBeUuxH0x7\",\"00grywxiyfsdchu910x7\",\"00godcilx1wLSyZBK0x7\",\"00gp5gaxawB8QeDMI0x7\",\"00g113sj1xdCD4Gq70x8\",\"00grqrhv5uJoLfMgR0x7\",\"00gq25nfxw6h4Hmck0x7\",\"00gy7j9kzjOLULvQR0x7\",\"00gpaljztfx5rbukZ0x7\",\"00gzcxhbd6jkhrACM0x7\",\"00gp5gaxawB8QeDMI0x7\",\"00gmmyprtuQBnqDJr0x7\",\"00grrqwag1ZvOpkzP0x7\",\"00gtf7xzd9TkN90Pp0x7\",\"00gzb99p8gxFb1WQE0x7\",\"00gqen5pmiywRoC9H0x7\",\"00gqs2i3qifLAPdhk0x7\",\"00gzrsx40cc6EHuXW0x7\",\"00gu67pqvgDQHq22r0x7\",\"00gvs1t13wDYvR6Ch0x7\",\"00gsu9g6bzxXD9P0K0x7\",\"00goudf1wd8UPLeln0x7\",\"00g101p7whip779Pi0x8\",\"00gs0w52k6ISYTrxc0x7\",\"00gpn4a5hv7GAkQzV0x7\",\"00g11ldklooZXPeMJ0x8\",\"00g13arvzdenzqTLM0x8\",\"00gqdz7gvhVb4W6H80x7\",\"00gri7f0gzCB3IXwx0x7\",\"00gv7os3cggy6KGiA0x7\",\"00grywxiyfsdchu910x7\",\"00g12vpesfhUAkspn0x8\",\"00g11cv0trmlyGfqm0x8\",\"00gofb7l23Brf5aMt0x7\",\"00gwa9bkimo4FC0zb0x7\",\"00guxhlgx7qMcfAhl0x7\",\"00gqc7sit02CLlkjh0x7\",\"00gue0qq2m4HmO2530x7\",\"00g12x1arj5DKSsOx0x8\",\"00gpr76fvjz9klNHo0x7\",\"00govbgkz84A4sLsK0x7\",\"00gv94tlqmhu6iwBM0x7\",\"00gq38cqqt7wsttwd0x7\",\"00g12rvmyilRiOvag0x8\",\"00gqlfqcuqWu76Ib30x7\",\"00g13cdwa19Zbxmwh0x8\",\"00gt2qeeu8nh1oIQA0x7\",\"00gwbhh31vcTuBHLr0x7\",\"00gw0pb9qtav5wIwX0x7\")",
                    "group_assignments": [
                    "00g103ilmswouYQ7c0x8"
                    ],
                    "id": "0pr103iltvvs5s8w20x8",
                    "name": "Sync groups to Aviator",
                    "remove_assigned_users": null,
                    "status": "ACTIVE",
                    "users_excluded": []
                },
                "after": {
                    "expression_type": "urn:okta:expression:1.0",
                    "expression_value": "isMemberOfAnyGroup(\"00gyrnahmildrAFyM0x7\",\"00gw18nd5ayVdpkFe0x7\",\"00goxavfgeCBeUuxH0x7\",\"00grywxiyfsdchu910x7\",\"00godcilx1wLSyZBK0x7\",\"00gp5gaxawB8QeDMI0x7\",\"00g113sj1xdCD4Gq70x8\",\"00grqrhv5uJoLfMgR0x7\",\"00gq25nfxw6h4Hmck0x7\",\"00gy7j9kzjOLULvQR0x7\",\"00gpaljztfx5rbukZ0x7\",\"00gzcxhbd6jkhrACM0x7\",\"00gp5gaxawB8QeDMI0x7\",\"00gmmyprtuQBnqDJr0x7\",\"00grrqwag1ZvOpkzP0x7\",\"00gtf7xzd9TkN90Pp0x7\",\"00gzb99p8gxFb1WQE0x7\",\"00gqen5pmiywRoC9H0x7\",\"00gqs2i3qifLAPdhk0x7\",\"00gzrsx40cc6EHuXW0x7\",\"00gu67pqvgDQHq22r0x7\",\"00gvs1t13wDYvR6Ch0x7\",\"00gsu9g6bzxXD9P0K0x7\",\"00goudf1wd8UPLeln0x7\",\"00g101p7whip779Pi0x8\",\"00gs0w52k6ISYTrxc0x7\",\"00gpn4a5hv7GAkQzV0x7\",\"00g11ldklooZXPeMJ0x8\",\"00g13arvzdenzqTLM0x8\",\"00gqdz7gvhVb4W6H80x7\",\"00gri7f0gzCB3IXwx0x7\",\"00gv7os3cggy6KGiA0x7\",\"00grywxiyfsdchu910x7\",\"00g12vpesfhUAkspn0x8\",\"00g11cv0trmlyGfqm0x8\",\"00gofb7l23Brf5aMt0x7\",\"00gwa9bkimo4FC0zb0x7\",\"00guxhlgx7qMcfAhl0x7\",\"00gqc7sit02CLlkjh0x7\",\"00gue0qq2m4HmO2530x7\",\"00g12x1arj5DKSsOx0x8\",\"00gpr76fvjz9klNHo0x7\",\"00govbgkz84A4sLsK0x7\",\"00gv94tlqmhu6iwBM0x7\",\"00gq38cqqt7wsttwd0x7\",\"00g12rvmyilRiOvag0x8\",\"00gqlfqcuqWu76Ib30x7\",\"00g13cdwa19Zbxmwh0x8\",\"00gt2qeeu8nh1oIQA0x7\",\"00gwbhh31vcTuBHLr0x7\",\"00gw0pb9qtav5wIwX0x7\",\"00g11a0unraMLIwPH0x8\")",
                    "group_assignments": [
                    "00g103ilmswouYQ7c0x8"
                    ],
                    "id": "0pr103iltvvs5s8w20x8",
                    "name": "Sync groups to Aviator",
                    "remove_assigned_users": null,
                    "status": "ACTIVE",
                    "users_excluded": []
                },
                "after_unknown": {},
                "before_sensitive": {
                    "group_assignments": [
                    false
                    ],
                    "users_excluded": []
                },
                "after_sensitive": {
                    "group_assignments": [
                    false
                    ],
                    "users_excluded": []
                }
                }
            }
    ]
    }
}

test_4_deny_for_okta_oauth_app{
    count(deny) != 0 with input as {
            "resource_changes": [
            {
            "address": "module.oauth_app.okta_app_oauth.app",
            "module_address": "module.oauth_app",
            "mode": "managed",
            "type": "okta_app_oauth",
            "name": "app",
            "provider_name": "registry.terraform.io/okta/okta",
            "change": {
            "actions": [
                "create"
            ],
            "before": null,
            "after": {
                "accessibility_error_redirect_url": null,
                "accessibility_login_redirect_url": null,
                "accessibility_self_service": false,
                "admin_note": null,
                "app_links_json": null,
                "app_settings_json": null,
                "authentication_policy": null,
                "auto_key_rotation": true,
                "auto_submit_toolbar": false,
                "client_basic_secret": null,
                "client_uri": null,
                "consent_method": "REQUIRED",
                "custom_client_id": null,
                "enduser_note": null,
                "grant_types": [
                "authorization_code",
                "implicit"
                ],
                "groups": null,
                "groups_claim": [],
                "hide_ios": true,
                "hide_web": true,
                "implicit_assignment": null,
                "issuer_mode": "ORG_URL",
                "jwks": [],
                "label": "wildcard-web-assets-server",
                "login_mode": "DISABLED",
                "login_scopes": [
                "email",
                "openid",
                "profile"
                ],
                "login_uri": null,
                "logo": null,
                "logo_uri": null,
                "omit_secret": false,
                "pkce_required": null,
                "policy_uri": null,
                "post_logout_redirect_uris": [
                "https://*.was.org_account.team"
                ],
                "profile": null,
                "redirect_uris": [
                "https://*.was.org_account.team/oauth2/idpresponse"
                ],
                "response_types": [
                "code",
                "id_token",
                "token"
                ],
                "skip_groups": false,
                "skip_users": false,
                "status": "ACTIVE",
                "timeouts": null,
                "token_endpoint_auth_method": "client_secret_basic",
                "tos_uri": null,
                "type": "web",
                "user_name_template": "${source.login}",
                "user_name_template_push_status": null,
                "user_name_template_suffix": null,
                "user_name_template_type": "BUILT_IN",
                "users": [],
                "wildcard_redirect": "SUBDOMAIN"
            },
            "after_unknown": {
                "client_id": true,
                "client_secret": true,
                "grant_types": [
                false,
                false
                ],
                "groups_claim": [],
                "id": true,
                "jwks": [],
                "login_scopes": [
                false,
                false,
                false
                ],
                "logo_url": true,
                "name": true,
                "post_logout_redirect_uris": [
                false
                ],
                "redirect_uris": [
                false
                ],
                "refresh_token_leeway": true,
                "refresh_token_rotation": true,
                "response_types": [
                false,
                false,
                false
                ],
                "sign_on_mode": true,
                "users": []
            },
            "before_sensitive": false,
            "after_sensitive": {
                "client_basic_secret": true,
                "client_secret": true,
                "grant_types": [
                false,
                false
                ],
                "groups_claim": [],
                "jwks": [],
                "login_scopes": [
                false,
                false,
                false
                ],
                "post_logout_redirect_uris": [
                false
                ],
                "redirect_uris": [
                false
                ],
                "response_types": [
                false,
                false,
                false
                ],
                "users": []
            }
            }
        }
    ]
    }
}