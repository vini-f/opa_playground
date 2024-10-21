
package main
import input as tfplan
import future.keywords.in
import data.okta_utils as utils


deny[msg] {    
    # utils.is_not_no_op_and_read(r)
    tfplan.resource_changes[r].type == "okta_app_saml"
    msg := "Creation/Updation of Okta APP's via Terraform are strictly prohibited. Kindly create a ticket in the Slack channel for any necessary adjustments."
}

deny[msg] {    
    # utils.is_not_no_op_and_read(r)
    tfplan.resource_changes[r].type == "okta_app_oauth"
    msg := "Creation/Updation of Okta APP's via Terraform are strictly prohibited. Kindly create a ticket in the Slack channel for any necessary adjustments."
}