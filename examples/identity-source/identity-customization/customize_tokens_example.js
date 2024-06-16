// Script to set the claims

setClaim('preferred_username', LoginUser.Get('preferred_username'));
setClaim('preferred_username', LoginUser.Get('mail'));
setClaim('given_name', LoginUser.Get('First_Name'));
setClaim('family_name', LoginUser.Get('Last_Name'));
setClaim('groups', LoginUser.RoleNames);
setClaim('Department', LoginUser.Get('user_dept'));

//Custom attribute
var projectList = LoginUser.Get('user_project').replace(" ", "").split(",");

//Converting attribute to List
setClaimArray('project_list', projectList);
setClaimArray('roles', LoginUser.RoleNames);

//Setting claim with json object
setClaimObject('session_config_json', {"timeout":120,"session_idle":30});

//Setting a claim with longer number < int64
setClaim('session_time_long', 92233720368547758);



/*
 * This script creates an OpenID Connect Authorization and UserInfo response.
 *
 * Parameters passed into this script are:
 *   Application -
 *      The application object from the cloud storage.
 *      Use the Get method to get a property from the storage.
 *      For example, var url = Application.Get('Url');
 *   Issuer -
 *      String value of the Issuer.
 *      This value is the same as Application.Get('Issuer');
 *   LoginUser
 *      The user object.
 *
 *      Availabe fields and methods:
 *
 *         Username
 *            The user's name as configured in the management portal's
 *            Apps -> <Application> -> 'Map to User Accounts' tab.
 *         Get(string Attribute)
 *            Gets the user's attribute from the directory service, for example,
 *            LoginUser.Get('mail');
 *         GroupNames
 *            An array of group names that the user is directly a member of.
 *         EffectiveGroupNames
 *            An array of ALL group names that the user is a member of.
 *            Warning: This array coulbe very long for a large organization and
 *            could result in a very large SAML assertion if added as a SAML attribute.
 *            Use only if it's really needed.
 *         GroupDNs
 *            An array of group DNs that the user is directly a member of.
 *         EffectiveGroupDNs
 *            An array of ALL group DNs that the user is a member of.
 *   Scopes -
 *      List of scopes passed in during authorization request
 *      To see the full list of scopes and claims, go to [OpenID Connect Core 1.0, Section 5.4]
 *      Use Scopes parameter to check standard or custom scopes.
 *      e.g.
 *      if (Scopes.Contains('my_custom_scope')) {
 *        setClaim('my_custom_claim_key', 'my_custom_claim_value');
 *      }
 *
 *     AuthAdditionalParams -
 *     Use the AuthAdditionalParams object to set claims with additional parameters and to check if the object is null. For example:
 *      if (AuthAdditionalParams  !== null) {
 *			setClaim('auth_request_additional_param',AuthAdditionalParams.Get('auth_request_additional_param'));
 *      }
 *
 * Functions available to this script:
 *   setClaim('Name', 'Value');
 *      Create a claim with name 'Name' and value 'Value' in the UserInfo response.
 *      If the value parameter is resolved to a null value, the claim will be set
 *      with an empty string value. If the Client does not allow the claim that has
 *      an empty string, you will have to check the claim value in this script first,
 *      and then decide to set claim or not.
 *      e.g. setClaim('Department', LoginUser.Get('department'));
 *   removeClaim('Name');
 *      Remove a claim with name 'Name'.
 *      e.g. removeClaim('Department');
 *   setIssuer(Issuer);
 *      Set Issuer value.
 *   getSignInUrl();
 *      Returns the login url for the user. Example usage:
 *      setClaim('signInUrl', getSignInUrl());
 *
 */