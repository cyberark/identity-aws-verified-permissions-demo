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
