###############################################
# This script must be run on a computer joined 
# to Active Directory
#
# Set the two variables below:

$exportlocation = "Z:\OneDrive\A\AD-Audit\"
$date = get-date -Format "yyMMdd"

# The script will create 3 files:
# adusers.csv - List of all users, including password settings
# adgroups.csv - List of all groups and users in each one
# emptygroups.csv - List of all groups that don't have any users

###############################################

# Retrieve AD Users list and export to CSV
$adusers = get-aduser -Filter * -Properties CannotChangePassword,CanonicalName,CN,Created,Department,Description,DisplayName,DistinguishedName,EmailAddress,EmployeeID,Enabled,GivenName,LastLogonDate,LockedOut,logonCount,Manager,Modified,Name,ObjectClass,ObjectGUID,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,SamAccountName,SID,Surname,UserPrincipalName,whenChanged,whenCreated
$adusersFN = $exportlocation + "adusers.csv"
$adusers | select CannotChangePassword,CanonicalName,CN,Created,Department,Description,DisplayName,DistinguishedName,EmailAddress,EmployeeID,Enabled,GivenName,LastLogonDate,LockedOut,logonCount,Manager,Modified,Name,ObjectClass,ObjectGUID,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,SamAccountName,SID,Surname,UserPrincipalName,whenChanged,whenCreated | export-csv $adusersFN -NoTypeInformation


# Retrieve AD Group List and then members of each group
$ADgroups = Get-ADGroup -filter *
$ADgroupmemberlist = ForEach ($ADgroup in $ADgroups) 
 {
 $groupresults = Get-ADGroupMember -Identity $ADgroup -Recursive 

 ForEach ($r in $groupresults){
 New-Object PSObject -Property @{
        GroupName = $ADgroup.Name
        Username = $r.name
        ObjectClass = $r.objectclass
        DistinguishedName = $r.distinguishedName
     }
    }
 } 
$ADgroupsFN = $exportlocation + "adgroups.csv"
$ADgroupmemberlist | export-csv $ADgroupsFN -NoTypeInformation

$EmptyGroups = $ADgroups | ?{@(Get-ADGroupMember $_).Length -eq 0} | select name,objectclass,DistinguishedName
$EmptyGroupsFN = $exportlocation + "emptygroups.csv"
$EmptyGroups | export-csv $EmptyGroupsFN -NoTypeInformation