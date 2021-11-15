param (
    [Parameter(Mandatory = $false)]
    [string]
    $tier0groups
)

Import-Module ActiveDirectory

$DefaultTier0Groups = `
    "Account Operators", `
    "Administrators", `
    "Backup Operators", `
    "Domain Admins", `
    "Enterprise Admins", `
    "Print Operators", `
    "Schema Admins", `
    "Server Operators"

function Get-ADNestedGroupMembers {
    [cmdletbinding()]
    param (
        [String]
        $Group
    )
    $Members = Get-ADGroupMember -Identity $Group -Recursive
    $members
    }

    Function Get-ADNestedGroups {
    param($Members)

    foreach ($member in $Members) {
        $out = Get-ADGroup -filter "DistinguishedName -eq '$member'" -properties members
        $out | Select-Object distinguishedName
        Get-ADNestedGroups -Members $out.Members
    }
}

$AllTier0GroupsDN = @()
$AllTier0UsersDN = @()

foreach ($Group in $DefaultTier0Groups) {
    $grpDN = (get-adgroup -identity $group).distinguishedname
    $AllTier0GroupsDN += $grpdn
}

if ($Tier0Groups) {
    $myTier0Groups = import-CSV -path $Tier0Groups
    foreach ($Group in $myTier0Groups) {
        $grpDN = get-adgroup -identity $group.DN
        $AllTier0GroupsDN += $grpdn.distinguishedname
    }
}

foreach ($group in $AllTier0GroupsDN) {
    $members = (Get-ADGroup -Identity $group -Properties Members).Members
    $all = Get-ADNestedGroups $members
    $AllTier0GroupsDN += $all.distinguishedname
}

$allgroups = $AllTier0GroupsDN | Sort-Object | Get-Unique

foreach ($group in $allgroups) {
    $grpDN = (get-adgroup -identity $group).distinguishedname
    $AllTier0UsersDN += (Get-ADGroupMember -Identity $grpdn -recursive).distinguishedname
}

$allusers = $AllTier0UsersDN | Sort-Object | Get-Unique

Write-Host "`nThese groups are recognized as a Tier 0 Groups `n"  -ForegroundColor Green
$allgroups

Write-Host "`nThese users are recognized as a Tier 0 Users `n"  -ForegroundColor Green
$allusers

Write-Host "`nTier 0 Groups and Users - membership" -ForegroundColor Green
foreach ($group in $allgroups) {
    Write-Host "`nGroup DN -" $group
    $members = Get-ADGroupmember -Identity $group
    foreach ($member in $members)  {
        Write-Host "["($member.objectclass).substring(0,1).toupper()"]" $member.distinguishedname
    }
}
