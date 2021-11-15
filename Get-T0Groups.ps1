param (
    [Parameter(Mandatory = $false)]
    [string]
    $tier0groups
)

$DefaultTier0Groups = `
    "Account Operators", `
    "Administrators", `
    "Backup Operators", `
    "Domain Admins", `
    "Enterprise Admins", `
    "Print Operators", `
    "Schema Admins", `
    "Server Operators"

Function Get-ADNestedGroups {
    param($Members)

    foreach ($member in $Members) {
        $out = Get-ADGroup -filter "DistinguishedName -eq '$member'" -properties members
        $out | Select-Object distinguishedName
        Get-ADNestedGroups -Members $out.Members
    }
}

foreach ($Group in $DefaultTier0Groups) {
    $AllTier0GroupsDN += (get-adgroup -identity $group).distinguishedname
}

if ($Tier0Groups) {
    $myTier0Groups = import-CSV -path $Tier0Groups
    foreach ($Group in $myTier0Groups) {
        $AllTier0GroupsDN += (get-adgroup -identity $group.DistinguishedName).distinguishedname
    }
}

foreach ($group in $AllTier0GroupsDN) {
    $members = (Get-ADGroup -Identity $group -Properties Members).Members
    $all = Get-ADNestedGroups $members
    $AllTier0GroupsDN += $all.distinguishedname
}

$allgroups = $AllTier0GroupsDN | Sort-Object | Get-Unique

Write-Host "`nThese groups are recognized as a Tier 0 Groups `n" 
$allgroups