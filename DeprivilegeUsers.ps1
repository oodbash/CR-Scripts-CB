    <#
    .SYNOPSIS
    Remove user accounts from either all or Tier0 security groups
    .DESCRIPTION
    Author: Vladimir Mutić
    Version 2.0

    This script will take list of users from the CSV and remove them from either all or Tier0 groups depending on stated parameter (full or tier0)
    .PARAMETER CSV (MANDATORY)
    Specify the full source to the CSV file i.e c:\temp\members.csv
    CSV need to have DN column defined
    .PARAMETER FULL (MANDATORY, Switch, Parameter set, other option is TIER0)
    Removes user from all security groups
    .PARAMETER TIER0 (MANDATORY, Switch, Parameter set, other option is TIER0)
    Removes user from Tier0 security groups
    .EXAMPLE
    .\deprivilegeusers.ps1 -CSV c:\temp\members.csv -full


    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]
        $CSV,
        [Parameter(Mandatory = $true, ParameterSetName="Type1")]
        [switch]
        $full,
        [Parameter(Mandatory = $true, ParameterSetName="Type2")]
        [switch]
        $tier0
    )
    
    BEGIN{
        #Checks if the user is in the administrator group. Warns and stops if the user is not.
        If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
            [Security.Principal.WindowsBuiltInRole] "Administrator"))
        {
            Write-Warning "You are not running this as local administrator. Run it again in an elevated prompt."
            Break
        }
        try {
        Import-Module ActiveDirectory
        }
        catch {
        Write-Warning "The Active Directory module was not found"
        }
        try {
        $Objects = Import-CSV $CSV
        }
        catch {
        Write-Warning "The CSV file was not found"
        }
    }
    
    PROCESS {
    
        if ($full) {
            foreach($Object in $Objects){
                Get-ADUser -Identity $Object.dn -Properties MemberOf | ForEach-Object {
                    $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
                    Write-Host "Deprivileging " $Object.dn
                }
            }
        }
        
        if ($tier0) {
    
            #You can add here more groups considered Tier0
            $Groups = `
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
    
            $RootTier0Groups = @()
            foreach ($Group in $Groups) {$RootTier0Groups += (get-adgroup -identity $group).distinguishedname}
    
            foreach ($group in $Groups) {
                $members = (Get-ADGroup -Identity $group -Properties Members).Members
                $all = Get-ADNestedGroups $members
                $allgroups += $all.distinguishedname
            }
    
            $allgroups = $allgroups + $RootTier0Groups | Sort-Object | Get-Unique
    
            $Objects = Import-CSV $CSV
    
            foreach($Object in $Objects) {
                $OUGs = Get-ADUser -Identity $Object.dn -Properties MemberOf
                $t0ougs = $ougs.memberof | Where-Object {$_ -in $allgroups}
    
                ForEach ($T0OUG in $T0OUGs) {
                    Remove-ADGroupMember -identity $t0oug -Members $object.dn -Confirm:$false
                }
                
                Write-Host "Deprivileging" $Object.dn
            }
        }
    }