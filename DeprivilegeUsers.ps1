    <#
    .SYNOPSIS
    Remove user accounts from either all or Tier0 security groups
    .DESCRIPTION
    Author: Vladimir Mutić
    Version 2.0

    This script will take list of users from the CSV and remove them from either all or Tier0 groups depending on stated parameter (full or tier0)
    .PARAMETER CSV (MANDATORY, CSV file, DistinguishedName)
    Specify the full source to the CSV file i.e c:\temp\members.csv
    CSV need to have DN column defined
    .PARAMETER FULL (MANDATORY, Switch, Parameter set, other option is TIER0)
    Removes user from all security groups
    .PARAMETER TIER0 (MANDATORY, Switch, Parameter set, other option is TIER0)
    Removes user from Tier0 security groups
    .PARAMETER TIER0GROUPS (OPTIONAL, CSV file, DistinguishedName)
    You can define additional groups considered as tier 0
    .PARAMETER MOVE (OPTIONAL, Switch, can be used only with TIER0 parameter)
    Move deprivileged users to "OU=T1-Accounts,OU=Tier 1,OU=Admin,$ddn"
    .EXAMPLE
    .\deprivilegeusers.ps1 -CSV c:\temp\members.csv -full

    .\deprivilegeusers.ps1 -CSV c:\temp\members.csv -tier0groups c:\temp\tier0groups.csv -tier0 -move

    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]
        $CSV,
        [Parameter(Mandatory = $false)]
        [string]
        $tier0groups,
        [Parameter(Mandatory = $true, ParameterSetName="Type1")]
        [switch]
        $full,
        [Parameter(Mandatory = $true, ParameterSetName="Type2")]
        [switch]
        $tier0,
        [Parameter(Mandatory = $false, ParameterSetName="Type2")]
        [switch]
        $move
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

            Write-Host "`nThese users will be removed from all groups `n" 
            foreach($Object in $Objects) { $object.distinguishedname }

            $remove = Read-Host "`nWould you like to proceed?"

            if ($remove -notin "YES","Y") {
                Write-Host "`nNothing happened. ByeBye.."
                break
            } else {Write-Host "`nProceeding..`n"}

            foreach($Object in $Objects){
                Get-ADUser -Identity $Object.distinguishedName -Properties MemberOf | ForEach-Object {
                    $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
                    Write-Host "Deprivileging" $Object.distinguishedName
                }
            }
        }
        
        if ($tier0) {
    
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

            if ($move) {
                $ddn = (Get-ADDomain).DistinguishedName

                while (![adsi]::Exists("LDAP://OU=Tier 1,OU=Admin,$ddn")) {
                    if (![adsi]::Exists("LDAP://OU=Admin,$ddn")) {
                        New-ADOrganizationalUnit -Name "Admin" -Path "$ddn"
                    } else {New-ADOrganizationalUnit -Name "Tier 1" -Path "OU=Admin,$ddn"}
                }
    
                if (![adsi]::Exists("LDAP://OU=T1-Accounts,OU=Tier 1,OU=Admin,$ddn")) {
                    New-ADOrganizationalUnit -Name "T1-Accounts" -Path "OU=Tier 1,OU=Admin,$ddn"
                }
    
                $Tier1AccOU = "OU=T1-Accounts,OU=Tier 1,OU=Admin,$ddn"
            }

            $AllTier0GroupsDN = @()

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

            Write-Host "`nThese users will be removed from Tier 0 Groups `n" 
            foreach($Object in $Objects) { $object.distinguishedname }

            $remove = Read-Host "`nWould you like to proceed?"

            if ($remove -notin "YES","Y") {
                Write-Host "`nNothing happened. ByeBye.."
                break
            } else {Write-Host "`nProceeding..`n"}
    
            foreach($Object in $Objects) {
                $OUGs = Get-ADUser -Identity $Object.DistinguishedName -Properties MemberOf
                $t0ougs = $ougs.memberof | Where-Object {$_ -in $allgroups}
    
                ForEach ($T0OUG in $T0OUGs) {
                    Remove-ADGroupMember -identity $t0oug -Members $object.DistinguishedName -Confirm:$false
                }

                if ($move) {
                    Move-ADObject  -Identity $object.DistinguishedName -TargetPath $Tier1AccOU
                }
                
                Write-Host "Deprivileging" $Object.DistinguishedName
            }
        }
    }