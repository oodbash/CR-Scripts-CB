    <#
    .SYNOPSIS
    Authors: Matt Fields and Vladimir Mutić
    Version 0.8

    Disables user accounts and move them to "Disable users" OU. Optionally, it can also deprivilege and rename accounts.

    .DESCRIPTION
    This script will take a list of users from the CSV disable them and move them to "Disable users" OU. Optionally, it can also deprivilege and rename accounts.

    .PARAMETER CSV (MANDATORY)
    Specify the full source to the CSV file i.e c:\temp\members.csv
    CSV need to have distinguishedname and samaccountname columns.
    .EXAMPLE
    .\DisableUsers.ps1 -CSV c:\temp\users.csv

    .PARAMETER RENAME (SWITCH, OPTIONAL)
    Set this parameter if you want to rename users. By default, script will put "old-" as a prefix to old acount.
    .EXAMPLE
    .\DisableUsers.ps1 -CSV c:\temp\users.csv -rename

    .PARAMETER DEPRIVILEGE (MANDATORY)
    Set this parameter if you want to deprivilege users. It will remove users from all groups.
    .EXAMPLE
    .\DisableUsers.ps1 -CSV c:\temp\users.csv -deprivilege


    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>


[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $CSV,
    [Parameter(Mandatory = $false)]
    [switch]
    $rename,
    [Parameter(Mandatory = $false)]
    [switch]
    $deprivilege
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
    break
    }
    try {
    $Objects = Import-CSV $CSV
    }
    catch {
    Write-Warning "The CSV file was not found"
    break
    }
}
PROCESS {

    $ddn = (Get-ADDomain).DistinguishedName

    if (![adsi]::Exists("LDAP://OU=Disabled Accounts,$ddn")) {
        New-ADOrganizationalUnit -Name "Disabled Accounts" -Path $ddn
    }

    # Import CSV 
    $AccountList = Import-Csv -Path $CSV
    # Specify target OU.This is where users will be moved.
    $TargetOU =  "OU=Disabled Accounts,$ddn"
    $change = "old-"

    if ($deprivilege) {
        foreach($account in $AccountList){
            try{
                Get-ADUser -Identity $account.distinguishedname -Properties MemberOf | ForEach-Object {
                    $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
                    Write-Host "Deprivileging" $account.samaccountname
                }
                
            }
            catch{
                Write-Host -Message "Failed to deprivilege" + $account.SamAccountName
            }
        }
    }   

    ForEach ($account in $AccountList) {
        # Retrieve DN of User.
        $User = Get-ADUser -Identity $account.distinguishedName
        set-aduser -identity $user -Enabled:$false -SmartcardLogonRequired:$true
        Move-ADObject  -Identity $User -TargetPath $TargetOU
        }

    if ($rename){
        foreach ($account in $AccountList) {
            $User = Get-ADUser -identity $account.samaccountname
            $NewSAM = $change + $User.SamAccountName
            $UPNSuffix = ($User.UserPrincipalName -split "@")[1]
            $NewUPN = $NewSam + '@' + $UPNSuffix
            $NewName = $change + $User.Name

            Try {       
                Set-ADUser $User.ObjectGUID -SamAccountName $NewSAM -UserPrincipalName $NewUPN -DisplayName $NewName `
                    -Replace @{info = "Account disabled and moved on as part of the Active Directory cleanup activity" } `
                    -Clear AdminCount
            }
            Catch {
                Write-Host "Failed to change SAM or UPN of" + $User.SamAccountName
            }

            Try {
                Rename-ADObject $user.ObjectGUID -NewName $NewName
            }
            Catch {
                Write-Host -Message "Failed to rename" + $User.SamAccountName
            }
        } 
    }
}