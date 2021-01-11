<#
.SYNOPSIS
Authors: Vladimir Mutić
Version 0.1

Moves users or computers to Tier 0 OU and join them to appropriate security group

.DESCRIPTION
This script will take a list of users or computers from the CSV and move them to Tier 0 OU and join them to appropriate security group

.PARAMETER CSV (MANDATORY)
Specify the full source to the CSV file i.e c:\temp\members.csv
CSV need to have distinguishedname and samaccountname columns.
.EXAMPLE
.\MakeItTier0.ps1 -CSV c:\temp\users.csv -users (or -computers or -service)

.PARAMETER USERS (SWITCH, Mandatory, ParameterSet)
Set this parameter if you want to make users Tier 0
.EXAMPLE
.\MakeItTier0.ps1 -CSV c:\temp\users.csv -users 

.PARAMETER COMPUTERS (SWITCH, Mandatory, ParameterSet)
Set this parameter if you want to make computers Tier 0
.EXAMPLE
.\MakeItTier0.ps1 -CSV c:\temp\users.csv -computers

.PARAMETER SERVICES (SWITCH, Mandatory, ParameterSet)
Set this parameter if you want to make service accounts Tier 0
.EXAMPLE
.\MakeItTier0.ps1 -CSV c:\temp\users.csv -services


.DISCLAIMER
All scripts and other powershell references are offered AS IS with no warranty.
These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $CSV,
    [Parameter(Mandatory = $true, ParameterSetName="Type1")]
    [switch]
    $users,
    [Parameter(Mandatory = $true, ParameterSetName="Type2")]
    [switch]
    $computers,
    [Parameter(Mandatory = $true, ParameterSetName="Type3")]
    [switch]
    $services
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
    $AccountList = Import-Csv -Path $CSV
    }
    catch {
    Write-Warning "The CSV file was not found"
    break
    }
}

PROCESS {

    $ddn = (Get-ADDomain).DistinguishedName

    $UsersOU = "OU=T0-Accounts,OU=Tier 0,OU=Admin,$ddn"
    $ComputersOU = "OU=T0-Servers,OU=Tier 0,OU=Admin,$ddn"
    $ServicesOU = "OU=T0-Service Accounts,OU=Tier 0,OU=Admin,$ddn"
    $UsersGroup = "Tier0Admins"
    $ComputersGroup = "Tier0Servers"
    $ServicesGroup = "Tier0ServiceAccounts"

    if ($users) {
        if (![adsi]::Exists("LDAP://$UsersOU")) {
            Write-Host "Required OU ($UsersOU) does not exists!"
            break
        }
        try {Get-ADGroup -Identity $UsersGroup >> $null}
        catch {
            Write-Host "Required security group ($UsersGroup) does not exists!"
            break
        }
    }

    if ($computers) {
        if (![adsi]::Exists("LDAP://$ComputersOU")) {
            Write-Host "Required OU ($ComputersOU) does not exists!"
            break
        }
        try {Get-ADGroup -Identity $ComputersGroup >> $null}
        catch {
            Write-Host "Required security group ($ComputersGroup) does not exists!"
            break
        }

    }
    
    if ($services) {
        if (![adsi]::Exists("LDAP://$ServicesOU")) {
            Write-Host "Required OU ($ServicesOU) does not exists!"
            break
        }
        try {Get-ADGroup -Identity $ServicesGroup >> $null}
        catch {
            Write-Host "Required security group ($ServicesGroup) does not exists!"
            break
        }
    }

    if ($users) {
        ForEach ($account in $AccountList) {
            $User = Get-ADUser -Identity $account.distinguishedName
            Add-ADGroupMember $UsersGroup -Members $User
            Move-ADObject -Identity $User -TargetPath $UsersOU
        }

    }

    if ($services) {
        ForEach ($account in $AccountList) {
            $service = Get-ADUser -Identity $account.distinguishedName
            Add-ADGroupMember $ServicesGroup -Members $service
            Move-ADObject -Identity $service -TargetPath $ServicesOU
        }
    }

    if ($computers) {
        ForEach ($account in $AccountList) {
            $computer = Get-ADComputer -Identity $account.distinguishedName
            Add-ADGroupMember $ComputersGroup -Members $computer
            Move-ADObject -Identity $computer -TargetPath $ComputersOU
        }
    }



}