    <#
    .SYNOPSIS
    Remove user accounts from all security groups
    .DESCRIPTION
    Author: Daniel Classon and Vladimir Mutić
    Version 1.1

    This script will take list of users from the CSV and remove them from all groups that they are member of.
    .PARAMETER CSV (MANDATORY)
    Specify the full source to the CSV file i.e c:\temp\members.csv
    CSV need to have NAME column defined
    .EXAMPLE
    .\deprivilege_users.ps1 -CSV c:\temp\members.csv

    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>

[CmdletBinding()]

param(
    [Parameter(Mandatory=$True, Helpmessage="Specify full path to CSV (i.e c:\temp\members.csv")][string]$CSV 
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

    foreach($Object in $Objects){
        try{
            Get-ADUser -Identity $Object.samaccountName -Properties MemberOf | ForEach-Object {
                $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
                Write-Host "Deprivileging " $Object.samaccountName
              }
            
        }
        catch{
        }

    }

}
