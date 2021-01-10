    <#
    .SYNOPSIS
    Query users defined in CSV file from AD. Idea is to verify Tier 0 users DNs. Results will be used to generate CSVs for PED. This script also returns users group membership in separate CSV.
    .DESCRIPTION
    Author: Vladimir Mutić
    Version 2.0

    This script will take list of users from the CSV return users parameters and group membership from AD.
    .PARAMETER CSV (MANDATORY)
    Specify the full source to the CSV file i.e c:\temp\members.csv
    CSV need to have DN column defined
    .EXAMPLE
    .\GetUserInfoDN.ps1 -CSV c:\temp\members.csv

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
    
    $users_array = @()
    $groups_array = @()

    $DomainDNSName = (Get-ADDomain).dnsroot
    $DomainName = (Get-ADDomain).Name
    $DomainDN = (Get-ADDomain).DistinguishedName
    $Forest = (Get-ADDomain).Forest

    foreach($Object in $Objects){
        try {
            $user = Get-ADUser -Identity $Object.DN
                    
            $item = New-Object PSObject
            $item | Add-Member -type NoteProperty -Name 'ForestName' -Value $Forest
            $item | Add-Member -type NoteProperty -Name 'DomainName' -Value $DomainName
            $item | Add-Member -type NoteProperty -Name 'DomainDNSName' -Value $DomainDNSName
            $item | Add-Member -type NoteProperty -Name 'DomainDN' -Value $DomainDN
            $item | Add-Member -type NoteProperty -Name 'Name' -Value $user.Name
            $item | Add-Member -type NoteProperty -Name 'SamAccountName' -Value $user.SamAccountName
            $item | Add-Member -type NoteProperty -Name 'UserPrincipalName' -Value $user.UserPrincipalName
            $item | Add-Member -type NoteProperty -Name 'DistinguishedName' -Value $user.DistinguishedName
            $item | Add-Member -type NoteProperty -Name 'Enabled' -Value $user.Enabled
            $item | Add-Member -type NoteProperty -Name 'PEDAction' -Value ""
            $item | Add-Member -type NoteProperty -Name 'NewSamAccountName' -Value ""
                                    
            $users_array += $item

            $grps = Get-ADPrincipalGroupMembership -identity $user.samaccountName
            foreach($grp in $grps){
                $item = New-Object PSObject
                $item | Add-Member -type NoteProperty -Name 'DomainDNSName' -Value $DomainDNSName
                $item | Add-Member -type NoteProperty -Name 'User' -Value $user.samaccountName
                $item | Add-Member -type NoteProperty -Name 'Group' -Value $grp.samaccountName
                $item | Add-Member -type NoteProperty -Name 'GroupDN' -Value $grp.distinguishedName

                $groups_array += $item
            }

		}
        catch {
            Write-Host "I was not able to find user" $Object.DN
        }
    }

    $users_array | Export-CSV "Tier0_Accs_$DomainDNSName.csv" -NoTypeInformation -Encoding UTF8
    $groups_array | Export-CSV "Tier0_Grp_Membership_$DomainDNSName.csv" -NoTypeInformation -Encoding UTF8
}