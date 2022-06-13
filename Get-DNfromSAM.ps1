    <#
    .SYNOPSIS
    Query users defined in CSV file by SAMAccountName and returns DNs, ready to be used in GetUserInfoDN.ps1
    .DESCRIPTION
    Author: Vladimir Mutić
    Version 1.0

    This script will take list of users (SAM attribute) from the CSV and return users DNs.
    Users from whole forest could be querid at once.
    .PARAMETER CSV (MANDATORY)
    Specify the full source to the CSV file i.e c:\temp\members.csv
    CSV need to have SAM column defined
    .EXAMPLE
    .\Get-DNfromSAM.ps1 -CSV c:\temp\members.csv

    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, Helpmessage="Specify full path to CSV (i.e c:\temp\members.csv)")]
        [string]
        $CSV
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
            try {
                $udn = (Get-ADUser -Identity $Object.SAM).DistinguishedName
                
                $item = New-Object PSObject
                $item | Add-Member -type NoteProperty -Name 'DN' -Value $udn
                                        
                $item | Export-CSV "Tier0_Accs_DN.csv" -NoTypeInformation -Encoding UTF8 -append
    
            }

            catch {
                Write-Host "I was not able to find user" $Object.SAM
            }
        }
    
    }