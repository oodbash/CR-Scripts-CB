 <#
    .SYNOPSIS
    Creates Active Directory users using a CSV file and puts users in defined OU. The OUs need to be existant prior to creation else the script will not create the objects
    .DESCRIPTION
    Author: Vikram Bedi and Vladimir Mutić
    Version 1.2

    .PARAMETER CSV (MANDATORY)
    Specify the full source to the CSV file i.e c:\temp\new_users.csv
    CSV file need to have following fields
        Firstname
        middleName
        Lastname
        Domain - Name of domain
        UPN - UPN sufix without @
        SAM
        OU - DN of OU
        Password - temporara password
        Description

    .EXAMPLE
    .\BulkADUserCreationToSpecificOU.ps1 -CSV c:\temp\new_users.csv


    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>

param(
    [Parameter(Mandatory=$True, Helpmessage="Specify full path to CSV (i.e c:\temp\members.csv")][string]$CSV
)

#Import the Active Directory Module
Import-module activedirectory 

#Make the System.Web assembly available
Add-Type -AssemblyName 'System.Web'

$length = 10
$nonAlphaChars = 1

#Import the list from the user
$Users = Import-Csv $CSV

$myarray = @()

foreach ($User in $Users)            
{   $Office         
    $Displayname =  $User.SamAccountName          
    $OU = $User.OrganizationalUnit
    $SAM = $User.SamAccountName       
    $UPN = $User.SamAccountName + "@" + $user.UserPrincipalNameSufix      
    $Description = $User.Description            
    #$Password = $User.Password
    $Password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
    $DC = Get-ADDomainController -discover -domain $user.DomainDNSName
    $servername  = $DC.name
    
	#Creation of the account with the requested formatting.
    New-ADUser -Name "$Displayname" -DisplayName "$Displayname" -SamAccountName $SAM -Office "Office" -UserPrincipalName $UPN -Description "$Description" -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -Enabled $true -Path "$OU" -ChangePasswordAtLogon $False –PasswordNeverExpires $false -server $servername            
    
    write-host $Displayname

    $usr = Get-ADUser -Identity $SAM
    #$domain = Get-ADDomain $user.DomainDNSName

    $item = New-Object PSObject
    #$item | Add-Member -type NoteProperty -Name 'DomainName' -Value $domain.Name
    #$item | Add-Member -type NoteProperty -Name 'Name' -Value $usr.Name
    $item | Add-Member -type NoteProperty -Name 'SamAccountName' -Value $usr.SamAccountName
    $item | Add-Member -type NoteProperty -Name 'UserPrincipalName' -Value $usr.UserPrincipalName
    $item | Add-Member -type NoteProperty -Name 'DistinguishedName' -Value $usr.DistinguishedName
    $item | Add-Member -type NoteProperty -Name 'Password' -Value $Password

    $myarray += $item
    
}

$myarray | Export-CSV -path ("New_accounts.csv") -NoTypeInformation -Encoding UTF8

