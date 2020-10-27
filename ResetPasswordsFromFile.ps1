<#
    .NOTES
        Copyright (c) Microsoft Corporation.  All rights reserved.

        Use of this sample source code is subject to the terms of the Microsoft
        license agreement under which you licensed this sample source code. If
        you did not accept the terms of the license agreement, you are not
        authorized to use this sample source code. For the terms of the license,
        please see the license agreement between you and Microsoft or, if applicable,
        see the LICENSE.RTF on your install media or the root of your tools installation.
        THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES.
       
    .AUTHOR
        Dario Brambilla and Vladimir Mutic

    .DESCRIPTION

      This script will take the list of users specified in the CSV (DistinguishedName column). Then, it will reset password for all stated account to some random value. Optionally it will write down that password in log file.

    .PARAMETER
      -showpass (writes down new passwords)

    .EXAMPLE
    .\ReserPasswordsFromFile_v2.ps1 -csv c:\ped\csv\service_accs.csv -showpass (parameter is optional)

    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
#>


param(
    [Parameter(Mandatory=$True, Helpmessage="Specify full path to CSV (i.e c:\temp\members.csv")][string]$CSV,
    [Parameter(Mandatory=$False, Helpmessage="Use 'Yes' if you want to get info about new passwords")][Switch]$ShowPass
)

Import-Module ActiveDirectory

#$Date = Get-Date -Format MM.dd.yyyy

#Get the Domain list
#$DomainList = (Get-ADForest).Domains

#Identify FSMO Owner
#$FSMORoleForest = Get-ADForest | Select-Object DomainNamingMaster,SchemaMaster

#GetForest Properties
#$ForestDomainName = (Get-ADForest).Name
#$ForestMode = (Get-ADForest).ForestMode

$passwordlenght = 24




$item = New-Object PSObject

#Perfrom Action for every domain
# foreach ($Domain in $DomainList) 
#    {

    $myarray = @()
    
    #GetDomain Properties
    #$DomainName = (Get-ADDomain -Identity $Domain).Name 
    #$DomainMode = (Get-ADDomain -Identity $Domain).DomainMode
    #$DomainSID = (Get-ADDomain -Identity $Domain).DomainSID
    $Domain = get-addomain
    $DomainDNS = $Domain.DNSRoot
        
    #Identify FSMO Owner
    #$FSMORoleDomain = Get-ADDomain -Identity $Domain | Select-Object DNSRoot,PDCEmulator,RidMaster,InfrastructureMaster
    
    #Get all account disable
    # $inputFile = Read-Host "Type Filename containing users from $Domain domain with full path (eg. c:\temp\myfile.csv) or if you want to skip this tomain enter SKIP)"
    #if ($inputFile -eq "skip" -or $inputFile -eq "Skip" -or $inputFile -eq "SKIP") {continue}
    #$allAccount = Import-Csv $inputFile
   
    $DisableAcc = Read-Host "Do you want also to disable these account? (answer with y or n)"

    <#
    switch ($DisableAcc) {
        'y' {$Enabled = $false}
        'n' {$Enabled = $true}
    }
    #>


    $allAccount = Import-Csv $CSV

    #$allAccount = Search-ADAccount -AccountDisabled -UsersOnly
    foreach ($account in $allAccount)
        {

            $accountidentity = Get-ADUser -Identity $account.distinguishedname -server $DomainDNS
            if($accountidentity.name -eq "DefaultAccount" -or $accountidentity.name -eq "Guest" -or $accountidentity.name -eq "krbtgt" -or $accountidentity.Name -like 'krbtgt*')
            {
                write-host "Skipping out" $accountidentity.name 
            }
            else
            {

                
                $Chars = [Char[]]"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%/()=?[]{}"
                $randomPWD = ($Chars | Get-Random -Count $passwordlenght) -join ""
                
                $SecPaswd= ConvertTo-SecureString –String $randomPWD –AsPlainText –Force

                Set-ADAccountPassword -Reset -NewPassword $SecPaswd –Identity $accountidentity -server $DomainDNS

                $randomPWD = ($Chars | Get-Random -Count $passwordlenght) -join ""
                
                $SecPaswd= ConvertTo-SecureString –String $randomPWD –AsPlainText –Force

                $item = New-Object PSObject
                if ($ShowPass) {
                    $item | Add-Member -type NoteProperty -Name 'Password' -Value $randomPWD
                }
                $item | Add-Member -type NoteProperty -Name 'AccountName' -Value $accountidentity.name
                $item | Add-Member -type NoteProperty -Name 'DistinguishedName' -Value $accountidentity.DistinguishedName
                $item | Add-Member -type NoteProperty -Name 'SamAccountName' -Value $accountidentity.SamAccountName
                $item | Add-Member -type NoteProperty -Name 'Status' -Value $accountidentity.Enabled

                Set-ADAccountPassword -Reset -NewPassword $SecPaswd –Identity $accountidentity -server $DomainDNS

                if ($DisableAcc -eq "y") {
                    Set-ADUser -identity $accountidentity.distinguishedname -server $DomainDNS -Enabled:$False
                }

                $myarray += $item
            }
        }

        $myarray| Export-CSV "New_Passwords.csv" -NoTypeInformation -Encoding UTF8
    #}