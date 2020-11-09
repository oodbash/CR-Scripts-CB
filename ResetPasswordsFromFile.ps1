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

Add-Type -AssemblyName 'System.Web'

$length = 10
$nonAlphaChars = 1


$item = New-Object PSObject

    $myarray = @()

    $Domain = get-addomain
    $DomainDNS = $Domain.DNSRoot
        
    # $DisableAcc = Read-Host "Do you want also to disable these account? (answer with y or n)"

    $allAccount = Import-Csv $CSV

    foreach ($account in $allAccount)
        {

            $accountidentity = Get-ADUser -Identity $account.distinguishedname -server $DomainDNS
            if($accountidentity.name -eq "DefaultAccount" -or $accountidentity.name -eq "Guest" -or $accountidentity.name -eq "krbtgt" -or $accountidentity.Name -like 'krbtgt*')
            {
                write-host "Skipping out" $accountidentity.name 
            }
            else
            {

                $randomPWD = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
                
                $SecPaswd = ConvertTo-SecureString –String $randomPWD –AsPlainText –Force

                Set-ADAccountPassword -Reset -NewPassword $SecPaswd –Identity $accountidentity -server $DomainDNS

                $item = New-Object PSObject
                if ($ShowPass) {
                    $item | Add-Member -type NoteProperty -Name 'Password' -Value $randomPWD
                }
                $item | Add-Member -type NoteProperty -Name 'AccountName' -Value $accountidentity.name
                $item | Add-Member -type NoteProperty -Name 'DistinguishedName' -Value $accountidentity.DistinguishedName
                $item | Add-Member -type NoteProperty -Name 'SamAccountName' -Value $accountidentity.SamAccountName
                $item | Add-Member -type NoteProperty -Name 'Status' -Value $accountidentity.Enabled

                Set-ADAccountPassword -Reset -NewPassword $SecPaswd –Identity $accountidentity -server $DomainDNS

                <#
                if ($DisableAcc -eq "y") {
                    Set-ADUser -identity $accountidentity.distinguishedname -server $DomainDNS -Enabled:$False
                }
                #>

                $myarray += $item
            }
        }

        $myarray| Export-CSV "New_Passwords.csv" -NoTypeInformation -Encoding UTF8
    #}