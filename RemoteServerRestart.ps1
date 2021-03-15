    <#
    .SYNOPSIS
    Remotely restarts servers in organized way. 

    Author: Vladimir Mutić
    Version 0.9

    .DESCRIPTION
    Servers should be organized in Restart Groups and script will restart group by group with possibilty to verify status befor proceeding with next group.
    IMPORTANT - CSV file must have CI (computer name) and SEQUENCE (restart group) columns. 
    .PARAMETER CSV (MANDATORY)
    Specify the full source to the CSV file i.e c:\temp\members.csv
    .EXAMPLE
    .\RemoteServerRestart.ps1 -CSV c:\temp\servers.csv
    .PARAMETER UG (OPTIONAL)
    If you specify parameter UG only servers from stated group will be restarted
    .EXAMPLE
    .\RemoteServerRestart.ps1 -CSV c:\temp\servers.csv -UG "DC1"

    .NOTES
    Restart-Computer only work on computers running Windows and requires WinRM and WMI to shutdown a system, including the local system.
    Restart-Computer uses the Win32Shutdown method of the Windows Management Instrumentation (WMI) Win32_OperatingSystem class.

    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>

param(
    [Parameter(Mandatory=$True, Helpmessage="Specify full path to CSV (i.e c:\temp\members.csv")][string]$CSV,
    [Parameter(Mandatory=$False, Helpmessage="Specify update goup name")][string]$UG,
    [Parameter(Mandatory=$False, Helpmessage="Ping test only..")][switch]$Test
    )

# $creds = get-credential

$serverGrp = Import-Csv $CSV | Group-Object -Property Sequence | Sort-Object -Property Name

if ($UG) {
    $serverGrp = $serverGrp | where-object { $_.name -eq $UG}
}

$domain = Get-ADDomain

$hostname = $env:computername

$DomainDNS = (Get-ADDomain -Identity $Domain).DNSRoot

$script:outputfile = "$DomainDNS-reboot-report.txt"

if (test-path "\.$DomainDNS-reboot-report.txt") {
    Clear-Content -Path $outputfile
}

$serverGrp | ForEach-Object {
    $phase = $PSItem.Name
    Write-Verbose "Working on phase $phase, $($PSItem.Count) items"
    Add-Content -Value "Working on phase $phase" -Path $outputfile
    Write-Host "Phase $phase" -ForegroundColor Yellow

    if (!$test) {
        foreach ($server in (($PSItem.Group).CI))
        {
            if ($Server -notlike $hostname) {
                write-Host "Restarting server $server"
                Add-Content -Value "Restarting server $server" -Path $outputfile
                Restart-Computer $Server -WsmanAuthentication Kerberos -Force
            } else {
                write-Host "Starting reboot for $server.. You maybe think you do, but you really don't want to reboot local server :)"
            }
        }
        
        Write-Host "Let's wait for 15 seconds before we proceed.."
        Start-Sleep -Seconds 15
        Write-Host "OK, let's see what happened.."
    }

    $c = "r"
    
    while ($c -eq "r") {
        foreach ($Server in (($PSItem.Group).CI))
        {
            $osInfo = Get-CimInstance -ComputerName $server -ClassName Win32_OperatingSystem
            if ($osInfo.ProductType -eq "2") {$isDC = $True} else {$isDC = $False}
            # Test-Connection $Server
            if ($isDC -eq $True) {
                if (get-item \\$server\sysvol -ea SilentlyContinue) {
                    $lastbootuptime = (Get-CimInstance -ComputerName $Server -ClassName win32_operatingsystem -ErrorAction ignore | Select-Object lastbootuptime).lastbootuptime
                    "Computer $Server is a DC and ADDS is up and running (SYSVOL IS reachable) at $(Get-Date), and last bootup time is $lastbootuptime" | Tee-Object -FilePath $outputfile -Append
                    # "Computer $Server verified to be responding to ping at $(Get-Date), and last bootup tmime is $lastbootuptime" | Add-Content -Path $outputfile 
                }
                else {
                    write-host "Computer $Server is a DC but ADDS is unresponsive (SYSVOL is NOT reachable) at $(Get-Date)"
                    "ADDS on $Server is unresponsive at $(Get-Date)" | Add-Content -Path $outputfile 
                }
            }
            else {
                if (Test-Connection $Server -quiet -Count 2 -Delay 1) {
                    $lastbootuptime = (Get-CimInstance -ComputerName $Server -ClassName win32_operatingsystem -ErrorAction ignore | Select-Object lastbootuptime).lastbootuptime
                    "Computer $Server is verified to be responding to ping at $(Get-Date), and last bootup time is $lastbootuptime" | Tee-Object -FilePath $outputfile -Append
                    # "Computer $Server verified to be responding to ping at $(Get-Date), and last bootup tmime is $lastbootuptime" | Add-Content -Path $outputfile 
                }
                else {
                    write-host "Computer $Server is unresponsive to ping at $(Get-Date)"
                    "Computer $Server is unresponsive to ping at $(Get-Date)" | Add-Content -Path $outputfile 
                }
            }
        }

        $c = Read-Host "If you want to redo test, enter (r)"
    }

}