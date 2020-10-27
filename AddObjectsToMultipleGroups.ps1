    <#
    .SYNOPSIS
    Puts Active Directory users or computers to Active Directory groups using a CSV
    .DESCRIPTION
    Author: Daniel Classon and Vladimir Mutić
    Version 1.1

    This script will take the information in the CSV and add the users or computers specified in the Object column and add them to the Group specified in the Group column
    IMPORTANT - Computers must have $ at the end eg. myDC01$
    .PARAMETER CSV (MANDATORY)
    Specify the full source to the CSV file i.e c:\temp\members.csv
    CSV file need to have GROUP and OBJECT column. Computer accounts need to have $ at the end.
    .EXAMPLE
    .\add_objects_to_multiple_groups.ps1 -CSV c:\temp\members.csv
    .PARAMETER CLEAN (OpTIONAL)
    If you specify parameter CLEAN (Switch parameter), script will clean up group so only users stated in CSV file will remain as members.
    .EXAMPLE
    .\add_objects_to_multiple_groups.ps1 -CSV c:\temp\members.csv -clean

    .DISCLAIMER
    All scripts and other powershell references are offered AS IS with no warranty.
    These script and functions are tested in my environment and it is recommended that you test these scripts in a test environment before using in your production environment.
    #>

[CmdletBinding()]

param(
    [Parameter(Mandatory=$True, Helpmessage="Specify full path to CSV (i.e c:\temp\members.csv")][string]$CSV, 
    [Parameter(Mandatory=$False, Helpmessage="Use this switch if you want to remove all object from groups if they are not found in CSV")][Switch]$Clean
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
            Add-ADGroupMember $Object.Group -Members $Object.Object -ErrorAction Stop -Verbose
        }
        catch{
        }

    }

    if ($Clean) {
        $Groups = $Objects | Group-Object -Property Group
        foreach ($Group in $Groups) {
		$grp = $group.group.group | Select-Object -unique
		#write-host ("Grupa")		
		#$grp            
        $validUsers = $Group.group.object | Get-ADUser -ErrorAction Ignore
		$validComputers = $Group.group.object | Get-ADComputer  -ErrorAction Ignore
		#write-host ("Validi")
		#$validUsers
		#$validComputers
        $invalidObjects = Get-ADGroupMember -identity $grp | Where-Object { $validusers.distinguishedName -notcontains $_.distinguishedName -and $validcomputers.distinguishedName -notcontains $_.distinguishedName}
		#write-host ("Invalidi")
		#$invalidObjects
		#$invalidComputers
        if ($invalidObjects -ne $null) {Remove-ADGroupMember $grp $invalidObjects}
        }
    }
}
END {
 
}