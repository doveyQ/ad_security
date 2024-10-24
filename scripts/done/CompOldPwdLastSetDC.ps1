# This script looks for Domain Controllers that haven't changed their password in a while

[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 61
    UUID = '113f7039-879b-4093-a42b-dce6b47b313c'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000061'
    Name = 'Computer Accounts in Privileged Groups'
    ScriptName = 'ComputersInPrivilegedGroup'
    Description = 'This indicator looks for computer accounts that are members of built-in privileged groups.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'If a computer account is a member of a domain privileged group, then anyone that compromises that computer account (i.e. becomes administrator) can act as a member of that group. Generally speaking, there is little reason for normal computer accounts to be part of privileged groups.'
    ResultMessage = 'Found {0} instances of computer membership within a privileged group.'
    Remediation = 'Check why those computer objects are members of privileged groups.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'ComputerDistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GroupDistinguishedName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()
try {
    $thresholdDate = (Get-Date).AddDays(-45)
    $dclist = Get-ADDomainController -Filter { isGlobalCatalog -eq $true }
    $outputObjects = @()

    foreach ($dc in $dclist) {
        $lastset = Get-ADComputer -Identity $dc.Name -Properties PasswordLastSet

        if ($lastset.PasswordLastSet -lt $thresholdDate) {
            $daysSinceLastSet = (New-TimeSpan -Start $lastset.PasswordLastSet -End (Get-Date)).Days
            
            $outputObjects += [PSCustomObject]@{
                DaysSinceLastSet = $daysSinceLastSet
                DistinguishedName = $lastset.DistinguishedName
                PasswordLastSet   = $lastset.PasswordLastSet
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status        = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count, 45
            ResultObjects = $outputObjects
            Remediation   = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status        = 'Passed'
            ResultMessage = "No Domain Controllers found with passwords unchanged for 45 days."
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}
return $res
