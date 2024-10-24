﻿[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 17
    UUID = '1e43868c-9a46-41e8-8daf-d8bfe57aaef7'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000017'
    Name = 'Kerberos KRBTGT account with old password'
    ScriptName = 'KerberosGoldenTicket'
    Description = '<p>This indicator checks the age of the password on the KRBTGT account.</p>'
    Weight = 4
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 4
    LikelihoodOfCompromise = '<p>The KRBTGT user account is a special user account in Active Directory that is a service account for the Key Distribution Center (KDC).</p><br /><p>If an attacker is able to compromise the KRBTGT account, they will be able to perform golden ticket attacks in Active Directory, which allow the attacker to impersonate any user.</p><br /><p>Beyond rotating the password twice a year, it is recommended that the password is rotated every time someone who had privileged access in Active Directory, such as a Domain Admin, leaves the organization. There are specific steps that are required to successfully rotate the KRBTGT password, please see the reference article from Semperis for further details.</p><h3>References</h3><p><a href="https://www.semperis.com/blog/golden-ticket-attacks-active-directory/" target="_blank">How to Defend Against Golden Ticket Attacks on Active Directory - Semperis</a></p><br /><p><a href="https://www.stigviewer.com/stig/windows_server_2016/2019-01-16/finding/V-91779" target="_blank">The password for the krbtgt account on a domain must be reset at least every 180 days - stigviewer.com</a></p><br /><p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts" target="_blank">Active Directory Accounts | Microsoft Learn</a></p>'
    ResultMessage = 'Found {0} domains whose KRBTGT''s password has not changed in the last {1} days.'
    Remediation = '<p>It is recommended that the KRBTGT account password is rotated as it is over 180 days old.</p><br /><p>Further, it recommended that the KRBTGT account password is rotated anytime someone that had privileged access in Active Directory, such as Domain Admins, leave the company, that the password is rotated.</p><br /><p>There are certain considerations that must be taken into account to ensure a successful rotation of the password. For security purposes the KRBTGT password needs to be reset twice, however, if it is reset before the password has fully replicated across Active Directory you can negatively impact the functionality and availability of Active Directory. Refer to the reference article from Semperis for further details.</p><h3>References</h3><p><a href="https://www.semperis.com/blog/golden-ticket-attacks-active-directory/" target="_blank">How to Defend Against Golden Ticket Attacks on Active Directory - Semperis</a></p><br /><p><a href="https://www.stigviewer.com/stig/windows_server_2016/2019-01-16/finding/V-91779" target="_blank">The password for the krbtgt account on a domain must be reset at least every 180 days - stigviewer.com</a></p><br /><p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts" target="_blank">Active Directory Accounts | Microsoft Learn</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Attribute'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'LastChanged'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_krbtgt') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()

try {
    $daysToRemove = 180
    $thresholdDate = (Get-Date).AddDays(-$daysToRemove)
    $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
    
    if ($krbtgt) {
        $lastChanged = $krbtgt.PasswordLastSet

        if ($lastChanged -lt $thresholdDate) {
            $failedDomainCount++
            $thisOutput = [PSCustomObject]@{
                DistinguishedName = $krbtgt.DistinguishedName
                LastChanged = $lastChanged
            }
            [void]$outputObjects.Add($thisOutput)
        }
    } else {
        throw "The KRBTGT account was not found in the domain."
    }
    
    if ($outputObjects.Count -gt 0){
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = "Passed"
            ResultMessage = "The KRBTGT password is up-to-date."
        }
    }

}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}
return $res
