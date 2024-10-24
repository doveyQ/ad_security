# This script looks for user accounts with a recent pwdLastSet change without a corresponding password replication

[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")][string]$DomainName
)

$Global:self = @{
    ID = 98
    UUID = 'f6c64dcf-bbcc-453e-a122-a81e998fe1af'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000098'
    Name = 'Abnormal Password Refresh'
    ScriptName = 'AbnormalPasswordRefresh'
    Description = 'This indicator looks for user accounts with a recent pwdLastSet change without a corresponding password replication.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = 'If an administrator marks the option "User must change password at next logon" and then clears (i.e. unchecks) the option later, the pwdLastSet is updated without the password actually being changed. This could be an administrative error or an attempt to bypass the organization''s password policy.'
    ResultMessage = 'Found {0} user(s) with a mismatch between pwdLastSet and unicodepwd.  This could indicate an attempt to bypass the organization''s password policy.'
    Remediation = 'Ensure that users change their password at least once every 6 months.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Persistence') }
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
$res = [PSCustomObject]@{
    Status         = 'Not Executed'
    ResultMessage  = ''
    Remediation    = ''
    Identity       = ''
}

try {
    $users = Get-ADUser -Filter * -Property SamAccountName, pwdLastSet

    foreach ($user in $users) {
        $replicationMetadata = Get-ADReplicationPartnerMetadata -Target $DomainName -Scope Domain |
            Where-Object { $_.Name -eq $user.SamAccountName }
        
        $lastReplicationTime = $replicationMetadata.LastReplicationTime

        if ($user.pwdLastSet -gt $lastReplicationTime) {
            $outputObject = [PSCustomObject]@{
                SamAccountName       = $user.SamAccountName
                PwdLastSet           = $user.pwdLastSet
                LastReplicationTime  = $lastReplicationTime
            }
            [void]$outputObjects.Add($outputObject)
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status         = "Passed"
            ResultMessage  = "No user accounts with a mismatch between pwdLastSet and password replication."
        }
    }

} catch {
    $res = [PSCustomObject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
