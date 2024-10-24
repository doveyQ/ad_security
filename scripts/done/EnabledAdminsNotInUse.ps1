# This script looks for enabled admin users that didn't log in for more than 90 days

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 38
    UUID = '750c9233-57b3-430c-af56-1e899e81b202'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000038'
    Name = 'Enabled admin accounts that are inactive'
    ScriptName = 'EnabledAdminsNotInUse'
    Description = 'This indicator looks for admin accounts that are enabled, but have not logged in for the past 90 days. Attackers who can compromise these accounts may be able to operate unnoticed.'
    Weight = 4
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 4
    LikelihoodOfCompromise = 'While the presence of an unused admin account is not automatically a problem, removing these accounts reduces the attack surface of AD.'
    ResultMessage = 'Found {0} enabled users that have not logged in in the last {1} days.'
    Remediation = 'Admin accounts that are not in use should be removed or disabled.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LastLogon'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Evict - Account Locking') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_user_accounts_dormant') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$daysToRemove = 0
$lastLogonThreshold = (Get-Date).AddDays(-$daysToRemove).ToFileTime()
$outputObjects = @()


try {
    $results = Get-ADUser -Filter {
        adminCount -eq 1 -and Enabled -eq $true -and LastLogonTimeStamp -lt $lastLogonThreshold
    } -Property LastLogonTimeStamp, SamAccountName, DistinguishedName -Server $DomainName

    $outputObjects = $results | ForEach-Object {
        [PSCustomObject]@{
            DistinguishedName = $_.DistinguishedName
            LastLogon = [DateTime]::FromFileTime($_.LastLogonTimeStamp).ToUniversalTime()
            SamAccountName = $_.SamAccountName
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
            Status = 'Passed'
            ResultMessage = "No enabled admin users found that haven't logged in in the last $daysToRemove days."
        }
    }

} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
