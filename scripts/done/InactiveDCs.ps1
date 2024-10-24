# This indicator looks for Domain Controllers that haven't authenticated to the domain in the last 45 days or more.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 73
    UUID = '1b6df9e8-e5ed-45f7-880c-44b4a9a7d6bd'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000073'
    Name = 'Domain controllers that have not authenticated to the domain for more than 45 days'
    ScriptName = 'InactiveDCs'
    Description = 'Domain controllers must authenticate and change their passwords at least every 30 days. Lack of domain authentication reveals out-of-sync machines. Out-of-sync domain controllers must be either reinstalled or removed. When reinstalling an out-of-sync domain controller, care must be taken not to introduce a new OWNER control path exposing its computer account. To avoid doing so, use of the Djoin utility is advised.'
    Weight = 4
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 4
    LikelihoodOfCompromise = 'Domain controllers that are not active in the domain would likely be out-of-sync with functional DCs and therefore a compromised offline DC may be of little value to an attacker. However, if an attacker could compromise an offline DC and crack credentials or re-connect it to the domain, they may be able to introduce unwanted changes to production AD that could compromise its security.'
    ResultMessage = 'Found {0} Domain Controllers which did not authenticate to the domain in the last {1} days.'
    Remediation = 'Ensure that any DCs that have not been in communication with the domain for more than 30 days are either de-commissioned or re-promoted into the environment to ensure consistency with the production AD.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LastLogonTimeStamp'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Isolate - Execution Isolation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_password_change_inactive_dc') }
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
    $daysToRemove = 45
    $DN = (Get-ADDomain $DomainName).DistinguishedName

    $syncInterval = (Get-ADDomain $DomainName).msDS_LogonTimeSyncInterval.TotalDays
    if ($syncInterval -gt $daysToRemove) {
        $daysToRemove = $syncInterval
    }

    $lastLogonThreshold = (Get-Date).AddDays(-$daysToRemove).ToFileTimeUtc()

    $results = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -and LastLogonTimestamp -le $lastLogonThreshold } -Properties LastLogonTimestamp -SearchBase $DN

    foreach ($result in $results) {
        $lastLogon = if ($result.LastLogonTimestamp) { [datetime]::FromFileTime($result.LastLogonTimestamp) } else { "Never" }
        $outputObject = [PSCustomObject]@{
            DistinguishedName = $result.DistinguishedName
            LastLogonTimestamp = $lastLogon
        } 
        [void]$outputObjects.Add($outputObject)
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
            ResultMessage = "All Domain Controllers have authenticated within the last $daysToRemove days."
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
