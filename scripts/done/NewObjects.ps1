# This script looks for AD objects that were created in the last 10 days

[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 44
    UUID = 'b3061191-07e0-468f-b2a0-bbf0485fa900'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000044'
    Name = 'AD objects created within the last 10 days'
    ScriptName = 'NewObjects'
    Description = 'This indicator looks for any AD objects that were created within the last 10 days. It is meant to be used for threat hunting, post-breach investigation or compliance validation.'
    Weight = 1
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 1
    LikelihoodOfCompromise = 'In some environments, object creation happens consistently; however, recently added accounts should be reviewed to ensure they are legitimate.'
    ResultMessage = 'Found {0} objects that were created in the last {1} days.'
    Remediation = 'Ensure that the new objects are known and legitimate.<br><br>MITRE D3fend based on the reference: <a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management" target="_blank">audit-user-account-management of Microsoft</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'ObjectName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ObjectClass'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Lateral Movement', 'Persistence') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Domain Account Monitoring') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $false
    Selected = 1
}


$outputObjects = [System.Collections.ArrayList]@()

$daysToRemove = 10
$startDate = (Get-Date).AddDays(-$daysToRemove)

try {
    $results = Get-ADObject -Filter { whenCreated -ge $startDate } -Properties DistinguishedName, whenCreated, name, objectClass -Server $DomainName

    foreach ($result in $results) {
        $thisOutput = [PSCustomObject][Ordered] @{
            DistinguishedName = $result.DistinguishedName
            ObjectClass = $result.objectClass
            ObjectName = $result.Name
            EventTimestamp = $result.whenCreated
        }
        [void]$outputObjects.Add($thisOutput)
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
            Status = 'Failed'
            ResultMessage = "Found $($outputObjects.Count) objects that were created in the last $daysToRemove days."
        }
    }

}
catch {
    $res = @{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
