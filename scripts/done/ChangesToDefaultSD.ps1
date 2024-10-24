[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 47
    UUID = '8c2e4eda-216e-47c5-89ea-a45a870f782b'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000047'
    Name = 'Changes to default security descriptor schema in the last 90 days'
    ScriptName = 'ChangesToDefaultSD'
    Description = 'This indicator detects changes made to the default security descriptor schema in the last 90 days. If an attacker gets access to the schema instance in a given forest, they can make changes to the defaultSecurityDescriptor attribute on any AD object class. These changes would then propagate as new default Access Control Lists (ACLs) on any newly created object in AD, potentially weakening AD security posture.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Changes to the default security descriptor are not common. An admin should know that the change was made and be able to articulate the reason for the change. If the change was not intentional, the likelihood of compromise is very high. The chances of compromise are lower if the change hardens the setting instead of weakening it.'
    ResultMessage = 'Found {0} objects whose default security descriptor has changed in the last {1} days.'
    Remediation = 'Ensure that the changes to the SD schema are appropriate and valid, else investigate the cause and source of the changes.<br><br>MITRE D3fend based on the reference: <a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management" target="_blank">audit-user-account-management of Microsoft</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Attribute'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Domain Account Monitoring') }
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
$daysToRemove = 90
$startFilter = (Get-Date).AddDays(-$daysToRemove)

try {
  
    $schemaRoot = (Get-ADRootDSE).schemaNamingContext
    $forestCreationDateTime = (Get-ADObject -Filter {ObjectClass -eq 'classSchema'} -SearchBase $schemaRoot -Properties whenCreated | Select-Object -First 1).whenCreated

    if ($startFilter -lt $forestCreationDateTime) {
        $startFilter = $forestCreationDateTime
    }

    $schemaChanges = Get-ADObject -Filter {(whenChanged -ge $startFilter) -and (ObjectClass -eq 'classSchema')} `
        -SearchBase $schemaRoot `
        -Properties defaultSecurityDescriptor, whenChanged

    foreach ($result in $schemaChanges) {
        if ($result.defaultSecurityDescriptor) {
            $outputObject = [PSCustomObject]@{
                DistinguishedName = $result.DistinguishedName
                Attribute = 'defaultSecurityDescriptor'
                EventTimestamp = $result.whenChanged
            }
            $outputObjects.Add($outputObject)
        }
    }
    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count, $daysToRemove
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No changes to default security descriptor in the last $daysToRemove days."
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
