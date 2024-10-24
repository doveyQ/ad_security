#Built-in Administrator account used within the last week
#This script checks each domain to determine if the administrator account on the domain has been logged into in the last 14 days or more - calculated by syncinterval
# Check Built-in Administrator account usage in the last 14 days
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 28
    UUID = '2c2b46b6-3bce-451c-bbc8-7c7652fecbf0'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000028'
    Name = 'Built-in domain Administrator account used within the last two weeks'
    ScriptName = 'AdminUsedRecently'
    Description = 'The Domain Administrator account should only be used for initial build activities and, when necessary, disaster recovery. This indicator checks to see if the lastLogonTimestamp for the built-in Domain Administrator account has been updated within the last two weeks. If so, it could indicate that the user has been compromised.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = 'If best practices are followed and domain Admin is not used, this would indicate a compromise. Ensure any logins to the built-in Domain Administrator account are legitimate and accounted for. If not accounted for, a breach is likely and should be investigated.'
    ResultMessage = 'Found {0} domains in which the built-in administrator was used recently.'
    Remediation = 'Ensure that the built-in domain Administrator account is not used regularly and has a complex password known only to highly privileged admins.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Credential Compromise Scope Analysis', 'Harden - Strong Password Policy') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


$outputObjects = @()

try {
    $startDate = (Get-Date).AddDays(-14)

    $adminSID = (Get-ADUser -Identity "Administrator" -Server $DomainName).SID.Value
    $adminAccount = Get-ADUser -Filter "objectSid -eq '$adminSID'" -Properties lastLogonTimestamp -Server $DomainName

    if ($adminAccount.lastLogonTimestamp -and [datetime]::FromFileTime($adminAccount.lastLogonTimestamp) -ge $startDate) {
        $outputObject = New-Object PSObject -Property @{
            DistinguishedName = $adminAccount.DistinguishedName
            EventTimestamp = [datetime]::FromFileTime($adminAccount.lastLogonTimestamp)
        }
        $outputObjects += $outputObject
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
            ResultMessage = "No recent logins detected for the built-in Administrator account."
        }

    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
