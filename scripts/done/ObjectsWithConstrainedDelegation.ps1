[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$DomainName
)

$Global:self = @{
    ID = 57
    UUID = 'b332f034-f6b9-4bc2-8796-6ea044db909f'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000057'
    Name = 'Objects with constrained delegation configured'
    ScriptName = 'ObjectsWithConstrainedDelegation'
    Description = 'This indicator looks for any objects that have values in the msDS-AllowedToDelegateTo attribute (i.e. Constrained Delegation) and does not have the UserAccountControl bit for protocol transition set.'
    Weight = 5
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 5
    LikelihoodOfCompromise = 'Attackers may utilize delegations to move laterally or escalate privileges if they compromise a service that is trusted to delegate. While constrained delegation is less likely to be compromised than unconstrained delegation, knowing all of the accounts within your environment that have this defined and ensuring they have strong passwords is a good thing.'
    ResultMessage = 'Found {0} objects with constrained delegation configured.'
    Remediation = 'Validate that every delegation configured is known and necessary.<br><br>MITRE D3fend based on the reference: <a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management" target="_blank">audit-user-account-management of Microsoft</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'AllowedToDelegateTo'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Lateral Movement', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Domain Account Monitoring') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


$outputObjects = @()

$excludedUACValues = @(512, 532480, 4096, 2080)

try {
    foreach ($domain in $DomainName) {
        $searchParams = @{
            Properties = "msDS-AllowedToDelegateTo", "DistinguishedName", "userAccountControl"
            SearchBase = (Get-ADDomain $domain).DistinguishedName
        }

        $results = Get-ADObject -Filter * @searchParams

        if ($results) {
            foreach ($result in $results) {
                if ($result."msDS-AllowedToDelegateTo" -and (-not $excludedUACValues.Contains($result.UserAccountControl))) {
                    $outputObjects += [PSCustomObject]@{
                        DistinguishedName = $result.DistinguishedName
                        AllowedToDelegateTo = $result."msDS-AllowedToDelegateTo" -join "; "
                        EventTimestamp = (Get-Date)
                    }
                }
            }
        }
    }

    if ($outputObjects) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No objects with constrained delegation configured found."
        }
    }

} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
