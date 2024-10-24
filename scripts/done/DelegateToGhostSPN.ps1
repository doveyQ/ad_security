[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 102
    UUID = 'abc12345-def6-7890-abcd-ef1234567890'
    Version = '1.0.0'
    CategoryID = 6
    ShortName = 'SI000102'
    Name = 'Detect Ghost SPNs with Constrained Delegation'
    ScriptName = 'DetectGhostSPNsWithDelegation'
    Description = '<p>This script checks for ghost SPNs and accounts with constrained delegation configured to them.</p>'
    Weight = 9
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 9
    LikelihoodOfCompromise = '<p>Ghost SPNs can be leveraged for attacks if not properly managed.</p>'
    ResultMessage = 'Found {0} ghost SPN(s) with constrained delegation.'
    Remediation = '<p>Remove or correct ghost SPNs and their associated delegation configurations.</p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ServicePrincipalName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') }
    )
    Products = @()
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = @()

try {
    $spns = Get-ADObject -Filter { servicePrincipalName -like '*' } -Properties servicePrincipalName | 
        Select-Object -ExpandProperty servicePrincipalName

    $delegatedAccounts = Get-ADObject -Filter { msDS-AllowedToDelegateTo -like '*' } -Properties msDS-AllowedToDelegateTo, DistinguishedName

    foreach ($spn in $spns) {
        $hostname = $spn -replace '^[^/]+/', ''  # Remove the service part (e.g., 'HTTP/')
        
        $resolvedIPs = Resolve-DnsName -Name $hostname -ErrorAction SilentlyContinue

        if (-not $resolvedIPs) {
            foreach ($acc in $delegatedAccounts) {
                if ($acc.'msDS-AllowedToDelegateTo' -like "*$spn*") {
                    # Add to output if both conditions are met
                    $outputObjects += [PSCustomObject]@{
                        DistinguishedName = $acc.DistinguishedName
                        ServicePrincipalName = $spn
                        EventTimestamp = (Get-Date)
                    }
                }
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No ghost SPNs with constrained delegation found."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
