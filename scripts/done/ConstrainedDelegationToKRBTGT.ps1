[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 99
    UUID = 'cfe3bfa1-f28e-4017-8e94-044bd6b914e3'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000099'
    Name = 'Accounts with Constrained Delegation configured to krbtgt'
    ScriptName = 'ConstrainedDelegationToKRBTGT'
    Description = '<p>This indicator checks for accounts that have constrained delegation configured to the KRBTGT account.</p>'
    Weight = 9
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 9
    LikelihoodOfCompromise = '<p>In Active Directory it is possible to create a Kerberos delegation to the KRBTGT account. This type of delegation to a user or computer would allow that principal to generate a ticket granting service (TGS) request to the KRBTGT account as any user.</p><br /><p>An attacker may attempt to compromise any account that has a delegation to the KRBTGT account. This particular type of configuration allows for an attack similar to a Golden Ticket attack.</p>'
    ResultMessage = 'Found {0} account(s) with Constrained Delegation configured to the krbtgt service.'
    Remediation = '<p>It is recommended to not allow constrained delegation to the KRBTGT account.</p><br /><p>This type of delegation to a user or computer would allow that principal to generate a ticket granting service (TGS) request to the KRBTGT account as any user.</p><br /><p>An attacker may attempt to compromise any account that has a delegation to the KRBTGT account. This particular type of configuration allows for an attack similar to a Golden Ticket attack.</p><br /><p>The delegations identified should be removed.</p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Domain Account Monitoring') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_delegation_a2d2') }
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
$foundAccounts = $false

try {
    $delegatedAccounts = Get-ADObject -Filter { msDS-AllowedToDelegateTo -like '*' } -Properties msDS-AllowedToDelegateTo |
        Select-Object DistinguishedName, msDS-AllowedToDelegateTo

    foreach ($acc in $delegatedAccounts) {
        if ($acc.'msDS-AllowedToDelegateTo' -like "*krbtgt*" -and ($acc.UserAccountControl -band 0x200000) -ne 0) {
            $outputObjects += [PSCustomObject]@{
                DistinguishedName = $acc.DistinguishedName
                DomainName = $DomainName
                EventTimestamp = (Get-Date)
            }
            $foundAccounts = $true
        }
    }

    if ($foundAccounts) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No accounts with Constrained Delegation configured to krbtgt service were found."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
