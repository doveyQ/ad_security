# This script checks each domain to determine if there are any computer or user accounts with unconstrained delegation configured
[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")][string]$DomainName
)

$Global:self = @{
    ID = 16
    UUID = '5d5d5b9c-5685-4786-b3a4-eb2ab1480a69'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000016'
    Name = 'Computer or user accounts with SPN that have unconstrained delegation'
    ScriptName = 'ComputerUserWithSPNUnconstrainedDelegation'
    Description = 'This indicator looks for computer or user accounts with SPN that are trusted for unconstrained Kerberos delegation. These accounts store users'' Kerberos TGT locally to authenticate to other systems on their behalf. Computers and users trusted with unconstrained delegation are good targets for Kerberos-based attacks.'
    Weight = 4
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 4
    LikelihoodOfCompromise = 'Attackers who control a service or user trusted for unconstrained delegation can dump local credentials and uncover cached TGT. These credentials could belong to users that accessed the service and who may be privileged.'
    ResultMessage = 'Found {0} objects configured with unconstrained Kerberos delegation.'
    Remediation = 'Accounts that require Kerberos delegation should be set to constrain that delegation to the particular service or services that require delegation. Attempts should be made to have Kerberos-enabled accounts not be privileged accounts.<br><br>MITRE D3fend based on the reference: <a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management" target="_blank">audit-user-account-management of Microsoft</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DisplayName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'ServicePrincipalName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'UserAccountControl'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion', 'Lateral Movement') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Domain Account Monitoring') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_delegation_t4d') }
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
    $delegationObjects = Get-ADObject -Filter { (UserAccountControl -band 0x80000) -or (UserAccountControl -band 0x100000) } -Properties UserAccountControl, ServicePrincipalName

    foreach ($obj in $delegationObjects) {
        $object = [PSCustomObject]@{
            DisplayName          = $obj.Name
            DistinguishedName    = $obj.DistinguishedName
            UserAccountControl   = $obj.UserAccountControl
        }
        [void]$outputObjects.Add($object)
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
            ResultMessage  = "No accounts with unconstrained delegation configured."
        }
    }
}
catch {
    $res.Status               = 'Error'
    $res.ResultMessage        = $_.Exception.Message
}

return $res
