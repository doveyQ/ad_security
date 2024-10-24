# This script looks for users with SPN associated

[CmdletBinding()]
param(
    [Parameter(Mandatory='True')][string]$DomainName
)

$Global:self = @{
    ID = 42
    UUID = '868c36af-b784-465b-a15c-291bd3c66d47'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000042'
    Name = 'Users with SPN defined'
    ScriptName = 'PrimaryUsersWithSPN'
    Description = 'This indicator provides a way to visually inventory all users accounts that have SPNs defined. Generally SPNs are only defined for "Kerberized" services, so if you see an account with an SPN that should not have one, this could be cause for concern.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'SPNs are generally only defined for service accounts or other services that use Kerberos. If you see SPNs on other accounts, they are worth investigating to determine if they are just an administrative error.'
    ResultMessage = 'Found {0} users with associated SPN.'
    Remediation = 'If possible use Group Managed Service Accounts instead of regular users or ensure that all users that have an SPN are not primary users and considered as service accounts.
      MITRE D3fend based on the reference: audit-user-account-management of Microsoft <a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management" target="_blank"></a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'AESEnabled'; Type = 'Boolean'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ServicePrincipalName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
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

$outputObjects = [System.Collections.ArrayList]@()

try {
    $allUsers = Get-ADUser -Filter * -Properties ServicePrincipalName

    foreach ($user in $allUsers) {
        if (![string]::IsNullOrWhiteSpace($user.ServicePrincipalName)) {
            $spns = $user.ServicePrincipalName.Split(',')
            $outputObject = [PSCustomObject]@{
                DistinguishedName = $user.DistinguishedName
                SamAccountName = $user.SamAccountName
                ServicePrincipalName = $spns -join ', '
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
            Status = 'Passed'
            ResultMessage = "No users with associated SPN were found."
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
