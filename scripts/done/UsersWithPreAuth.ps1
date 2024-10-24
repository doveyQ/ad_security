[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    [string]$DomainName
)

$Global:self = @{
    ID = 27
    UUID = 'ad0f14a9-580c-4709-b8d2-c1be16b22a3e'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000027'
    Name = 'Users with Kerberos pre-authentication disabled'
    ScriptName = 'UsersWithPreAuth'
    Description = 'This indicator identifies users with Kerberos pre-authentication disabled, which exposes them to potential ASREP-Roasting attacks, such as ''Kerberoasting''. please refer to this resource: <a href="https://social.technet.microsoft.com/wiki/contents/articles/23559.kerberos-pre-authentication-why-it-should-not-be-disabled.aspx" target="_blank">https://social.technet.microsoft.com/wiki/contents/articles/23559.kerberos-pre-authentication-why-it-should-not-be-disabled.aspx</a>.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '3d'
    Impact = 5
    LikelihoodOfCompromise = 'If an account has Kerberos pre-authentication disabled, it makes it easier for attackers to send dummy requests to a DC to try and crack its Ticket Granting Ticket (TGT).'
    ResultMessage = 'Found {0} users with pre-authentication disabled.'
    Remediation = 'Ensure that pre-authentication is enabled on all users if possible; if not possible, consider reducing their privileges instead.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_kerberos_properties_preauth_priv', 'vuln2_kerberos_properties_preauth') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

try {
    $users = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Server $DomainName -Properties DistinguishedName, DoesNotRequirePreAuth |
             Select-Object DistinguishedName, SamAccountName, DoesNotRequirePreAuth

    foreach ($user in $users){
        $outputObjects += [PSCustomObject]@{
            DistinguishedName = $user.DistinguishedName
            SamAccountName = $user.SamAccountName
            DoesNotRequirePreAuth = $user.DoesNotRequirePreAuth
        }
    }

    if ($users) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = "Passed"
            ResultMessage = "No users with pre-authentication disabled found."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res
