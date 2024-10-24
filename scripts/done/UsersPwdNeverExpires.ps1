[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 29
    UUID = '3653043f-2790-4255-a625-3359e6dc8ef6'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000029'
    Name = 'Users with Password Never Expires flag set'
    ScriptName = 'UsersPwdNeverExpires'
    Description = 'This indicator identifies user accounts where the Password Never Expires flag is set. These accounts can be targets for brute force password attacks, given that their passwords may not be strong when they were set. These accounts also tend to be service accounts with privileged access to applications and services, including Kerberos-based services.'
    Weight = 1
    Severity = 'Informational'
    Schedule = '3d'
    Impact = 1
    LikelihoodOfCompromise = 'Passwords that never expire may be weak and easier to crack. These credentials can provide attackers opportunities for moving laterally or escalating privileges.'
    ResultMessage = 'Found {0} users with password never expires.'
    Remediation = 'Move any user accounts away from Password Never Expires by having a good password rotation scheme and ensure any accounts that require this flag have the least privileges required. If this is a service account, considering using Group Managed Service Accounts (gMSA).<br><br>MITRE D3fend based on the reference: <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf" target="_blank">NIST.SP.800-63-3</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PasswordLastSet'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ServicePrincipalName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_dont_expire') }
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
$foundUsers = $false

try {
    $domainDN = (Get-ADDomain -Identity $DomainName).DistinguishedName

    $users = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordLastSet, ServicePrincipalNames -SearchBase $domainDN -ErrorAction Stop

    foreach ($user in $users) {
        $pwdLastSet = if ($user.PasswordLastSet) {
            $user.PasswordLastSet.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        } else {
            "Never"
        }

        $outputObjects += [PSCustomObject]@{
            DistinguishedName = $user.DistinguishedName
            SamAccountName = $user.SamAccountName
            PasswordLastSet = $pwdLastSet
        }

        $foundUsers = $true
    }

    if ($foundUsers) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No users found with the password never expires flag set."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res