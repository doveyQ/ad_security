[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 67
    UUID = '755d0eba-b8dc-4216-a9d4-44ab43bfb7b5'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000067'
    Name = 'Privileged accounts with a password that never expires'
    ScriptName = 'UsersPwdNeverExpiresAdmin'
    Description = 'This indicator identifies privileged accounts (adminCount attribute set to 1) where the Password Never Expires flag is set.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '3d'
    Impact = 6
    LikelihoodOfCompromise = 'User accounts whose passwords never expire are ripe targets for brute force password guessing. If these users are also administrative or privileged accounts, this makes them even more of a target.'
    ResultMessage = 'Found {0} users with password never expires.'
    Remediation = 'Enforce that users with privileged access must change their passwords on a regular basis and ensure that those passwords are complex and ideally require MFA to authenticate.<br><br>MITRE D3fend based on the reference: <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf" target="_blank">NIST.SP.800-63-3</a>'
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
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_dont_expire_priv') }
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

try {
    $domainDN = ($DomainName -split '\.') | ForEach-Object { "DC=$_" }
    $domainDN = [string]::Join(',', $domainDN)

    $users = Get-ADUser -Filter { (PasswordNeverExpires -eq $true) -and (adminCount -eq 1) } `
                        -SearchBase $domainDN -Properties SamAccountName, PasswordLastSet, ServicePrincipalName
    
    if ($users) {
        foreach ($user in $users) {
            $pwdLastSet = if ($user.PasswordLastSet) { [datetime]$user.PasswordLastSet } else { "Never" }

            $outputObjects += [PSCustomObject]@{
                DistinguishedName      = $user.DistinguishedName
                SamAccountName         = $user.SamAccountName
                PasswordLastSet        = $pwdLastSet
                ServicePrincipalName   = ($user.ServicePrincipalName -join "; ")
            }
        }

        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No users with password never expires found."
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ErrorMessage = $_.Exception.Message
    }
}

return $res
