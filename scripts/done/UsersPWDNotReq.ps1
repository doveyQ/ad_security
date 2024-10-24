[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    [string]$DomainName
)

$Global:self = @{
    ID = 74
    UUID = '32c2a92b-fe99-4e5c-bfbb-7497b759946d'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000074'
    Name = 'User accounts with password not required'
    ScriptName = 'UsersPWDNotReq'
    Description = 'This indicator identifies user accounts where a password is not required.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '3d'
    Impact = 6
    LikelihoodOfCompromise = 'Accounts with weak access controls are often targeted by attackers seeking to move laterally or gain a persistent foothold within the environment.'
    ResultMessage = 'Found {0} users with PASSWD_NOTREQD flag set on their User Account Control value.'
    Remediation = 'This flag represents a potential weakness in user accounts, which if left in place, could make these accounts targets of takeover attacks. If the flag is required, ensure that these accounts have the least privileges possible.<br><br>MITRE D3fend based on the reference: <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf" target="_blank">NIST.SP.800-63-3</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Created'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'LastChanged'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'ManagedBy'; Type = 'String'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'UserAccountControl'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Lateral Movement') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') }
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
$scoreObjects = @()

try {
    $results = Get-ADUser -Filter {(PasswordNotRequired -eq $true) -and (Name -ne "Guest")} -Properties PasswordNotRequired | Select-Object Name, PasswordNotRequired, DistinguishedName

    if ($results) {
        foreach ($user in $results) {
            $uac = $user.PasswordNotRequired 

            $thisOutput = [PSCustomObject][Ordered] @{
                DistinguishedName = $user.DistinguishedName
                SamAccountName = $user.Name
                UserAccountControl = "$uac [Password Not Required]"
            }
            $outputObjects += $thisOutput
        }
    } else {
        $scoreObjects += 100
    }

    if ($outputObjects.Count -gt 0){
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    }
    else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No users with PASSWD_NOTREQD flag set on their User Account Control value found."
        }
    }
} catch {
    $res = [pscustomobject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
