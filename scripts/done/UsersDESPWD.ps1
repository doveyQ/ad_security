[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")]
    [string]$DomainName
)

$Global:self = @{
    ID = 75
    UUID = 'ca67406b-a063-4aba-ba61-261be7f9ee96'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000075'
    Name = 'User accounts that use DES encryption'
    ScriptName = 'UsersDESPWD'
    Description = 'This indicator identifies user accounts with the "Use Kerberos DES encryption types for this account" flag set. DES is an older cipher with a 56-bit key length that is relatively easy to crack. The only legitimate use for this flag is to support older systems and environments that only support DES.'
    Weight = 4
    Severity = 'Informational'
    Schedule = '3d'
    Impact = 4
    LikelihoodOfCompromise = 'Attackers can easily crack DES passwords using widely available tools, making these accounts ripe for takeover.'
    ResultMessage = 'Found {0} users with USE_DES_KEY_ONLY flag set on their User Account Control value.'
    Remediation = 'This flag represents a potential weakness in user accounts, which if left in place, could make these accounts targets of takeover attacks. It is strongly advised to move to AES-256 or AES-128. If the flag is required, ensure that these accounts have the least privileges possible and are closely monitored.'
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
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_kerberos_properties_deskey') }
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
    if ($PSCmdlet.MyInvocation.BoundParameters['DomainName']) {
        $DomainName = $DomainName | ForEach-Object { $_.ToLower() }
    }

    $results = Get-ADUser -Filter 'UserAccountControl -band 0x200000' -Server $DomainName -Properties UserAccountControl, DistinguishedName, WhenCreated, WhenChanged, ManagedBy | Select-Object Name, UserAccountControl, DistinguishedName, WhenCreated, WhenChanged, ManagedBy

    if ($results) {
        foreach ($user in $results) {
            $uac = $user.UserAccountControl
            $thisOutput = [PSCustomObject]@{
                DistinguishedName = $user.DistinguishedName
                SamAccountName = $user.Name
                UserAccountControl = "$uac [DES Encryption Enabled]"
                ManagedBy = $user.ManagedBy
                LastChanged = $user.WhenChanged
                Created = $user.WhenCreated
            }
            $outputObjects += $thisOutput
        }
    } else {
        $scoreObjects += 100
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
            ResultMessage = "No users found with USE_DES_KEY_ONLY flag set."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ErrorMessage = $_.Exception.Message
    }
}

return $res
