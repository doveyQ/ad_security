# This script checks if the built-in Administrator password has not been changed in the last 180 days

[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")][string]$DomainName
)

$Global:self = @{
    ID = 49
    UUID = '82901792-3b6e-4b3f-94d7-64d4743273fb'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000049'
    Name = 'Built-in domain Administrator account with old password (180 days)'
    ScriptName = 'AdminPWNotChanged'
    Description = '<p>This indicator checks if the password of the built-in Domain Administrator account is older than 180 days.</p>'
    Weight = 4
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 4
    LikelihoodOfCompromise = '<p>The built-in Domain Administrator account is a well-known SID that is easily discoverable, regardless of attempts to obfuscate the account, such as renaming it.</p><br /><p>It is recommended that this account is not used for administration of Active Directory, but due to lack of use, this account in many organizations also goes unmonitored. Attackers may target this account for brute force password attacks.</p><h3>References</h3><p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers" target="_blank">Security identifiers | Microsoft Learn</a></p>'
    ResultMessage = 'Found {0} domains whose administrator''s password has not changed in the last {1} days.'
    Remediation = '<p>It is recommended to rotate the password on the built-in Administrator account every 180 days, or whenever there is the possibility that the password has become known or compromised.</p><br /><p>The built-in Domain Administrator account is a well-known SID that is easily discoverable, regardless of attempts to obfuscate the account, such as renaming it.</p><h3>References</h3><p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers" target="_blank">Security identifiers | Microsoft Learn</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LastChanged'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'DaysSinceLastSet'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'PasswordLastSet'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_password_change_priv') }
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
$res = [PSCustomObject]@{
    Status         = 'Not Executed'
    ResultMessage  = ''
    Remediation    = ''
    Identity       = ''
}

try {
    $daysToRemove = 180
    $lastChangeThreshold = (Get-Date).AddDays(-$daysToRemove)

    $adminUser = Get-ADUser -Identity "Administrator" -Server $DomainName -Properties PasswordLastSet

    if ($adminUser.PasswordLastSet -lt $lastChangeThreshold) {
        $outputObject = [PSCustomObject]@{
            SamAccountName       = $adminUser.SamAccountName
            PasswordLastSet      = $adminUser.PasswordLastSet
            DaysSinceLastChange  = ((Get-Date) - $adminUser.PasswordLastSet).Days
        }
        [void]$outputObjects.Add($outputObject)


        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status     = "Passed"
            ResultMessage  = "The built-in Administrator account's password has been changed within the last $daysToRemove days."
            Remediation     = "No action required."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res
