[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 68
    UUID = '4eab7c02-aae3-4b4c-ba3b-d08977ce7c18'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000068'
    Name = 'Trust accounts with old passwords'
    ScriptName = 'TrustPwdLastSet'
    Description = 'This indicator looks for trust accounts whose password has not changed within the last year. This could mean that a trust relationship was removed but its corresponding trust account wasn''t cleaned up.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'Trust accounts facilitate authentication across trusts. As such they should be protected just like privileged user accounts. Normally trust account passwords are rotated automatically so a trust account without a recent password change could indicate an orphaned trust account.'
    ResultMessage = 'Found {0} trusted domain objects whose password has not changed in the last {1} days.'
    Remediation = 'Old passwords on trust accounts usually indicate the trust is no longer valid. Verify that the trust account is no longer needed and then delete it.<br><br>MITRE D3fend based on the reference: <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf" target="_blank">NIST.SP.800-63-3</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LastChanged'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'PasswordLastSet'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'DaysSinceLastSet'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Initial Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_trusts_accounts') }
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
    $trusts = Get-ADTrust -Filter * -Server $DomainName
    $daysToRemove = 365 

    foreach ($trust in $trusts) {
        $account = Get-ADTrust -Identity $trust.Name -Server $DomainName
        
        $passwordLastSet = [datetime]::FromFileTime($account.PwdLastSet)
        $daysSinceLastSet = ((Get-Date) - $passwordLastSet).Days

        if ($daysSinceLastSet -gt $daysToRemove) {
            $outputObjects += [PSCustomObject]@{
                DistinguishedName = $account.DistinguishedName
                PwdLastSet = $passwordLastSet
                DaysSinceLastChange = $daysSinceLastSet
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status = "Failed"
            ResultMessage = $self.ResultMessage -f $outputObjects.Count, $daysToRemove
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = "Passed"
            ResultMessage = "No trust accounts with outdated passwords found."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res
