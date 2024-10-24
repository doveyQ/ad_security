[CmdletBinding()]
param(
    [Parameter(Mandatory="True")][string]$DomainName
)

$Global:self = @{
    ID = 151
    UUID = 'f8af8921-8901-466e-ba91-df970a56cc21'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000151'
    Name = 'RC4 or DES encryption type are supported by Domain Controllers'
    ScriptName = 'RC4EnabledOnDC'
    Description = 'This indicator checks if RC4 or DES encryption is supported by Domain Controllers'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'RC4 and DES are considered an insecure form of encryption, susceptible to various cryptographic attacks. Multiple vulnerabilities in the RC4 and DES algorithms allow MitM and deciphering attacks. See <a href="https://nvd.nist.gov/vuln/detail/CVE-2013-2566" target="_blank">CVE-2013-2566</a> and <a href="https://nvd.nist.gov/vuln/detail/CVE-2015-2808" target="_blank">CVE-2015-2808</a>.'
    ResultMessage = 'Found {0} Domain Controllers that support RC4 or DES encryption'
    Remediation = 'It is best practice to disable support for RC4 and DES on domain controllers. Proceed with caution, as this can cause clients that request RC4 encrypted kerberos tickets by default to fail.
        Disable it by adding the group policy Network security: Configure encryption types allowed for Kerberos and select only AES-128, AES-256 encryption types, to a GPO that affects the Domain Controllers container.
        The group policy path is Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SupportedEncryptionTypes'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Credential Access') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_dc_crypto', 'vuln4_dc_crypto') }
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
$failedUserCount = 0

try {
    $desUsers = Get-ADUser -Filter 'UserAccountControl -band 0x200000' -Properties UserAccountControl, DistinguishedName

    foreach ($user in $desUsers) {
        try {
            $outputObjects += [PSCustomObject]@{
                DistinguishedName = $user.DistinguishedName
                SupportedEncryptionTypes = "DES encryption is supported"
            }
            $failedUserCount++
        } catch {
            Write-Host "Failed to process user: $($user.SamAccountName)"
        }
    }

    if ($failedUserCount -gt 0) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No user accounts found with RC4 or DES encryption enabled."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res