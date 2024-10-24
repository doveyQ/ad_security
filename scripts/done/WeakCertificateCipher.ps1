[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 86
    UUID = '966491f1-e550-48ae-aae5-2fc1b0ae4a60'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000086'
    Name = 'Weak certificate cipher'
    ScriptName = 'WeakCertificateCipher'
    Description = 'This indicator looks for certificates stored in Active Directory with a key size smaller than 2048 bits or that use DSA encryption.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'Weak certificates can be abused by attackers to gain access to systems using certificate authentication.'
    ResultMessage = 'Found {0} certificates with weak configuration.'
    Remediation = 'Problematic certificates need to be revoked and re-issued. Children certificates must also be re-issued. Expired certificates should also be purged from trusted certificate stores. Use RSA or ECDSA for certificate signature, with RSA key length of 2048 or greater.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'KeyLength'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'SignatureAlgorithmOID'; Type = 'String'; IsCollection = $false },
        @{ Name = 'SubjectName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ValidTo'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Certificate-based Authentication') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_certificates_vuln') }
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
$failedCerts = 0

try {
    $domainDN = (Get-ADDomain -Server $DomainName).DistinguishedName
    $searchBase = "CN=Configuration,$domainDN"
    
    $certObjects = Get-ADObject -SearchBase $searchBase -Filter {
        ObjectClass -eq "pKICertificate" -or 
        ObjectClass -eq "certificationAuthority" -or 
        ObjectClass -eq "pKIEnrollmentService" -or 
        ObjectClass -eq "pKICertificateTemplate"
    } -Properties msPKI-Minimal-Key-Size, cACertificate

    # DSA OIDs for signature algorithm checks
    $dsaOids = @("1.2.840.10040.4.1", "1.2.840.10040.4.3")

    foreach ($certObject in $certObjects) {
        if ($certObject.'msPKI-Minimal-Key-Size' -lt 2048) {
            $thisOutput = [PSCustomObject]@{
                SubjectName = $certObject.Name
                KeyLength = $certObject.'msPKI-Minimal-Key-Size'
            }
            [void]$outputObjects.Add($thisOutput)
            $failedCerts++
        }

        # Check for DSA encryption in certificates
        $certificates = $certObject.cACertificate
        foreach ($certBytes in $certificates) {
            try {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @(,$certBytes)
                
                if ($cert.SignatureAlgorithm.Value -in $dsaOids) {
                    $thisOutput = [PSCustomObject]@{
                        SubjectName = $cert.Subject
                        KeyLength = $cert.PublicKey.Key.KeySize
                        SignatureAlgorithmOID = $cert.SignatureAlgorithm.Value
                        ValidTo = $cert.NotAfter
                    }
                    [void]$outputObjects.Add($thisOutput)
                    $failedCerts++
                }
            } catch {
                Write-Warning "Failed to process certificate for object $($certObject.DistinguishedName): $_"
            }
        }
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
            Status = "Passed"
            ResultMessage = "No certificates with weak configuration found."
        }
    }

} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
