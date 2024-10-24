[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 157
    UUID = '790e1c72-5786-4907-83cd-9f310db70f1b'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000157'
    Name = 'Certificate templates that allow requesters to specify a subjectAltName'
    ScriptName = 'CertificateTemplatesWithSANAllowed'
    Description = 'This indicator checks if certificate templates are enabling requesters to specify a subjectAltName in the CSR.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'When certificate templates allow requesters to specify a subjectAltName in the CSR, the result is that they can request a certificate as anyone. For example, a domain admin. When that is combined with an authentication EKU present in the certificate template it can become extremely dangerous.'
    ResultMessage = 'Found {0} certificate templates that allow SAN'
    Remediation = 'Ensure that when a SAN is allowed on a certificate template it is absolutely required on the template, so that the certificate must specify a subjectAltName. If not absolutely required, it should be disabled. This configuration can be viewed under the &quot;Supply in request&quot; option in the &quot;Subject Name&quot; tab in certtmpl.msc. When an authentication EKU is also present on the certificate template this becomes very dangerous and action should be taken to disable SAN on it.<br><br>MITRE D3fend based on the reference: <a href="https://www.nccoe.nist.gov/sites/default/files/library/sp1800/tls-serv-cert-mgt-nist-sp1800-16b-final.pdf" target="_blank">NIST-SP1800-16B</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'CertificateCanBeUsedForAuthentication'; Type = 'String'; IsCollection = $false },
        @{ Name = 'CertificateTemplateName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Published'; Type = 'Boolean'; IsCollection = $false },
        @{ Name = 'SANEnabled'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Certificate Analysis') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_adcs_template_auth_enroll_with_name') }
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
$AUTH_EKUS = @("1.3.6.1.5.5.7.3.2","1.3.6.1.5.2.3.4","1.3.6.1.4.1.311.20.2.2","2.5.29.37.0")

try {
    $certificateTemplates = Get-ADObject -Filter 'objectClass -eq "pKICertificateTemplate"' -Properties msPKI-Certificate-Name-Flag, pkIExtendedKeyUsage, DistinguishedName

    $results = $certificateTemplates | Where-Object {
        $_.'msPKI-Certificate-Name-Flag' -eq 1 -and 
        ($_.DistinguishedName -match 'CN=EnrollmentAgentOffline|CN=WebServer|CN=CA|CN=SubCA|CN=IPSECIntermediateOffline|CN=OfflineRouter|CN=CEPEncryption|CN=ExchangeUser|CN=ExchangeUserSignature|CN=CrossCA|CN=CAExchange')
    }

    foreach ($result in $results) {
        $templateEKU = $result.pkIExtendedKeyUsage -join ','
        $canBeUsedForAuthText = "False"

        foreach ($eku in $AUTH_EKUS) {
            if ($templateEKU -like "*$eku*") {
                $canBeUsedForAuthText = "True"
                break
            }
        }

        $thisOutput = [PSCustomObject][Ordered] @{
            DistinguishedName = $result.DistinguishedName
            CertificateTemplateName = $result.Name
            SANEnabled = "Requester can specify a subjectAltName"
            CertificateCanBeUsedForAuthentication = $canBeUsedForAuthText
        }
        [void]$outputObjects.Add($thisOutput)
    }

    if ($outputObjects.Count -gt 0) {
        $res = @{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = @{
            Status = 'Passed'
            ResultMessage = "No certificate templates found that allow the requester to specify a subjectAltName."
        }
    }
} catch {
    $res = @{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
