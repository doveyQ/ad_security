[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 156
    UUID = 'd64cab17-754c-4643-872b-a9113fbb7808'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000156'
    Name = 'Certificate templates with 3 or more insecure configurations'
    ScriptName = 'CertificateTemplatesAreVulnerable'
    Description = 'This indicator checks if certificate templates in the forest have a minimum of three insecure configurations - Manager approval is disabled, No authorized signatures are required, SAN enabled, Authentication EKU present.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'The following configurations of a certificate template can be exploited by adversaries:
        <br>        </br>
      1. Manager approval is disabled - new certificates are automatically approved if the user has the correct enrollment rights.
      <br>        </br>
      2. No authorized signatures are required - CSRs (Certificate Signing Requests) are not signed by any existing authorized certificate.
      <br>        </br>
      3. SAN (Subject Alternative Name) Enabled - Allowing the creator of a certificate template to specify the subjectAltName in the CSR, thus they can make the request as anyone, even a domain admin.
      <br>        </br>
      4. Authentication EKU (Enhanced Key Usage) present - if present, the EKU created from the certificate template will allow the user to authenticate with it.'
    ResultMessage = 'Found {0} certificate templates that can potentially be abused.'
    Remediation = 'Multiple actions can be taken to ensure certificate templates will be less vulnerable:
1. Enable manager approval - make sure manager approval is enabled and required on the certificate, and approve each request manually after inspecting it.
2. No authorized signatures are required - it is recommended to set it to 1 so that each request will have to be signed by an authorized certificate.
3. SAN Enabled - evaluate if the certificate needs to specify a subjectAltName, if not disable this option.
4. Authentication EKU present - make sure the certificate template is being used for authentication only.<br> For example, a certificate that is solely used for code signing should not also be used for authentication.<br>MITRE D3fend based on the reference: MITRE D3fend based on the reference: <a href="https://www.nccoe.nist.gov/sites/default/files/library/sp1800/tls-serv-cert-mgt-nist-sp1800-16b-final.pdf" target="_blank">NIST-SP1800-16B</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'CertificateTemplateName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PotentialAbusableProblems'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Published'; Type = 'Boolean'; IsCollection = $false }
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
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

if ($Metadata) { return $self | ConvertTo-Json -Depth 8 -Compress }

$outputObjects = [System.Collections.ArrayList]@()

# Define the OIDs for Authentication EKUs
$AuthEKU = @("1.3.6.1.5.5.7.3.2","1.3.6.1.5.2.3.4","1.3.6.1.4.1.311.20.2.2","2.5.29.37.0")


try {
    $forestDN = (Get-ADDomain -Server $DomainName).DistinguishedName

    $builtInTemplatesCNs = @(
        "EnrollmentAgentOffline", "WebServer", "CA", "SubCA", "IPSECIntermediateOffline", "OfflineRouter",
        "CEPEncryption", "ExchangeUser", "ExchangeUserSignature", "CrossCA", "CAExchange", "User",
        "UserSignature", "SmartcardUser", "ClientAuth", "SmartcardLogon", "EFS", "Administrator",
        "EFSRecovery", "CodeSigning", "CTLSigning", "EnrollmentAgent", "MachineEnrollmentAgent",
        "Machine", "DomainController", "IPSECIntermediateOnline", "KeyRecoveryAgent",
        "DomainControllerAuthentication", "DirectoryEmailReplication", "Workstation",
        "RASAndIASServer", "OCSPResponseSigning", "KerberosAuthentication"
    )

    $results = Get-ADObject -LDAPFilter "(objectClass=pKICertificateTemplate)" -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$forestDN" -Properties msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag, pKIExtendedKeyUsage, msPKI-RA-Signature, cn

    foreach ($result in $results) {
        if ($builtInTemplatesCNs -contains $result.cn) {
            continue
        }

        $cn = $result.cn
        $sanEnabled = ([int]$result.'msPKI-Certificate-Name-Flag') -band 1
        $managerApprovalNeeded = ([int]$result.'msPKI-Enrollment-Flag') -band 2
        $securitySignaturesNeeded = [int]$result.'msPKI-RA-Signature'
        $templateEKU = $result.'pKIExtendedKeyUsage'
        $authEKUPresent = 0
    
        if ($templateEKU) {
            foreach ($oid in $AuthEKU) {
                if ($templateEKU -contains $oid) {
                    $authEKUPresent++
                }
            }
        }
    
        $abusableProblems = ""
    

        $countAbusableProblems = 0
        if ($sanEnabled) { $countAbusableProblems++; $abusableProblems += "SAN Enabled, " }
        if ($managerApprovalNeeded -eq 0) { $countAbusableProblems++; $abusableProblems += "no Manager Approval needed, " }
        if ($securitySignaturesNeeded -eq 0) { $countAbusableProblems++; $abusableProblems += "No Signatures needed, " }
        if ($authEKUPresent -gt 0) { $countAbusableProblems++; $abusableProblems += "Authentication EKU present" }

        if ($countAbusableProblems -ge 3) {
            $outputObjects.Add([PSCustomObject][Ordered]@{
                DistinguishedName = $result.DistinguishedName
                CertificateTemplateName = $cn
                PotentialAbusableProblems = $abusableProblems.TrimEnd(', ')
            })
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
            Status = 'Passed'       
            ResultMessage = 'No vulnerable certificate templates found.'
        }
    }

}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'       
        ResultMessage = $_.Exception.Message
    }
}

return $res
