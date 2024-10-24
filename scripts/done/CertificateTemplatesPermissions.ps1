# This script looks for non-privileged users with the ability to write properties on a certificate template

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 90
    UUID = 'a76ea884-afef-4d00-9820-b24117a12661'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000090'
    Name = 'Dangerous control paths expose certificate templates'
    ScriptName = 'CertificateTemplatesPermissions'
    Description = 'This indicators looks for non-default principals with the ability to write properties on a certificate template.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Controlling certificate templates allows one to have the certificate authority issue an arbitrary certificate. It becomes possible to obtain a smartcard authentication certificate for any user, thus stealing his identity.'
    ResultMessage = 'Found {0} certificate templates on which unprivileged users can write properties.'
    Remediation = 'Unprivileged users should not be able to write properties on certificate templates. Doing so potentially gives them the ability to escalate their access and create vulnerable certificates to enroll. Remove unnecessary permissions from the certificate template.<br><br>MITRE D3fend based on the reference: <a href="https://www.nccoe.nist.gov/sites/default/files/library/sp1800/tls-serv-cert-mgt-nist-sp1800-16b-final.pdf" target="_blank">NIST-SP1800-16B</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Access'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Identity'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_adcs_template_control') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Certificate Analysis') }
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
try {
    $domainSID = (Get-ADDomain -Server $DomainName).DomainSID.Value

    $allowedSIDs = @(
        "$domainSID-500", # Domain Administrator
        "$domainSID-502", # KRBTGT
        "$domainSID-512", # Domain Admins
        "$domainSID-514", # Domain Guests
        "$domainSID-515", # Domain Computers
        "$domainSID-516", # Domain Controllers
        "$domainSID-518", # Schema Admins (root domain)
        "$domainSID-519", # Enterprise Admins (root domain)
        "$domainSID-521", # Read-Only Domain Controllers
        "$domainSID-498", # Enterprise Read-Only Domain Controllers
        "S-1-5-32-544",   # BUILTIN/Administrators
        "S-1-5-18",       # SYSTEM (non-domain specific)
        "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
        "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
        "S-1-5-9"         # Enterprise Domain Controllers

    )

    $searchDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$($DomainName -replace '\.', ',DC=')"
    
    $results = Get-ADObject -LDAPFilter "(objectClass=pKICertificateTemplate)" -SearchBase $searchDN -Properties ntSecurityDescriptor

    foreach ($template in $results) {
        if ($null -ne $template.ntSecurityDescriptor) {
            $accessRules = Get-Acl -Path "AD:\$($template.DistinguishedName)" | Select-Object -ExpandProperty Access
            
            foreach ($rule in $accessRules) {
                if ($rule.AccessControlType -eq 'Allow' -and -not ($allowedSIDs -contains $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)) {
                    $thisOutput = [PSCustomObject][Ordered] @{
                        DistinguishedName = $template.DistinguishedName
                        Identity = $rule.IdentityReference.ToString()
                        Access = "$($rule.AccessControlType): $($rule.ActiveDirectoryRights) on: $($rule.ObjectType)"
                    }
                    [void]$outputObjects.Add($thisOutput)
                }
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No certificate templates found with writable properties for unprivileged users."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
