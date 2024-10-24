# This script looks for non-default principals with permissions on the NTAuthCertificates object.
[CmdletBinding()]
param(
    [Parameter(Mandatory, ParameterSetName='Execution')][string]$DomainName
)

$Global:self = @{
    ID = 91
    UUID = 'e441aeb0-ba69-426b-bbc1-028bf258c3d8'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000091'
    Name = 'Dangerous control paths expose certificate containers'
    ScriptName = 'CertificatesNTAuthPermissions'
    Description = 'This indicator looks for non-default principals with permissions on the NTAuthCertificates container. This container holds the intermediate CA certificates that can be used to authenticate to AD.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'These control paths allow adding a malicious certificate authority, which allow an attacker to authenticate as arbitrary users or services.'
    ResultMessage = 'Found {0} principals that have non default permissions on the NTAuthCertificates object.'
    Remediation = 'Unprivileged users should not have permissions on the NTAuthCertificates. Doing so potentially gives them the ability to escalate their access and make the domain trust a rouge CA. Remove unnecessary permissions from the object.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Access'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'Identity'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Credential Transmission Scoping') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_adcs_control') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


try {
    $domainSid = (Get-ADDomain).DomainSID.Value

    $allowedSIDs = @(
        "$domainSid-500", # Domain Administrator
        "$domainSid-502", # KRBTGT
        "$domainSid-512", # Domain Admins
        "$domainSid-515", # Domain Computers
        "$domainSid-516", # Domain Controllers
        "$domainSid-517", # Cert Publishers
        "$domainSid-518", # Schema Admins (root domain)
        "$domainSid-519", # Enterprise Admins (root domain)
        "S-1-5-32-544",   # BUILTIN/Administrators
        "S-1-5-18",       # SYSTEM (non-domain specific)
        "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
        "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
        "S-1-5-4",        # Interactive
        "S-1-5-6"         # Service
    )
    $objectDN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$($DomainName -replace '\.', ',DC=')"
    $acl = Get-Acl "AD:$objectDN"
    $outputObjects = @()

    $acl.Access | ForEach-Object {
        $user = $_.IdentityReference
        $sid = New-Object System.Security.Principal.NTAccount($user).Translate([System.Security.Principal.SecurityIdentifier])

        if ($allowedSIDs -notcontains $sid.Value) {
            $outputObjects += [PSCustomObject] @{
                UserOrGroup    = $user
                SID            = $sid.Value
                AccessRights   = $_.ActiveDirectoryRights
                InheritanceType = $_.InheritanceType
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
        $res = [PSCustomObject] @{
            Status = 'Passed'
            ResultMessage = "No principals with permissions on the NTAuthCertificates object were found."
            Remediation = $self.Remediation
        }
    }
} catch {
    $res = [PSCustomObject] @{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res