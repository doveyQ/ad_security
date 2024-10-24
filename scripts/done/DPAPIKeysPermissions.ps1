# This script checks the domain controllers to determine if non-default principals are permitted to access private information (e.g., retrieve the DPAPI backup key).
[CmdletBinding()]
param(
    [Parameter(Mandatory, ParameterSetName='Execution')][string]$DomainName
)

$Global:self = @{
    ID = 92
    UUID = '4d30c9d8-375e-48cc-8244-0073107f29a4'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000092'
    Name = 'Non-default access to DPAPI key'
    ScriptName = 'DPAPIKeysPermissions'
    Description = 'This indicator uses API calls to check whether each DC has non-default principals permitted to retrieve the domain DPAPI backup key (using LsaRetrievePrivateData).'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'An attacker could recover all domain data encrypted via DPAPI, if they gain access to such data.'
    ResultMessage = 'Found {0} DCs that allows non default principals to read private data from the LSA policy database.'
    Remediation = 'These permissions allow a principal to use LsaRetrievePrivateData to retrieve the domain DPAPI backup keys. Review these principals, investigate and remove any unneeded permissions using adsiedit.msc or the ldp utility.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'AllowedPrincipals'; Type = 'String'; IsCollection = $false },
        @{ Name = 'HostName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - User Account Permissions') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_permissions_dpapi') }
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
$couldNotQuery = 0

$domainControllers = Get-ADDomainController -Filter * -Server $DomainName

$domainSID = (Get-ADDomain $DomainName).DomainSID

$allowedSIDs = @(
    "$domainSID-500", # Domain Administrator
    "$domainSID-501", # Domain Guest
    "$domainSID-502", # KRBTGT
    "$domainSID-512", # Domain Admins
    "$domainSID-513", # Domain Users
    "$domainSID-514", # Domain Guests
    "$domainSID-515", # Domain Computers
    "$domainSID-516", # Domain Controllers
    "$domainSID-517", # Cert Publishers
    "$domainSID-518", # Schema Admins (root domain)
    "$domainSID-519", # Enterprise Admins (root domain)
    "$domainSID-521", # Read-Only Domain Controllers
    "$domainSID-498", # Enterprise Read-Only Domain Controllers
    "$domainSID-553", # RAS and IAS Servers
    "S-1-5-32-544",   # BUILTIN/Administrators
    "S-1-5-18",       # SYSTEM (non-domain specific)
    "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
    "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
    "S-1-5-11",       # Authenticated Users
    "S-1-1-0",        # Everyone
    "S-1-5-4",        # Interactive
    "S-1-5-6",        # Service
    "S-1-5-9"         # Enterprise Domain Controllers
)

try {
    foreach ($dc in $domainControllers) {
        $dcDN = $dc.ComputerObjectDN
        $sd = Get-ACL "AD:$dcDN"
        $allowedPrincipals = @()

        foreach ($access in $sd.Access) {
            if ($access.ActiveDirectoryRights -band 4) {
                $identityAccount = New-Object System.Security.Principal.NTAccount($access.IdentityReference.Value)
                
                try {
                    $identitySID = $identityAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    
                    if ($identitySID -notin $allowedSIDs) {
                        $allowedPrincipals += $access.IdentityReference.Value
                    }
                } catch {
                    continue
                }
            }
        }

        if ($allowedPrincipals) {
            $thisOutput = [pscustomobject]@{
                HostName = $dcDN
                AllowedPrincipals = $allowedPrincipals -join "; "
            }
            $outputObjects += $thisOutput
        } else {
            $couldNotQuery++
        }
    }

    if ($outputObjects.Count -gt 0){
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [pscustomobject]@{
            Status = 'Passed'
            ResultMessage = "No DCs found with non-default principals."
        }
    }

    if ($couldNotQuery -gt 0) {
        $res.ResultMessage += " There were $couldNotQuery DCs that couldn't be queried."
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res
