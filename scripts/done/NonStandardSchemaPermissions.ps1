[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$DomainName
)

$Global:self = @{
    ID = 81
    UUID = '96995af9-8efb-46d4-b0f3-dfcfac74aaae'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000081'
    Name = 'Non-standard schema permissions'
    ScriptName = 'NonStandardSchemaPermissions'
    Description = 'This indicator looks for additional  principals with any permissions beyond generic Read to the schema partitions.Schema is one of three main Active Directory naming context. It contains every object attribute definitions of the forest. For additional information and remediation advice, see the <a href="https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#permissions_schema" target="_blank">ANSSI website</a>.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'By default, modification permissions on schema are limited to Schema Admins. These permissions grant the trusted Principal complete control over Active Directory.'
    ResultMessage = 'Found {0} non default ACEs on the schema.'
    Remediation = 'It is recommended to revert schema permissions to default state. See indicator description for additional info and link.'
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
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_permissions_schema') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - System Configuration Permissions') }
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

try {
    $dse = [ADSI]"LDAP://RootDSE"
    $schemaPartitions = @(
        [ADSI]("LDAP://" + $dse.defaultNamingContext),
        [ADSI]("LDAP://" + $dse.configurationNamingContext)
    )

    $domainSID = (Get-ADDomain -Identity $DomainName).DomainSID.Value
    
    $allowedSIDs = @(
        "$domainSID-500",  # Domain Administrator
        "$domainSID-502",  # KRBTGT
        "$domainSID-512",  # Domain Admins
        "$domainSID-516",  # Domain Controllers
        "$domainSID-517",  # Cert Publishers
        "$domainSID-518",  # Schema Admins (root domain)
        "$domainSID-519",  # Enterprise Admins (root domain)
        "$domainSID-520",  # Group Policy Creator Owners
        "$domainSID-521",  # Read-Only Domain Controllers
        "$domainSID-522",  # Cloneable Controllers
        "$domainSID-526",  # Key Admins
        "$domainSID-527",  # Enterprise Key Admins
        "$domainSID-498",  # Enterprise Read-Only Domain Controllers
        "$domainSID-553",  # RAS and IAS Servers
        "S-1-5-32-544",   # BUILTIN/Administrators
        "S-1-5-32-554",   # Authenticated Users
        "S-1-5-32-557"
        "S-1-1-0",        # Everyone
        "S-1-5-10",
        "S-1-5-18",       # SYSTEM (non-domain specific)
        "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
        "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
        "S-1-5-11",       # Authenticated Users
        "S-1-5-4",        # Interactive
        "S-1-5-6",        # Service
        "S-1-5-9",        # Enterprise Domain Controllers
        "S-1-3-0",        # Creator Owner
        "S-1-3-1",        # Creator Group
        "S-1-3-2",        # Owner Rights
        "S-1-3-3",        # Group Rights
        "S-1-3-4"         # All Users
    )

    $allowedPrincipals = @()
    foreach ($sid in $allowedSIDs) {
        try {
            $accountName = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
            $allowedPrincipals += $accountName
        } catch {
            Write-Warning "Could not translate SID ${sid}: $_"
        }
    }

    foreach ($partition in $schemaPartitions) {
        $AccessList = $partition.psbase.ObjectSecurity.Access

        foreach ($access in $AccessList) {
            $identityName = $null
            try {
                $identityName = $access.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                $identityName = $access.IdentityReference.Value
            }

            if ($access.ActiveDirectoryRights -ne 'ReadProperty' -and 
                $access.ActiveDirectoryRights -ne 'GenericRead' -and 
                ($allowedPrincipals -notcontains $identityName -and $allowedSIDs -notcontains $identityName)) {
                $outputObjects += [PSCustomObject]@{
                    DistinguishedName = $partition.distinguishedName
                    Identity = $identityName
                    HasPermission = $true
                    Access = $access.ActiveDirectoryRights.ToString()
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
            Status = "Success"
            ResultMessage = "No non-standard permissions found on schema."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res
