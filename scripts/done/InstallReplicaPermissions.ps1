[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$DomainName
)

$Global:self = @{
    ID = 89
    UUID = 'a5174a20-4a4d-480c-99e3-da8017a10450'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000089'
    Name = 'Users with permissions to set Server Trust Account'
    ScriptName = 'InstallReplicaPermissions'
    Description = 'Checks for permissions on the domain NC head that enables a user to set a UAC flag - Server_Trust_Account on computer objects. This flag gives that computer object special permissions similar to a domain controller.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'A persistence technique originally reported by Stealthbits researchers, an attacker that is able to seed authenticated user(s) with these permissions can then utilize their access to these users to "promote" any computer they control to Domain Controller status, enabling privilege escalation to AD services and carrying out credential access attacks such as DCSync. More information available <a href="https://stealthbits.com/blog/server-untrust-account/" target="_blank">here</a>.'
    ResultMessage = 'Found {0} objects with install replica permissions.'
    Remediation = 'Ensure that there are no unnecessary install replica permissions and investigate suspicious permissions.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Access'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Enabled'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Identity'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') }
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
$PermissionName = "Replicating Directory Changes"

try {
    $dse = [ADSI]"LDAP://RootDSE"
    $defaultNC = [ADSI]("LDAP://" + $dse.defaultNamingContext)
    $configNC = [ADSI]("LDAP://" + $dse.configurationNamingContext)
    
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
        "$domainSID-526",  # Key Admins
        "$domainSID-527",  # Enterprise Key Admins
        "$domainSID-498",  # Enterprise Read-Only Domain Controllers
        "$domainSID-553",  # RAS and IAS Servers
        "S-1-5-32-544",   # BUILTIN/Administrators
        "S-1-5-18",       # SYSTEM (non-domain specific)
        "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
        "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
        "S-1-5-11",       # Authenticated Users
        "S-1-1-0",        # Everyone
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

    $extRights = [ADSI]("LDAP://CN=Extended-Rights," + $dse.configurationNamingContext)
    $right = $extRights.psbase.Children | Where-Object { $_.DisplayName -eq $PermissionName }

    if ($null -eq $right) {
        Write-Warning "Install replica permissions not found."
    }
    else {
        $Entries = @($defaultNC, $configNC)
        
        foreach ($entry in $Entries) {
            $AccessList = $entry.psbase.ObjectSecurity.Access

            foreach ($access in $AccessList) {
                $identityName = try {
                    $access.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    $access.IdentityReference.Value
                }

                if ($access.ObjectType -eq [GUID]$right.RightsGuid.Value -and $allowedPrincipals -notcontains $identityName) {
                    $outputObjects += [PSCustomObject]@{
                        DistinguishedName = $entry.distinguishedName
                        Identity = $identityName
                        HasPermission = $true
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
                Status = "Passed"
                ResultMessage = "No unauthorized users with install replica permissions found."          
            }
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message   
    }
}

return $res
