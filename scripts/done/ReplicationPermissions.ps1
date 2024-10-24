# This script looks for non-default objects with Replication permissions
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 21
    UUID = 'bcb85336-3507-4565-91a2-9c1360c5a5f1'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000021'
    Name = 'Non-default principals with DC Sync rights on the domain'
    ScriptName = 'ReplicationPermissions'
    Description = 'Any security principals with Replicate Changes All and Replicate Directory Changes permissions on the domain naming context object can potentially retrieve password hashes for any and all users in an AD domain ("DCSync" attack). Additionally, Write DACL / Owner also allows assignment of these privileges. This can then lead to all kinds of credential-theft based attacks, including Golden and Silver Ticket attacks.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'DCSync is an attack for accessing credentials through this method. If an attacker gets ahold of these privileges, it is straight-forward to retrieve credential material using tools like Mimikatz, for any user in a domain.'
    ResultMessage = 'Found {0} objects with replication permissions.'
    Remediation = 'Ensure that there are no unnecessary replication permissions and investigate suspicious permissions. Under certain situations (e.g. Microsoft PAM Tiering), an empty group may appear in the results - this is normal but keep in mind that this is a highly privileged group.'
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
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_permissions_naming_context') }
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
    $guidHT = @{
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes"
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
        "89e95b76-444d-4c62-991a-0facbeda640c" = "DS-Replication-Get-Changes-In-Filtered-Set"
        "00000000-0000-0000-0000-000000000000" = "All Properties"
    }

    $domainSID = (Get-ADDomain).DomainSID
    $allowedSIDs = @(
        "$domainSID-500", # Domain Administrator
        "$domainSID-502", # KRBTGT
        "$domainSID-512", # Domain Admins
        "$domainSID-515", # Domain Computers
        "$domainSID-516", # Domain Controllers
        "$domainSID-518", # Schema Admins (root domain)
        "$domainSID-519", # Enterprise Admins (root domain)
        "$domainSID-521", # Read-Only Domain Controllers
        "$domainSID-526", # Key Admins
        "$domainSID-527", # Enterprise Key Admins
        "$domainSID-498", # Enterprise Read-Only Domain Controllers
        "S-1-5-32-544",   # BUILTIN/Administrators
        "S-1-5-18",       # SYSTEM (non-domain specific)
        "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
        "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
        "S-1-5-10",       # SELF
        "S-1-5-15",       # ORGANIZATION
        "S-1-5-9"         # Enterprise Domain Controllers
    )
    
    $DN = (Get-ADDomain -Identity $DomainName).DistinguishedName
    $acl = Get-ACL -Path "AD:$DN"

    foreach ($access in $acl.Access) {
        try {
            $ntAccount = $access.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            Write-Verbose "Could not translate IdentityReference: $($_.Exception.Message)"
            continue
        }

        $identitySID = $access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value

        if ($access.ActiveDirectoryRights -eq "ExtendedRight" -and $guidHT.ContainsKey($access.ObjectType.Guid) -and (-not $allowedSIDs.Contains($identitySID))) {
            $enabled = -not ($ntAccount -match '\$')
            $thisOutput = [PSCustomObject][Ordered]@{
                DistinguishedName = $DN
                Identity = $ntAccount
                Access = $guidHT[$access.ObjectType.Guid] + ": " + $access.ActiveDirectoryRights
                Enabled = $enabled.ToString()
            }
            [void]$outputObjects.Add($thisOutput)
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
            ResultMessage = "No objects found with replication permissions."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
