# This script looks for non-privileged users with the ability to link GPOs at the domain level

[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")][string]$DomainName
)

$Global:self = @{
    ID = 32
    UUID = '2cfda02d-2ac4-4d4d-bc9c-bff9c51024d0'
    Version = '1.124.1'
    CategoryID = 4
    ShortName = 'SI000032'
    Name = 'GPO linking delegation at the domain level'
    ScriptName = 'WeakGPOLinkingOnDomain'
    Description = 'When non-privileged users can link GPOs at the domain level, they have the ability to effect change across all users and computers in the domain as well as potentially elevate access and change domain-wide security posture. This indicator looks for non-default principals who have write permissions on the GPLink attribute or Write DACL/Write Owner on the object.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Just being able to link GPOs doesn''t provide the whole picture. An attacker would need to find or edit a GPO that contains the instructions they want to achieve. However, if an attacker can find an existing GPO that meets their needs, then having this write permission gives them the keys to the kingdom.'
    ResultMessage = 'Found {0} objects with write permissions on the GPLink attribute at the domain level.'
    Remediation = 'Unprivileged users should not be able to link GPOs at the domain object level. Doing so essentially gives them the ability to escalate their access, change domain-level security posture, and use GPOs to effect all systems and users in AD. Remove the unnecessary permissions from the NC Head.'
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
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion', 'Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_permissions_gpo_priv') }
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

# Allowed SIDs
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
    "S-1-5-9"         # Enterprise Domain Controllers
)
function IsMemberOfAllowedGroup($sid, $allowedSIDs) {
    try {
        $adObject = Get-ADObject -Filter { ObjectSID -eq $sid } -Properties MemberOf

        if ($null -ne $adObject) {
            # Get the groups the user is a member of
            $groups = $adObject.MemberOf
            
            foreach ($groupDN in $groups) {
                $group = Get-ADGroup -Identity $groupDN
                if ($group.SID.Value -in $allowedSIDs) {
                    return $true
                }
            }
        }
    } catch {
        Write-Warning "Failed to check group membership for SID: $sid - $_"
    }
    return $false
}

try {
    $acl = Get-ACL "AD:\CN=Policies,CN=System,DC=$($DomainName -replace '\.',',DC=')"

    if (-not $acl.Access) {
        throw "No access entries found in the ACL."
    }

    $writeAccessUsers = $acl.Access | Where-Object { $_.ActiveDirectoryRights -match 'Write' }

    foreach ($entry in $writeAccessUsers) {
        $identitySID = $entry.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value

        if (($identitySID -in $allowedSIDs) -or (IsMemberOfAllowedGroup $identitySID $allowedSIDs)) {
            continue
        }

        $adObject = Get-ADObject -Filter { ObjectSID -eq $identitySID } -ErrorAction SilentlyContinue
        
        if ($null -ne $adObject) {
            $identityUser = $adObject.Name
        } else {
            $identityUser = "Can't get user: $identitySID"
        }


        $object = [PSCustomObject]@{
            Access             = 'Write'
            GPODistinguishedName = "CN=Policies,CN=System,DC=$($DomainName -replace '\.',',DC=')"
            Identity           = $identityUser
        }
        [void]$outputObjects.Add($object)
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
            ResultMessage = "No objects with write permissions on the GPLink attribute at the domain level found."
        }
    }

} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res