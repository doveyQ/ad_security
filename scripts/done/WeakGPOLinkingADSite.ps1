[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    [String]$DomainName
)

$Global:self = @{
    ID = 41
    UUID = 'eab117be-3114-494c-b3d8-dbdecaf9a050'
    Version = '1.124.1'
    CategoryID = 4
    ShortName = 'SI000041'
    Name = 'GPO linking delegation at the AD Site level'
    ScriptName = 'WeakGPOLinkingADSite'
    Description = 'When non-privileged users can link GPOs at the AD Site level, they have the ability to effect change on domain controllers as well as potentially elevate access and change domain-wide security posture. This indicator looks for non-default principals who have write permissions on the GPLink attribute or Write DACL/Write Owner on the object.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Just being able to link GPOs doesn''t provide the whole picture. An attacker would need to find or edit a GPO that contains the instructions they want to achieve. However, if an attacker can find an existing GPO that meets their needs, then having this write permission gives them the keys to the kingdom.'
    ResultMessage = 'Found {0} objects with write permissions on the GPLink attribute at the AD Site level.'
    Remediation = 'Unprivileged users should not be able to link GPOs at the AD Site Level. Doing so essentially gives them the ability to escalate their access, change domain-level security posture, and use GPOs to effect all systems and users in AD. Remove unnecessary permissions from the AD Site.'
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
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Execution') },
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

$outputObjects = @()
$failedSiteCount = 0

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
    $searchBase = "CN=Sites,CN=Configuration,DC=$($DomainName.Split('.')[0]),DC=$($DomainName.Split('.')[1])"
    $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$searchBase", "(objectClass=site)")
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    
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
        "S-1-5-9"         # Enterprise Domain Controllers
    )
    
    $results = $searcher.FindAll()
    
    $results = $searcher.FindAll()

    foreach ($result in $results) {
        if ($null -ne $result) {
            $site = $result.GetDirectoryEntry()
            $siteACL = $site.psbase.ObjectSecurity.Access
    
            $distinguishedName = $site.Properties["distinguishedName"][0]
    
            foreach ($acl in $siteACL) {
                try {
                    $sid = $acl.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    
                    if (($acl.ActiveDirectoryRights -match "WriteProperty|ReadProperty|GenericAll") -and ($sid -notin $allowedSIDs)) {
                        
                        $isInAllowedGroup = IsMemberOfAllowedGroup $sid $allowedSIDs
                        
                        if (-not $isInAllowedGroup) {
                            $outputObjects += [pscustomobject]@{
                                DistinguishedName = $distinguishedName
                                Identity = $acl.IdentityReference
                                SID = $sid
                                Access = "$($acl.AccessControlType): $($acl.ActiveDirectoryRights) on gpLink"
                            }
                            $failedSiteCount++
                        }
                    }
                } catch {
                    Write-Warning "Failed to process ACL: $_"
                }
            }
        }
    }
    
    if ($failedSiteCount -gt 0) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = "Passed"
            ResultMessage = "No objects with write permissions on the GPLink attribute at the AD Site level found."
        }    
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res