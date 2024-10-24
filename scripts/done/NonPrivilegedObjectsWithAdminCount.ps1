# This script looks for objects with adminCount=1 that are not members of any default or privileged groups.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 34
    UUID = 'e08bbf6a-b17e-4417-a9cd-8f4b7b6210f9'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000034'
    Name = 'Unprivileged accounts with adminCount=1'
    ScriptName = 'NonPrivilegedObjectsWithAdminCount'
    Description = 'This indicator looks for any users or groups that may have been under the control of SDProp (adminCount=1) but are no longer members of privileged groups and should not be considered privileged.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'The most common scenario for this behavior is if a user is moved from a privileged group to a non-privileged one and their adminCount variable is not reset. While this is benign, it may cause issues for security controls that monitor privileged users and reduces the overall hygiene of the environment. In rare cases, this might also be evidence of an attacker that attempted to cover their tracks and remove a user they used for compromise.'
    ResultMessage = 'Found {0} objects with adminCount=1 that are not members of a privileged group.'
    Remediation = 'Remove the adminCount = 1 attribute from these users. Investigate unknown users with this attribute.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Type'; Type = 'String'; IsCollection = $false }
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

try {
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
        "$domainSID-1101", # DnsAdmins
        "$domainSID-525", # Protected Users
        "$domainSID-522", # Cloneable Domain Controllers
        "$domainSID-517", # Cert Publisher
        "S-1-5-32-548",   # Account Operators
        "S-1-5-32-549",   # Server Operators
        "S-1-5-32-569",   # Cryptographic Operators
        "S-1-5-32-550",   # Print Operators
        "S-1-5-32-551",   # Backup Operators
        "S-1-5-32-552",   # Replicator
        "S-1-5-32-544",   # BUILTIN/Administrators
        "S-1-5-18",       # SYSTEM (non-domain specific)
        "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
        "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
        "S-1-5-10",       # SELF
        "S-1-5-15",       # ORGANIZATION
        "S-1-5-9"         # Enterprise Domain Controllers
    )

    $usersWithAdminCount = Get-ADUser -Filter { adminCount -eq 1 } -Properties SamAccountName, adminCount, memberOf, DistinguishedName -Server $DomainName

    foreach ($user in $usersWithAdminCount) {
        if (!($allowedSIDs -contains $user.SID) -and (-not ($user.memberOf | Where-Object { $allowedSIDs -contains (Get-ADGroup $_).SID }))) {
            $outputObjects += [PSCustomObject]@{
                UserName = $user.SamAccountName
                DistinguishedName = $user.DistinguishedName
                AdminCount = $user.adminCount
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
            ResultMessage = "No unprivileged accounts found with adminCount=1."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
