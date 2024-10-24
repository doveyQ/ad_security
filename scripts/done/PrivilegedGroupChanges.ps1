[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 43
    UUID = '3abeddaa-cdc0-4357-8834-3662c68cf073'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000043'
    Name = 'Changes to privileged group membership in the last 7 days'
    ScriptName = 'PrivilegedGroupChanges'
    Description = 'This indicator looks for changes to the built-in privileged groups within the last 7 days, which could indicate attempts to escalate privilege.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = 'Recent additions or deletions to privileged group members could be normal operational changes or could indicate attempts at persistence or cleaning up of tracks after an attack (e.g. detection of temporary group membership changes).'
    ResultMessage = 'Found {0} changes on privileged groups'' membership.'
    Remediation = 'Confirm that any additions/removals from privileged groups are valid and properly accounted for.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'GroupDistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Operation'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Persistence') }
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

    $searchBase = "DC=$($DomainName -replace '\.', ',DC=')"
    $sevenDaysAgo = (Get-Date).AddDays(-7)

    $groupChanges = Get-ADGroup -Filter { whenChanged -ge $sevenDaysAgo } -SearchBase $searchBase -Properties whenChanged, SID 

    $groupChangeCheck = $groupChanges | Where-Object { 
        $allowedSIDs -contains $_.SID
    }

    foreach ($groupChange in $groupChangeCheck) {
        $outputObject = [PSCustomObject]@{
            GroupDistinguishedName = $groupChange.DistinguishedName
            EventTimestamp = $groupChange.whenChanged
            Operation = "Modified" 
        }
        [void]$outputObjects.Add($outputObject)
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
            ResultMessage = "No recent changes on privileged groups' membership."
        }
    }
}
catch {
    $res = @{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res | Format-Table -AutoSize