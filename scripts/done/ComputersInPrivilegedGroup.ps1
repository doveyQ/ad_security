[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 61
    UUID = '113f7039-879b-4093-a42b-dce6b47b313c'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000061'
    Name = 'Computer Accounts in Privileged Groups'
    ScriptName = 'ComputersInPrivilegedGroup'
    Description = 'This indicator looks for computer accounts that are members of built-in privileged groups.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'If a computer account is a member of a domain privileged group, then anyone that compromises that computer account (i.e. becomes administrator) can act as a member of that group. Generally speaking, there is little reason for normal computer accounts to be part of privileged groups.'
    ResultMessage = 'Found {0} instances of computer membership within a privileged group.'
    Remediation = 'Check why those computer objects are members of privileged groups.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'ComputerDistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GroupDistinguishedName'; Type = 'String'; IsCollection = $false }
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

    $domainControllers = Get-ADDomainController -Filter * -Server $DomainName | Select-Object -ExpandProperty ComputerObjectDN

    $allComputers = Get-ADComputer -Filter * -Properties DistinguishedName, memberOf -Server $DomainName | 
        Where-Object { $_.DistinguishedName -notin $domainControllers }

    foreach ($computer in $allComputers) {
        foreach ($group in $computer.memberOf) {
            $groupSID = (Get-ADGroup -Identity $group -Properties SID).SID
            if ($allowedSIDs -contains $groupSID) {
                $object = [PSCustomObject]@{
                    ComputerDistinguishedName = $computer.DistinguishedName
                    GroupDistinguishedName     = $group
                }
                [void]$outputObjects.Add($object)
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status        = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation   = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status        = 'Passed'
            ResultMessage = "No instances of computer membership within a privileged group found."
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}
return $res
