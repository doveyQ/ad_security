[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 33
    UUID = 'c4218bf3-aca4-4d17-90a3-9ba3f4ec42e7'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000033'
    Name = 'Recent privileged account creation activity'
    ScriptName = 'NewPrivilegedUsers'
    Description = 'This indicator looks for any users or groups that were created within the last month. Privileged accounts and groups are defined by having their adminCount attribute set to 1.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'In most environments, creation of privileged accounts and groups is tightly controlled and audited. This indicator provides a fast method to create a list of new privileged accounts (where adminCount = 1) for investigation and review.'
    ResultMessage = 'Found {0} objects that were created in the last {1} days and are members of a privileged group.'
    Remediation = 'Review the list and verify that all privileged accounts and groups that were recently created are valid. Ideally, all privileged account creation goes through an approval-based workflow and gets periodic attestation.<br><br>MITRE D3fend based on the reference: <a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-user-account-management" target="_blank">audit-user-account-management of Microsoft</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Persistence') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Domain Account Monitoring') }
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
$daysToRemove = 30
$startDate = (Get-Date).AddDays(-$daysToRemove)

$domainSID = (Get-ADDomain).DomainSID
$allowedSIDs = @(
    "$domainSID-500", # Domain Administrator
    "$domainSID-502", # KRBTGT
    "$domainSID-512", # Domain Admins
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

try {
    $searchBase = "DC=$($DomainName -replace '\.', ',DC=')"


    $createdObjects = Get-ADUser -Filter {(whenCreated -ge $startDate) -and (samAccountName -ne 'Administrator') -and (samAccountName -ne 'krbtgt')} `
        -SearchBase $searchBase -Properties adminCount, whenCreated, samAccountName, SID, MemberOf

    foreach ($createdObject in $createdObjects) {
        if (($createdObject.MemberOf | Where-Object { $allowedSIDs -contains (Get-ADGroup $_).SID }) -or ($createdObject.adminCount -eq "1")) {
            $outputObject = [PSCustomObject]@{
                DistinguishedName = $createdObject.DistinguishedName
                SamAccountName = $createdObject.SamAccountName
                EventTimestamp = $createdObject.whenCreated
                GroupMembership = $createdObject.memberOf -join ', '
            }
            [void]$outputObjects.Add($outputObject)
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count, $daysToRemove
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No objects created in the last $daysToRemove days with privileged memebership"
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res