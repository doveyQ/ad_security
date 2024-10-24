[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 96
    UUID = '22388d19-f301-46bf-9503-4562a03f12fb'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000096'
    Name = 'Privileged Users with Weak Password Policy'
    ScriptName = 'PrivilegedUsersWeakPasswordPolicy'
    Description = 'This indicator looks for privileged users in each domain that don''t have a strong password policy enforced, according to ANSSI framework. It checks both FGPP (Fine-Grained Password Policy) and the password policy applied to the domain. A strong password as defined by ANSSI is at least 8 characters long and updated no later than every 3 years.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'Weak passwords are easier to crack via brute-force attacks, they can provide attackers opportunities for moving laterally or escalating privileges. The risk is even higher for privileged accounts, for when easily compromised, they improve the attacker''s chance to quickly advance within the network.'
    ResultMessage = 'Found {0} privileged users with a password policy but whose compliance with them could not be determined'
    Remediation = 'Apply appropriate password policies for privileged users.<br><br>MITRE D3fend based on the reference: <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf">NIST.SP.800-63-3</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'ComplexityEnabled'; Type = 'Boolean'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'History'; Type = 'String'; IsCollection = $false },
        @{ Name = 'MaxAge'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'MinAge'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'MinLength'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'PasswordPolicyDistinguishedName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Discovery') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_privileged_members_password') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

function IsMemberOfAllowedGroup($sid, $allowedSIDs) {
    try {
        $adObject = Get-ADObject -Filter { ObjectSID -eq $sid } -Properties MemberOf

        if ($null -ne $adObject) {
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

$outputObjects = @()
$foundUsers = $false

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
    "S-1-5-32-548",   # Account Operators
    "S-1-5-32-549",   # Server Operators
    "S-1-5-32-550",   # Print Operators
    "S-1-5-32-551",   # Backup Operators
    "S-1-5-32-544",   # BUILTIN/Administrators
    "S-1-5-18",       # SYSTEM (non-domain specific)
    "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
    "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
    "S-1-5-10",       # SELF
    "S-1-5-15",       # ORGANIZATION
    "S-1-5-9"         # Enterprise Domain Controllers
)
try {
    $results = Get-ADObject -Filter { adminCount -eq 1 -and SamAccountName -ne 'krbtgt' -and SamAccountName -ne 'Administrator' } -Server $DomainName -SearchScope Subtree -Properties SamAccountName, memberOf, ObjectSID

    foreach ($result in $results) {
        $userSID = $result.ObjectSID
        if ($userSID -is [System.Object[]]) {
            $userSID = $userSID[0]
        }

        if ($allowedSIDs -contains $userSID -or (IsMemberOfAllowedGroup -sid $userSID -allowedSIDs $allowedSIDs)) {
            continue 
        }

        $outputObjects += [PSCustomObject]@{
            DistinguishedName = $result.DistinguishedName
            SamAccountName    = $result.SamAccountName
            Type              = $result.objectClass
        }
        $foundUsers = $true
    }

    if ($foundUsers) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
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