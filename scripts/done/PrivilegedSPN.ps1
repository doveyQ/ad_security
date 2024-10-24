[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DomainName
)

$Global:self = @{
    ID = 19
    UUID = '34d7d270-3b7b-4a0e-b0c4-15e8e2551c31'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000019'
    Name = 'Privileged users with SPN defined'
    ScriptName = 'PrivilegedSPN'
    Description = 'This indicator looks for accounts with the adminCount attribute set to 1 AND ServicePrincipalNames (SPNs) defined on the account. In general, privileged accounts should not have SPNs defined on them, as it makes them targets for Kerberos-based attacks that can elevate privileges to those accounts. By default, the krbtgt account falls under this category but is a special case and is not considered part of this indicator.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'This is a significant issue that can allow an attacker to elevate privileges in a domain. Audit all accounts where privileged access is possible looking for anomalous access. If found, a breach or ongoing attack should be further investigated.'
    ResultMessage = 'Found {0} privileged users with associated SPN.'
    Remediation = 'Remove SPN from privileged accounts when not required or mitigate by other means.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'AESEnabled'; Type = 'Boolean'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ServicePrincipalName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_spn_priv') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
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

$outputObjects = [System.Collections.ArrayList]@()

try {
    $res = New-Object PSObject
    
    $privilegedGroupDNs = @()
    foreach ($group in $privilegedGroups) {
        $groupDN = (Get-ADGroup -Filter { Name -eq $group } -Server $DomainName).DistinguishedName
        if ($groupDN) {
            $privilegedGroupDNs += $groupDN
        }
    }

    $krbtgtDN = (Get-ADUser -Filter { SamAccountName -eq 'krbtgt' } -Server $DomainName).DistinguishedName

    $results = Get-ADUser -Filter { servicePrincipalName -like "*" } -Properties MemberOf, ServicePrincipalName, msds-supportedencryptiontypes, ObjectSID -Server $DomainName
    
    if ($results) {
        foreach ($result in $results) {
            $isPrivileged = $false
            foreach ($groupDN in $privilegedGroupDNs) {
                if ($result.MemberOf -contains $groupDN) {
                    $isPrivileged = $true
                    break
                }
            }

            if ($result.DistinguishedName -eq $krbtgtDN) {
                $isPrivileged = $true
            }

            $userSID = $result.ObjectSID
            if ($userSID -is [System.Object[]]) {
                $userSID = $userSID[0]
            }

            if ($allowedSIDs -contains $userSID -or (IsMemberOfAllowedGroup -sid $userSID -allowedSIDs $allowedSIDs)) {
                continue 
            }

            if ($isPrivileged) {
                $aes = $false
                $SET = $result."msds-supportedencryptiontypes"
                if ($SET -in (8, 16, 24)) {
                    $aes = $true
                }
                
                $thisOutput = [PSCustomObject][Ordered] @{
                    DistinguishedName = $result.DistinguishedName
                    SamAccountName = $result.SamAccountName
                    ServicePrincipalName = $result.ServicePrincipalName -join "; "
                    AESEnabled = $aes
                }
                
                [void]$outputObjects.Add($thisOutput)
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
        $res = @{
            Status = 'Passed'
            ResultMessage = "No privileged accounts with Service Principal Names (SPN) found."
        }
    }
}
catch {
    $res = @{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
