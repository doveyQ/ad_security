[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 35
    UUID = '9f532969-6a43-40a5-9035-f4f2e9cf9e88'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000035'
    Name = 'Changes to MS LAPS read permissions'
    ScriptName = 'ObjectsWithLapsRead'
    Description = 'This indicator looks for permissions on computer accounts that could allow inadvertent exposure of local administrator accounts in environments that use the Microsoft LAPS solution...'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'Only authorized administrative users should have access to LAPS passwords. Attackers may use this capability to laterally move through a domain using local compromised administrator accounts.'
    ResultMessage = 'Found {0} computers on which some normal users can read their LAPS password.'
    Remediation = 'Ensure that there are no unnecessary principals who can read computer administrator account passwords via Extended Rights on the ms-Mcs-AdmPwd attribute.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Access'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
}

$outputObjects = [System.Collections.ArrayList]@()

try {
    $searchBase = (Get-ADDomain -Identity $DomainName).DistinguishedName
    $domainSID = (Get-ADDomain -Server $DomainName).DomainSID.Value

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
        "$domainSID-1000", # Custom group examples
        "$domainSID-1101", # Custom group examples
        "S-1-5-32-544",   # BUILTIN/Administrators
        "S-1-5-18",       # SYSTEM (non-domain specific)
        "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
        "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
        "S-1-5-11",       # Authenticated Users
        "S-1-1-0",        # Everyone
        "S-1-5-4",        # Interactive
        "S-1-5-6",        # Service
        "S-1-5-9",        # Enterprise Domain Controllers
        "S-1-3-0",        # Custom SIDs
        "S-1-2-1"         # Custom SIDs
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

    $computerAccounts = Get-ADComputer -Filter * -SearchBase $searchBase
    foreach ($computer in $computerAccounts) {
        $acl = Get-ACL -Path "AD:$($computer.DistinguishedName)"
        $accessRules = $acl.Access | Where-Object { 
            $_.ObjectType -eq '00299570-246d-11d0-a768-00aa006e0529' -and $_.ActiveDirectoryRights -eq 'ReadProperty' 
        }

        foreach ($rule in $accessRules) {
            $holder = (New-Object System.Security.Principal.SecurityIdentifier($rule.IdentityReference.Value)).Translate([System.Security.Principal.NTAccount]).Value
            if ($allowedPrincipals -notcontains $holder) {
                $outputObjects.Add([PSCustomObject]@{
                    DistinguishedName = $computer.DistinguishedName
                    Access = "$holder has ReadProperty access on: ms-Mcs-AdmPwd"
                })
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
            Status = 'Passed'
            ResultMessage = 'No computers on which some normal users can read their LAPS password found.'
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
