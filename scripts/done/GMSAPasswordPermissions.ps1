# This script returns every gMSA object and the principals who can read the password
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 83
    UUID = '5962cacc-495f-4487-9770-2a87ee8fc50a'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000083'
    Name = 'Non-privileged users with access to gMSA passwords'
    ScriptName = 'GMSAPasswordPermissions'
    Description = 'This indicator looks for principals listed within MSDS-groupMSAmembership that are not in the built-in admin groups.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'An attacker that controls access to the gMSA account can retrieve passwords for resources managed with gMSA.'
    ResultMessage = 'There are {0} Group Managed Service Accounts that unprivileged principals can potentially read their password'
    Remediation = 'Ensure that there are no unnecessary principals who can read Group Managed Service Account passwords via the msDS-GroupMSAMembership attribute.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Access'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Identity'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Source'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$domain = Get-ADDomain -Server $DomainName
$domainSID = $domain.Sid.Value

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
    "$domainSID-1000", # Group Policy Creator Owners
    "$domainSID-1001", # Account Operators
    "$domainSID-1002", # Backup Operators
    "$domainSID-1003", # Server Operators
    "$domainSID-1004", # Print Operators
    "$domainSID-1005", # Network Configuration Operators
    "S-1-5-32-544",    # BUILTIN\Administrators
    "S-1-5-32-549",    # BUILTIN\Server Operators
    "S-1-5-32-550",    # BUILTIN\Print Operators
    "S-1-5-32-551",    # BUILTIN\Backup Operators
    "S-1-5-32-552",    # BUILTIN\Replicators
    "S-1-5-32-548",    # BUILTIN\Account Operators
    "S-1-5-32-547"     # BUILTIN\Power Users
)
try {
    $gMSAAccounts = Get-ADServiceAccount -Filter { (objectClass -eq "msDS-GroupManagedServiceAccount") } -Properties msDS-GroupMSAMembership, PrincipalsAllowedToRetrieveManagedPassword -Server $DomainName
    $outputObjects = @()

    foreach ($gMSA in $gMSAAccounts) {
        if ($gMSA.PrincipalsAllowedToRetrieveManagedPassword) {
            $allowedPrincipals = @($gMSA.PrincipalsAllowedToRetrieveManagedPassword)

            foreach ($principal in $allowedPrincipals) {
                try {
                    $principalObject = Get-ADUser -Identity $principal -Server $DomainName -Properties DistinguishedName, SID, MemberOf
                } catch {
                    Write-Warning "Could not retrieve user object for principal: $principal. Error: $_"
                    continue
                }

                $isAllowedMember = $false

                foreach ($group in $principalObject.MemberOf) {
                    try {
                        $groupSID = (Get-ADGroup -Identity $group -Server $DomainName -Properties SID).SID
                        Write-Host "Checking group: $group with SID: $groupSID"
                        
                        if ($allowedSIDs -contains $groupSID) {
                            Write-Host "Principal $($principalObject.DistinguishedName) is a member of allowed group: $group"
                            $isAllowedMember = $true
                            break
                        }
                    } catch {
                        Write-Warning "Could not retrieve SID for group: $group. Error: $_"
                    }
                }

                if ($allowedSIDs -notcontains $principalObject.SID) {
                    if (-not $isAllowedMember) {
                        $outputObject = [PSCustomObject]@{
                            DistinguishedName = $gMSA.DistinguishedName
                            Name              = $principalObject.DistinguishedName
                            Access            = "Can read password"
                            Source            = "PrincipalsAllowedToRetrieveManagedPassword"
                        }
                        $outputObjects += $outputObject
                    } else {
                        Write-Warning "Principal $($principalObject.DistinguishedName) is a member of an allowed group."
                    }
                } else {
                    Write-Warning "Principal $($principalObject.DistinguishedName) has an allowed SID."
                }
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status = "Failed"
            ResultObjects = $outputObjects
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = "Passed"
            ResultMessage = $self.ResultMessage -f 0
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res