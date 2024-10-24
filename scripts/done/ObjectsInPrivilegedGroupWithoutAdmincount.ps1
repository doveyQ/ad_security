# This script looks for members of privileged groups that have adminCount not equal to 1

[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 46
    UUID = 'b5df966a-2202-401e-8c0c-0e212d7f666d'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000046'
    Name = 'Objects in privileged groups without adminCount=1 (SDProp)'
    ScriptName = 'ObjectsInPrivilegedGroupWithoutAdmincount'
    Description = 'This indicator looks for objects in privileged groups with AdminCount not equal to 1. AdminCount is an object flag that is set by the SDProp process (run by default every 60 minutes) if that object''s DACLs are modified to sync with the AdminSDHolder object through inheritance. If an object within these groups has an AdminCount not equal to 1 then it could signify that the DACLs were manually set (no inheritance) or that there is an issue with SDProp. For more information see: <a href="https://docs.microsoft.com/en-us/previous-versions/technet-magazine/ee361593(v=msdn.10)" target="_blank">https://docs.microsoft.com/en-us/previous-versions/technet-magazine/ee361593(v=msdn.10)</a>'
    Weight = 4
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 4
    LikelihoodOfCompromise = 'While not immediately indicative of an attack, privileged users that are not clearly marked as such (adminCount =1) represent an exposure in that they may be used nefariously without being detected. Additionally, an attacker may add a privileged account and attempt to hide it using this method.'
    ResultMessage = 'Found {0} privileged users that do not have adminCount equal to 1.'
    Remediation = 'Set adminCount=1 and ensure that SDProp is working properly.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'GroupDistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'UserAccountControl'; Type = 'String'; IsCollection = $false },
        @{ Name = 'UserDistinguishedName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion', 'Persistence') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = @()

try {
    $domainSID = (Get-ADDomain -Server $DomainName).DomainSID.Value

    $privilegedGroups = @(
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
    

    foreach ($groupSID in $privilegedGroups) {
        $groupObject = Get-ADGroup -Filter { ObjectSID -eq $groupSID } -ErrorAction Stop
        
        if ($null -eq $groupObject) {
            Write-Host "Group not found for SID: $groupSID"
            continue
        }
        
        $groupDN = $groupObject.DistinguishedName

        try {
            $groupMembers = Get-ADGroupMember -Identity $groupDN -ErrorAction Stop
        } catch {
            Write-Host "Failed to get members for group: $groupDN. Error: $_"
            continue
        }

        foreach ($member in $groupMembers) {
            if ($member.objectClass -eq 'user') {
                $userProps = Get-ADUser -Identity $member -Properties adminCount -ErrorAction Stop

                if ($userProps.adminCount -ne 1) {
                    $thisOutput = [PSCustomObject]@{
                        DistinguishedName        = $userProps.DistinguishedName
                        UserAccountControl       = $userProps.UserAccountControl
                        GroupDistinguishedName   = $groupDN
                    }
                    $outputObjects += $thisOutput
                }
            } else {
                Write-Host "Skipping non-user member: $($member.SamAccountName)"
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status           = 'Failed'
            ResultMessage    = $self.ResultMessage -f $outputObjects.Count
            ResultObjects    = $outputObjects
            Remediation      = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status          = 'Passed'
            ResultMessage   = "All members in privileged groups have adminCount equal to 1."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status          = 'Error'
        ErrorMessage    = $_.Exception.Message
    }
}

return $res
