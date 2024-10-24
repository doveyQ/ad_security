[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 150
    UUID = '681db401-004b-4cec-a4b8-07926a63e281'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000150'
    Name = 'Operators Groups that are not empty'
    ScriptName = 'OperatorsGroupsAreNotEmpty'
    Description = '<p>This indicator checks if the Account Operators, Server Operators, Backup Operators and Print Operators groups in Active Directory are populated.</p>'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = '<p>The operator groups in Active Directory, Account Operators, Server Operators, Backup Operators, and Print Operators, all provide users within these groups certain privileges over different critical domain resources in Active Directory and different levels of access to domain controllers.</p><br /><p>An attacker may target users in these groups for further privilege escalation and lateral movement in Active Directory.</p><h3>References</h3><p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups" target="_blank">Active Directory security groups | Microsoft Learn</a></p>'
    ResultMessage = 'Found {0} Members in Operator Groups'
    Remediation = '<p>Organizations should evaluate the use of these groups, and work to reduce and remove membership of these groups.</p><br /><p>Organizations that are using these groups should implement an appropriate rights delegation to the necessary OUs in Active Directory as an alternative. For Backup Operators, organizations should implement a different group and manage access to lower tier servers or workstations through group policy objects.</p><br /><p>If the organization accepts the risk of these groups being populated, they should use attack path analysis software, such as Forest Druid, to determine the attack paths that exist due to the population of these groups, and further consider members of this group to be Tier 0.</p><h3>References</h3><p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups" target="_blank">Active Directory security groups | Microsoft Learn</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'MemberDistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GroupDistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Credential Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - User Account Permissions') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.5'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()
$failedDomainCount = 0

$operatorGroups = @(
    @{ Name = 'Account Operators'; SID = 'S-1-5-32-548' },
    @{ Name = 'Server Operators'; SID = 'S-1-5-32-549' },
    @{ Name = 'Print Operators'; SID = 'S-1-5-32-550' },
    @{ Name = 'Backup Operators'; SID = 'S-1-5-32-551' },
    @{ Name = 'Cryptographic Operators'; SID='S-1-5-32-569'},
    @{ Name = 'Network Configuration Operators'; SID='S-1-5-32-556'}
)

try {
    foreach ($groupInfo in $operatorGroups) {
        try {
            $groupMembers = Get-ADGroupMember -Identity $groupInfo.Name -Recursive | Where-Object { $_.objectClass -eq 'user' }
            foreach ($member in $groupMembers) {
                $thisOutput = [PSCustomObject]@{
                    MemberDistinguishedName = $member.DistinguishedName
                    GroupDistinguishedName  = $groupInfo.Name
                    DomainName              = $DomainName
                }
                [void]$outputObjects.Add($thisOutput)
            }
        } catch {
            Write-Warning "Failed to retrieve members of group $($groupInfo.Name): $_"
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
            Status        = 'Passed'
            ResultMessage = "No members found in Operator Groups"
        }
    }

    if ($failedDomainCount -gt 0) {
        $res.Status = 'Error'
        $res.ResultMessage += " Failed to run because the following domains were unavailable."
    }
}
catch {
    $res = [PSCustomObject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
