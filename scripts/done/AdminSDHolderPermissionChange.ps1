# This script looks for permissions changes on AdminSDHolder that occurred in the last 6 months

[CmdletBinding()]
param(
    [Parameter(Mandatory='True')][string]$DomainName
)

$Global:self = @{
    ID = 55
    UUID = '39293315-4817-44f6-be2d-e76daeaf8208'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000055'
    Name = 'Permission changes on AdminSDHolder object'
    ScriptName = 'AdminSDHolderPermissionChange'
    Description = '<p>This indicator checks for inheritance modifications on the access control list (ACL) of the AdminSDHolder object.</p>'
    Weight = 10
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 10
    LikelihoodOfCompromise = '<p>The AdminSDHolder object in Active Directory holds the permissions that will be applied to privileged groups and users, including Domain Admins. By default, permissions on privileged users are more restrictive to protect them from compromise. If an organization adjusts the permissions on the AdminSDHolder object, they may weaken the security of these privileged users.</p><br /><p>An attacker may discover these weaker permissions on privileged users and groups, and with a greater surface area, an attacker has a stronger chance of formulating attack paths to compromise users such as a Domain Admin, and then compromising Active Directory.</p><h3>References</h3><p><a href="https://www.semperis.com/resources/improving-your-active-directory-security-posture-adminsdholderto-the-rescue/" target="_blank">AdminSDHolder to improve Active Directory Security | Semperis</a></p>'
    ResultMessage = 'Found {0} domains with AdminSDHolder container permission changes in the last 6 months.'
    Remediation = '<p>Organizations should investigate the permissions on the AdminSDHolder object if modified, and use attack path analysis software, such as Forest Druid, to analyze attack paths to privileged users in Active Directory.</p><br /><p>Organizations, if changing the permissions on AdminSDHolder, should have an established process in place for awareness.</p><br /><p>Unplanned changes to AdminSDHolder should be considered <b>highly suspicious</b> and <b>must</b> be investigated further. Unplanned changes to AdminSDHolder are a <b>very strong indicator</b> of compromise of Active Directory.</p><h3>References</h3><p><a href="https://www.semperis.com/resources/improving-your-active-directory-security-posture-adminsdholderto-the-rescue/" target="_blank">AdminSDHolder to improve Active Directory Security | Semperis</a></p><br /><p><a href="https://www.semperis.com/blog/7-active-directory-misconfigurations-to-find-and-fix-now/" target="_blank">7 Active Directory Misconfigurations to Find and Fix—Now - Semperis</a></p><br /><p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory" target="_blank">Appendix C - Protected Accounts and Groups in Active Directory | Microsoft Learn</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Attribute'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion', 'Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_permissions_adminsdholder', 'vuln1_privileged_members_perm') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


try {

    $lastOriginatingChangeThreshold = (Get-Date).AddMonths(-6)

        
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,DC=$($DomainName -replace '\.', ',DC=')"

    $adminSDHolder = Get-ADObject -Identity $adminSDHolderDN -Properties ntSecurityDescriptor, whenChanged

    if ($adminSDHolder.whenChanged -gt $lastOriginatingChangeThreshold) {
        $thisOutput = [PSCustomObject]@{
            DistinguishedName = $adminSDHolder.DistinguishedName
            Attribute = "ntSecurityDescriptor"
            EventTimestamp = $adminSDHolder.whenChanged
        }
        $outputObjects += $thisOutput
    }

    if ($outputObjects) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = "Passed"
            ResultMessage = "No changes found on AdminSDHolder permissions in the last 6 months."        }
    }

} catch {
    $res = [PSCustomObject][Ordered]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res
