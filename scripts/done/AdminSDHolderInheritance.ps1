# This script looks at AdminSDHolder object to see if inheritance is enabled (it should not be)

[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 106
    UUID = '216596bf-333e-4f59-a3f5-8af65acbba9b'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000106'
    Name = 'Inheritance enabled on AdminSDHolder object'
    ScriptName = 'AdminSDHolderInheritance'
    Description = '<p>This indicator checks for inheritance enabled on the access control list (ACL) of the AdminSDHolder object.</p>'
    Weight = 10
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 10
    LikelihoodOfCompromise = '<p>The AdminSDHolder object in Active Directory holds the permissions that will be applied to privileged groups and users, including Domain Admins. By default, permissions on privileged users are more restrictive to protect them from compromise. If an organization adjusts the permissions on the AdminSDHolder object, including enabling inheritance, they may weaken the security of these privileged users.</p><br /><p>An attacker may discover these weaker permissions on privileged users and groups, and with a greater surface area, an attacker has a stronger chance of formulating attack paths to compromise users such as a Domain Admin, and then compromising Active Directory.</p><h3>References</h3><p><a href="https://www.semperis.com/resources/improving-your-active-directory-security-posture-adminsdholderto-the-rescue/" target="_blank">AdminSDHolder to improve Active Directory Security | Semperis</a></p>'
    ResultMessage = 'Found {0} domains containing an AdminSDHolder container with inheritance enabled.'
    Remediation = '<p>Organizations should investigate the permissions on the AdminSDHolder object if inheritance is enabled, and use attack path analysis software, such as Forest Druid, to analyze attack paths to privileged users in Active Directory.</p><br /><p>Organizations, if changing the permissions on AdminSDHolder, should have an established process in place for awareness.</p><br /><p>Unplanned changes to AdminSDHolder should be considered <b>highly suspicious</b> and <b>must</b> be investigated further. Unplanned changes to AdminSDHolder are a <b>very strong indicator</b> of compromise of Active Directory.</p><h3>References</h3><p><a href="https://www.semperis.com/resources/improving-your-active-directory-security-posture-adminsdholderto-the-rescue/" target="_blank">AdminSDHolder to improve Active Directory Security | Semperis</a></p><br /><p><a href="https://www.semperis.com/blog/7-active-directory-misconfigurations-to-find-and-fix-now/" target="_blank">7 Active Directory Misconfigurations to Find and Fix—Now - Semperis</a></p><br /><p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory" target="_blank">Appendix C - Protected Accounts and Groups in Active Directory | Microsoft Learn</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Attribute'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LastChanged'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion', 'Privilege Escalation') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


$outputObjects = @()

try {
    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,DC=$($DomainName -replace '\.', ',DC=')"

    $inheritanceEnabled = Get-ADObject -Filter * -SearchBase $adminSDHolderDN -Properties ntSecurityDescriptor | 
        Select-Object DistinguishedName,@{Name="InheritanceEnabled";Expression={If ($_.ntSecurityDescriptor.AreAccessRulesProtected) {$False} Else {$True}}}

    if($inheritanceEnabled.InheritanceEnabled -eq $true){
        $outputObjects += [PSCustomObject]@{
            DistinguishedName = $adminSDHolderDN
            InheritanceEnabled = $inheritanceEnabled
        }

        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject][Ordered]@{
            Status = "Passed"
            ResultMessage = "Inheritance on AdminSDHolder is not enabled"
        }
    }
}
catch {
    $res = [PSCustomObject][Ordered]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res

