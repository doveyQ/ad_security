[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$DomainName
)

$Global:self = @{
    ID = 20
    UUID = 'b4ee6e7c-5b7c-4e63-82cd-668d3d0b3354'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000020'
    Name = 'Protected Users group not in use'
    ScriptName = 'ProtectedUsersNotUsed'
    Description = '<p>This indicator checks if privileged users are in the Protected Users security group.</p>'
    Weight = 1
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 1
    LikelihoodOfCompromise = '<p>The Protected Users security group was introduced in Server 2012 R2 Active Directory to minimize credential exposure for privileged accounts. As a defense in depth measure privileged accounts, such as Domain Admins, should be added to the Protected Users security group.</p><br /><p>Attackers targeting privileged accounts in Active Directory will find a much higher level of friction in certain types of attempts to compromise the accounts due to the protections offered.</p><h3>References</h3><p><a href="https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group" target="_blank">Protected Users Security Group | Microsoft Learn</a></p>'
    ResultMessage = 'Found {0} privileged users that are not members of the Protected Users group.'
    Remediation = '<p>It is recommended to ensure that all privileged users are members of the Protected Users security group.</p><br /><p>If the organization is already using the Protected Users security group functionality, is it recommended to add the identified privileged users.</p><br /><p>If the Active Directory schema is pre Server 2012 R2, this functionality does not exist, and it is recommended to upgrade the schema.</p><br /><p>For full details on the protections offered and the implementation of the Protected Users security group, please refer to the reference article.</p><h3>References</h3><p><a href="https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group" target="_blank">Protected Users Security Group | Microsoft Learn</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Enabled'; Type = 'Boolean'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'ANSSI'; Tags = @('vuln3_protected_users') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


try {
    $protectedUsersGroup = Get-ADGroup -Filter { Name -eq 'Protected Users' } -Server $DomainName
    if (-not $protectedUsersGroup) {
        Write-Host "Protected Users group not found in domain: $DomainName"
        return
    }

    $protectedUsersDN = $protectedUsersGroup.DistinguishedName

    $outputObjects = Get-ADUser -Filter { adminCount -eq 1 -and SamAccountName -ne 'krbtgt' } -Properties SamAccountName, MemberOf, userAccountControl |
        Where-Object { $_.MemberOf -notcontains $protectedUsersDN } |
        ForEach-Object {
            [PSCustomObject]@{
                DistinguishedName = $_.DistinguishedName
                SamAccountName    = $_.SamAccountName
                Enabled           = (-not ($_.userAccountControl -band 2))
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
            ResultMessage = "No privileged users found outside the Protected Users group."
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
