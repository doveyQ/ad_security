[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 351
    UUID = 'd6456fa7-456b-4cde-a8ef-9de5903d0419'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000351'
    Name = 'Shadow Credentials on privileged objects'
    ScriptName = 'ShadowCredentials'
    Description = 'This indicator looks for users with write access to the msDS-KeyCredentialLink attribute of privileged users and DCs.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'Attackers who can write to these privileged objects and Kerberos PKINIT is enabled will be able to elevate privileges to them.'
    ResultMessage = 'Found {0} privileged objects that can have their msDS-KeyCredentialLink written to.'
    Remediation = 'Make sure these users should have this write access and that it is necessary, if it''s not remove them.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'UsersWithWriteAccess'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Lateral Movement') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - User Account Permissions') }
    )
    Products = @(
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

try {
    $outputObjects = @()

    $privilegedUsers = Get-ADObject -Filter { adminCount -eq 1 } -Properties DistinguishedName
    $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty ComputerObjectDN

    $allPrivilegedObjects = $privilegedUsers.DistinguishedName + $domainControllers

    $msDSKeyCredentialLinkGuid1 = [Guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'
    $msDSKeyCredentialLinkGuid2 = [Guid]'9b026da6-0d3c-465c-8bee-5199d7165cba'

    foreach ($obj in $allPrivilegedObjects) {
        $acl = Get-Acl -Path "AD:$obj"
        foreach ($ace in $acl.Access) {
            if (($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -and
                ($ace.ObjectType -eq $msDSKeyCredentialLinkGuid1 -or $ace.ObjectType -eq $msDSKeyCredentialLinkGuid2) -and
                $ace.AccessControlType -eq 'Allow') {
                
                $userWithWriteAccess = $ace.IdentityReference

                if ($userWithWriteAccess -is [System.Security.Principal.NTAccount]) {
                    $user = $userWithWriteAccess.Value

                    $thisOutput = [PSCustomObject]@{
                        DistinguishedName    = $obj
                        UsersWithWriteAccess = $user
                    }
                    $outputObjects += $thisOutput
                } else {
                    Write-Host "Unexpected ACE IdentityReference type: $($userWithWriteAccess.GetType().FullName)"
                }
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }

    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No objects found with write access to msDS-KeyCredentialLink or related attributes."
        }
    }
} catch {
    return [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
