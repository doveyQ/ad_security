[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 314
    UUID = 'c4a19ff8-3bfd-46f9-b215-2b6c0179b0aa'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000314'
    Name = 'Unexpected accounts in Cert Publishers Group'
    ScriptName = 'AccountsInCertPublishers'
    Description = 'This indicator checks to see if the Cert Publishers Group contains members that aren''t expected to be there.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'Individuals belonging to Cert Publishers Group have the ability to introduce a potentially harmful Certificate Authority (CA) within an ADCS environment, that will be trusted by all clients. Although certificates issued by this CA may not receive automatic trust for client authentication via PKINIT or SChannel, they remain susceptible to exploitation for other malicious purposes. The combination of Cert Publishers membership and write access to NTAuthcertificates poses the greatest risk in such situations, allowing the forging and solicitation of certificates for client authentication against any user in the domain.'
    ResultMessage = 'Found {0} unexpected members in Cert Publishers Group'
    Remediation = 'After careful investigation, remove any accounts that do not belong from the Cert Publishers Group.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        
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
    IgnoreListSupport = $false
    Selected = 1
}


$outputObjects = @()

$res = [PSCustomObject]@{
    Status         = 'Not Executed'
    ResultMessage  = ''
    Remediation    = ''
}

try {
    $privilegedGroups = @(
        "CN=Enterprise Admins,CN=Users,DC=$($DomainName -replace '\.', ',DC=')",
        "CN=Domain Admins,CN=Users,DC=$($DomainName -replace '\.', ',DC=')",
        "CN=DnsAdmins,CN=Users,DC=$($DomainName -replace '\.', ',DC=')",
        "CN=Account Operators,CN=Users,DC=$($DomainName -replace '\.', ',DC=')",
        "CN=Backup Operators,CN=Users,DC=$($DomainName -replace '\.', ',DC=')",
        "CN=Schema Admins,CN=Users,DC=$($DomainName -replace '\.', ',DC=')",
        "CN=Administrators,CN=Builtin,DC=$($DomainName -replace '\.', ',DC=')"
    )

    $certPublishersGroupMembers = Get-ADGroupMember -Identity "Cert Publishers" -Server $DomainName

    $unexpectedMembers = $certPublishersGroupMembers | Where-Object {
        if ($_.objectClass -eq 'user') {
            $userGroups = (Get-ADUser $_.DistinguishedName -Server $DomainName -Properties MemberOf).MemberOf
            $isPrivileged = $false
            foreach ($privilegedGroup in $privilegedGroups) {
                if ($userGroups -contains $privilegedGroup) {
                    $isPrivileged = $true
                    break
                }
            }
            return -not $isPrivileged
        }
    }

    $unexpectedMembers | ForEach-Object {
        $outputObjects += [PSCustomObject]@{
            MemberName     = $_.Name
            SamAccountName = $_.SamAccountName
            Group          = "Cert Publishers"
            Domain         = $DomainName
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
            Status         = "Passed"
            ResultMessage  = "No unexpected members found in Cert Publishers Group"
        }
    }
}

catch {
    $res = [PSCustomObject]@{
        Status        = "Error"
        ResultMessage = $_.Exception.Message
    }
}

return $res
