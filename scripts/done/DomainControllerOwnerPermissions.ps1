# This script checks that domain controllers have either the enterprise admins, domain admins or administrator as owner
[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 50
    UUID = 'd2df85d9-abbc-4585-be11-123a6d90a871'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000050'
    Name = 'Domain Controller owner is not an administrator'
    ScriptName = 'DomainControllerOwnerPermissions'
    Description = 'This indicator looks for Domain Controller computer accounts whose owner is not a Domain Admins, Enterprise Admins, or built-in Administrator account.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'Control of DC machine accounts allows for an easy path to compromising the domain. While Domain Controller objects are typically created during DCPromo by privileged accounts, if an accidental ownership change occurs on a DC object, it can have large consequences for security of the domain, since object owners can change permissions on the object to perform any number of actions.'
    ResultMessage = 'Found {0} domain controllers with non-default owners.'
    Remediation = 'Ensure that only privileged Tier 0 admin accounts and the domain''s built-in groups, such as Enterprise Admins, Domain Admins, and Administrators, have ownership of Domain Controller computer objects. Any unrecognized owner may be a sign of compromise.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Owner'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - System Configuration Permissions') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_permissions_dc') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


$outputObjects = [System.Collections.ArrayList]@()

try {
    $domainControllers = Get-ADDomainController -Filter * -Server $DomainName | Select-Object -ExpandProperty Name

    $results = Get-ADComputer -Filter * -Properties ntSecurityDescriptor -PipelineVariable p -Server $DomainName | 
        Where-Object { $domainControllers -contains $_.Name } |
        Select-Object -ExpandProperty ntSecurityDescriptor |
        Select-Object @{n="Computer";e={ $p.Name }}, @{n="Owner";e={ $_.Owner }}

    if ($results) {
        foreach ($result in $results) {
            $ownerName = $result.Owner -replace '^.*\\', ''

            if ($ownerName -notin @("Domain Admins", "Enterprise Admins", "Administrator", "Administrators", "Administratoren")) {
                $outputObjects.Add([PSCustomObject][Ordered]@{
                    DistinguishedName = $result.Computer
                    Owner = $result.Owner
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
            Status = "Passed"
            ResultMessage = "All Domain Controller Owners are either Enterprise Admins, Domain Admins or Administrator."
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
