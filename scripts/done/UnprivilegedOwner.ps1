[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 25
    UUID = '40499bf5-9087-4d55-9db3-2cb641a47ac8'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000025'
    Name = 'Privileged objects with unprivileged owners'
    ScriptName = 'UnprivilegedOwner'
    Description = 'If a privileged object (as determined by adminCount=1) is owned by an account that is unprivileged, then any compromise of that unprivileged account could result in those privileged objects'' delegation being modified, since owners can override any delegation on an object, if only temporarily.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'Most privileged objects are owned by privileged groups or users. But if a privileged object were to be owned by an unprivileged account, it could be easily taken over. And even though SDProp might correct any delegation done by an attacker who has compromised an owner, the attacker could have up to 1 hour to perform any changes on the privileged object (e.g. group membership changes or password changes) before SDProp corrects it.'
    ResultMessage = 'Found {0} privileged objects with unprivileged owner.'
    Remediation = 'Remove unprivileged owner from privileged objects.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Owner'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_permissions_adminsdholder') }
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
    $privilegedObjects = Get-ADObject -Filter { adminCount -eq 1 } -Properties DistinguishedName, ntSecurityDescriptor -Server $DomainName

    foreach ($privilegedObject in $privilegedObjects) {
        if ($privilegedObject.ntSecurityDescriptor) {
            $ownerName = $privilegedObject.ntSecurityDescriptor.Owner -replace '^.*\\', ''

            if ($ownerName -notin @("Domain Admins", "Enterprise Admins", "Administrator", "Administrators", "SYSTEM", "Administratoren")) {
                $outputObjects.Add([PSCustomObject]@{
                    DistinguishedName = $privilegedObject.DistinguishedName  # Use the correct DistinguishedName
                    Owner = $ownerName
                })
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status = "Failed"
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = "Passed"
            ResultMessage = "All privileged objects are owned by appropriate privileged accounts."
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
