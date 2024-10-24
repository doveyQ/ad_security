[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DomainName
)

$Global:self = @{
    ID = 80
    UUID = 'eb99e786-3ce1-4172-9801-dd4203cfd3e2'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000080'
    Name = 'Write access to RBCD on krbtgt account'
    ScriptName = 'RBCDWriteOnkrbtgt'
    Description = 'This indicator looks for Write access on RBCD for the krbtgt account to users who are not in Domain Admins, Enterprise Admins and Built-in Admins groups.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    ResultMessage = 'Found {0} principals that can write to msds-AllowedToActOnBehalfOfOtherIdentity on krbtgt.'
    Remediation = 'Review the list and ensure that there are no unnecessary principals who can set resource-based constrained delegation on krbtgt.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Access'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Identity'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
}

$outputObjects = @()
$krbtgt = Get-ADUser -Identity 'krbtgt' -Properties msds-AllowedToActOnBehalfOfOtherIdentity

if ($krbtgt.'msds-AllowedToActOnBehalfOfOtherIdentity') {
    $acl = (Get-Acl -Path "AD:\$($krbtgt.DistinguishedName)").Access
    $filteredAces = $acl | Where-Object { 
        $_.ObjectType -eq 'msds-AllowedToActOnBehalfOfOtherIdentity' -and
        $_.ActiveDirectoryRights -match 'WriteProperty'
    }

    foreach ($ace in $filteredAces) {
        $user = Get-ADUser -Identity $ace.IdentityReference
        $userGroups = Get-ADUser -Identity $user | Get-ADGroup | Select-Object -ExpandProperty Name

        if ($user -notmatch $null) {
            $outputObjects += [PSCustomObject]@{
                DistinguishedName = $user.DistinguishedName
                Identity          = $user.SamAccountName
                Access            = 'Write access to msds-AllowedToActOnBehalfOfOtherIdentity'
            }
        }
    }
}

if ($outputObjects) {
    [PSCustomObject]@{
        ResultMessage = "Found $($outputObjects.Count) principals with write access to msds-AllowedToActOnBehalfOfOtherIdentity on krbtgt."
        ResultObjects = $outputObjects
        Status = 'Failed'
    }
} else {
    [PSCustomObject]@{
        ResultMessage = "No unauthorized principals found with write access on krbtgt."
        Status = 'Pass'
        ResultObjects = @()
    }
}
