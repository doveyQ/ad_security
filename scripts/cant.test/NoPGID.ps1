[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 78
    UUID = 'f7659564-5968-4ea6-acb2-ce5abd47d8f6'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000078'
    Name = 'Users and computers without readable PGID'
    ScriptName = 'NoPGID'
    Description = 'This indicator finds users and computers for whom it can''t read the PGID.'
    Weight = 5
    Severity = 'Warning'
    ResultMessage = 'Found {0} objects whose Primary Group ID cannot be queried.'
    Remediation = 'Ensure that these objects are known and legitimate and check their nTSecurityDescriptor to see if some ACE is causing the Primary Group ID attribute to be unreadable.'
}

$outputObjects = [System.Collections.ArrayList]@()
$everyoneSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")

try {
    $DN = (Get-ADDomain -Identity $DomainName).DistinguishedName

    $userFilter = "objectClass -eq 'user' -and objectCategory -eq 'person'"
    $computerFilter = "objectClass -eq 'computer'"

    $searchParams = @{
        Filter = "($userFilter) -or ($computerFilter)"
        Properties = @("distinguishedName", "samAccountName", "primaryGroupID", "objectSid", "objectClass")
        SearchBase = $DN
        SearchScope = "Subtree"
    }

    $results = Get-ADObject @searchParams -ErrorAction Stop

    foreach ($result in $results) {
        $pgidReadable = $true

        try {
            $target = [ADSI]"LDAP://$($result.DistinguishedName)"
            $objectSecurity = $target.PsBase.ObjectSecurity

            $denyRules = $objectSecurity.Access | Where-Object {
                $_.IdentityReference -eq $everyoneSID -and $_.AccessControlType -eq "Deny" -and 
                $_.ActiveDirectoryRights -eq "ReadProperty" -and 
                $_.ObjectType -eq "bf967a00-0de6-11d0-a285-00aa003049e2"
            }

            if ($denyRules.Count -gt 0) {
                $pgidReadable = $false
            }
        } catch {
            $pgidReadable = $false
        }

        if (-not $pgidReadable) {
            $thisOutput = [PSCustomObject]@{
                DistinguishedName = $result.DistinguishedName
                SamAccountName    = $result.SamAccountName
            }
            [void]$outputObjects.Add($thisOutput)
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
            ResultMessage = "No objects found whose Primary Group ID cannot be queried."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
