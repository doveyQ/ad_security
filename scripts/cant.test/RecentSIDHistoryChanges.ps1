# This script looks for recent changes on sIDHistory attribute

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 60
    UUID = '7f12a52e-87a4-40c3-8e80-431934743207'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000060'
    Name = 'Recent sIDHistory changes on objects'
    ScriptName = 'RecentSIDHistoryChanges'
    Description = '<p>This indicator checks for any recent changes to sIDHistory on objects.</p>'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = '<p>Security Identifier (SID) history is used by Active Directory to maintain access rights during domain migrations.</p><br /><p>An attacker can abuse SID history by injecting a privileged SID into the sIDHistory of another user object, allowing the user to act with the same privileges. Writing to the sIDHistory does require privileges in Active Directory, so it is likely that Active Directory is already compromised; this method is primarily used by an attacker for gaining persistence.</p><h3>Resources</h3><p><a href="https://www.semperis.com/blog/how-to-defend-against-sid-history-injection/" target="_blank">How to Defend Against SID History Injection | Semperis Guides</a></p>'
    ResultMessage = 'Found {0} objects with sIDHistory attribute changes in the last {1} months.'
    Remediation = '<p>If the identified SID is known due to efforts such as migration, ensure that it is known and documented, and also understand the risk involved of retaining this sIDHistory.</p><br /><p>If the identified SID is unknown and there is not a clear chain of ownership of the change, the user identified should be treated as highly suspicious, as this may be a strong sign of a compromise of Active Directory. Organizations should start further investigation into the integrity of their Active Directory.</p><h3>Resources</h3><p><a href="https://www.semperis.com/blog/how-to-defend-against-sid-history-injection/" target="_blank">How to Defend Against SID History Injection | Semperis Guides</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Attribute'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SIDHistory'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_sidhistory_dangerous') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}
$monthsToRemove = 6
$startOriginatingChangeThreshold = (Get-Date).AddMonths(-$monthsToRemove)
$outputObjects = @()

try {
    $searchRoot = (Get-ADDomain -Identity $DomainName).DistinguishedName
    $results = Get-ADObject -Filter { sIDHistory -like "*" } -SearchBase $searchRoot -Properties sIDHistory, whenChanged | Where-Object { 
        $_.whenChanged -ge $startOriginatingChangeThreshold 
    }

    foreach ($result in $results) {
        $sIDHistory = $result.sIDHistory -join ";"
        $thisOutput = [pscustomobject]@{
            DistinguishedName = $result.DistinguishedName
            Attribute = "sIDHistory"
            EventTimestamp = $result.whenChanged
            SIDHistory = $sIDHistory
        }
        $outputObjects += $thisOutput
    }


    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status        = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count, $monthsToRemove
            ResultObjects = $outputObjects
            Remediation   = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status        = 'Passed'
            ResultMessage = "No objects with sIDHistory attribute changes in the last $($monthsToRemove) months found."
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