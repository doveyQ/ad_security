[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 103
    UUID = '88725ad5-1a8c-43f7-a11f-a52b6eb3b601'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000103'
    Name = 'FGPP not applied to Group'
    ScriptName = 'FGPPNotAppliedToAGroup'
    Description = 'This indicator looks for FGPP targeted to a Universal or Domain Local group.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = 'Changing a group''s scope settings from Global group to Universal or Domain Local group, will result in FGPP settings no longer applying to that group, and decreasing its password security controls.'
    ResultMessage = 'Found {0} Group(s) with no FGPP applied to them.'
    Remediation = 'Confirm that the following groups should be Universal or Domain Local, otherwise change their scope settings to Global for FGPP to apply to them.<br><br>MITRE D3fend based on the reference: <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf" target="_blank">NIST.SP.800-63-3</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'AppliedFGGPPolicies'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'GroupType'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Persistence', 'Credential Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') }
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
    $fgppPolicies = Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object -Property AppliesTo, DistinguishedName

    $groups = Get-ADGroup -Filter { GroupScope -eq 'Universal' -or GroupScope -eq 'DomainLocal' } -Server $DomainName

    foreach ($group in $groups) {
        $groupDn = $group.DistinguishedName
        $appliedFGPP = $fgppPolicies | Where-Object { $_.AppliesTo -contains $groupDn }

        if (-not $appliedFGPP) {
            $thisOutput = [PSCustomObject][Ordered]@{
                DistinguishedName = $group.DistinguishedName
                GroupType = $group.Scope
                AppliedFGGPPolicies = ''
            }
            [void]$outputObjects.Add($thisOutput)
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
        $res = @{
            Status = 'Passed'
            ResultMessage = "All groups have FGPP applied."
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
