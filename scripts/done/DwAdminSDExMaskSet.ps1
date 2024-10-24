# Checks if dwAdminSDExMask mask on dSHeuristics has been set--indicating some change to SDProp behavior that could compromise security

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 53
    UUID = 'f2f975fd-6ce2-491b-8247-9662a0126187'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000053'
    Name = 'Operator groups no longer protected by AdminSDHolder and SDProp'
    ScriptName = 'DwAdminSDExMaskSet'
    Description = 'This indicator checks if dwAdminSDExMask mask on dsHeuristics has been set, which indicates a change to the SDProp behavior that could compromise security. Certain groups can be removed from SDProp protection with this setting.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = 'Normally the default behavior for AdminSDHolder SDProp should be left intact. If its behavior is modified, this could indicate an attempt at defense evasion.'
    ResultMessage = 'Found non-default configuration on the forest for SDProp''s protected groups.'
    Remediation = 'Set dwAdminSDExMask flag (16th byte) on dsHeuristics to 0 or SDProp (AdminSDHolder) behavior will not fully apply to Operator groups. For more information see <a href=`"https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5`">6.1.1.2.4.1.2 dSHeuristics</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DSHeuristics'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GroupsExcluded'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LastChanged'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - User Account Permissions') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_dsheuristics_bad') }
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
$failcount = 0

try {
    $DN = (Get-ADDomain -Identity $DomainName).DistinguishedName
    $searchParams = @{
        Filter = "objectClass -eq 'nTDSService'"
        Properties = @("whenChanged", "dsHeuristics")
        SearchBase = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DN"
    }

    $result = Get-ADObject @searchParams -ErrorAction Stop

    if ($result) {
        if ($null -ne $result.dSHeuristics) {
            [array]$flag = $result.dSHeuristics.ToString().ToCharArray()
            if ($flag.Count -ge 16 -and $flag[15] -ne "0") {
                $grouplist = @()

                if ("0123456789abcdef" -match $flag[15]) {
                    $operatorflag = [Convert]::ToInt32($flag[15], 16)

                    $operatorgroups = @{
                        1  = "Account Operators"
                        2  = "Server Operators"
                        4  = "Print Operators"
                        8  = "Backup Operators"
                    }

                    foreach ($key in $operatorgroups.Keys) {
                        if ($operatorflag -band $key) {
                            $grouplist += $operatorgroups[$key]
                        }
                    }
                } else {
                    $grouplist += "Invalid value"
                }

                $thisOutput = [PSCustomObject]@{
                    DistinguishedName = $result.DistinguishedName
                    DSHeuristics = $result.dSHeuristics
                    GroupsExcluded = $grouplist -join ", "
                    LastChanged = $result.whenchanged
                }
                [void]$outputObjects.Add($thisOutput)
                $failcount++
            }
        } else {
            $thisOutput = [PSCustomObject]@{
                DSHeuristics = "Not Set"
                GroupsExcluded = "None"
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
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No non-default configurations found."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
