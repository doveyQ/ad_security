# This script looks for GPOs with Group Policy Preference passwords stored in SYSVOL for a given domain.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 15
    UUID = '1d22bc08-5152-4e07-badf-3d0c15e5ecd9'
    Version = '1.124.1'
    CategoryID = 4
    ShortName = 'SI000015'
    Name = 'Reversible passwords found in GPOs'
    ScriptName = 'GPPrefPasswords'
    Description = 'This script searches for Group Policy Preference password entries ("Cpassword" entries) that are still in use and can be easily decrypted.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'Older systems may still store these passwords, which attackers can easily decrypt.'
    ResultMessage = 'Found {0} Group Policy Preference password entries.'
    Remediation = 'Remove any discovered GPO password entries to prevent exposure of credentials.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GPOName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GPOSide'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PolicyArea'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = @()
$DN = (Get-ADDomain -Identity $DomainName).DistinguishedName

try{
    $results = Get-ADObject -Filter { objectClass -eq 'groupPolicyContainer' -and (gPCMachineExtensionNames -like '*{91FBB303-0CD5-4055-BF42-E512A681B325}*' -or gPCMachineExtensionNames -like '*{AADCED64-746C-4633-A97C-D61349046527}*') } -SearchBase "CN=Policies,CN=System,$DN" -Properties gPCFileSysPath, DisplayName

    foreach ($gpo in $results) {
        $GPPFiles = Get-ChildItem -Path $gpo.gPCFileSysPath -Recurse -Include *.xml
        foreach ($GPPFile in $GPPFiles) {
            if (Select-String -Path $GPPFile.FullName -Pattern "cpassword") {
                $side = if ($GPPFile.DirectoryName -like "*machine*") { "Computer" } else { "User" }
                $area = switch ($GPPFile.Name.ToLower()) {
                    'services.xml' { "System Services" }
                    'scheduledtasks.xml' { "Scheduled Tasks" }
                    'groups.xml' { "Local Users and Groups" }
                    'datasources.xml' { "Data Sources" }
                    'drives.xml' { "Drives" }
                    Default { "Unknown" }
                }
                $outputObject = [PSCustomObject]@{
                    DomainName  = $DomainName
                    GPOName     = $gpo.DisplayName
                    GPOSide     = $side
                    PolicyArea  = $area
                }
                $outputObjects += $outputObject
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultObjects  = $outputObjects
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status        = "Passed"
            ResultMessage = $self.ResultMessage -f 0
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}
return $res
