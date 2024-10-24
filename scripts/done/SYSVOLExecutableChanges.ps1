# This script checks SYSVOL for recently changed executables across multiple domain controllers.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 101
    UUID = '9e036f83-4eba-48e8-9a5c-a399377ee6a1'
    Version = '1.124.1'
    CategoryID = 4
    ShortName = 'SI000101'
    Name = 'SYSVOL Executable Changes'
    ScriptName = 'SYSVOLExecutableChanges'
    Description = 'This indicator looks for modifications to executable files within SYSVOL. It only examines files and executables that have read access to them.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'Changes to the executable files within SYSVOL should be accounted for by the administrators. If the change can not be accounted for, investigate the change looking for potential weakening of security posture and why the change was made.'
    ResultMessage = 'Found {0} SYSVOL executables that have been recently modified.'
    Remediation = 'Ensure all recently created/modified executables are safe.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'FileDirectory'; Type = 'String'; IsCollection = $false },
        @{ Name = 'FileName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GPODisplayName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Execution', 'Persistence') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - File Analysis') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-A', 'DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}


$outputObjects = [System.Collections.ArrayList]@()
$startSearchWindow = (Get-Date).AddDays(-14)

$domainControllers = Get-ADDomainController -Filter * -Server $DomainName | Select-Object -ExpandProperty Hostname

try {
    foreach ($dc in $domainControllers) {
        $sysvolUNCPath = "\\$dc\SYSVOL\$DomainName"
        $sysvolLocalPath = "C:\Windows\SYSVOL\sysvol\$DomainName"
    
        $sysvolPath = if (Test-Path $sysvolUNCPath) {
            $sysvolUNCPath
        } elseif (Test-Path $sysvolLocalPath) {
            $sysvolLocalPath
        } else {
            Write-Host "SYSVOL path not found for domain controller: $dc"
            continue
        }
        Get-ChildItem -Path $sysvolPath -ErrorAction Stop | Out-Null

        # Get GPO mapping
        $searchBase = "CN=Policies,CN=System," + (Get-ADDomain -Identity $DomainName).DistinguishedName
        $gpoDict = Get-ADObject -Filter 'objectCategory -eq "groupPolicyContainer"' -SearchBase $searchBase -Properties displayName | 
            ForEach-Object {
                [PSCustomObject]@{
                    CN = $_.DistinguishedName -replace '^.*?CN=|\}.*$', ''
                    DisplayName = $_.displayName
                }
            }

        Get-ChildItem -Path $sysvolPath -Recurse | Where-Object {
            ($_.LastWriteTime -gt $startSearchWindow) -and
            ($_.Name -like '*.exe' -or $_.Name -like '*.ps1' -or $_.Name -like '*.bat' -or 
             $_.Name -like '*.dll' -or $_.Name -like '*.cmd' -or $_.Name -like '*.vbs')
        } | ForEach-Object {
            $gpoMatch = $gpoDict | Where-Object { $_.CN -eq $_.DirectoryName -replace '^.*?\\(\{.*?\}).*$', '$1' }
            $gpoDisplayNames = @()

            if ($gpoMatch.Count -gt 0) {
                foreach ($gpo in $gpoMatch) {
                    $gpoDisplayNames += $gpo.DisplayName
                }
            }

            $GPODisplayName = if ($gpoDisplayNames.Count -gt 0) {
                $gpoDisplayNames -join ', '
            } else {
                'No related GPO'
            }

            [void]$outputObjects.Add([PSCustomObject]@{
                FileName = $_.Name
                FileDirectory = $_.DirectoryName
                GPODisplayName = $GPODisplayName
                EventTimestamp = $_.LastWriteTime
            })
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
                ResultMessage = "No recently modified SYSVOL executables found."
            }
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
