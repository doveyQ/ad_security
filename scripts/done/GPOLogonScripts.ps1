[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 305
    UUID = 'd79f37e5-c83b-4ae6-9858-bb45a2291bc3'
    Version = '1.124.1'
    CategoryID = 4
    ShortName = 'SI000305'
    Name = 'GPO Logon Scripts Permissions Check'
    ScriptName = 'GPOLogonScriptsPermissions'
    Description = 'This indicator checks the permissions of logon scripts configured in GPOs.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'Potential unauthorized code execution via misconfigured logon scripts.'
    ResultMessage = 'Found {0} GPO logon scripts with issues.'
    Remediation = 'Review the permissions of the identified logon scripts and ensure they are appropriate.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'ScriptPath'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Policy'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PolicyName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Result'; Type = 'String'; IsCollection = $false },
        @{ Name = 'UsersWithPrivOnFolder'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @()
    Products = @()
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()
$domainSID = (Get-ADDomain -Server $DomainName).DomainSID.Value

$trustedSids = @(
    "S-1-3-0", "S-1-3-1", "S-1-3-4", "S-1-5-9", "S-1-5-18", "S-1-5-19", "S-1-5-20",
    "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", 
    "S-1-5-32-551", "S-1-5-32-552", "S-1-16-12288", "S-1-16-16384", 
    "S-1-16-20480", "S-1-16-28672", "S-1-5-32-557", "S-1-5-32-562", 
    "S-1-5-32-577", "S-1-5-32-578", "S-1-5-32-580", "S-1-5-32-545",         
    "$domainSID-500", # Domain Administrator
    "$domainSID-502", # KRBTGT
    "$domainSID-512", # Domain Admins
    "$domainSID-515", # Domain Computers
    "$domainSID-516", # Domain Controllers
    "$domainSID-518", # Schema Admins (root domain)
    "$domainSID-519", # Enterprise Admins (root domain)
    "$domainSID-521", # Read-Only Domain Controllers
    "$domainSID-498", # Enterprise Read-Only Domain Controllers
    "S-1-5-18",       # SYSTEM (non-domain specific)
    "S-1-5-19",       # LOCAL SERVICE (non-domain specific)
    "S-1-5-20",       # NETWORK SERVICE (non-domain specific)
    "S-1-5-9"         # Enterprise Domain Controllers
)

function Get-Scripts($ExtData, $GPO, $Scope) {
    $ArrResult = @()
    ForEach ($ExtensionData in $ExtData) {
        If ($ExtensionData.Name -eq "Scripts") {
            $GPOScripts = $ExtensionData.Extension.Script
            ForEach ($GPOScript in $GPOScripts) {
                $GPOScriptConfig = New-Object PSObject -Property @{
                    GPO       = $GPO.Name
                    Name      = $GPOScript.Command
                    Type      = $GPOScript.Type
                }
                $ArrResult += $GPOScriptConfig
            }
        }
    }
    return $ArrResult
}

try {
    $gpoReports = Get-GPO -All | Get-GPOReport -ReportType Xml
    $scripts = @()

    foreach ($report in $gpoReports) {
        $GPO = ([xml]$report).GPO
        $ExtData = $GPO.Computer.ExtensionData
        $scripts += Get-Scripts $ExtData $GPO "Computer"

        $ExtData = $GPO.User.ExtensionData
        $scripts += Get-Scripts $ExtData $GPO "User"
    }

    foreach ($script in $scripts) {
        $scriptPath = $script.Name

        if (Test-Path -Path $scriptPath) {
            $fileACL = Get-Acl -Path $scriptPath -ErrorAction SilentlyContinue
            if ($fileACL) {
                $usersWithPrivileges = [System.Collections.ArrayList]@()
                foreach ($acl in $fileACL.Access) {
                    $sid = try {
                        (New-Object System.Security.Principal.NTAccount($acl.IdentityReference)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch {
                        $acl.IdentityReference.ToString()
                    }

                    if (-not $trustedSids.Contains($sid)) {
                        $usersWithPrivileges.Add($acl.IdentityReference)
                    }
                }

                if ($usersWithPrivileges.Count -gt 0) {
                    $outputObjects += [PSCustomObject] @{
                        ScriptPath            = $scriptPath
                        Policy                = $script.GPO
                        Result                = "Script exists but has low-privileged users."
                        UsersWithPrivOnFolder = ($usersWithPrivileges -join "; ")
                    }
                }
            }
        } else {
            $folderPath = Split-Path -Path $scriptPath
            $folderACL = Get-Acl -Path $folderPath -ErrorAction SilentlyContinue
            if ($folderACL) {
                $usersWithFolderPrivileges = [System.Collections.ArrayList]@()
                foreach ($acl in $folderACL.Access) {
                    $sid = try {
                        (New-Object System.Security.Principal.NTAccount($acl.IdentityReference)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch {
                        $acl.IdentityReference.ToString()
                    }

                    if (-not $trustedSids.Contains($sid)) {
                        $usersWithFolderPrivileges.Add($acl.IdentityReference)
                    }
                }

                if ($usersWithFolderPrivileges.Count -gt 0) {
                    $outputObjects += [PSCustomObject] @{
                        ScriptPath            = $scriptPath
                        Policy                = $script.GPO
                        Result                = "Script does not exist, but parent folder has privileged users."
                        UsersWithPrivOnFolder = ($usersWithFolderPrivileges -join "; ")
                    }
                }
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status        = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation   = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status        = 'Passed'
            ResultMessage = "No dangerous logon script paths found."
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
