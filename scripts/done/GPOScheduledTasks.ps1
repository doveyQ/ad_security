[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 316
    UUID = '20cacac3-f001-41ca-8a96-3dd02e429f37'
    Version = '1.124.1'
    CategoryID = 4
    ShortName = 'SI000316'
    Name = 'GPO with Scheduled Tasks configured'
    ScriptName = 'GPOScheduledTasks'
    Description = 'When a scheduled task launches an executable, it checks to see if low-privilege users have permissions to modify GPOs.'
    Weight = 2
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 2
    LikelihoodOfCompromise = 'Scheduled tasks configured through group policies can be risky if not set up correctly.'
    ResultMessage = 'Found {0} GPO set with Scheduled Tasks'
    Remediation = 'It is crucial to properly configure group policies with scheduled tasks and grant appropriate levels of access to users and groups in order to inhibit misuse and abuse.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Executable'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GPOFilePath'; Type = 'String'; IsCollection = $false },
        @{ Name = 'GpoName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LinkedOUs'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Result'; Type = 'String'; IsCollection = $false },
        @{ Name = 'RunLevel'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ScheduledTaskName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'TaskType'; Type = 'String'; IsCollection = $false },
        @{ Name = 'UserContext'; Type = 'String'; IsCollection = $false },
        @{ Name = 'UsersWithPrivOnFolder'; Type = 'String'; IsCollection = $false },
        @{ Name = 'UsersWithPrivOnFile'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Lateral Movement') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Detect - Script Execution Analysis', 'Detect - File Creation Analysis') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '2.5'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()

try {
    $domainSID = (Get-ADDomain $DomainName).DomainSID

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

    $gpoResults = Get-GPO -All | Where-Object { $_.DomainName -eq $DomainName }

    foreach ($gpo in $gpoResults) {
        $gpoFolderPath = "\\$($DomainName)\SYSVOL\$($DomainName)\Policies\{$($gpo.Id)}\User\Preferences\ScheduledTasks\"
        if (Test-Path $gpoFolderPath) {
            $xmlFiles = Get-ChildItem -Path $gpoFolderPath -Filter '*.xml'
            foreach ($xmlFile in $xmlFiles) {
                [xml]$taskFile = Get-Content $xmlFile.FullName

                $scheduledTasks = $taskFile.ScheduledTasks.Task

                foreach ($task in $scheduledTasks) {
                    $userContext = $task.Properties.userContext
                    $executables = $task.Properties.appName

                    if ($executables) {
                        $fileACL = Get-Acl -Path $executables -ErrorAction SilentlyContinue
                        $folderPath = Split-Path -Path $executables
                        $folderACL = Get-Acl -Path $folderPath -ErrorAction SilentlyContinue

                        $usersWithPrivOnFile = @()
                        if ($fileACL) {
                            foreach ($acl in $fileACL.Access) {
                                $sid = try {
                                    (New-Object System.Security.Principal.NTAccount($acl.IdentityReference)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                                } catch {
                                    $acl.IdentityReference.ToString()
                                }
                                if (-not $trustedSids.Contains($sid)) {
                                    $usersWithPrivOnFile += $acl.IdentityReference
                                }
                            }
                        }

                        $usersWithPrivOnFolder = @()
                        if ($folderACL) {
                            foreach ($acl in $folderACL.Access) {
                                $sid = try {
                                    (New-Object System.Security.Principal.NTAccount($acl.IdentityReference)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                                } catch {
                                    $acl.IdentityReference.ToString()
                                }
                                if (-not $trustedSids.Contains($sid)) {
                                    $usersWithPrivOnFolder += $acl.IdentityReference
                                }
                            }
                        }

                        $outputObjects.Add([PSCustomObject][Ordered]@{
                            GpoName              = $gpo.DisplayName
                            GPOPath              = $gpo.Path
                            ScheduledTaskName    = $task.Properties.name
                            UserContext          = $userContext
                            Executable           = $executables
                            UsersWithPrivOnFile  = ($usersWithPrivOnFile -join "; ")
                            UsersWithPrivOnFolder = ($usersWithPrivOnFolder -join "; ")
                        })
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
            ResultMessage = "No risky scheduled tasks found."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
