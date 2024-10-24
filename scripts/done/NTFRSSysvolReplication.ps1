# This script looks for indication of usage of FRS for sysvol replication

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 97
    UUID = 'ef678af3-8766-45f0-b4f7-7c3582bfea1a'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000097'
    Name = 'NTFRS SYSVOL Replication'
    ScriptName = 'NTFRSSysvolReplication'
    Description = 'This indicator looks for indication of usage of FRS for sysvol replication. Domain controllers are configured to use the NTFRS replication protocol (especially for SYSVOL replication). This protocol is obsolete and unnecessarily adds administrative interfaces to domain controllers. In addition, this protocol is no longer supported by the latest versions of Windows Server, which prevents migration to the latest versions.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'NTFRS is an older protocol that has been replaced by DFSR. Attackers that can manipulate NTFRS vulnerabilities to compromise SYSVOL can potentially change GPOs and logon scripts to propagate malware and move laterally across the environment.'
    ResultMessage = 'Found {0} domains that are suspected to use NTFRS for SYSVOL replication.'
    Remediation = 'This protocol is obsolete since Windows Server 2008. Migration instruction to DFSR are documented <a href=`"https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr`">here.</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DomainName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Lateral Movement') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_sysvol_ntfrs') }
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
    if (-not (Get-ADDomain $DomainName -ErrorAction SilentlyContinue)) {
        return [PSCustomObject]@{
            Status        = 'Error'
            ResultMessage = "The domain '$DomainName' is unavailable."
            ResultObjects = $null
        }
    }

    $currentDomain = (Get-ADDomainController).hostname
    $defaultNamingContext = (([ADSI]"LDAP://$currentDomain/rootDSE").defaultNamingContext)

    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=computer)(dNSHostName=$currentDomain))"
    $searcher.SearchRoot = "LDAP://$currentDomain/OU=Domain Controllers,$defaultNamingContext"
    $dcObjectPath = $searcher.FindAll() | ForEach-Object { $_.Path }

    $searchDFSR = New-Object DirectoryServices.DirectorySearcher
    $searchDFSR.Filter = "(&(objectClass=msDFSR-Subscription)(name=SYSVOL Subscription))"
    $searchDFSR.SearchRoot = $dcObjectPath
    $dfsrSubObject = $searchDFSR.FindAll()

    $searchFRS = New-Object DirectoryServices.DirectorySearcher
    $searchFRS.Filter = "(&(objectClass=nTFRSSubscriber)(name=Domain System Volume (SYSVOL share)))"
    $searchFRS.SearchRoot = $dcObjectPath
    $frsSubObject = $searchFRS.FindAll()

    if ($frsSubObject.Count -gt 0) {
        $frsPath = $frsSubObject | ForEach-Object { $_.Properties.frsrootpath }
        $output= [PSCustomObject][Ordered]@{
            DomainName                    = $DomainName
            SYSVOLReplicationMechanism     = 'FRS'
            Path                          = $frsPath -join ', '
        }
        [void]$outputObjects.Add($output)
    } elseif ($dfsrSubObject.Count -gt 0){
        $output= [PSCustomObject][Ordered]@{
            DomainName                    = $DomainName
            SYSVOLReplicationMechanism     = 'DFSR'
        }
        [void]$outputObjects.Add($output)    
    }

    if ($outputObjects.Count -gt 0 -and $outputObjects.SYSVOLReplicationMechanism -eq "FSR"){
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status        = "Passed"
            ResultMessage = "No FSR replication mechanisms for SYSVOL found. DFSR used!"
        }
    }
}
catch {
    return [PSCustomObject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
