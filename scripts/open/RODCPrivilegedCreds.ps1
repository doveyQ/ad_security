﻿# This script checks if privileged users have credentials cached on RODCs

[CmdletBinding()]
param(
    [Parameter(Mandatory,ParameterSetName='Execution')][string]$ForestName,
    [Parameter(Mandatory,ParameterSetName='Execution')][string[]]$DomainNames,
    [Parameter(ParameterSetName='Execution')]$StartAttackWindow,
    [Parameter(ParameterSetName='Execution')]$EndAttackWindow,
    [Parameter(ParameterSetName='Metadata',Mandatory)][switch]$Metadata
)

$Global:self = @{
    ID = 138
    UUID = '5442096e-aee4-4fea-ab7d-a121ea528742'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000138'
    Name = 'Privileged user credentials cached on RODC'
    ScriptName = 'RODCPrivilegedCreds'
    Description = '<p>This indicator checks for privileged user credentials that are cached to RODCs.</p>'
    Weight = 4
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 4
    LikelihoodOfCompromise = '<p>In many instances, read-only domain controllers (RODCs) are deployed in area where there is a lower level of physical security to the servers.</p><br /><p>Attackers may try to target read-only domain controllers due to the lower level of security around these. While it is not a direct indicator of an attack, credentials for privileged users should not be cached on RODCs in the case the domain controller is compromised.</p><h3>References</h3><p><a href="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc753223(v=ws.10)" target="_blank">RODC Features | Microsoft Learn</a></p>'
    ResultMessage = 'Found {0} privileged users with credentials cached to an RODC.'
    Remediation = '<p>It is recommended to adjust the password replication policy on the RODC to deny replication of credentials for the identified privileged users.</p><br /><p>You can review the current settings by opening <b>Active Directory Users and Computers</b>, locate the identified <b>RODC</b>, and then right-click and select <b>Properties</b>.</p><br /><p>In the <b>Properties</b> of the RODC, select the <b>Password Replication Policy</b> tab.</p><br /><p>Review the replication policies, identify the policy that is permitting replication of credentials, and adjust to ensure there is a deny policy for the privileged users.</p><h3>References</h3><p><a href="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc753223(v=ws.10)" target="_blank">RODC Features | Microsoft Learn</a></p>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'RODCName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Lateral Movement', 'Privilege Escalation') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '2.0'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}
if($Metadata){ return $self | ConvertTo-Json -Depth 8 -Compress }

Import-Module -Name 'Semperis-Lib'

$outputObjects = [System.Collections.ArrayList]@()
$failedObject = [System.Collections.ArrayList]@()
$largeGroups = [System.Collections.ArrayList]@()
if ($PSBoundParameters['ForestName'] -and $PSBoundParameters['DomainNames']) {
    $ForestName = $ForestName.ToLower()
    $DomainNames = ConvertTo-Lowercase -DomainNames $DomainNames
}
$forestNetBIOS = Get-NetBIOSName -dnsDomain $forestName -DomainNames $DomainNames -ForestName $ForestName

$script:rodcMatches = @()

function Search-PrivilegedGroup {
    param(
        [string]$targetDomain,
        [string]$targetGroupDN
    )

    try {
        $searchParams = @{
            dnsDomain = $targetDomain
            attributes = @("msds-membertransitive","samAccountName")
            baseDN = $targetGroupDN
            scope = "base"
            filter = "distinguishedname=$targetGroupDN"
        }

        $groupMembers = Search-AD @searchParams

        if ($groupMembers.Attributes."msds-membertransitive;range=0-4499") {
            $groupSAM = $groupMembers.Attributes.samaccountname[0]
            [void]$largeGroups.Add("$forestNetBIOS\$groupSAM")

            $memberAttribute = "msds-membertransitive;range=0-4499"
        }
        else {
            $memberAttribute = "msds-membertransitive"
        }

        if (!($groupMembers.Attributes."msds-membertransitive"[0]) -and !($memberAttribute -match "range")) {
            continue
        }

        foreach ($adminDN in $groupMembers.Attributes.$memberAttribute.GetValues("string")) {
            if ($revealed_users -match $adminDN) {
                $matchedRODC = ($revealed_users -match $adminDN).split(";")[0].replace("$","")
                $matchedPAIR = "$matchedRODC;$adminDN"

                if ($script:rodcMatches.Contains("$matchedPAIR")) {
                    continue
                }

                $script:rodcMatches += $matchedPAIR

                $thisOutput = [PSCustomObject][Ordered] @{
                    DistinguishedName = $adminDN
                    RODCName = $matchedRODC
                }
                [void]$outputObjects.Add($thisOutput)
            }
        }
    }
    catch {
        [void]$failedObject.Add($targetGroupDN)
    }
}

try {
    $res = New-Result


    # In each domain, get revealed credentials for every RODC
    $revealed_users = [System.Collections.ArrayList]@()
    $unavailableDomains = [System.Collections.ArrayList]@()
    foreach ($domain in $DomainNames) {
        if (-not (Confirm-DomainAvailability $domain)) {
            [void]$unavailableDomains.Add($domain)
            continue
        }
        $DN = "DC=$($domain -replace '\.',',DC=')"
        $domainNetBIOS = Get-NetBIOSName -dnsDomain $domain -forestName $forestName -DomainNames $DomainNames

        $searchParams = @{
            dnsDomain = $domain
            attributes = @("msds-revealedlist","samAccountName")
            baseDN = $DN
            scope = "subtree"
            filter = "(primaryGroupId=521)"
        }

        $domainRODCs = Search-AD @searchParams

        foreach ($domainRODC in $domainRODCs) {
            if ($domainRODC.Attributes.'msds-revealedlist') {
                $rodcSAM = $domainRODC.Attributes.samaccountname[0].Replace("$","")
                $rodc_item = "$domainNetBIOS\$rodcSAM"

                $revealed_values = $domainRODC.Attributes.'msds-revealedlist'.GetValues("string")

                foreach ($revealed_value in $revealed_values) {
                    $revealed_user = $revealed_value.split(":")[-1]
                    $revealed_item = "$rodc_item;$revealed_user"
                    if (!$revealed_users.Contains($($revealed_item))) {
                        [void]$revealed_users.Add("$revealed_item")
                    }
                }
            }
        }
    }

    $forestPrivilegedGroups = @("519","518")
    $forestDN = Get-DN $ForestName
    $forestSID = Get-DomainSID $ForestName

    foreach ($groupRID in $forestPrivilegedGroups) {
        $searchParams = @{
            dnsDomain = $ForestName
            attributes = @("")
            baseDN = $forestDN
            scope = "subtree"
            filter = "(&(objectSid=$forestSID-$groupRID)(objectCategory=group))"
        }

        $forestGroupObject = Search-AD @searchParams

        if ($forestGroupObject) {
            $groupDN = $($forestGroupObject.DistinguishedName)
            Search-PrivilegedGroup -targetDomain $ForestName -targetGroupDN $groupDN
        }
    }

    $builtinPrivilegedGroups = @("S-1-5-32-551","S-1-5-32-552","S-1-5-32-548","S-1-5-32-549","S-1-5-32-550","S-1-5-32-544")
    $domainPrivilegedRIDs = @("512","516")

    $privilegedRIDs = @("512","516","518","519")
    $primaryGroupFilter = "(|"
    foreach($privilegedRID in $privilegedRIDs) {
        $primaryGroupFilter += "(primaryGroupID=$privilegedRID)"
    }
    $primaryGroupFilter += ")"

    foreach ($domain in $DomainNames) {
        if ($unavailableDomains.Contains($domain)) {
            continue
        }
        elseif (-not (Confirm-DomainAvailability $domain)) {
            [void]$unavailableDomains.Add($domain)
            continue
        }
        $domainSID = Get-DomainSID $domain
        $DN = Get-DN -dnsDomain $domain

        $domainGroups = [System.Collections.ArrayList]@()

        $searchParams = @{
            dnsDomain = $domain
            attributes = @("")
            baseDN = $DN
            scope = "subtree"
            filter = $primaryGroupFilter
        }

        $primaryResults = Search-AD @searchParams

        foreach ($primaryResult in $primaryResults) {
            $primaryDN = $primaryResult.DistinguishedName

            if ($revealed_users -match $primaryDN) {
                $matchedRODC = ($revealed_users -match $primaryDN).split(";")[0].replace("$","")
                $matchedPAIR = "$matchedRODC;$primaryDN"

                if ($script:rodcMatches.Contains("$matchedPAIR")) {
                    continue
                }

                $script:rodcMatches += $matchedPAIR

                $thisOutput = [PSCustomObject][Ordered] @{
                    DistinguishedName = $primaryDN
                    RODCName = $matchedRODC
                }
                [void]$outputObjects.Add($thisOutput)
            }
        }

        foreach ($domainPrivilegedRID in $domainPrivilegedRIDs) {
            $searchParams = @{
                dnsDomain = $domain
                attributes = @("")
                baseDN = $DN
                scope = "subtree"
                filter = "(&(objectSid=$domainSID-$domainPrivilegedRID)(objectCategory=group))"
            }

            $groupObject = Search-AD @searchParams

            if ($groupObject) {
                [void]$domainGroups.add("$($groupObject.DistinguishedName)")
            }
        }

        # Get a list of the groups DN
        foreach ($sid in $builtinPrivilegedGroups) {
            $searchParams = @{
                dnsDomain = $domain
                attributes = @("")
                baseDN = $DN
                scope = "subtree"
                filter = "(&(objectSid=$sid)(objectCategory=group))"
            }

            $groupObject = Search-AD @searchParams

            if ($groupObject) {
                [void]$domainGroups.add("$($groupObject.DistinguishedName)")
            }
        }

        foreach($groupDN in $domainGroups) {
            Search-PrivilegedGroup -targetDomain $domain -targetGroupDN $groupDN
        }
    }

    # Calculate score
    if ($outputObjects){
        $configArgs = @{
            ScriptName = $self.ScriptName
            Path = $MyInvocation.MyCommand.ScriptBlock.File
            Fields = $outputObjects[0]
        }
        $config = Resolve-Configuration @configArgs
        $outputObjects | Set-IgnoredFlag -Configuration $config
        $scoreOutput = $outputObjects | Get-Score -Impact $self.Impact
        if($scoreOutput.Score -lt 100)
        {
            $res.ResultObjects = $outputObjects
            $res.ResultMessage = $self.ResultMessage -f $($outputObjects.Count)
            $res.Remediation = $self.Remediation
            $res.Status = 'Failed'
            if ($largeGroups) {
                $res.ResultMessage += " While processing group membership, group(s) were discovered to have more than 4500 transitive members. Only the first 4500 members were processed by this indicator. A secure environment should not have such a high number of privileged group members. Please review membership for the following group(s) to ensure only necessary objects are contained:  $($largeGroups -join '; ')."
            }
            if ($failedObject) {
                $res.ResultMessage += " The following objects were identified in the group enumeration but could not be read due to ACL restrictions on the object or OU. It is suggested to check why these objects are hidden.  $($failedObject -join '; ')."
            }
            $res.Score = $scoreOutput.Score
        }
        if ($scoreOutput.Ignoredcount -gt 0)
        {
            $res.ResultMessage += " ($($scoreOutput.Ignoredcount) Objects ignored)."
            $res.ResultObjects = $outputObjects
        }
    }
    else {
        if ($largeGroups) {
            $res.ResultMessage += " While processing group membership, group(s) were discovered to have more than 4500 transitive members. Only the first 4500 members were processed by this indicator. A secure environment should not have such a high number of privileged group members. Please review membership for the following group(s) to ensure only necessary objects are contained:  $($largeGroups -join '; ')."
            $res.Status = 'Error'
        }
        if ($failedObject) {
            $res.ResultMessage += " The following objects were identified in the group enumeration but could not be read due to ACL restrictions on the object or OU. It is suggested to check why these objects are hidden.  $($failedObject -join '; ')."
            $res.Status = 'Error'
        }
    }

    # deal with unavailabile domains
    if ($unavailableDomains.Count -gt 0) {
        $res.Status = 'Error'
        $res.ResultMessage += " Failed to run because the following domains were unavailable: $($unavailableDomains -join ', ')"
    }
}
catch {
    return ConvertTo-ErrorResult $_
}
return $res

# SIG # Begin signature block
# MIIuDgYJKoZIhvcNAQcCoIIt/zCCLfsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB7JpFXceBzMtZc
# YK21T2aGKm+wqy1fzokqJC4GvzeRc6CCE3wwggVyMIIDWqADAgECAhB2U/6sdUZI
# k/Xl10pIOk74MA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDAzMTgwMDAwMDBaFw00NTAzMTgwMDAwMDBaMFMx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQD
# EyBHbG9iYWxTaWduIENvZGUgU2lnbmluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALYtxTDdeuirkD0DcrA6S5kWYbLl/6VnHTcc5X7s
# k4OqhPWjQ5uYRYq4Y1ddmwCIBCXp+GiSS4LYS8lKA/Oof2qPimEnvaFE0P31PyLC
# o0+RjbMFsiiCkV37WYgFC5cGwpj4LKczJO5QOkHM8KCwex1N0qhYOJbp3/kbkbuL
# ECzSx0Mdogl0oYCve+YzCgxZa4689Ktal3t/rlX7hPCA/oRM1+K6vcR1oW+9YRB0
# RLKYB+J0q/9o3GwmPukf5eAEh60w0wyNA3xVuBZwXCR4ICXrZ2eIq7pONJhrcBHe
# OMrUvqHAnOHfHgIB2DvhZ0OEts/8dLcvhKO/ugk3PWdssUVcGWGrQYP1rB3rdw1G
# R3POv72Vle2dK4gQ/vpY6KdX4bPPqFrpByWbEsSegHI9k9yMlN87ROYmgPzSwwPw
# jAzSRdYu54+YnuYE7kJuZ35CFnFi5wT5YMZkobacgSFOK8ZtaJSGxpl0c2cxepHy
# 1Ix5bnymu35Gb03FhRIrz5oiRAiohTfOB2FXBhcSJMDEMXOhmDVXR34QOkXZLaRR
# kJipoAc3xGUaqhxrFnf3p5fsPxkwmW8x++pAsufSxPrJ0PBQdnRZ+o1tFzK++Ol+
# A/Tnh3Wa1EqRLIUDEwIrQoDyiWo2z8hMoM6e+MuNrRan097VmxinxpI68YJj8S4O
# JGTfAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzANBgkqhkiG9w0BAQwFAAOCAgEA
# Xiu6dJc0RF92SChAhJPuAW7pobPWgCXme+S8CZE9D/x2rdfUMCC7j2DQkdYc8pzv
# eBorlDICwSSWUlIC0PPR/PKbOW6Z4R+OQ0F9mh5byV2ahPwm5ofzdHImraQb2T07
# alKgPAkeLx57szO0Rcf3rLGvk2Ctdq64shV464Nq6//bRqsk5e4C+pAfWcAvXda3
# XaRcELdyU/hBTsz6eBolSsr+hWJDYcO0N6qB0vTWOg+9jVl+MEfeK2vnIVAzX9Rn
# m9S4Z588J5kD/4VDjnMSyiDN6GHVsWbcF9Y5bQ/bzyM3oYKJThxrP9agzaoHnT5C
# JqrXDO76R78aUn7RdYHTyYpiF21PiKAhoCY+r23ZYjAf6Zgorm6N1Y5McmaTgI0q
# 41XHYGeQQlZcIlEPs9xOOe5N3dkdeBBUO27Ql28DtR6yI3PGErKaZND8lYUkqP/f
# obDckUCu3wkzq7ndkrfxzJF0O2nrZ5cbkL/nx6BvcbtXv7ePWu16QGoWzYCELS/h
# AtQklEOzFfwMKxv9cW/8y7x1Fzpeg9LJsy8b1ZyNf1T+fn7kVqOHp53hWVKUQY9t
# W76GlZr/GnbdQNJRSnC0HzNjI3c/7CceWeQIh+00gkoPP/6gHcH1Z3NFhnj0qinp
# J4fGGdvGExTDOUmHTaCX4GUT9Z13Vunas1jHOvLAzYIwgga/MIIEp6ADAgECAhEA
# gU5CF6Epf+1azNQX+JGtdTANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJCRTEZ
# MBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xvYmFsU2lnbiBD
# b2RlIFNpZ25pbmcgUm9vdCBSNDUwHhcNMjQwNjE5MDMyNTExWhcNMzgwNzI4MDAw
# MDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEv
# MC0GA1UEAxMmR2xvYmFsU2lnbiBHQ0MgUjQ1IENvZGVTaWduaW5nIENBIDIwMjAw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDWQk3540/GI/RsHYGmMPdI
# Pc/Q5Y3lICKWB0Q1XQbPDx1wYOYmVPpTI2ACqF8CAveOyW49qXgFvY71TxkkmXzP
# ERabH3tr0qN7aGV3q9ixLD/TcgYyXFusUGcsJU1WBjb8wWJMfX2GFpWaXVS6UNCw
# f6JEGenWbmw+E8KfEdRfNFtRaDFjCvhb0N66WV8xr4loOEA+COhTZ05jtiGO792N
# hUFVnhy8N9yVoMRxpx8bpUluCiBZfomjWBWXACVp397CalBlTlP7a6GfGB6KDl9U
# Xr3gW8/yDATS3gihECb3svN6LsKOlsE/zqXa9FkojDdloTGWC46kdncVSYRmgiXn
# Qwp3UrGZUUL/obLdnNLcGNnBhqlAHUGXYoa8qP+ix2MXBv1mejaUASCJeB+Q9Hup
# Uk5qT1QGKoCvnsdQQvplCuMB9LFurA6o44EZqDjIngMohqR0p0eVfnJaKnsVahzE
# aeawvkAZmcvSfVVOIpwQ4KFbw7MueovE3vFLH4woeTBFf2wTtj0s/y1KiirsKA8t
# ytScmIpKbVo2LC/fusviQUoIdxiIrTVhlBLzpHLr7jaep1EnkTz3ohrM/Ifll+FR
# h2npIsyDwLcPRWwH4UNP1IxKzs9jsbWkEHr5DQwosGs0/iFoJ2/s+PomhFt1Qs2J
# JnlZnWurY3FikCUNCCDx/wIDAQABo4IBhjCCAYIwDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FNqzjcAkkKNrd9MMoFndIWdkdgt4MB8GA1UdIwQYMBaAFB8Av0aACvx4ObeltEPZ
# VlC7zpY7MIGTBggrBgEFBQcBAQSBhjCBgzA5BggrBgEFBQcwAYYtaHR0cDovL29j
# c3AuZ2xvYmFsc2lnbi5jb20vY29kZXNpZ25pbmdyb290cjQ1MEYGCCsGAQUFBzAC
# hjpodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9jb2Rlc2lnbmlu
# Z3Jvb3RyNDUuY3J0MEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFs
# c2lnbi5jb20vY29kZXNpZ25pbmdyb290cjQ1LmNybDAuBgNVHSAEJzAlMAgGBmeB
# DAEEATALBgkrBgEEAaAyATIwDAYKKwYBBAGgMgoEAjANBgkqhkiG9w0BAQsFAAOC
# AgEAMhDkvBelgxBAndOp/SfPRXKpxR9LM1lvLDIxeXGE1jZn1at0/NTyBjputdbL
# 8UKDlr193pUsGu1q40EcpsiJMcJZbIm8KiMDWVBHSf1vUw4qKMxIVO/zIxhbkjZO
# vKNj1MP7AA+A0SDCyuWWuvCaW6qkJXoZ2/rbe1NP+baj2WPVdV8BpSjbthgpFGV5
# nNu064iYFFNQYDEMZrNR427JKSZk8BTRc3jEhI0+FKWSWat5QUbqNM+BdkY6kXgZ
# c77+BvXXwYQ5oHBMCjUAXtgqMCQfMne24Xzfs0ZB4fptjePjC58vQNmlOg1kyb6M
# 0RrJZSA64gD6TnohN0FwmZ1QH5l7dZB0c01FpU5Yf912apBYiWaTZKP+VPdNquvl
# IO5114iyHQw8vKGSoFbkR/xnD+p4Kd+Po8fZ4zF4pwsplGscJ10hJ4fio+/IQJAu
# XBcoJdMBRBergNp8lKhbI/wgnpuRoZD/sw3lckQsRxXz1JFyJvnyBeMBZ/dptd4F
# tv4okIx/oSk7tyzaZCJplsT001cNKoXGu2horIvxUktkbqq4t+xNFBz6qBQ4zuwl
# 6+Ri3TX5uHsHXRtDZwIIaz2/JSODgZZzB+7+WFo8N9qg21/SnDpGkpzEJhwJMNol
# 5A4dkHPUHodOaYSBkc1lfuc1+oOAatM0HUaneAimeDIlZnowggc/MIIFJ6ADAgEC
# AgxsjPy20SAh5jGEkUUwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNpZ24gR0ND
# IFI0NSBDb2RlU2lnbmluZyBDQSAyMDIwMB4XDTI0MDYwNDEzMDU0NVoXDTI3MDcx
# NTE0MzA0NFowgYoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRAw
# DgYDVQQHEwdIb2Jva2VuMRYwFAYDVQQKEw1TRU1QRVJJUyBJTkMuMRYwFAYDVQQD
# Ew1TRU1QRVJJUyBJTkMuMSQwIgYJKoZIhvcNAQkBFhVjb2Rlc2lnbkBzZW1wZXJp
# cy5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCNYiocFDfmQmq3
# ngxGCT305SbMYRrXTVpotaqQbcpoesQbYwj/Wq94RNeh7cAXSLaMaQt5YlyhAO/a
# ND5VxLBiWi9+Y2v8cGziq1XGTGSFV6Rwc0Go777qQP0lc76Q8qGijZNWqIWWSaE3
# cS57dIFwNAWnpWVtUhtfz3LJZ1ok7vP+UQT8zC5qfbM7pAxJ8T6vrsInAG5iClrw
# uspeuUmAaLbWMKHFn2yeLOXAbEqVSwn8R8gNUBVVSMkXKooXDU35fr5xGRBuSVtd
# nguHL7jAPuDu5btcOggLcCgD9fegjXQeKphZVdpdRchpXe3idFYHAVx21552cFfs
# hEHL4M4I3YcOC/5JJcyLMIHP63MXPzQbbZ3IZQ9++sIZora75v7Bynx04xl/2mO5
# Y2LGiu4DHs6rxgBYU8AnA5ncM/mcrEoG/Ce03z7nt7Mnl7KC3GjYBnx5XCwYc0sL
# r6sHLKJdsd3bjwL/watiUxV60+lW+t5Z1JYQGlBjHwMEfQYliZHMix2Pe+9KsMbk
# vLeHMGo31pUZqeBl7hEPCD0x5KqP4VrBNPySHDhJMk582TvJdoHCKZYfJHdkChHz
# ADIbvUcAE69bTFsTOp/ypC/yOTFrZFuBr6w30+x+9UVy4+jsx1MUoNBOLv6on1Mm
# YaTH5sp4/MoA6LkPG0h7ZJUq2qlNXwIDAQABo4IB0zCCAc8wDgYDVR0PAQH/BAQD
# AgeAMIGbBggrBgEFBQcBAQSBjjCBizBKBggrBgEFBQcwAoY+aHR0cDovL3NlY3Vy
# ZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NnY2NyNDVjb2Rlc2lnbmNhMjAyMC5j
# cnQwPQYIKwYBBQUHMAGGMWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2Nj
# cjQ1Y29kZXNpZ25jYTIwMjAwVgYDVR0gBE8wTTBBBgkrBgEEAaAyATIwNDAyBggr
# BgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8w
# CAYGZ4EMAQQBMAkGA1UdEwQCMAAwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS9nc2djY3I0NWNvZGVzaWduY2EyMDIwLmNybDAgBgNV
# HREEGTAXgRVjb2Rlc2lnbkBzZW1wZXJpcy5jb20wEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwHwYDVR0jBBgwFoAU2rONwCSQo2t30wygWd0hZ2R2C3gwHQYDVR0OBBYEFD9A
# ijmjNjU3CNw8Unvu8bt4SgXDMA0GCSqGSIb3DQEBCwUAA4ICAQAQD+KrgTxd7wyL
# ivnLriAHzIjTtvC5k8ov1rWGJgajZsA3MWQJ91mRkZzpDGYdrXgoX0f8D3qxpujk
# POOsq8z8+AlM957IzpDoq6oqLapaw25ADPTsPhlSxzY49Y9/B6pLOMVwCCTjGXDl
# DwtHiJHEyUkV0icoXCxmSGSzT4fA8HHSDRf5xd1FTFtZ2CZFf40VN9ZjNXeNs602
# dI9t4LtsXY8Y6g+wxEKc9Iwhuitp+gdXnDQ312nKo3p8Hsx5TGwRTkPJNCNq+BYt
# ba7Z7fu9m3lowjm3SaRfxgkZhW4//V8licRnrsMA3U2X4SkuXCMlC9t3NITiSPq5
# uEyhqhueu7wZbOo6hr3+2j7Y5sDrHQ0g6GpvillfX+aiDuMwx1Oo+CmJezn7UIE8
# kFC934D8QEH/veD9GtVY1YOa4pXnn6d1Kd1tPPG4R5OXrjiRmwIU9c1UVR84t86m
# euqt+dOJo7L2i1RaNdcPLOExrzHZGZEUSZaizZxBN+XKWXDHWShq0zA+llH59l/R
# IbVZRUqt6c1MD/egPtsm0XGJABzhioGtjSmALmJiv4XWXg77pyhuy1SXELjOAW9W
# gLLv4xQaO4FiXHO/yqLwh+XawyLk+iKLx3Gch3nGR8MepeRfqTg85PthgPQklS5F
# VN+q9Y6t3yR/sUxkJCMAt0B9E7sFVDGCGegwghnkAgEBMGkwWTELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNp
# Z24gR0NDIFI0NSBDb2RlU2lnbmluZyBDQSAyMDIwAgxsjPy20SAh5jGEkUUwDQYJ
# YIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgUeqdvvC8EJrUe8tNmdpVMDL2fxq6+0cwPi/gEi8a
# OAcwDQYJKoZIhvcNAQEBBQAEggIAZn3G0AtTMIsKWSF90C5UwhbAoJ6HDIpTF4/1
# 9WdtVBwBp5Ubl/JBAOCRRrbUWXmojzqwzXrMFO0UbUXn8o2W83P5joFRfxVCrv47
# wWAgCg5Gw53eu/t9nwZqbrdp99FwpyL/G39jtb/5Yrn4H+ys42A4KzeMbbEi+BZF
# k5j9+MsGAaWdkVxZV4dlxW0iEFEBlZfbYoM1MUwYZk4kEMhucG/lkNY243U83Efw
# 7xCNPA2rZcB9hsR831uku4GhzRbYMs0MNxqa0/p1U7vVvmobUfbzq8NL2DEbRA1g
# 0Pjbq5pu6irkYmEl2rHSm1n3qQjLn1CfAj8mZ8QftNp0PNuq2DTLEn/zoThvhW4p
# ImW+HF3kpBXPEktLkKgjwlY+wIQKEUT3sXobMqUbtZ0NNsJXsy8OHulytiJHiRiX
# f5LRJfFmzF5e29AYEkrgp3JVYbWnKVnl59G/LsCaJcXcVWOOhmZrctltAZO4hqsB
# 4bUz8e7c1wBR8yFtG2mR5YO7EVKSCF1Ec3HgWY7VPXM0DCqOBz/bY87+pxOW0Z6+
# yH/mRSMXUhXja7rD3r3guqlT2es7WYYp0x9LRbEz0F4ffranA5IYHB6caeGOoUAs
# qL5ccl+4ZYImKoTa/NwVSfV5I9XIiMtVRg5ETtWnUFGhWC6ic+GIXF3IRup4RDI9
# 3bFmLd6hghbJMIIWxQYKKwYBBAGCNwMDATGCFrUwghaxBgkqhkiG9w0BBwKgghai
# MIIWngIBAzENMAsGCWCGSAFlAwQCATCB5QYLKoZIhvcNAQkQAQSggdUEgdIwgc8C
# AQEGCSsGAQQBoDICAzAxMA0GCWCGSAFlAwQCAQUABCDJ0i1m2mjTYawFOFv5yR5O
# I+7dEDPGkZ9wnV002vVQZAIUR3TJU0IWXOMk30q9363S2rM2veEYDzIwMjQwNzEw
# MTYxMjAzWjADAgEBoGCkXjBcMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAwwpR2xvYmFsc2lnbiBUU0EgZm9yIEFkdmFuY2Vk
# IC0gRzQgLSAyMDIzMTGgghJTMIIGazCCBFOgAwIBAgIQARl1dHHJktdE36WW67lw
# FTANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0Eg
# LSBTSEEzODQgLSBHNDAeFw0yMzExMDIxMDMwMDJaFw0zNDEyMDQxMDMwMDJaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKDBBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# DClHbG9iYWxzaWduIFRTQSBmb3IgQWR2YW5jZWQgLSBHNCAtIDIwMjMxMTCCAaIw
# DQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALI1RnSqg43Vlqc8SNXFyqjfVL4I
# q6HfXOlJ0GBetaUa90NYQ5c89GdjCDI8GX8r2VVG1dSMwFzPpMWlGrqnK84mQiE8
# 5buho5XdYOoSVa7vztwyhO2jteA/c9E1uJu7xUTd4bjr81mtifZxj1oK+gqSBYQN
# lwG/Bbv8WAGzjcnUBYWnkCturNPZTtqnJDWWb6qzoEE74PnnEY7VZgKALT3Mzx6k
# losXgNxMORokdSzFdxbZkYMmf+cTi6JFVOa2Snfn0i0u57A8SNnGjft69Cu8piJI
# otferXhHiAxfm/SRSgYc+gOealYeKzDj845ZsLQfHmE4hnn5g4OUjwkwQjO0DreI
# ghgtP9eBiyegafHTBa7GRaPCH5ut6cDIT9fnxqdBMmj/WcpUXPu/2R8W8FLSz7g1
# laWRzqMd9XZSmOyRYYsJoa2ZmeislCiXOIwJrjyc+H5RojdqyHG6HU8NJgFWflfD
# dULYU+BjY91+nh2oYujO/plZU/bzAIr9k5XP0QIDAQABo4IBqDCCAaQwDgYDVR0P
# AQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMB0GA1UdDgQWBBTEvu6H
# PIl0Dt6z7hkbhQzOQU5/nTBWBgNVHSAETzBNMAgGBmeBDAEEAjBBBgkrBgEEAaAy
# AR4wNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVw
# b3NpdG9yeS8wDAYDVR0TAQH/BAIwADCBkAYIKwYBBQUHAQEEgYMwgYAwOQYIKwYB
# BQUHMAGGLWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2NhL2dzdHNhY2FzaGEz
# ODRnNDBDBggrBgEFBQcwAoY3aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9j
# YWNlcnQvZ3N0c2FjYXNoYTM4NGc0LmNydDAfBgNVHSMEGDAWgBTqFsZp5+PLV0U5
# M6TwQL7Qw71lljBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL2NhL2dzdHNhY2FzaGEzODRnNC5jcmwwDQYJKoZIhvcNAQELBQADggIB
# ALMy0epn/9vfp7Q3RF3tHr52I8nOA+1N1GrnM4w8XyBi2+7pbDg55Zlx+yaRHyex
# c1wDGc9oMtDV5nZ4Sqo8lzLSFe56HDI8YKdByrk+8UHqw9Pxx+W+3hrGwY4i39aA
# 5Y/yrLIhjXi2xImMlL0yc7jYl0Q812ZsDRwQXF6oiEC9oK5OWi1kTwYlpYTGOHDH
# VHMUjVcWqTAcqAlJ36UBBgO/E7N0lJsHga8NQZBVKbBgqVT6OCAzzgm6DkxnWIGG
# qe2IhqmY47blRpckR2xI0RBqynGyPl3DPS0hgmuDY2+XwJH++32WuarAHM2lrZB4
# gNZ9bYkqQI6sJfrriDYjfoby+7UG7SiDLLPamnpvSBEWlDa1RUCdgTUNxbGMmzvm
# POl6GFD5OYqSd7uRIm6guVsqAUAo5NFIqTCOooYSN03JWZnHpgN/4ZEKfQr4C0IO
# ca72z7rlMfj5Hy3w4AqMhIylOaM7sPM22UPVm5gkD9DC4yY+reH7+x6r3gb2+2hB
# 7DHfqckejBn2PvYemC7RYIFbJnT0VE5ABN+1XtT37vANh29AQKdp6ijIoalPdxKJ
# MWrpmoN3i6nFRDPut2lOLLSntJV4m9aqQCw2GqdEQ7NS2GDGc1e/fNY10yOjYEIi
# 1hYVzhMa6c715c9avqw/c+n6c78ZzaKXZsocYA2ivVTMMIIGWTCCBEGgAwIBAgIN
# AewckkDe/S5AXXxHdDANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxT
# aWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMK
# R2xvYmFsU2lnbjAeFw0xODA2MjAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFsxCzAJ
# BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhH
# bG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0MIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8ALiMCP64BvhmnSzr3WDX6lHUsdhOmN8
# OSN5bXT8MeR0EhmW+s4nYluuB4on7lejxDXtszTHrMMM64BmbdEoSsEsu7lw8nKu
# jPeZWl12rr9EqHxBJI6PusVP/zZBq6ct/XhOQ4j+kxkX2e4xz7yKO25qxIjw7pf2
# 3PMYoEuZHA6HpybhiMmg5ZninvScTD9dW+y279Jlz0ULVD2xVFMHi5luuFSZiqgx
# kjvyen38DljfgWrhsGweZYIq1CHHlP5CljvxC7F/f0aYDoc9emXr0VapLr37WD21
# hfpTmU1bdO1yS6INgjcZDNCr6lrB7w/Vmbk/9E818ZwP0zcTUtklNO2W7/hn6gi+
# j0l6/5Cx1PcpFdf5DV3Wh0MedMRwKLSAe70qm7uE4Q6sbw25tfZtVv6KHQk+JA5n
# Jsf8sg2glLCylMx75mf+pliy1NhBEsFV/W6RxbuxTAhLntRCBm8bGNU26mSuzv31
# BebiZtAOBSGssREGIxnk+wU0ROoIrp1JZxGLguWtWoanZv0zAwHemSX5cW7pnF0C
# TGA8zwKPAf1y7pLxpxLeQhJN7Kkm5XcCrA5XDAnRYZ4miPzIsk3bZPBFn7rBP1Sj
# 2HYClWxqjcoiXPYMBOMp+kuwHNM3dITZHWarNHOPHn18XpbWPRmwl+qMUJFtr1eG
# fhA3HWsaFN8CAwEAAaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8E
# CDAGAQH/AgEAMB0GA1UdDgQWBBTqFsZp5+PLV0U5M6TwQL7Qw71lljAfBgNVHSME
# GDAWgBSubAWjkxPioufi1xzWx/B/yGdToDA+BggrBgEFBQcBAQQyMDAwLgYIKwYB
# BQUHMAGGImh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjYwNgYDVR0f
# BC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXI2LmNy
# bDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cu
# Z2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQEMBQADggIBAH/i
# iNlXZytCX4GnCQu6xLsoGFbWTL/bGwdwxvsLCa0AOmAzHznGFmsZQEklCB7km/fW
# pA2PHpbyhqIX3kG/T+G8q83uwCOMxoX+SxUk+RhE7B/CpKzQss/swlZlHb1/9t6C
# yLefYdO1RkiYlwJnehaVSttixtCzAsw0SEVV3ezpSp9eFO1yEHF2cNIPlvPqN1eU
# kRiv3I2ZOBlYwqmhfqJuFSbqtPl/KufnSGRpL9KaoXL29yRLdFp9coY1swJXH4uc
# /LusTN763lNMg/0SsbZJVU91naxvSsguarnKiMMSME6yCHOfXqHWmc7pfUuWLMwW
# axjN5Fk3hgks4kXWss1ugnWl2o0et1sviC49ffHykTAFnM57fKDFrK9RBvARxx0w
# xVFWYOh8lT0i49UKJFMnl4D6SIknLHniPOWbHuOqhIKJPsBK9SH+YhDtHTD89szq
# SCd8i3VCf2vL86VrlR8EWDQKie2CUOTRe6jJ5r5IqitV2Y23JSAOG1Gg1GOqg+ps
# cmFKyfpDxMZXxZ22PLCLsLkcMe+97xTYFEBsIB3CLegLxo1tjLZx7VIh/j72n585
# Gq6s0i96ILH0rKod4i0UnfqWah3GPMrz2Ry/U02kR1l8lcRDQfkl4iwQfoH5DZSn
# ffK1CfXYYHJAUJUg1ENEvvqglecgWbZ4xqRqqiKbMIIFgzCCA2ugAwIBAgIORea7
# A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2ln
# biBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkds
# b2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcNMzQxMjEwMDAwMDAwWjBMMSAwHgYD
# VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2ln
# bjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQssgrRIxutbPK6DuEGSMxSkb3/pKszG
# sIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuTToVBu1kZguSgMpE3nOUTvOniX9PeGMI
# yBJQbUJmL025eShNUhqKGoC3GYEOfsSKvGRMIRxDaNc9PIrFsmbVkJq3MQbFvuJt
# MgamHvm566qjuL++gmNQ0PAYid/kD3n16qIfKtJwLnvnvJO7bVPiSHyMEAc4/2ay
# d2F+4OqMPKq0pPbzlUoSB239jLKJz9CgYXfIWHSw1CM69106yqLbnQneXUQtkPGB
# zVeS+n68UARjNN9rkxi+azayOeSsJDa38O+2HBNXk7besvjihbdzorg1qkXy4J02
# oW9UivFyVm4uiMVRQkQVlO6jxTiWm05OWgtH8wY2SXcwvHE35absIQh1/OZhFj93
# 1dmRl4QKbNQCTXTAFO39OfuD8l4UoQSwC+n+7o/hbguyCLNhZglqsQY6ZZZZwPA1
# /cnaKI0aEYdwgQqomnUdnjqGBQCe24DWJfncBZ4nWUx2OVvq+aWh2IMP0f/fMBH5
# hc8zSPXKbWQULHpYT9NLCEnFlWQaYw55PfWzjMpYrZxCRXluDocZXFSxZba/jJvc
# E+kNb7gu3GduyYsRtYQUigAZcIN5kZeR1BonvzceMgfYFGM8KEyvAgMBAAGjYzBh
# MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSubAWj
# kxPioufi1xzWx/B/yGdToDAfBgNVHSMEGDAWgBSubAWjkxPioufi1xzWx/B/yGdT
# oDANBgkqhkiG9w0BAQwFAAOCAgEAgyXt6NH9lVLNnsAEoJFp5lzQhN7craJP6Ed4
# 1mWYqVuoPId8AorRbrcWc+ZfwFSY1XS+wc3iEZGtIxg93eFyRJa0lV7Ae46ZeBZD
# E1ZXs6KzO7V33EByrKPrmzU+sQghoefEQzd5Mr6155wsTLxDKZmOMNOsIeDjHfrY
# BzN2VAAiKrlNIC5waNrlU/yDXNOd8v9EDERm8tLjvUYAGm0CuiVdjaExUd1URhxN
# 25mW7xocBFymFe944Hn+Xds+qkxV/ZoVqW/hpvvfcDDpw+5CRu3CkwWJ+n1jez/Q
# cYF8AOiYrg54NMMl+68KnyBr3TsTjxKM4kEaSHpzoHdpx7Zcf4LIHv5YGygrqGyt
# Xm3ABdJ7t+uA/iU3/gKbaKxCXcPu9czc8FB10jZpnOZ7BN9uBmm23goJSFmH63sU
# YHpkqmlD75HHTOwY3WzvUy2MmeFe8nI+z1TIvWfspA9MRf/TuTAjB0yPEL+GltmZ
# WrSZVxykzLsViVO6LAUP5MSeGbEYNNVMnbrt9x+vJJUEeKgDu+6B5dpffItKoZB0
# JaezPkvILFa9x8jvOOJckvB595yEunQtYQEgfn7R8k8HWV+LLUNS60YMlOH1Zkd5
# d9VUWx+tJDfLRVpOoERIyNiwmcUVhAn21klJwGW45hpxbqCo8YLoRT5s1gLXCmeD
# BVrJpBAxggNJMIIDRQIBATBvMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBD
# QSAtIFNIQTM4NCAtIEc0AhABGXV0ccmS10TfpZbruXAVMAsGCWCGSAFlAwQCAaCC
# AS0wGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3DQEJNDEeMBww
# CwYJYIZIAWUDBAIBoQ0GCSqGSIb3DQEBCwUAMC8GCSqGSIb3DQEJBDEiBCB7h7MX
# MHk0PgZNWbGL7/YGd9mvFS8zPX+n0sc5IvtgyDCBsAYLKoZIhvcNAQkQAi8xgaAw
# gZ0wgZowgZcEIAt5ojmuQhCN71azVAW/j82OWadLhO7i3sPZccHqFzTsMHMwX6Rd
# MFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYD
# VQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0AhAB
# GXV0ccmS10TfpZbruXAVMA0GCSqGSIb3DQEBCwUABIIBgFQYhd4drPw//ROZy+Z+
# zL6DM4pG87Du+02ncPDIx1kHIFXDtKH/oC26Cv4BRgcTUicpl7eIGxyj317xDH9i
# myvAnrFdy5PkJZYWPXrzEihdmcIS1fkQsucvC2BLeN0eR/+wGtBA4xWZaMVVVU1u
# OKgWi4hXrNI9egDTWwe10KbJv+VWdnRFCqn3Gggym5iSRZEQ/+x0eCVw6fiEkwsJ
# PLirX03XLUZDb369bJW/k8cXrc81KvidnmD3tJLXEak+ZRKtUet1T+RcY2jgdt4Y
# 1PFNen4P4mxksLSTFONCpLwnm5+uVVm5g2gU3bHrlNBBhFaGYLhPNaapWQslrKfQ
# cu1wg45eCm3fccTAYhW3A44LLcDWcM9eCGvnRAgFhyf/S/bub7pRQvzNj6T5xM6Q
# 5ZBpDZhWC+22Oc4gLBnt4/EQUgs+sgRUyGR9AuYZR3sqt/D4DAuIhyz1ZLj7rTNG
# /hdGpeR1pFmQ7XdE76kZbFwR6m4Mwm2rJkqdSxmOiUybzA==
# SIG # End signature block
