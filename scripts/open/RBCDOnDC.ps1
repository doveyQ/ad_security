﻿# This script looks for Domain Controllers that has values in msds-allowedtoactonbehalfofotheridentity

[CmdletBinding()]
param(
    [Parameter(Mandatory,ParameterSetName='Execution')][string]$ForestName,
    [Parameter(Mandatory,ParameterSetName='Execution')][string[]]$DomainNames,
    [Parameter(ParameterSetName='Execution')]$StartAttackWindow,
    [Parameter(ParameterSetName='Execution')]$EndAttackWindow,
    [Parameter(ParameterSetName='Metadata',Mandatory)][switch]$Metadata
)

$Global:self = @{
    ID = 66
    UUID = '6df6c2ee-a77b-411b-8540-4357e5d0a1fb'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000066'
    Name = 'Domain controllers with Resource-Based Constrained Delegation (RBCD) enabled'
    ScriptName = 'RBCDOnDC'
    Description = 'This indicator detects a configuration that grants certain accounts with complete delegation to domain controllers. Delegations towards privileged resources such as DCs should be avoided. Resource-based constrained delegation is configured on the target resource, as opposed to other delegation types that are configured on the accounts accessing the resource.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'An attacker needs to know the Service Principal Name (SPN) of the object they want to delegate, as well as be able to populate the msDS-AllowedToActOnBehalfOfOtherIdentity attribute with a computer account that they control. This is sometimes possible when unprivileged users are by default allowed to create computer accounts (MachineAccountQuota) and write the attribute to the target computer.'
    ResultMessage = 'Found {0} Domain Controller objects with Resource Based Constrained Delegation configured.'
    Remediation = 'Ensure that the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on any DC is empty - this is the normal state for a DC.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'PrincipalsAllowedToDelegate'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Defense Evasion', 'Lateral Movement', 'Privilege Escalation') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_delegation_sourcedeleg') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}
if($Metadata){ return $self | ConvertTo-Json -Depth 8 -Compress }

Import-Module -Name 'Semperis-Lib'

$outputObjects = [System.Collections.ArrayList]@()
$failedDomainCount = 0
try {
    if ($PSBoundParameters['ForestName'] -and $PSBoundParameters['DomainNames']) {
        $ForestName = $ForestName.ToLower()
        $DomainNames = ConvertTo-Lowercase -DomainNames $DomainNames
    }
    $res = New-Result

    $unavailableDomains = [System.Collections.ArrayList]@()
    foreach ($domain in $DomainNames) {
        if (-not (Confirm-DomainAvailability $domain)) {
            [void]$unavailableDomains.Add($domain)
            continue
        }
        $results = @()
        $DN = Get-DN $domain

        # Get a list of all objects with RBCD configured
        $searchParams = @{
            dnsDomain = $domain
            attributes = "msds-allowedtoactonbehalfofotheridentity"
            baseDN = $DN
            scope = "Subtree"
            filter = "(&(msds-allowedtoactonbehalfofotheridentity=*)(primarygroupid=516)(samaccounttype=805306369))"
            PropertyFilter = "msds-allowedtoactonbehalfofotheridentity"
            StartAttackWindow = $StartAttackWindow
            EndAttackWindow = $EndAttackWindow
        }

        $results = Search-ADHelper @searchParams

        if ($results.Count) {
            $failedDomainCount++
            foreach($result in $results) {
                $delegateSD = (New-Object System.Security.AccessControl.RawSecurityDescriptor(@($result.Attributes."msds-allowedtoactonbehalfofotheridentity"[0],0)))
                $delegatePrincipals = @()
                foreach ($Dacl in $delegateSD.DiscretionaryAcl) {
                    $principalSID = $Dacl.SecurityIdentifier
                    $principal = Search-AD -dnsDomain $domain -baseDN $DN -scope "subtree" -filter "(objectSid=$principalSID)"
                    if ($principal) {
                        $delegatePrincipals += $principal.DistinguishedName
                    }
                }
                $thisOutput = new-object psobject -Property @{
                    DistinguishedName = $result.DistinguishedName
                    PrincipalsAllowedToDelegate = $delegatePrincipals -join ";"
                }
                $attrMetaData = $result.Attributes.'attributemetadata'
                Update-IndicatorOutputAttackWindow -ThisOutput $thisOutput -Metadata $attrMetaData `
                    -StartAttackWindow $StartAttackWindow -EndAttackWindow $EndAttackWindow
                [void]$outputObjects.Add($thisOutput)
            }
        }
    }

    # Count is the number of domains that failed the test
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
            $res.ResultMessage = "Found $($outputObjects.Count) Domain Controller objects with Resource Based Constrained Delegation configured."
            $res.Remediation = "Ensure that the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on any DC is empty - this is the normal state for a DC."
            $res.Status = 'Failed'
            $res.Score = $scoreOutput.Score
        }
        if ($scoreOutput.Ignoredcount -gt 0)
        {
            $res.ResultMessage += " ($($scoreOutput.Ignoredcount) Objects ignored)."
            $res.ResultObjects = $outputObjects
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACTvkdBQEho+wN
# 8yxGheTEXkHsM2N9p3T9D/DOj9ebm6CCE3wwggVyMIIDWqADAgECAhB2U/6sdUZI
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
# FTAvBgkqhkiG9w0BCQQxIgQgqRL7X10suZvPXZ3b5U4AaOV5MKOFVbFMm4DNZakW
# yqIwDQYJKoZIhvcNAQEBBQAEggIAG1C7V8kjgJ8ixa+fnQMmPoHHKlCZ++pdzP9f
# LKArotWWKWFVCpXmZZ4WvSHZaqoEV0DVa2Tiwb/02ZSdZ6jFHgASM2b6IMNsK4VE
# cMLxboHcI+cjNi+DlvzL6JaWejiNoBTJS7GpxxTLySK/1Xl7ldrBMyLEV+6AfcgY
# JOUC/4MU4nAS4rk/UfMf8oHvFtlR6L+u9FSYlxLmQIJ95VuqOGs+nNMTjLXYdwhy
# GA5JeMw/SSfkuVQOfZLF+zbJR6CWArhGpC2s0ktrgqBu3OktM45Nos9WfEYhnpGF
# RgCJ48pb3dOXzVsI85ecD5xerPM6myTIwrqdn4OnjbaXjN1DJVnNWnsY/MDUFbel
# eHi2JJgjxzgjbx9F5Gko2mWhNcVshCUvL5Mi3sF4wCrUNV4CzsP2vKFXOV8N6JEf
# AVSktB9ACb6SsYVw8FCYaVp8jzW/THoEdHrdCUh3pZtBLkZvY7AqPu2k1JYVXq4t
# NuQfUM/WamZQ+tVgUIpVEH9AmMEKShturcY61Vc53nZNnXHV8EzavPXeFVxi26Ux
# hTe0mRPtdRG56CkBuscEkralrhA+QVo0LlEDex62VGBijYZ9Rnla24wagsUD5cZA
# 1AouFDIgx6nC55FhBvlpDnMcf2R2QBn9WMd7CXbRFrzlEgNt2lbmDAQoO+Tv2HbH
# oORRElKhghbJMIIWxQYKKwYBBAGCNwMDATGCFrUwghaxBgkqhkiG9w0BBwKgghai
# MIIWngIBAzENMAsGCWCGSAFlAwQCATCB5QYLKoZIhvcNAQkQAQSggdUEgdIwgc8C
# AQEGCSsGAQQBoDICAzAxMA0GCWCGSAFlAwQCAQUABCDtS9B3OFMiB9/IsbsO3FF/
# mnBsv3LVD8E665Yu6fL1JgIUcEleqiGMlg1YELTXd4Y0bTI/eU8YDzIwMjQwNzEw
# MTYxMTI4WjADAgEBoGCkXjBcMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
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
# CwYJYIZIAWUDBAIBoQ0GCSqGSIb3DQEBCwUAMC8GCSqGSIb3DQEJBDEiBCAaOlKK
# Yt5HlqxoMlX13kQgSfcHw+I7XQQOFRFiyuzT9DCBsAYLKoZIhvcNAQkQAi8xgaAw
# gZ0wgZowgZcEIAt5ojmuQhCN71azVAW/j82OWadLhO7i3sPZccHqFzTsMHMwX6Rd
# MFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYD
# VQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0AhAB
# GXV0ccmS10TfpZbruXAVMA0GCSqGSIb3DQEBCwUABIIBgAFHggxUWjqgg+X7huVY
# p6RP+Z6qD8wNox9GmQG7KCBWkG/m/1yvpoI/KYS7ubPXx6/QJeMogQTjaC0mcpZ8
# UZz7yuU7GzU9cJs3qTyaYD3grw+4jCAYcb75PPyLstvWtS4tmvgtovxPRg6jyrQ1
# 2XjE9FCWaP0zFJh7b3fNqjCr5B3RAky1NSDy5rCVYWRMEmCjHUbIskZnaXhg5UEp
# ZfTfMlBR5BrHcvCUhgKrqhV0BiwyK/u16zlxTixs768KsVJceoE2FSggUo0Ms7RV
# 6fcgRM6KVeMqtxN236uX83uXjsUcG2SRmHjDPDawKZCipPyip1nYJCVpixlTZpLF
# AILdamblqVxjptJU0mNBHHTFMXyrJA4xD1DDTW8aTUr8IYlDpKqu9qusYu8ANvr7
# Ou4vy3a0Ep/ZKtvRjGOqICZq8hTSOg7jiUtt5t5Y8QAP8uSRxAM1lc0OL+wNSuim
# IWxBYtApmK7IE5OhTisNe1pcwEuw1bNOSf7P1mQC7P5p1g==
# SIG # End signature block
