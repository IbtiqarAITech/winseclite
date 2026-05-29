rule Suspicious_PowerShell_Encoded_Or_Download
{
    meta:
        description = "Defensive heuristic rule for suspicious PowerShell script indicators"
        severity = "medium"
    strings:
        $enc1 = "EncodedCommand" nocase
        $enc2 = "FromBase64String" nocase
        $iex1 = "Invoke-Expression" nocase
        $iex2 = "IEX" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "Invoke-WebRequest" nocase
    condition:
        any of ($enc*) or (any of ($iex*) and any of ($dl*))
}

rule Suspicious_Windows_Script_Persistence_Indicators
{
    meta:
        description = "Defensive heuristic rule for script-based persistence indicators"
        severity = "medium"
    strings:
        $r1 = "CurrentVersion\\Run" nocase
        $s1 = "schtasks" nocase
        $s2 = "New-ScheduledTask" nocase
        $h1 = "-WindowStyle Hidden" nocase
    condition:
        any of them
}
