rule Trojan_Win32_UacBypass_G_2147949399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UacBypass.G!MTB"
        threat_id = "2147949399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UacBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe" wide //weight: 1
        $x_1_2 = "add" wide //weight: 1
        $x_1_3 = "hkcu\\software\\classes\\ms-settings\\shell\\open\\command" wide //weight: 1
        $x_1_4 = "c:\\windows\\system32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_UacBypass_H_2147949400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UacBypass.H!MTB"
        threat_id = "2147949400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UacBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe" wide //weight: 1
        $x_1_2 = "add" wide //weight: 1
        $x_1_3 = "hkcu\\software\\classes\\ms-settings\\shell\\open\\command" wide //weight: 1
        $x_1_4 = "DelegateExecute\" /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

