rule Trojan_Win32_RokRat_MA_2147847984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RokRat.MA!MTB"
        threat_id = "2147847984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RokRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1a 2b f1 d1 fe 33 c9 4e 85 f6 7e ?? 83 c2 02 8a 02 8d 52 02 2a c3 88 04 39 41 3b ce 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RokRat_YAC_2147948323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RokRat.YAC!MTB"
        threat_id = "2147948323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RokRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {56 8b c1 8b f2 30 18 40 83 ee 01 75 f8 5e 57}  //weight: 3, accuracy: High
        $x_1_2 = "Release\\InjectShellcode.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

