rule Trojan_Win32_SuspClickFix_A_2147941552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.A"
        threat_id = "2147941552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = "http" wide //weight: 3
        $x_3_3 = " -o " wide //weight: 3
        $x_1_4 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_9 = ".aliyuncs.com/" wide //weight: 1
        $x_1_10 = ".myqcloud.com/" wide //weight: 1
        $x_1_11 = {5c 00 4d 00 75 00 73 00 69 00 63 00 5c 00 [0-48] 2e 00 6d 00 73 00 69 00}  //weight: 1, accuracy: Low
        $x_1_12 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 [0-48] 2e 00 70 00 64 00 66 00}  //weight: 1, accuracy: Low
        $x_4_13 = {20 00 2d 00 4c 00 20 00 25 00 ?? ?? ?? ?? 25 00 ?? ?? ?? ?? 25 00 ?? ?? ?? ?? 25 00 ?? ?? ?? ?? 25 00 ?? ?? ?? ?? 25 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_B_2147941553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.B"
        threat_id = "2147941553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "http" wide //weight: 1
        $n_10_4 = "--url http" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_SuspClickFix_C_2147941554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.C"
        threat_id = "2147941554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = "iwr " wide //weight: 5
        $x_1_3 = "iex $" wide //weight: 1
        $x_1_4 = "| iex" wide //weight: 1
        $x_1_5 = "|iex" wide //weight: 1
        $x_1_6 = ";iex " wide //weight: 1
        $x_1_7 = "iex(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_D_2147941555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.D"
        threat_id = "2147941555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = "http" wide //weight: 5
        $x_1_3 = "| powershell" wide //weight: 1
        $x_1_4 = "|powershell" wide //weight: 1
        $x_1_5 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-32] 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_E_2147941628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.E"
        threat_id = "2147941628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 63 00 61 00 6c 00 6c 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_F_2147942715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.F"
        threat_id = "2147942715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 00 74 00 61 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = {20 00 2d 00 78 00 66 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 2d 00 43 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 00 2d 00 78 00 66 00 20 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = " -C C:\\ProgramData\\" wide //weight: 1
        $x_1_6 = {20 00 2d 00 78 00 66 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 [0-48] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = " -C C:\\Users\\Public\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_H_2147943617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.H"
        threat_id = "2147943617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " cmd.exe /c cmd.exe /c " wide //weight: 1
        $x_1_3 = "POST" wide //weight: 1
        $x_1_4 = "http" wide //weight: 1
        $x_1_5 = ".php" wide //weight: 1
        $x_1_6 = " -o " wide //weight: 1
        $x_1_7 = "&& start " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_I_2147947479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.I"
        threat_id = "2147947479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 66 00 74 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $n_10_2 = "57859b6e-ec4b-479a-a155-a5e9248683d6" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_J_2147947870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.J"
        threat_id = "2147947870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-16] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_K_2147947871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.K"
        threat_id = "2147947871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-16] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

