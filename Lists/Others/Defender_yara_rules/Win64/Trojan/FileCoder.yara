rule Trojan_Win64_FileCoder_NF_2147893871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c8 ff eb 31 48 8b cb e8 a5 00 00 00 48 85 c0 75 05 83 cf ?? eb 0e 48 89 05 b8 1c 05 00 48 89 05 99 1c 05 00 33 c9 e8 5a 32}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_NF_2147893871_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 41 01 48 83 f8 ?? 7c dc 31 c0 eb 19 48 89 c1 48 c1 e0 ?? 48 8d 15 43 2b 59 00 48 01 c2}  //weight: 5, accuracy: Low
        $x_1_2 = "ZZXuK7T" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_NF_2147893871_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0a 83 e1 0f 4a 0f be 84 ?? d8 ca 04 00 42 8a 8c ?? e8 ca 04 00 48 2b d0 8b 42 fc d3 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 43 ff 48 8d 04 80 4c 8d 0c 87 4d 03 cb e9 58 ff ff ff e8 ab cb fe ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_NF_2147893871_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "File encrypted and original deleted" ascii //weight: 2
        $x_1_2 = "Error encrypting file" ascii //weight: 1
        $x_2_3 = "Send X Bitcoin to address Y to theoretically decrypt them" ascii //weight: 2
        $x_1_4 = "Your files have been theoretically encrypted" ascii //weight: 1
        $x_1_5 = "Starting theoretical encryption of directory:" ascii //weight: 1
        $x_2_6 = "THEORETICAL RANSOM NOTE" ascii //weight: 2
        $x_1_7 = "Generated Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_NF_2147893871_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.NF!MTB"
        threat_id = "2147893871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RansomwareWindowClass" ascii //weight: 2
        $x_1_2 = "cmd /c reg delete HKCU\\Software\\Classes\\ms-settings /f" ascii //weight: 1
        $x_1_3 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "wbadmin delete catalog -quiet" ascii //weight: 1
        $x_1_5 = "Your PC is Encrypted" ascii //weight: 1
        $x_1_6 = "lol, maddox" ascii //weight: 1
        $x_1_7 = "lets sit down as your files are encrypted and then deleted" ascii //weight: 1
        $x_1_8 = "don't try to reset, your pc is already fucked by the time you read this line." ascii //weight: 1
        $x_1_9 = "file decryption is impossible. the decryption keys have already been deleted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FileCoder_ARAZ_2147933262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FileCoder.ARAZ!MTB"
        threat_id = "2147933262"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c8 89 c1 48 8d 55 a0 48 8b 85 c8 04 00 00 48 01 d0 88 08 48 83 85 c8 04 00 00 01 48 8b 85 c8 04 00 00 48 3b 85 a8 04 00 00 72 a1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

