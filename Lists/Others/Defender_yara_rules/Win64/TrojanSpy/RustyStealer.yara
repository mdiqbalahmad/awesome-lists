rule TrojanSpy_Win64_RustyStealer_B_2147946254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/RustyStealer.B"
        threat_id = "2147946254"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 c1 ea 08 34 30 80 f2 02 41 80 f0 c4 45 0f b6 c0}  //weight: 1, accuracy: High
        $x_1_2 = {49 c1 e0 30 0f b6 d2 48 c1 e2 28 4c 09 c2 0f b6 c0 48 c1 e0 20 48 09 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win64_RustyStealer_C_2147946999_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/RustyStealer.C"
        threat_id = "2147946999"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\lucak\\Desktop\\rust-c2\\client\\libs\\memexec\\src\\peparser\\pe.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win64_RustyStealer_D_2147947555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/RustyStealer.D"
        threat_id = "2147947555"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "server_listkeepalive_timeis_killerpersistence_installedenable_keyloggerkeylogger_pathstruct ConfigDataencrypted_datastruct Config" ascii //weight: 1
        $x_1_2 = "slktikpipkpstruct Config" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

