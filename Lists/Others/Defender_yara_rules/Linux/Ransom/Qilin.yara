rule Ransom_Linux_Qilin_A_2147903423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Qilin.A!MTB"
        threat_id = "2147903423"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Qilin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Qilin" ascii //weight: 1
        $x_1_2 = "vmsvc/snapshot.removeall %llu" ascii //weight: 1
        $x_1_3 = "_RECOVER.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Qilin_B_2147949076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Qilin.B!MTB"
        threat_id = "2147949076"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Qilin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Elapsed for payload encryption: %llu ms" ascii //weight: 1
        $x_1_2 = "Renamed encrypted file '%s' to %s" ascii //weight: 1
        $x_1_3 = "%s_RECOVER.txt" ascii //weight: 1
        $x_1_4 = "Kill processes disabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

