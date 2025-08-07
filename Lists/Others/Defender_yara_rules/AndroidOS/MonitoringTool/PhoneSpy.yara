rule MonitoringTool_AndroidOS_PhoneSpy_A_328571_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.A!xp"
        threat_id = "328571"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.spy<.>6pp.w<.>7bbrows<.>7r" ascii //weight: 1
        $x_1_2 = "ch<.>7ck_<.>9nblock_p<.>6ssword.php" ascii //weight: 1
        $x_1_3 = "com.bbm.<.>9<.>8.<.>6ct<.>8v<.>8t<.>8<.>7s.Conv<.>7rs<.>6t<.>8onAct<.>8v<.>8ty" ascii //weight: 1
        $x_1_4 = "org.<.>6ppspot.<.>6pprtc.SCREENCAPTURE" ascii //weight: 1
        $x_1_5 = "Lorg/webrtc/voiceengine/WebRtcAudioRecord$AudioRecordThread" ascii //weight: 1
        $x_1_6 = "r<.>7cord<.>8ng VOICE_RECOGNITION" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_AndroidOS_PhoneSpy_D_331792_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.D!MTB"
        threat_id = "331792"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com.as.monitoringapp.logging" ascii //weight: 10
        $x_5_2 = "CallRecordTracer" ascii //weight: 5
        $x_5_3 = "ChromeHistoryHistory" ascii //weight: 5
        $x_5_4 = "Stock Browser" ascii //weight: 5
        $x_5_5 = "CallHistoryTracker" ascii //weight: 5
        $x_5_6 = "read_chats_logs" ascii //weight: 5
        $x_1_7 = "SendPost_uploadCalendar.txt" ascii //weight: 1
        $x_1_8 = "SendPost_uploadcontact.txt" ascii //weight: 1
        $x_1_9 = "_img_logs_ScreenShot.txt" ascii //weight: 1
        $x_1_10 = "BkgroundWork.txt" ascii //weight: 1
        $x_1_11 = "Notify_sz.txt" ascii //weight: 1
        $x_1_12 = "Callrecord.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule MonitoringTool_AndroidOS_PhoneSpy_C_332023_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.C!MTB"
        threat_id = "332023"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/monspap/alarm/SMSReceiver" ascii //weight: 1
        $x_1_2 = "CallRecordingService" ascii //weight: 1
        $x_1_3 = "TrackLocation" ascii //weight: 1
        $x_1_4 = "LocationSave" ascii //weight: 1
        $x_1_5 = "PhoneCallReceiver" ascii //weight: 1
        $x_1_6 = "NEW_OUTGOING_CALL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_PhoneSpy_C_332023_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.C!MTB"
        threat_id = "332023"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallRecordingService" ascii //weight: 1
        $x_1_2 = "CommunicationWakefulService" ascii //weight: 1
        $x_1_3 = "ScreenChancedReceiver" ascii //weight: 1
        $x_1_4 = "FileManagerUploadFile" ascii //weight: 1
        $x_1_5 = "com/spa_app/alarm" ascii //weight: 1
        $x_1_6 = "TrackLocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_PhoneSpy_E_365047_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.E!MTB"
        threat_id = "365047"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.spy<!>6pp.w<!>7bbrows<!>7r" ascii //weight: 1
        $x_1_2 = "sms_phon<!>7_l<!>8st" ascii //weight: 1
        $x_1_3 = "RemoteRecordingService" ascii //weight: 1
        $x_1_4 = "com/spa_app/alarm" ascii //weight: 1
        $x_1_5 = "s<!>7nd_d<!>6t<!>6_n<!>7w.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_PhoneSpy_G_426275_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.G!MTB"
        threat_id = "426275"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/spa_mot_app/alarm" ascii //weight: 1
        $x_1_2 = "CloseInternetAndGps" ascii //weight: 1
        $x_1_3 = "CallRecordingService" ascii //weight: 1
        $x_1_4 = "sms_phone_list" ascii //weight: 1
        $x_1_5 = "ServerCommunicate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_PhoneSpy_F_432133_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.F!MTB"
        threat_id = "432133"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/phone_tra_app_sp/alert" ascii //weight: 1
        $x_1_2 = "ScreenChancedReceiver" ascii //weight: 1
        $x_1_3 = "Actv_other" ascii //weight: 1
        $x_1_4 = "Rec_other" ascii //weight: 1
        $x_1_5 = "CallRecordingService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_PhoneSpy_H_451905_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.H!MTB"
        threat_id = "451905"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/sptrakappp/alarm/SMSReceiver" ascii //weight: 1
        $x_1_2 = "RemoteRecordingService" ascii //weight: 1
        $x_1_3 = "ScreenChancedReceiver" ascii //weight: 1
        $x_1_4 = "call_phone_list" ascii //weight: 1
        $x_1_5 = "disable_browser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_PhoneSpy_I_462749_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.I!MTB"
        threat_id = "462749"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 83 d7 02 6e 20 f1 04 36 00 0a 03 38 03 08 00 52 63 37 01 b1 a3 01 24 01 45 28 06 52 63 37 01 01 34 01 93 01 a5 52 8b d7 02 13 10 00 00 33 ab 1e 00 54 6b 39 01 6e 10 63 08 0b 00 0a 0b 14 0c ff ff ff 7f 32 43 2c 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 62 3c 01 52 63 eb 00 52 04 56 00 12 05 71 55 60 04 32 45 0a 02 6e 55 ed 04 f6 21 52 81 d7 02 33 a1 0e 00 6e 20 b5 04 e9 00 0a 01 54 62 39 01 6e 20 5b 08 f2 00 0a 02 b0 12 28 0d 6e 20 b8 04 e9 00 0a 02 54 61 39 01 6e 20 5b 08 f1 00 0a 01 91 01 02 01 52 83 d7 02 54 00 10 01 33 a3 06 00 6e 20 af 04 f0 00 28 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_PhoneSpy_I_462749_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/PhoneSpy.I!MTB"
        threat_id = "462749"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "PhoneSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/spatrakappp/alarm/activities/PhoneAlreadyRegistered" ascii //weight: 1
        $x_1_2 = "Lcom/spatrakappp/alarm/activities/EnableNotificationAccess" ascii //weight: 1
        $x_1_3 = "Lcom/spatrakappp/alarm/services/RemoteRecordingService" ascii //weight: 1
        $x_1_4 = "Lcom/spatrakappp/alarm/services/TrackLocation" ascii //weight: 1
        $x_1_5 = "Lcom/spatrakappp/alarm/ServerCommunicate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

