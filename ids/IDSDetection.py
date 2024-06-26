import __builtin__
from ../packetcapture/packetcapture import fcolor
import joblib
from pcapanalysis import processing_packet_conversion
import numpy as np

def ShowIDSDetection(CMD):
    __builtin__.MSG_IDSDetection =""
    __builtin__.MSG_IDSDetectionOverAll =""
    __builtin__.List_AttackingMAC=[]
    WarningCount=0
    TotalProbe=0
    TotalPackets=0
    ProbeMAC=""
    BeaconPrivacy=""
    BeaconChannel=""
    MSG_ATTACK=""
    PrivacyInfo=""
    ConfuseWDS=0
    ConfuseWDSList=""
    ConfuseWDSPkt=0
    ConfuseWDSMAC=""
    AuthFlood=0
    AuthFloodList=""
    AuthFloodPkt=0
    AuthFloodMAC=""
    DetailInfo=fcolor.BBlue + "     [Details]\n"
    Breaks=DrawLine("-",fcolor.CReset + fcolor.Black,"","1")
    package = "/.SYWorks/WAIDPS//waidps/tmp/tcpdump.cap"
    class_pkg = ""
    attack_pkg = ""
    class_map = {
        0: "normal",
        1: "anomal"
    }

    attack_map = {
        0: "amok",
        1: "arp",
        2: "authentication_request",
        3: "beacon",
        4: "cafe_latte",
        5: "deauthentication",
        6: "evil_twin",
        7: "fragmentation",
        8: "probe_response"
    }
    data = processing_packet_conversion(package)
    model=joblib.load('./rf_anomaly_detection/rf_anomaly_detection.pkl')
    model_classification = joblib.load('./rf_anomaly_detection/rf_anomaly_classification.pkl')
    y_prob = model.predict(data)
    y_pred = np.argmax(y_prob, axis = 1)
    if(y_pred != 0):
        y_classification_prob = model_classification.predict(data)
        y_classification_pred = np.argmax(y_classification_prob, axis = 1)
        attack_pkg = attack_map[y_classification_pred]
    class_pkg = class_map[y_pred]
    
    if len(__builtin__.OfInterest_List)>0:
        x=0
        tmpInterestList=[]
        while x<len(__builtin__.OfInterest_List):
            tmpInterestList=str(__builtin__.OfInterest_List[x]).split("\t")
            FrMAC=tmpInterestList[0]
            ToMAC=tmpInterestList[1]
            ToBSSID=tmpInterestList[2]
            GET_DATAARP=tmpInterestList[3]
            GET_DATA86=tmpInterestList[4]
            GET_DATA94=tmpInterestList[5]
            GET_DATA98=tmpInterestList[6]
            GET_AUTH=tmpInterestList[7]
            GET_DEAUTH=tmpInterestList[8]
            GET_DEAUTH_AC=tmpInterestList[9]
            GET_ASSOC=tmpInterestList[10]
            GET_DISASSOC=tmpInterestList[11]
            GET_REASSOC=tmpInterestList[12]
            GET_RTS=tmpInterestList[13]
            GET_CTS=tmpInterestList[14]
            GET_ACK=tmpInterestList[15]
            GET_EAPOL_STD=tmpInterestList[16]
            GET_EAPOL_START=tmpInterestList[17]
            GET_WPS=tmpInterestList[18]
            GET_BEACON=tmpInterestList[19]
            GET_PRQX=tmpInterestList[20]
            GET_PRESP=tmpInterestList[21]
            GET_NULL=tmpInterestList[22]
            GET_QOS=tmpInterestList[23]
            YOURMAC=tmpInterestList[24]
            GET_PROBE=tmpInterestList[25]
            MSG_ATTACK=""
            PrivacyInfo=""
            DetailInfo=fcolor.BBlue + "     [Details]\n"
            tGET_PROBE=RemoveColor(GET_PROBE)
            tGET_PROBE=tGET_PROBE.replace(" / <<Broadcast>> / "," / ").replace(" / <<Broadcast>>","").replace("<<Broadcast>> / ","")
            GET_PROBEList=[]
            GET_PROBEList=tGET_PROBE.split(" / ")
            if str(GET_PROBE).find("\\")!=-1 or FrMAC!=ToBSSID:
                GET_PROBEList=[]
            NotesInfo1="";NotesInfo2="";NotesInfo3=""
            AddMACToList(FrMAC,List_AttackingMAC)
            AddMACToList(ToMAC,List_AttackingMAC)
            AddMACToList(ToBSSID,List_AttackingMAC)
            PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
            if int(GET_ASSOC)>int(__builtin__.THRESHOLD_ASSOC) and int(GET_AUTH)<int(__builtin__.THRESHOLD_AUTH) and FrMAC!=ToBSSID:	# ASSOCIATION
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_ASSOC + " Association " + fcolor.BGreen + " / " + fcolor.BRed + GET_AUTH + " Authentication " + fcolor.BGreen + " / " + fcolor.BRed + GET_DEAUTH + " DeAuth "
               ATTACK_TYPE="Association Flood"
               NotesInfo1="The data pattern match those persistent associating with AP."
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
               if PrivacyInfo!="":
                   if PrivacyInfo=="WEP":
                       if WPSInfo=="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + ", it likely continuious fake authentication is deploy."
                       else:
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and WPS is enabled, likely WPS PIN bruteforcing."
                   else:
                       if WPSInfo!="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and is WPS enabled, continuious association may indicated WPS bruteforcing."
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be flooding Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] with association request"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_ASSOC)<int(__builtin__.THRESHOLD_ASSOC) and int(GET_AUTH)>int(__builtin__.THRESHOLD_AUTH) and FrMAC!=ToBSSID:	# ASSOCIATION
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_AUTH + " Authentication " + fcolor.BGreen + " / " + fcolor.BRed + GET_ASSOC + " Association " + fcolor.BGreen + " / " + fcolor.BRed + GET_DEAUTH + " DeAuth "
               ATTACK_TYPE="Authentication Flood"
               if FrMAC=="FF:FF:FF:FF:FF:FF" and ToBSSID==ToMAC:
                   ConfuseWDS=ConfuseWDS+1
                   if str(ConfuseWDSList).find(ToBSSID)==-1:
                       ConfuseWDSList=ConfuseWDSList + ToBSSID + " / "
                   ConfuseWDSPkt=ConfuseWDSPkt + int(GET_AUTH)
                   ConfuseWDSMAC=ToBSSID
               elif FrMAC!="FF:FF:FF:FF:FF:FF" and ToBSSID==ToMAC:
                   AuthFloodPkt=AuthFloodPkt + int(GET_AUTH)
                   AuthFlood=AuthFlood + 1
                   if str(AuthFloodList).find(ToBSSID)==-1:
                       AuthFloodList=AuthFloodList + ToBSSID + " / "
                       AuthFloodMAC=FrMAC
               NotesInfo1="The data pattern match those persistent authenticating with AP."
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
               if PrivacyInfo!="":
                   if PrivacyInfo=="WEP":
                       if WPSInfo=="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + ", it likely continuious fake authentication is deploy."
                       else:
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and WPS is enabled, likely WPS PIN bruteforcing."
                   else:
                       if WPSInfo!="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and is WPS enabled, continuious association may indicated WPS bruteforcing."
               if int(GET_AUTH)>200 and int(GET_ASSOC)==0:
                   InfoTxt="Too much Authentication request and signature seem to be " + fcolor.BRed + "MDK3 Authentication DoS Mode (a) - Standard " + fcolor.SWhite + ".."
                   if NotesInfo2!="":
                       NotesInfo2=NotesInfo2 + "\n                         " + InfoTxt
                   else:
                       NotesInfo2=InfoTxt
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be flooding Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] with authentication request"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_ASSOC)>int(__builtin__.THRESHOLD_ASSOC) and int(GET_AUTH)>int(__builtin__.THRESHOLD_AUTH) and FrMAC!=ToBSSID:	# ASSOCIATION
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_ASSOC + " Association " + fcolor.BGreen + " / " + fcolor.BRed + GET_AUTH + " Authentication " + fcolor.BGreen + " / " + fcolor.BRed + GET_DEAUTH + " DeAuth "
               ATTACK_TYPE="Association/Authentication Flood"
               if FrMAC=="FF:FF:FF:FF:FF:FF" and ToBSSID==ToMAC:
                   ConfuseWDS=ConfuseWDS+1
                   if str(ConfuseWDSList).find(ToBSSID)==-1:
                       ConfuseWDSList=ConfuseWDSList + ToBSSID + " / "
                   ConfuseWDSPkt=ConfuseWDSPkt + int(GET_AUTH)
                   ConfuseWDSMAC=ToBSSID
               NotesInfo1="The data pattern match those persistent associating/authenticating with AP."
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
               if PrivacyInfo!="":
                   if PrivacyInfo=="WEP":
                       if WPSInfo=="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + ", it likely continuious fake authentication is deploy."
                       else:
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and WPS is enabled, likely WPS PIN bruteforcing."
                   else:
                       if WPSInfo!="":
                           NotesInfo2="The encryption for Access Point is " + fcolor.BYellow  + PrivacyInfo + ColorStd2 + " and is WPS enabled, continuious association may indicated WPS bruteforcing."
               if int(GET_ASSOC)>int(GET_AUTH) and int(GET_ASSOC)>100:
                   InfoTxt="There is a possibility of " + fcolor.BRed + "MDK3 Authentication DoS Mode (Intelligent Test -i) " + fcolor.SWhite + ".."
                   if NotesInfo2!="":
                       NotesInfo2=NotesInfo2 + "\n                         " + InfoTxt
                   else:
                       NotesInfo2=InfoTxt
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be flooding Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] with association/authentication request"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if (int(GET_DATAARP)>int(__builtin__.THRESHOLD_DATAARP) and PrivacyInfo=="WEP") or (class_pkf == "anomal" and attack_pkg == "arp"):	# ARP 
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_DATAARP
               NotesInfo1="The data pattern match those used in Aireplay-NG ARP-Replay Request Attack."
               ATTACK_TYPE="WEP - ARP-Replay Request"
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               if PrivacyInfo=="WEP":
                   NotesInfo2="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WEP" + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is attacking Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ]"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_DATA98)>int(__builtin__.THRESHOLD_DATA98):	# CHOPCHOP - GUESSING PROCESS
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_DATA98
               NotesInfo1="The data pattern match those used in Aireplay-NG KoreK Chopchop Attack."
               ATTACK_TYPE="WEP - KoreK Chopchop"
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               if PrivacyInfo=="WEP":
                   NotesInfo2="The KoreK Chopchop attacks will usually come before an ARP-Replay Request after it obtained the decrypted WEP byte"
                   NotesInfo3="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WEP" + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is attacking Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ]"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               ToMAC="FF:FF:FF:FF:FF:FF"
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            ## TESTING - mdk3 mon0 m -t <TARGET BSSID>
            if int(GET_DATA94)>int(__builtin__.THRESHOLD_DATA94) and FrMAC=="00:00:00:00:00:00" and ToMAC==ToBSSID:	# Michael Shutdown Exploitation (TKIP)
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_DATA94
               NotesInfo1="The data pattern match those used in MDK3 Michael Shutdown Exploitation (TKIP) Attack."
               ATTACK_TYPE="MDK3 - Michael Shutdown Exploitation (TKIP)"
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               foundloc=FindMACIndex(ToBSSID,ListInfo_BSSID)
               PrivacyInfo=str(ListInfo_Privacy[foundloc])
               CipherInfo=str(ListInfo_Cipher[foundloc])
               if str(PrivacyInfo).find("WPA")!=-1 and str(CipherInfo).find("TKIP")!=-1:
                   NotesInfo2="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WPA - TKIP" + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is attacking Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ]"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(ToBSSID,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if len(GET_PROBEList)>1 and ToMAC=="FF:FF:FF:FF:FF:FF":		# ROGUE AP
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_BEACON
               NotesInfo1="The response pattern match those used in Rogue Access Point."
               ATTACK_TYPE="Rogue Access Point"
               NotesInfo2="Do note that if SSID Name looks similar, it may not a Rogue Access Point due to malformed packets"
               NotesInfo3="Unless similar Rogue AP is pick up by WAIDPS several time with different ESSID, it may not be a Rogue AP."
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               if PrivacyInfo=="OPN":
                   NotesInfo3=fcolor.BRed + "Rogue AP in most cases will be an Open network and response to probe request by devices. Current AP match the profile."
               tGET_PROBE=RemoveColor(tGET_PROBE)
               tProbeCt=tGET_PROBE.split(" / ")
               ProbeCt=0
               ProbeCt=int(len(tProbeCt))
               ProbeCt=ProbeCt+1
               F5M=str(FrMAC[:5])
               foundloc=FindMACIndex(FrMAC,ListInfo_BSSID)
               BChannel=ListInfo_Channel[foundloc]
               if ProbeMAC=="":
                   ProbeMAC=FrMAC
                   TotalPackets=TotalPackets + int(PACKET_SENT)
                   TotalProbe=TotalProbe + int(ProbeCt)
                   if BChannel!="":
                       BeaconChannel=BChannel + " / "
               elif ProbeMAC!="" and ProbeMAC[:5]==F5M:
                   ProbeMAC= ProbeMAC + " / " + FrMAC
                   TotalPackets=TotalPackets + int(PACKET_SENT)
                   TotalProbe=TotalProbe + int(ProbeCt)
                   if BeaconPrivacy!="":
                       if str(BeaconPrivacy).find(PrivacyInfo)==-1:
                           BeaconPrivacy=BeaconPrivacy + " / " + PrivacyInfo
                   else:
                       BeaconPrivacy=PrivacyInfo
                   if BChannel!="" and str(BeaconChannel).find(BChannel + " / ")==-1:
                       BeaconChannel=BeaconChannel + BChannel + " / "
               if PrivacyInfo!="" and BeaconPrivacy=="":
                   BeaconPrivacy=PrivacyInfo
               tGET_PROBE=ReplaceSlash(tGET_PROBE,fcolor.BBlue,fcolor.SWhite)
               GET_PROBE=GET_PROBE.replace(" / ", fcolor.SWhite + " / " + fcolor.BBlue)
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] broadcasted itself as [ " + fcolor.BBlue + tGET_PROBE + fcolor.BGreen + " ]"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               ToMAC="FF:FF:FF:FF:FF:FF"
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_QOS)>int(__builtin__.THRESHOLD_QOS):	# TKIPTUN-NG
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_QOS 
               NotesInfo1="The data pattern match those used in TKIPTUN-NG Attacks."
               ATTACK_TYPE="TKIPTUN-NG Injection"
               PrivacyInfo=GetPrivacyInfo(ToMAC,ToBSSID,ToBSSID,0)
               if PrivacyInfo=="WPA" or PrivacyInfo=="WPA2":
                   NotesInfo2="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WPA/WPA2" + "\n"
                   CipherInfo=GetPrivacyInfo(ToMAC,ToBSSID,ToBSSID,1)
                   if str(CipherInfo).find("TKIP")!=-1:
                       NotesInfo3="The Cipher of the BSSID also Match Attack Criteria : " + fcolor.BYellow + str(CipherInfo) + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] <Fake MAC> injecting to Station [ " + fcolor.BRed + ToMAC + fcolor.BGreen + " ] ==> BSSID [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ]"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(ToMAC,ToBSSID,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_DEAUTH_AC)>int(__builtin__.THRESHOLD_DEAUTH_AC) or (class_pkg == "anomal" and attack_pkg == "amok"): # and int(GET_DISASSOC)==0:	# DEAUTH - A
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_DEAUTH_AC
               if int(GET_DISASSOC)==0:
                   NotesInfo1="The data pattern match those used in " + fcolor.BRed + "Aireplay-NG Deauthenticate Request" + fcolor.SWhite + "..."
               elif int(GET_DISASSOC)>int(__builtin__.THRESHOLD_DISASSOC):
                   NotesInfo1="The data pattern match those used in " + fcolor.BRed + "MDK3 Deauthentication / Disassoication Amok Mode" + fcolor.SWhite + "..."
               ATTACK_TYPE="Deauthentication Attack"
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               if PrivacyInfo=="WPA" or PrivacyInfo=="WPA2":
                   NotesInfo2="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WPA/WPA2" + "\n\n"
                   ATTACK_TYPE="Deauthentication - WPA Handshake"
               if ToMAC!="FF:FF:FF:FF:FF:FF":
                   sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is calling deauthentication to [ " + fcolor.BCyan + ToMAC + fcolor.BGreen + " ]"
               else:
                   sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is calling deauthentication to all stations"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_DEAUTH_AC)>0 and int(GET_DISASSOC)>1 and int(GET_DEAUTH)==0:	# WPA DOWNGRADE
               PrivacyInfo=GetPrivacyInfo(FrMAC,ToMAC,ToBSSID,0)
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               if FrMAC=="FF:FF:FF:FF:FF:FF" or ToMAC=="FF:FF:FF:FF:FF:FF":
                   PACKET_SENT=GET_DEAUTH_AC + " Deauth / " + GET_DISASSOC + " Disassociation"
                   if str(PrivacyInfo).find("WPA")!=-1:
                       NotesInfo2="The Encryption of the BSSID also Match Attack Criteria : " + fcolor.BYellow + "WPA/WPA2" + "\n\n"
                   NotesInfo1="The data pattern match those used in MDK3 - WPA Downgrade Test (g) / Deauthentication/Disassociation Amok Mode (d)"
                   ATTACK_TYPE="MDK3 - WPA Downgrade Test / Deauthentication/Disassociation Amok Mode"
                   if FrMAC!="FF:FF:FF:FF:FF:FF" and ToMAC=="FF:FF:FF:FF:FF:FF" and FrMAC!=ToBSSID:
                       sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] is calling deauthentication/disassociation to [ " + fcolor.BCyan + "Broadcast" + fcolor.BGreen + " ] on Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ].."
                   elif FrMAC=="FF:FF:FF:FF:FF:FF" and ToMAC!="FF:FF:FF:FF:FF:FF" and ToMAC!=ToBSSID:
                       sData=fcolor.BGreen + "[ " + fcolor.BRed + "Broadcast"  + fcolor.BGreen + " ] deauthentication/disassociation to station [ " + fcolor.BCyan + str(ToMAC) + fcolor.BGreen + " ] on Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ].."
                   elif FrMAC=="FF:FF:FF:FF:FF:FF" and ToMAC!="FF:FF:FF:FF:FF:FF" and ToMAC==ToBSSID:
                       sData=fcolor.BGreen + "[ " + fcolor.BRed + "Broadcast" + fcolor.BGreen + " ] deauthentication/disassociation to Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ].."
                   elif FrMAC!="FF:FF:FF:FF:FF:FF" and ToMAC=="FF:FF:FF:FF:FF:FF" and FrMAC==ToBSSID:
                       sData=fcolor.BGreen + "[ " + fcolor.BCyan + str(FrMAC) + fcolor.BGreen + " ], the Access Point is calling deauthentication/disassociation to [ " + fcolor.BRed + "Broadcast" + fcolor.BGreen + " ].."
                   else:
                       sData=fcolor.BGreen + "[ " + fcolor.BRed + str(FrMAC) + fcolor.BGreen + " ] calling deauthentication/disassociation to [ " + fcolor.BCyan + str(ToMAC) + fcolor.BGreen + " ].."
                   MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
                   MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
                   MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_EAPOL_START)>int(__builtin__.THRESHOLD_EAPOL_START) and FrMAC!=ToBSSID and int(GET_EAPOL_START)>int(GET_WPS):	# REAVER - WPS - EAPOL START
               WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
               PACKET_SENT=GET_EAPOL_START + " EAPOL Start" + fcolor.BGreen + " / " + fcolor.BRed + GET_WPS + " EAP Request "
               ATTACK_TYPE="WPS - PIN Bruteforce Attempting"
               NotesInfo1="The data pattern match those used in WPS Communication."
               WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
               if WPSInfo!="":
                   WPSInfo=str(WPSInfo).replace("Lock?", fcolor.BWhite + "Lock?" + fcolor.SWhite).replace(" : No",fcolor.SWhite + " : " + fcolor.BGreen + "No" + fcolor.SWhite).replace(" : Yes",fcolor.SWhite + " : " + fcolor.BRed + "Yes" + fcolor.SWhite).replace(" : Null",fcolor.SWhite + " : " + fcolor.BWhite + "Null" + fcolor.SWhite).replace(" : -",fcolor.SWhite + " : " + fcolor.BWhite + "-" + fcolor.SWhite).replace("Ver - ",fcolor.BWhite + " Ver - " + fcolor.BGreen)
                   NotesInfo2="Having too much EAP Start request than EAP Message,it likely station failed to attack Access Point.. Observe the pattern."
                   NotesInfo3="The Access Point has WPS [ " + str(WPSInfo) + " ] and Match Attack Criteria : " + fcolor.BYellow + "WPS" + "\n\n"
               sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be attacking Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] via EAP Start / WPS authentication"
               MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
               MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
               MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            if int(GET_WPS)>int(__builtin__.THRESHOLD_WPS) or int(GET_EAPOL_START)>int(__builtin__.THRESHOLD_EAPOL_START):   # and FrMAC!=ToBSSID:	# REAVER - WPS
               if FrMAC!=ToBSSID:
                   WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
                   PACKET_SENT=GET_EAPOL_START + " EAPOL Start " + fcolor.SGreen + "/" + fcolor.BRed + GET_EAPOL_STD + " EAPOL Standard " + fcolor.SGreen + "/" + fcolor.BRed + GET_WPS + " EAP Request"
                   ATTACK_TYPE="WPS - PIN Bruteforce"
                   NotesInfo1="The data pattern match those used in WPS Communication."
                   WPSInfo=GetWPSInfo(FrMAC,ToMAC,ToBSSID)
                   if WPSInfo!="":
                       WPSInfo=str(WPSInfo).replace("Lock?", fcolor.BWhite + "Lock?" + fcolor.SWhite).replace(" : No",fcolor.SWhite + " : " + fcolor.BGreen + "No" + fcolor.SWhite).replace(" : Yes",fcolor.SWhite + " : " + fcolor.BRed + "Yes" + fcolor.SWhite).replace(" : Null",fcolor.SWhite + " : " + fcolor.BWhite + "Null" + fcolor.SWhite).replace(" : -",fcolor.SWhite + " : " + fcolor.BWhite + "-" + fcolor.SWhite).replace("Ver - ",fcolor.BWhite + " Ver - " + fcolor.BGreen)
                       NotesInfo2="Usually a WPS Pin Brutefore will be slow and continuous.. Observe the pattern."
                       NotesInfo3="The Access Point has WPS [ " + str(WPSInfo) + " ] and Match Attack Criteria : " + fcolor.BYellow + "WPS" + "\n\n"
                   sData=fcolor.BGreen + "[ " + fcolor.BRed + FrMAC + fcolor.BGreen + " ] could be attacking Access Point [ " + fcolor.BCyan + ToBSSID + fcolor.BGreen + " ] via WPS authentication"
                   MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
                   MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
                   MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll+RemoveDoubleLF(str(MSG_ATTACK)) #+ str(Breaks) + "\n"
            x += 1
    
    ## TESTING ---- MDK3 BEACON FLOODING WITH DIFFERENT ESSID = mdk3 mon0 b 
    if ProbeMAC!="" and int(TotalProbe)>20:
        WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3=""
        PACKET_SENT=TotalPackets
        NotesInfo1="The data pattern match those used in MDK3 Beacon Flooding Mode (b)"
        ATTACK_TYPE="MDK3 - Beacon Flooding Mode"
        ProbeMACA=str(ProbeMAC).replace("/",fcolor.SWhite + "/" + fcolor.BRed)
        ProbeMACB=str(ProbeMAC).replace("/",fcolor.SWhite + "/" + fcolor.BCyan)
        if BeaconChannel!="" and BeaconChannel[-3:]==" / ":
            BeaconChannel=BeaconChannel[:-3]
        BeaconChannel=str(BeaconChannel).replace("/",fcolor.SWhite + "/" + fcolor.BGreen)
        BeaconPrivacy=str(BeaconPrivacy).replace("/",fcolor.SWhite + "/" + fcolor.BGreen)
        sData=fcolor.BGreen + "[ " + fcolor.BRed + ProbeMACA + fcolor.BGreen + " ] is broadcasting numerous ESSIDs"
        MACInfo = "     " + fcolor.SGreen + "From BSSID [ " + fcolor.BCyan + str(ProbeMACB) + fcolor.SWhite + " ] ==> To MAC [ " + fcolor.BRed + "FF:FF:FF:FF:FF:FF"  + fcolor.SWhite + " ].\n"
        MACInfo = MACInfo + "     " + fcolor.SWhite + "  Beacons  [ " + fcolor.BYellow + str(TotalPackets) + " Beacons Found" + fcolor.SWhite + " ]\n"
        MACInfo = MACInfo + "     " + fcolor.SWhite + "  ESSIDs   [ " + fcolor.BYellow + str(TotalProbe) + " ESSIDs Found" + fcolor.SWhite + " ]\n"
        MACInfo = MACInfo + "     " + fcolor.SWhite + "  Channels [ " + fcolor.BGreen + str(BeaconChannel) + fcolor.SWhite + " ]\n"
        MACInfo = MACInfo + "     " + fcolor.SWhite + "  Privacy  [ " + fcolor.BGreen + str(BeaconPrivacy) + fcolor.SWhite + " ]\n"
        MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
        MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
        __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll+RemoveDoubleLF(str(MSG_ATTACK)) #+ str(Breaks) + "\n"
        F5M=str(ProbeMAC[:5])
        RemoveFloodedAP("",str(F5M))
    ## TESTING ---- MDK3 BEACON FLOODING WITH SIMILAR ESSID = mdk3 mon0 b -n AAAAAA
    tmpAll_ESSID=[]
    x=0
    y=0
    Similar_ESSID=ListDuplicate(ListInfo_ESSID)
    Similar_ESSID=filter(None,Similar_ESSID)
    if len(Similar_ESSID)>0:
        SimilarCt=0
        SimilarChannel=""
        SimilarBSSID=""
        SimilarPrivacy=""
        x=0
        while x<len(Similar_ESSID): # and CheckWhitelist(Similar_ESSID[x])=="":
            y=0
            while y<len(ListInfo_ESSID):
                if Similar_ESSID[x]!="" and Similar_ESSID[x]==ListInfo_ESSID[y]:
                    SimilarCt=SimilarCt+1
                    if SimilarChannel=="":
                        SimilarChannel=ListInfo_Channel[y] + " / "
                    elif SimilarChannel!="":
                        if str(SimilarChannel).find(ListInfo_Channel[y] + " / ")==-1:
                            SimilarChannel=SimilarChannel + ListInfo_Channel[y] + " / "
                    if SimilarBSSID=="":
                        SimilarBSSID=ListInfo_BSSID[y] + " / "
                        AddMACToList(ListInfo_BSSID[y],List_AttackingMAC)
                    elif SimilarBSSID!="":
                        if str(SimilarBSSID).find(ListInfo_BSSID[y] + " / ")==-1:
                            SimilarBSSID=SimilarBSSID + ListInfo_BSSID[y] + " / "
                            AddMACToList(ListInfo_BSSID[y],List_AttackingMAC)
                    if SimilarPrivacy=="" and ListInfo_Privacy[y]!="":
                        SimilarPrivacy=ListInfo_Privacy[y] + " / "
                    elif SimilarPrivacy!="" and ListInfo_Privacy[y]!="":
                        if str(SimilarPrivacy).find(ListInfo_Privacy[y] + " / ")==-1:
                            SimilarPrivacy=SimilarPrivacy + ListInfo_Privacy[y] + " / "
                y += 1
            if SimilarCt>15:
                WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3="";MACInfo=""
                NotesInfo1="The data pattern match those used in MDK3 Beacon Flooding Mode (b) with Similar ESSID."
                ATTACK_TYPE="MDK3 - Beacon Flooding Mode (Similar ESSID)"
                tBSSIDCt=SimilarBSSID.split("/")
                BSSIDCt=int(len(tBSSIDCt)) - 1
                if SimilarBSSID!="" and SimilarBSSID[-3:]==" / ":
                    SimilarBSSID=SimilarBSSID[:-3]
                SimilarBSSID=str(SimilarBSSID).replace("/",fcolor.SWhite + "/" + fcolor.SRed)
                if SimilarChannel!="" and SimilarChannel[-3:]==" / ":
                    SimilarChannel=SimilarChannel[:-3]
                SimilarChannel=str(SimilarChannel).replace("/",fcolor.SWhite + "/" + fcolor.BGreen)
                if SimilarPrivacy!="" and SimilarPrivacy[-3:]==" / ":
                    SimilarPrivacy=SimilarPrivacy[:-3]
                SimilarPrivacy=str(SimilarPrivacy).replace("/",fcolor.SWhite + "/" + fcolor.BGreen)
                sData=fcolor.BGreen + "[ " + fcolor.SRed + SimilarBSSID + fcolor.BGreen + " ] is broadcasting as [ " + fcolor.BPink + Similar_ESSID[x] + fcolor.BGreen + " ]"
                MACInfo = "     " + fcolor.SWhite + "  BSSIDs   [ " + fcolor.BGreen + str(BSSIDCt) + " BSSIDs Found" + fcolor.SWhite + " ]\n"
                MACInfo = MACInfo + "     " + fcolor.SWhite + "  ESSIDs   [ " + fcolor.BGreen + str(SimilarCt) + " Similar ESSID Found" + fcolor.SWhite + " ]\n"
                MACInfo = MACInfo + "     " + fcolor.SWhite + "  Channels [ " + fcolor.BGreen + str(SimilarChannel) + fcolor.SWhite + " ]\n"
                MACInfo = MACInfo + "     " + fcolor.SWhite + "  Privacy  [ " + fcolor.BGreen + str(SimilarPrivacy) + fcolor.SWhite + " ]\n"
                MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,"",NotesInfo1,NotesInfo2,NotesInfo3)
                MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
                __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll+RemoveDoubleLF(str(MSG_ATTACK)) #+ str(Breaks) + "\n"
                RemoveFloodedAP(Similar_ESSID[x],"")
            x += 1
    
    ## TESTING ---- MDK3 PROBING & ESSID BRUTEFORCE = mdk3 mon0 p -b abcdefg -p TEST-AP -c 2 -t <AP_MAC>
    x=0
    ProbeLen=0
    SimilarProbeCt=0
    SingleProbe=0
    ProbedESSID=""
    StationID=""
    while x<len(ListInfo_STATION):
        if ListInfo_CBSSID[x]=="Not Associated" and len(ListInfo_PROBE[x])>0:
            tProbe=[]
            if ListInfo_PROBE[x]!="":
                tProbe=str(ListInfo_PROBE[x]).split (" / ")
                ProbeCt=len(tProbe)
            else:
                ProbeCt=0
            if ProbeCt==1:
                SingleProbe=SingleProbe+1
                ProbedESSID=ProbedESSID + ListInfo_PROBE[x] + " / "
                StationID=StationID + ListInfo_STATION[x] + " / "
                if ProbeLen==len(ListInfo_PROBE[x]):
                    SimilarProbeCt=SimilarProbeCt+1
                else:
                    ProbeLen=len(ListInfo_PROBE[x])
        x +=1
    if int(SingleProbe)>50:
        WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3="";MACInfo=""
        NotesInfo1="The data pattern match those used in MDK3 Basic Probing and ESSID Bruteforce Mode (p)"
        ATTACK_TYPE="MDK3 - Basic Probing & ESSID BruteForce Mode"
        if StationID!="" and StationID[-3:]==" / ":
            StationID=StationID[:-3]
        StationID=str(StationID).replace("/",fcolor.SWhite + "/" + fcolor.BRed)
        if ProbedESSID!="" and ProbedESSID[-3:]==" / ":
            ProbedESSID=ProbedESSID[:-3]
        ProbedESSID=str(ProbedESSID).replace("/",fcolor.SWhite + "/" + fcolor.BBlue)
        sData=fcolor.BGreen + "[ " + fcolor.BRed + "Multiple Station MACs" + fcolor.BGreen + " ] is probing [ " + fcolor.BPink + "Multiple ESSID" + fcolor.BGreen + " ]"
        MACInfo = "     " + fcolor.SWhite + "  Stations [ " + fcolor.BRed + str(StationID) + "" + fcolor.SWhite + " ]\n"
        MACInfo = MACInfo + "     " + fcolor.SWhite + "  Probes   [ " + fcolor.BBlue + str(ProbedESSID) + " " + fcolor.SWhite + " ]\n"
        MACInfo = MACInfo + "     " + fcolor.SWhite + "  Detected [ " + fcolor.BGreen + str(SingleProbe) + fcolor.SGreen + " Stations with Single Probe" + fcolor.SWhite + " ]\n"
        MACInfo = MACInfo + "     " + fcolor.SWhite + "  Detected [ " + fcolor.BGreen + str(SimilarProbeCt) + fcolor.SGreen + " Probes with same ESSID length" + fcolor.SWhite + " ]\n"
        MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,"",NotesInfo1,NotesInfo2,NotesInfo3)
        MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
        __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll+RemoveDoubleLF(str(MSG_ATTACK))
        RemoveUnassociatedClient("")
        MSG_ATTACK=""
    ## TESTING ---- MDK3 WIDS/WIPS/WDS CONFUSION = mdk3 mon0 w -e Test -c 6
    if ConfuseWDS!=0:
        ConfuseWDSListCt=0
        tCt=[]
        WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3="";MACInfo=""
        NotesInfo1="The data pattern match those used in MDK3 WIDS/WIPS/WDS Confusion Mode (w)"
        if ConfuseWDSList!="" and ConfuseWDSList[-3:]==" / ":
            tCt=ConfuseWDSList.split("/")
            ConfuseWDSListCt=len(tCt) - 1
            ConfuseWDSList=ConfuseWDSList[:-3]
        ConfuseWDSList=str(ConfuseWDSList).replace("/",fcolor.SWhite + "/" + fcolor.BCyan)
        if ConfuseWDS==1:
            ATTACK_TYPE="MDK3 - WIDS/WIPS/WDS Confusion Mode - Single"
            sData=fcolor.BGreen + "[ " + fcolor.BRed + "Broadcast" + fcolor.BGreen + " ] authentication flood to [ " + fcolor.BCyan + str(ConfuseWDSMAC) + fcolor.BGreen + " ]"
            MACInfo=DisplayMACSInformation(FrMAC,ToMAC,ToBSSID)
        else:
            ATTACK_TYPE="MDK3 - WIDS/WIPS/WDS Confusion Mode - Multiple"
            sData=fcolor.BGreen + "[ " + fcolor.BRed + "Broadcast" + fcolor.BGreen + " ] authentication flood to [ " + fcolor.BPink + "Multiple Access Points" + fcolor.BGreen + " ]"
            MACInfo = "     " + fcolor.SWhite + "  A.Points [ " + fcolor.BGreen + str(ConfuseWDSListCt) + "" + fcolor.SWhite + " ] - " + fcolor.BCyan + ConfuseWDSList + "\n"
            MACInfo = MACInfo + "     " + fcolor.SWhite + "  Detected [ " + fcolor.BRed + str(ConfuseWDS) + fcolor.SGreen + " Affected Access Points (Authentication Flooding)" + fcolor.SWhite + " ]\n"
        PACKET_SENT=ConfuseWDSPkt
        MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
        MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
        __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll+RemoveDoubleLF(str(MSG_ATTACK))
        RemoveFloodedAP("<NONE>","")
        MSG_ATTACK=""
    ## TESTING ---- MDK3 AUTHENTICATION FLOOD TO ALL ACCESS POINTS = mdk3 mon0 a
    if AuthFlood>3:
        AuthFloodListCt=0
        tCt=[]
        WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3="";MACInfo=""
        NotesInfo1="The data pattern match those used in MDK3 Authentication DoS (a) to all Access Points "
        tCt=[]
        if AuthFloodList!="" and AuthFloodList[-3:]==" / ":
            tCt=AuthFloodList.split("/")
            AuthFloodListCt=len(tCt) - 1
            AuthFloodList=AuthFloodList[:-3]
        AuthFloodList=str(AuthFloodList).replace("/",fcolor.SWhite + "/" + fcolor.BCyan)
        ATTACK_TYPE="MDK3 - Authentication DoS (a) to Multiple Access Points"
        sData=fcolor.BGreen + "[ " + fcolor.BRed + str(AuthFloodMAC) + fcolor.BGreen + " ] authentication flood to [ " + fcolor.BPink + "Multiple Access Points" + fcolor.BGreen + " ]"
        MACInfo = "     " + fcolor.SWhite + "  A.Points [ " + fcolor.BGreen + str(AuthFloodListCt) + "" + fcolor.SWhite + " ] - " + fcolor.BCyan + AuthFloodList + "\n"
        MACInfo = MACInfo + "     " + fcolor.SWhite + "  Detected [ " + fcolor.BRed + str(AuthFloodListCt) + fcolor.SGreen + " Affected Access Points (Authentication Flooding)" + fcolor.SWhite + " ]\n"
        PACKET_SENT=str(AuthFloodPkt) + " Authentication"
        MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,PACKET_SENT,NotesInfo1,NotesInfo2,NotesInfo3)
        MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
        __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll+RemoveDoubleLF(str(MSG_ATTACK))
        MSG_ATTACK=""
 
 
    ## TESTING ---- MDK3 AUTHENTICATION FLOODING WITH CLIENTS = mdk3 mon0 a -a <AP MAC> -m
    x=0
    DoSAP=0
    DoSST=0
    DoSAPList=""
    while x<len(__builtin__.ListInfo_BSSID):
        if int(__builtin__.ListInfo_ConnectedClient[x])>100:
            DoSST=DoSST+ int(__builtin__.ListInfo_ConnectedClient[x])
            DoSAPList = DoSAPList + str(__builtin__.ListInfo_BSSID[x]) + " / "
            WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3="";MACInfo="";MSG_ATTACK=""
            ATTACK_TYPE="Authentication Flood with Multiple Stations"
            NotesInfo1="Unusual large number of station associated to an Access Point."
            NotesInfo2="There is a possibility of " + fcolor.BRed + "MDK3 Authentication DoS Mode " + fcolor.SWhite + " with [ " + fcolor.BRed + "-m" + fcolor.SWhite + " ] option.."
            NotesInfo3=fcolor.BRed + str(int(__builtin__.ListInfo_ConnectedClient[x])) + fcolor.SWhite + " stations found to be associated to the Access Point."
            sData=fcolor.BGreen + "[ " + fcolor.BRed + "Multiple Stations MAC" + fcolor.BGreen + " ] could be flooding Access Point [ " + fcolor.BCyan + str(__builtin__.ListInfo_BSSID[x]) + fcolor.BGreen + " ] with authentication request"
            MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,"",NotesInfo1,NotesInfo2,NotesInfo3)
            MACInfo=DisplayMACSInformation("FF:FF:FF:FF:FF:FF",str(__builtin__.ListInfo_BSSID[x]),str(__builtin__.ListInfo_BSSID[x]))
            MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
            __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll+RemoveDoubleLF(str(MSG_ATTACK))
            RemoveUnassociatedClient(str(__builtin__.ListInfo_BSSID[x]))
            DoSAP=DoSAP+1
        x += 1
    MSG_ATTACK=""
    ## TESTING ---- MDK3 AUTHENTICATION FLOODING WITH CLIENTS TO MULTIPLE AP = mdk3 mon0 a -m
    if DoSAP>1:
        WarningCount=WarningCount+1;NotesInfo1="";NotesInfo2="";NotesInfo3="";MACInfo="";MSG_ATTACK=""
        if DoSAPList!="" and DoSAPList[-3:]==" / ":
            tCt=DoSAPList.split("/")
            DoSAPListCt=len(tCt) - 1
            DoSAPList=DoSAPList[:-3]
        DoSAPList=str(DoSAPList).replace("/",fcolor.SWhite + "/" + fcolor.BCyan)
        ATTACK_TYPE="Authentication Flood with Multiple Stations To Multiple Access Point"
        NotesInfo1="Unusual large number of station associated to multiple Access Points."
        NotesInfo2="There is a possibility of " + fcolor.BRed + "MDK3 Authentication DoS Mode to All Access Points (a) " + fcolor.SWhite + " with [ " + fcolor.BRed + "-m" + fcolor.SWhite + " ] option.."
        NotesInfo3=fcolor.BRed + str(DoSST) + fcolor.SWhite + " stations found to be associated to [ " + fcolor.BRed + str(DoSAP) + fcolor.SWhite + " ] Access Points."
        sData=fcolor.BGreen + "[ " + fcolor.BRed + "Multiple Stations MAC" + fcolor.BGreen + " ] could be flooding [ " + fcolor.BCyan + "Multiple Access Points" + fcolor.BGreen + " ] with authentication request"
        MSG_ATTACK=MSG_ATTACK + DisplayAttackMsg(WarningCount,ATTACK_TYPE, sData ,"-",NotesInfo1,NotesInfo2,NotesInfo3)
        MACInfo = "     " + fcolor.SWhite + "  A.Points [ " + fcolor.BGreen + str(DoSAPListCt) + "" + fcolor.SWhite + " ] - " + fcolor.BCyan + DoSAPList + "\n"
        MSG_ATTACK=MSG_ATTACK + "" + DetailInfo + MACInfo+ "\n" + Breaks + "\n"
        __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll+RemoveDoubleLF(str(MSG_ATTACK))
    MSG_ATTACK=""

    ### Use of AI to detect attack
    
    if int(WarningCount)>0 and __builtin__.SHOW_IDS=="Yes":
        BeepSound()
        CenterText(fcolor.BGIRed + fcolor.BWhite,"< < <<  WARNING !!! - POSSIBLE ATTACKS DETECTED BY RULE AND AI MODEL  >> > >      ")
        print ""
        __builtin__.MSG_IDSDetectionOverAll=__builtin__.MSG_IDSDetectionOverAll + "" + fcolor.BWhite + "Total Warning : " + fcolor.BRed + str(WarningCount) + "\n" + fcolor.SCyan + "Reported : " + str(Now()) + "\n"
        print str(__builtin__.MSG_IDSDetectionOverAll)
        WriteAttackLog(__builtin__.MSG_IDSDetectionOverAll + "\n")
        __builtin__.MSG_AttacksLogging=str(__builtin__.MSG_AttacksLogging) + str(__builtin__.MSG_IDSDetectionOverAll) + "\n"
        __builtin__.MSG_CombinationLogs=str(__builtin__.MSG_CombinationLogs) + str(__builtin__.MSG_IDSDetectionOverAll) + "\n"
        if __builtin__.SAVE_ATTACKPKT=="Yes":
            SaveFilteredMAC(List_AttackingMAC,"ATTACK*",attackdir)
        LineBreak()