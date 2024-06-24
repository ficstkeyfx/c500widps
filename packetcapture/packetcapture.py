import os
import subprocess
def RunPacketCapture():
    Search="WAIDPS - Capturing Packets"
    KillProc(Search)
    if SHOW_IDS=="Yes" or SHOW_SUSPICIOUS_LISTING=="Yes":
        DelFile (tmpdir + "MON_*",1)
        if __builtin__.FIXCHANNEL==0:
            cmdLine="xterm -geometry 100x10-0-200 -iconic -bg black -fg white -fn 5x8 -title 'WAIDPS - Capturing Packets' -e '" + "tshark -i " + str(__builtin__.SELECTED_MON) + " -w " + str(__builtin__.PacketDumpFile) + "'"
        else:
            cmdLine="xterm -geometry 100x10-0-200 -iconic -bg black -fg white -fn 5x8 -title 'WAIDPS - Capturing Packets' -e '" + "tshark -i " + str(__builtin__.SELECTED_MON) + " -w " + str(__builtin__.PacketDumpFile) + "'"
        ps=subprocess.Popen(cmdLine , shell=True, stdout=subprocess.PIPE,stderr=open(os.devnull, 'w'),preexec_fn=os.setsid)	
        __builtin__.PCapProc=ps.pid