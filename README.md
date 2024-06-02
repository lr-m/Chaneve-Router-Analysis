# Chaneve-Router-Analysis
These are the tools created from my analysis of a cheap router utilising the mt7628 router on a chip. I'd highly recommend reading [my blog](https://luke-r-m.github.io/vr/analysing-a-dirt-cheap-router/) if you think these tools are relevant to something you are investigating.

<p align="center">

  <img src="https://github.com/luke-r-m/Chaneve-Router-Analysis/assets/47477832/58732de8-1e3d-4645-a586-c635e196fec9" width="400">

</p>

## Blogs

[Analysing a Dirt-cheap Router [0] : Getting Started](https://luke-m.xyz/router/p1.md)

[Analysing a Dirt-cheap Router [1] : Finding Bugs](https://luke-m.xyz/router/p2.md)

[Analysing a Dirt-cheap Router [2] : MIPS Code Execution with ROP](https://luke-m.xyz/router/p3.md)

[Analysing a Dirt-cheap Router [3]: Process Continuation + Shellcode](https://luke-m.xyz/router/p4.md)

[Analysing a Dirt-cheap Router [4]: A Complex Payload](https://luke-m.xyz/router/p5.md)

## Telnet

`python .\wodesys.py telnet -h`

### Scanning for Config Values

This tries to brute force all of the ID's of possible values in the config, and determines if this is a valid ID based on the response. It is pretty slow :(

`python .\wodesys.py telnet -s`

### Dumping the Flash

This dumps the flash of the router via the telnet interface with the *os spi* command. It automatically splits the commands into chunks as to not get malloc errors. Note that there can be random MAC addresses that appear in the output, I have no idea why it does this but the script will indicate where any dodgy output is when you try to convert the log into a binary.

`python .\wodesys.py telnet -d`

### Converting Flash Dump into Binary

This takes the log output by the telnet interface, and converts it into a usable binary that can be decompiled. 

`python .\wodesys.py telnet -c dump_log.txt`

### Sending Telnet Commands

You can use the -m flag to send telnet commands, specify the module you want, and the the payload you wish to send.

`python .\wodesys.py telnet -m cfg 'get SYS_ADMPASS'`

## HTTP

`python .\wodesys.py http -h`

### Attacking HTTP Auth

You can try and crack the admin password by using a wordlist to guess passwords until one is accepted.

`python .\wodesys.py http -d ./wordlist.txt`

### Setting Config Values

If you know the name of the config value that you wish to set, you can use this command to set any value in the config via the HTTP interface.

`python .\wodesys.py http -s admin_pwd SYS_ADMPASS new_adm_pass`

### Searching for Config Values

I added a simple substring search that allows you to easily find config values, the dictionary of config values was created using the telnet scan created earlier on.

`python .\wodesys.py http -f SYS`

### Sending HTTP Commands

The script can be used to send HTTP payloads to the router, it uses the /do_cmd.htm endpoint to execute commands on the device (see blog for possible commands).

`python .\wodesys.py http -p admin_pwd 'CMD=SYS_LOG'`

## Crashes

These demonstrate the crashes on the router caused by various bugs

`python ./wodesys.py http -c admin_pwd type` where type is an integer from 1-9

- 1: WLN_SSID1 config stack overflow (requires power cycle to work)
- 2: RT_ADD config stack overflow
- 3: HTTP null pointer dereference 1
- 4: HTTP null pointer dereference 2
- 5: UPnP M-SEARCH stack overflow (uuid:)
- 6: UPnP M-SEARCH stack overflow (urn:schemas-upnp-org:service:)
- 7: UPnP M-SEARCH stack overflow (urn:schemas-upnp-org:device:)
- 8: UPnP M-SEARCH stack overflow (urn:schemas-wifialliance-org:service:)
- 9: UPnP M-SEARCH stack overflow (urn:schemas-wifialliance-org:device:)

## ROP

`python ./wodesys.py http -r type` where type is an integer from 1-5

These exploit the UPnP M-SEARCH (uuid:) stack overflow to get the router to do interesting things using a simple ROP chain:
- 1: Prints a firmware string to the UART
- 2: Sends 'hello' to IP on the network via UDP
- 3: Gets the admin password from the console and prints to UART
- 4: Gets admin password and sends it to device on the network via UDP (port 4900)
- r: Uses hexdump function to dump large area of memory (will need a restart after use)
- w: Uses single gadget to write memory on the router
- nc: Proof that the buffer can be overflowed without causing a crash

## Shellcode

`python ./wodesys.py http -s type` where type is 1 or 2

These exploit the UPnP M-SEARCH (uuid:) stack overflow to get the router to do interesting things without crashing by injecting shellcode:
- 1: Print 'hello' to debug interfaces
- 2: Gets admin password and sends it to device on the network via UDP (port 4900)
- 3: Creates a task that acts as a blackjack dealer, players can connect with netcat (`netcat 192.168.188.1 1337`)
