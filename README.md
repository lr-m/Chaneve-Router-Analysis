# Aliexpress-Router
These are the tools created from my analysis of a cheap router utilising the mt7628 router on a chip. I'd highly recommend reading my blog if you think these tools are relevant to something you are investigating.

## Telnet

python .\wodesys.py telnet -h

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

`python .\wodesys.py http -p admin_pwd 'CMD=SYS_LOG'
