typedef unsigned long uint64_t;
typedef int uint32_t;
typedef short uint16_t;
typedef char uint8_t;

#define MAX_PLAYERS 8

#define min(x, y)(((x) < (y)) ? (x) : (y))

int PayloadEntry();

// Card values
const char *values[] = {
   "A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"
};

const char scores[] = {
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 10, 10
};

const char *cards_structures[] = {
    " _______\n|A _ _  |\n| ( v ) |\n|  \\ /  |\n|   .   |\n|______V|\n", // Hearts
    " _______\n|A  ^   |\n|  / \\  |\n|  \\ /  |\n|   .   |\n|______V|\n", // Diamonds
    " _______\n|A  _   |\n|  ( )  |\n| (_'_) |\n|   |   |\n|______V|\n", // Clubs
    " _______\n|A  .   |\n|  /.\\  |\n| (_._) |\n|   |   |\n|______V|\n" // Spades
};

// For the players, each has a hand
typedef struct {
    int socket; // Socket the player is using to talk to the game
    uint32_t hand[5]; // The players hand, all visible to other players
    uint32_t current_bet; // The bet the player has placed in the current game
    uint32_t funds; // Money remaining in players balance
    uint32_t card_count;
    uint32_t bust;
    uint32_t score;
    uint32_t broke;
} Player;

// For the dealer
typedef struct {
    int socket;
    uint32_t card_count;
    uint32_t hand[5]; // The cards the dealer picks up once all players have played
} Dealer;

struct sockaddr {
    uint16_t sa_family; // Address family (e.g., AF_INET for IPv4, AF_INET6 for IPv6)
    uint8_t sa_data[14];         // Protocol-specific address data
};

// Wrapper for the socket function on the router
int socket(int domain, int type, int protocol) {
    typedef int (*SocketFunc)(int, int, int);
    SocketFunc func = (SocketFunc)0x801293d0; 
    return func(domain, type, protocol);
}

// Wrapper for the bind function on the router
int bind(int sockfd, const struct sockaddr *addr, uint32_t addrlen) {
    typedef int (*BindFunc)(int, const struct sockaddr *, uint32_t);
    BindFunc func = (BindFunc)0x8012910c; 
    return func(sockfd, addr, addrlen);
}

// Wrapper for the listen function on the router
int listen(int sockfd, int backlog) {
    typedef int (*ListenFunc)(int, int);
    ListenFunc func = (ListenFunc)0x80128e70; 
    return func(sockfd, backlog);
}

// Wrapper for the strlen function on the router
uint32_t strlen(const char* str) {
    typedef int (*StrlenFunc)(const char*);
    StrlenFunc func = (StrlenFunc)0x801a717c; 
    return (uint32_t) func(str);
}

// Wrapper for the strcmp function on the router
uint32_t strcmp(const char* str1, const char* str2) {
    typedef int (*StrcmpFunc)(const char*, const char*);
    StrcmpFunc func = (StrcmpFunc)0x801a6f4c; 
    return (uint32_t) func(str1, str2);
}

// Wrapper for the accept function on the router
int accept(int sockfd, struct sockaddr *addr, uint32_t *addrlen) {
    typedef int (*AcceptFunc)(int, struct sockaddr *, uint32_t *);
    AcceptFunc func = (AcceptFunc)0x80129240; 
    return func(sockfd, addr, addrlen);
}

// Wrapper for the recv function on the router
int recv(int sockfd, void *buf, uint32_t len, int flags) {
    typedef uint32_t (*RecvFunc)(int, void *, uint32_t, int);
    RecvFunc func = (RecvFunc)0x80128e64;
    return func(sockfd, buf, len, flags);
}

// Wrapper for the send function on the router
int send(int sockfd, const void *buf, uint32_t len, int flags) {
    typedef uint32_t (*SendFunc)(int, const void *, uint32_t, int);
    SendFunc func = (SendFunc)0x80128d04; 
    return func(sockfd, buf, len, flags);
}

// Wrapper for the close function on the router
int close(int sockfd) {
    typedef int (*CloseFunc)(int);
    CloseFunc func = (CloseFunc)0x801aa6c0; 
    return func(sockfd);
}

// Wrapper for the //printf function on the router (> 4 arguments will cause issues due to differences in calling convention)
#define printf(format, ...) \
do { \
    typedef void (*PrintfFunc)(const char*, ...); \
    PrintfFunc func = (PrintfFunc)0x8019a3a0; \
    func(format, ##__VA_ARGS__); \
} while(0)

// Wrapper for the sprintf function on the router (> 4 arguments will cause issues due to differences in calling convention)
#define sprintf(buffer, ...) \
do { \
    typedef void (*SprintfFunc)(const char*, ...); \
    SprintfFunc func = (SprintfFunc)0x8019a464; \
    func(buffer, ##__VA_ARGS__); \
} while(0)

// Wrapper for the sleep function present on the router
#define sleep(centiseconds) \
do { \
    typedef void (*SleepFunc)(uint32_t); \
    SleepFunc func = (SleepFunc)0x8019abac; \
    func(centiseconds); \
} while(0)

// Creates a card ascii-art and places into provided buffer
void createCard(char *buffer, int number, int suite) {
    sprintf(buffer, "%s", cards_structures[suite]);
    if (number == 9){
        buffer[10] = values[number][0];
        buffer[11] = values[number][1];
        buffer[55] = values[number][0];
        buffer[56] = values[number][1];
    } else {
        buffer[10] = values[number][0];
        buffer[56] = values[number][0];
    }
}

// Shuffles the deck of cards
void shuffle(uint32_t* deck, uint32_t deck_size) {
    // Fisher-Yates shuffle algorithm
    uint32_t time_microseconds = *((uint32_t*) 0x80261b04);

    // Seed the custom random number generator with time_microseconds
    uint32_t seed = time_microseconds;

    for (uint32_t i = deck_size - 1; i > 0; i--) {
        // Modify the seed by multiplying and taking modulo
        time_microseconds = time_microseconds * 6364136223846793005ULL + 1;

        // Generate a random index 'j' between 0 and 'i'
        uint32_t j = time_microseconds % i;
        if (j < 0)
            j*=-1;

        // Swap deck[i] and deck[j]
        uint32_t temp = deck[i];
        deck[i] = deck[j];
        deck[j] = temp;
    }
}

// Checks if an integer is at the start of a provided string
int isIntegerAtStart(char *str) {
    if (*str == '\0') {
        // Empty string or NULL is not a valid integer
        return 0;
    }

    // Check for digits
    int integer_detected = 0;
    while (*str != '\0') {
        if (*str < '0' || *str > '9') {
            // Non-digit character found
            if (integer_detected == 1){
                *str = 0; // Force the null terminator
                return 1;
            }
            return 0;
        }
        integer_detected = 1;
        str++;
    }

    return 1;
}

// Gets minimum score to check for bust
int getMinimumPlayerTotal(Player player) {
    int total = 0;
    for (int i = 0; i < player.card_count; i++) {
        total += scores[player.hand[i] % 13];
    }
    return total;
}

// Calculates the score for the dealers hand
uint32_t calculateScoreDealer(Dealer dealer){
    uint32_t ace = 0;
    uint32_t total = 0;

    // Count the value of the dealers cards
    for (int i = 0; i < dealer.card_count; i++){
        uint32_t number = dealer.hand[i] % 13;

        // If ace and first ace, indicate ace exists, after this aces count as 1
        if ((number == 0) && (ace == 0)){
            ace++;
        } else {
            total += scores[number];
        }
    }

    // With cards totalled, add aces
    if ((ace == 1) && ((total + 11) <= 21)){
        return total + 11;
    } else if (ace){
        return total + 1;
    }

    // If no aces return the total
    return total;
}

// Calculates the score for the players hand
uint32_t calculateScorePlayer(Player player){
    uint32_t ace = 0;
    uint32_t total = 0;

    // Count the value of the dealers cards
    for (int i = 0; i < player.card_count; i++){
        uint32_t number = player.hand[i] % 13;

        // If ace and first ace, indicate ace exists, after this aces count as 1
        if ((number == 0) && (ace == 0)){
            ace++;
        } else {
            total += scores[number];
        }
    }

    // With cards totalled, add aces
    if ((ace == 1) && ((total + 11) <= 21)){
        return total + 11;
    } else if (ace){
        return total + 1;
    }

    // If no aces return the total
    return total;
}

// Implementation for strtoul
unsigned long strtoul(const char *nptr, int base) {
    unsigned long result = 0;

    // Convert the string to an unsigned long integer
    while (*nptr != '\0') {
        char digit = *nptr;
        unsigned int value = 0;

        if (digit >= '0' && digit <= '9') {
            value = digit - '0';
        } else if (digit >= 'a' && digit <= 'z') {
            value = digit - 'a' + 10;
        } else if (digit >= 'A' && digit <= 'Z') {
            value = digit - 'A' + 10;
        } else {
            break; // Invalid character, stop parsing
        }

        if (value >= base) {
            break; // Invalid digit for the specified base, stop parsing
        }

        result = result * base + value;
        nptr++;
    }

    return result;
}

// The entry point from Init.S
// (yes I know this function is HUGE and needs to be split up, I'm too tired rn)
int PayloadEntry()
{   
    Player players[MAX_PLAYERS];
    Dealer dealer;
    int player_count = 0;
    int next_card_index = 0;

    int server_socket, client_socket; // fds for client/server sockets
    uint32_t serv_addr[4]; // sockaddr for server
    uint32_t client_addr[4]; // sockaddr for client

    char buffer[256];

    // Construct the deck and shuffle it
    uint32_t deck[52];
    for (int i = 0; i < 52; i++)
        deck[i] = i;

    // Create UDP socket
    server_socket = socket(2, 1, 0);

    sleep(50); // Need this sleep to let other threads run - stupid watchdog

    // Manually construct the serv_addr struct in the memory
    for (int i = 0; i < 0x4; i++)
        serv_addr[i] = 0;
    serv_addr[0] = 0x39050220;

    // Bind the socket
    bind(server_socket, (struct sockaddr *)&serv_addr, 0x10);

    // Set socket to listen for any incoming connections
    listen(server_socket, MAX_PLAYERS);

    int expected_player_count = -1;
    while (1) {
        // Accept incoming connections
        uint32_t client_addr_len = 0x10;
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
            
        if ((player_count == 0) || (player_count < expected_player_count)) {
            // Store client socket and player-specific data
            players[player_count].socket = client_socket;
            players[player_count].funds = 100;
            players[player_count].broke = 0;

            sprintf(buffer, "\n   ___  __         __     _          __  \n  / _ )/ /__ _____/ /__  (_)__ _____/ /__\n / _  / / _ `/ __/  '_/ / / _ `/ __/  '_/\n/____/_/\\_,_/\\__/_/\\_\\_/ /\\_,_/\\__/_/\\_\\ \n                    |___/\n\n");
            send(client_socket, buffer, strlen(buffer), 0);

            // Say hello to connected client
            if (player_count == 0){
                sprintf(buffer, "Welcome player %d!\nEnter player count (including yourself)\n", player_count + 1);
                send(client_socket, buffer, strlen(buffer), 0);

                // First player needs to specify how many other players will be joining the game
                while (1) {
                    uint32_t recv_result = recv(client_socket, buffer, sizeof(buffer), 0);
                    if (recv_result <= 0) {
                        // Client disconnected or an error occurred, close the socket
                        close(client_socket);
                        break;
                    } else {
                        buffer[recv_result] = '\0';
                        if (expected_player_count == -1){
                            if (isIntegerAtStart(buffer) == 1){
                                expected_player_count = strtoul(buffer, 10);
                                
                                // Limit amount of players to 8
                                if (expected_player_count > MAX_PLAYERS){
                                    expected_player_count = -1;
                                    continue;
                                }

                                sprintf(buffer, "\nWaiting for %d other players to join...\n", expected_player_count - 1);
                                send(client_socket, buffer, strlen(buffer), 0);
                                break;
                            }
                        }
                    }
                }
            } else {
                sprintf(buffer, "Welcome player %d!\n", player_count + 1);
                send(client_socket, buffer, strlen(buffer), 0);
            }

            // Increment the player count
            player_count++;
            shuffle(deck, 52); // Shuffle the deck every time a new player joins

            if (player_count == expected_player_count){
                sprintf(buffer, "Game starting!\n");
                for (int i = 0; i < expected_player_count; i++){
                    send(players[i].socket, buffer, strlen(buffer), 0);
                }
                break;
            }
        } else {
            // Inform the client that the game is full
            sprintf(buffer, "Sorry, the game is full.\n");
            send(client_socket, buffer, strlen(buffer), 0);
            close(client_socket);
        }
    }

    // Now we are in the game
    while(1){
        next_card_index = 0;
        shuffle(deck, 52);
       
        // Print intro to round
        for (int i = 0; i < player_count; i++){
            sprintf(buffer, "\n\nAs it stands:\n");
            send(players[i].socket, buffer, strlen(buffer), 0);
        }

        // Send all funds to all other players
        for (int i = 0; i < player_count; i++){
            for (int j = 0; j < player_count; j++){
                sprintf(buffer, "- Player %d has $%d\n", i+1, players[i].funds);
                send(players[j].socket, buffer, strlen(buffer), 0);
            }
        }

        // Make sure all players are not bust anymore and clear cards
        for (int i = 0; i < player_count; i++){
            players[i].bust = 0;
            players[i].card_count = 0;
            players[i].score = 0;
        }
        dealer.card_count = 0;

        // First, each player places their bet
        for (int i = 0; i < player_count; i++){ // Player requesting from
            // Skip broke players go
            if (players[i].broke == 1){
                continue;
            }

            // Notify other players
            for (int j = 0; j < player_count; j++){
                if (j == i){
                    // This is the player that is placing the bet
                    sprintf(buffer, "\nPlace your bet player %d...\n> ", i+1);
                } else {
                    // This is the other players
                    sprintf(buffer, "\nPlayer %d is placing their bet\n", i+1);
                }
                send(players[j].socket, buffer, strlen(buffer), 0);
            }

            while (1) {
                uint32_t recv_result = recv(players[i].socket, buffer, sizeof(buffer), 0);
                if (recv_result <= 0) {
                    // Client disconnected or an error occurred, close the socket
                    close(client_socket);
                    break;
                } else {
                    buffer[recv_result] = '\0';
                    if (isIntegerAtStart(buffer) == 1){
                        uint32_t bet = strtoul(buffer, 10);
                        if (bet > players[i].funds){
                            bet = players[i].funds;
                        }
                        players[i].current_bet = bet;
                        for (int k = 0; k < player_count; k++){
                            sprintf(buffer, "Player %d has bet $%d\n", i + 1, players[i].current_bet);
                            send(players[k].socket, buffer, strlen(buffer), 0);
                        }
                        break;
                    }
                }
            }

        }

        // Now each player gets 2 cards
        for (int i = 0; i < player_count; i++){ // Player requesting from
            // Skip broke players go
            if (players[i].broke == 1){
                continue;
            }

            for (int j = 0; j < player_count; j++){
                sprintf(buffer, "\nPlayer %d cards:\n", i + 1);
                send(players[j].socket, buffer, strlen(buffer), 0);
            }

            // Get 2 random cards from deck for player
            for (int j = 0; j < 2; j++){
                uint32_t next_card = deck[next_card_index];
                next_card_index++;
                uint32_t number = next_card % 13;
                uint32_t suite = (uint32_t) ((next_card - number) / 13);
                
                // Send the result to all the other players
                for (int k = 0; k < player_count; k++){
                    createCard(buffer, number, suite);
                    send(players[k].socket, buffer, strlen(buffer), 0);
                }

                // Set the card in players hand
                players[i].hand[j] = next_card;
            }

            // Set players card count now that they have 2
            players[i].card_count = 2;
        }

        // Now get the dealers cards, 1 unhidden and 1 hidden
        for (int k = 0; k < player_count; k++){
            sprintf(buffer, "\nDealers card:\n");
            send(players[k].socket, buffer, strlen(buffer), 0);
        }

        // This is the unhidden one
        uint32_t next_card = deck[next_card_index];
        next_card_index++;
        uint32_t number = next_card % 13;
        uint32_t suite = (uint32_t) ((next_card - number) / 13);
        
        // Send the result to all the other players
        for (int k = 0; k < player_count; k++){
            createCard(buffer, number, suite);
            send(players[k].socket, buffer, strlen(buffer), 0);
        }

        dealer.hand[0] = next_card;
        dealer.card_count++;

        // This is the hidden one
        next_card = deck[next_card_index];
        next_card_index++;

        dealer.hand[1] = next_card;
        dealer.card_count++;

        // Now iterate over the players stick or twist
        for (int i = 0; i < player_count; i++){
            // Skip broke players go
            if (players[i].broke == 1){
                continue;
            }

            for (int j = 0; j < player_count; j++){
                sprintf(buffer, "\nPlayer %d's move...\n", i + 1);
                send(players[j].socket, buffer, strlen(buffer), 0);
            }
            
            // Loop until stick or bust
            while (1) {
                sprintf(buffer, "Stick or twist?\n> ");
                send(players[i].socket, buffer, strlen(buffer), 0);
                uint32_t recv_result = recv(players[i].socket, buffer, sizeof(buffer), 0);
                if (recv_result > 0) {
                    buffer[recv_result] = 0x0;
                    if (*buffer == 's'){
                        for (int j = 0; j < player_count; j++){
                            sprintf(buffer, "\nPlayer %d chose to stick\n", i + 1);
                            send(players[j].socket, buffer, strlen(buffer), 0);
                            
                        }
                        
                        players[i].score = calculateScorePlayer(players[i]);
                        for (int j = 0; j < player_count; j++){
                            sprintf(buffer, "\nPlayer %d final score: %d\n", i + 1, players[i].score);
                            send(players[j].socket, buffer, strlen(buffer), 0);
                        }
                        // stick
                        break;
                    } else if (*buffer == 't'){
                        // twist
                        for (int j = 0; j < player_count; j++){
                            sprintf(buffer, "\nPlayer %d chose to twist:\n", i + 1);
                            send(players[j].socket, buffer, strlen(buffer), 0);
                        }

                        // Get another card
                        uint32_t next_card = deck[next_card_index];
                        next_card_index++;
                        uint32_t number = next_card % 13;
                        uint32_t suite = (uint32_t) ((next_card - number) / 13);
                        
                        // Send the result to all the other players
                        for (int k = 0; k < player_count; k++){
                            createCard(buffer, number, suite);
                            send(players[k].socket, buffer, strlen(buffer), 0);
                        }

                        players[i].hand[players[i].card_count] = next_card;
                        players[i].card_count++;

                        if (getMinimumPlayerTotal(players[i]) > 21){
                            for (int k = 0; k < player_count; k++){
                                sprintf(buffer, "\nPlayer %d is bust!\n", i + 1);
                                send(players[k].socket, buffer, strlen(buffer), 0);
                            }
                            players[i].bust = 1;
                            break;
                        }
                    }
                }
            }
        }

        // Flip dealers card
        for (int k = 0; k < player_count; k++){
            sprintf(buffer, "\nAll players done...\n\nThe dealers hidden card is:\n");
            send(players[k].socket, buffer, strlen(buffer), 0);
        }

        number = dealer.hand[1] % 13;
        suite = (uint32_t) ((dealer.hand[1] - number) / 13);
        
        // Send the result to all the other players
        for (int k = 0; k < player_count; k++){
            createCard(buffer, number, suite);
            send(players[k].socket, buffer, strlen(buffer), 0);
        }

        uint32_t dealer_score = calculateScoreDealer(dealer);;
        for (int k = 0; k < player_count; k++){
            sprintf(buffer, "\nDealers current score: %d\n", dealer_score);
            send(players[k].socket, buffer, strlen(buffer), 0);
        }

        // Now determine if the dealer needs another card
        // Dealer must keep taking cards until total is 17 or more
        // If dealer has an ace and counting it as 11 would bring the total to 17 or more (but not over 21), dealer must stand
        // If multiple aces, first ace counts as 11 unles it busts the hand, subsequent aces count as 1
        uint32_t dealer_bust = 0;
        
        while(1){
            if (dealer_score < 17){
                for (int k = 0; k < player_count; k++){
                    sprintf(buffer, "Dealer is twisting\n");
                    send(players[k].socket, buffer, strlen(buffer), 0);
                }
            } else {
                for (int k = 0; k < player_count; k++){
                    sprintf(buffer, "Dealer is sticking\n");
                    send(players[k].socket, buffer, strlen(buffer), 0);
                }
                break;
            }

            // Take another card
            // This is the unhidden one
            next_card = deck[next_card_index];
            next_card_index++;
            number = next_card % 13;
            suite = (uint32_t) ((next_card - number) / 13);
            
            // Send the result to all the other players
            for (int k = 0; k < player_count; k++){
                createCard(buffer, number, suite);
                send(players[k].socket, buffer, strlen(buffer), 0);
            }

            dealer.hand[dealer.card_count] = next_card;
            dealer.card_count++;

            // Check if bust
            dealer_score = calculateScoreDealer(dealer);
            for (int k = 0; k < player_count; k++){
                sprintf(buffer, "\nDealers current score: %d\n", dealer_score);
                send(players[k].socket, buffer, strlen(buffer), 0);
            }

            if (dealer_score > 21){
                // Send the result to all the other players
                for (int k = 0; k < player_count; k++){
                    sprintf(buffer, "Dealer is bust!\n");
                    send(players[k].socket, buffer, strlen(buffer), 0);
                    dealer_bust = 1;
                }
            }

            if (dealer_bust == 1){
                break;
            }
        }

        // If dealer busts, give each player that hasn't bust 2x their bet
        if (dealer_bust == 1){
            for (int i = 0; i < player_count; i++){
                // Skip broke players go
                if (players[i].broke == 1){
                    continue;
                }

                if (players[i].bust == 0){
                    sprintf(buffer, "\nYou won $%d!\n", players[i].current_bet);
                    send(players[i].socket, buffer, strlen(buffer), 0);
                    players[i].funds += players[i].current_bet;
                } else {
                    // Eliminate player if funds <= 0
                    players[i].funds -= players[i].current_bet;
                    if (players[i].funds == 0){
                        players[i].broke = 1;
                        sprintf(buffer, "\nYou've run out of funds!\n");
                    } else {
                        sprintf(buffer, "\nBetter luck next round!\n");
                    }
                    send(players[i].socket, buffer, strlen(buffer), 0);
                }
            }
        } else {
            for (int i = 0; i < player_count; i++){
                // Skip broke players go
                if (players[i].broke == 1){
                    continue;
                }

                if (players[i].score > dealer_score){
                    sprintf(buffer, "\nYou won $%d!\n", players[i].current_bet);
                    send(players[i].socket, buffer, strlen(buffer), 0);
                    players[i].funds += players[i].current_bet;
                } else {
                    // Eliminate player if funds <= 0
                    players[i].funds -= players[i].current_bet;
                    if (players[i].funds == 0){
                        players[i].broke = 1;
                        sprintf(buffer, "\nYou've run out of funds!\n");
                    } else {
                        sprintf(buffer, "\nBetter luck next round!\n");
                    }
                    send(players[i].socket, buffer, strlen(buffer), 0);
                }
            }
        }

        for (int i = 0; i < player_count; i++){
           sprintf(buffer, "\nOnto the next round!\n", players[i].current_bet);
           send(players[i].socket, buffer, strlen(buffer), 0);
        }
    }
   
    return 0;
}
