typedef unsigned long uint64_t;
typedef int uint32_t;
typedef short uint16_t;
typedef char uint8_t;

#define MAX_PLAYERS 8
#define BLACKJACK 21
#define DEALER_TWIST_UNTIL 17
#define CARDS_IN_SUITE 13
#define BASE_FUNDS 250

int PayloadEntry();

// Card values
const char *values[] = {
   "A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"
};

const char scores[] = {
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 10, 10
};

// const char *cards_structures[] = {
//     " _______\n|A _ _  |\n| ( v ) |\n|  \\ /  |\n|   .   |\n|______V|\n", // Hearts
//     " _______\n|A  ^   |\n|  / \\  |\n|  \\ /  |\n|   .   |\n|______V|\n", // Diamonds
//     " _______\n|A  _   |\n|  ( )  |\n| (_'_) |\n|   |   |\n|______V|\n", // Clubs
//     " _______\n|A  .   |\n|  /.\\  |\n| (_._) |\n|   |   |\n|______V|\n" // Spades
// };

const char *heart_structure[] = {
    " _______ ", "|A _ _  |", "| ( v ) |", "|  \\ /  |", "|   .   |", "|______V|", // Hearts
};

const char *diamond_structure[] = {
    " _______ ", "|A  ^   |", "|  / \\  |", "|  \\ /  |", "|   .   |", "|______V|", // Diamonds
};

const char *club_structure[] = {
    " _______ ", "|A  _   |", "|  ( )  |", "| (_'_) |", "|   |   |", "|______V|", // Clubs
};

const char *spade_structure[] = {
    " _______ ", "|A  .   |", "|  /.\\  |", "| (_._) |", "|   |   |", "|______V|" // Spades
};

// Struct for storing the player/dealer hand
typedef struct {
    uint8_t cards[16];
    uint8_t card_count;
} Hand;

// For the players
typedef struct {
    int socket; // Socket the player is using to talk to the game
    Hand hand;
    uint32_t current_bet; // The bet the player has placed in the current game
    uint32_t funds; // Money remaining in players balance
    uint8_t score;
    uint8_t bust;
    uint8_t broke;
    uint8_t blackjack;
} Player;

// For the dealer
typedef struct {
    Hand hand;
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
// void createSingleCard(char *buffer, int number, int suite) {
//     sprintf(buffer, "%s", cards_structures[suite]);
//     if (number == 9){
//         buffer[10] = values[number][0];
//         buffer[11] = values[number][1];
//         buffer[55] = values[number][0];
//         buffer[56] = values[number][1];
//     } else {
//         buffer[10] = values[number][0];
//         buffer[56] = values[number][0];
//     }
// }

// Creates multiple cards on the same line (rather than above/below eachother), sends line by line instead of filling a buffer and returning like single card
void createMultipleCardsAndSend(char* buffer, uint8_t* card_indexes, int number_of_cards, int socket){
    // send it 1 line at a time
    for (uint32_t line_no = 0; line_no < 6; line_no++){ // 6 is the number of lines in the card structure
        for (uint32_t card_index = 0; card_index < number_of_cards; card_index++){
            uint32_t number = card_indexes[card_index] % CARDS_IN_SUITE;
            uint32_t suite = (uint32_t) ((card_indexes[card_index] - number) / CARDS_IN_SUITE);
        
            // Construct the line
            switch (suite){
                case 0:
                    sprintf(&buffer[card_index * 10], "%s ", heart_structure[line_no]);
                    break;
                case 1:
                    sprintf(&buffer[card_index * 10], "%s ", diamond_structure[line_no]);
                    break;
                case 2:
                    sprintf(&buffer[card_index * 10], "%s ", club_structure[line_no]);
                    break;
                case 3:
                    sprintf(&buffer[card_index * 10], "%s ", spade_structure[line_no]);
                    break;
            }
            
            if (line_no == 1){
                if (number == 9){
                    buffer[(card_index * 10) + 1] = values[number][0];
                    buffer[(card_index * 10) + 2] = values[number][1];
                } else {
                    buffer[(card_index * 10) + 1] = values[number][0];
                }
            } else if (line_no == 5){
                if (number == 9){
                    buffer[(card_index * 10) + 6] = values[number][0];
                    buffer[(card_index * 10) + 7] = values[number][1];
                } else {
                    buffer[(card_index * 10) + 7] = values[number][0];
                }
            }
        }

        // Send to the socket
        uint32_t bufflen = strlen(buffer);
        buffer[bufflen] = '\n'; // add newline to end of line
        buffer[bufflen + 1] = 0; // null terminate
        send(socket, buffer, strlen(buffer), 0);
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

// Calculates the score for the dealers hand
uint32_t calculateScore(Hand hand){
    uint8_t ace = 0;
    uint32_t total = 0;

    // Count the value of the dealers cards
    for (uint32_t i = 0; i < hand.card_count; i++){
        uint32_t number = hand.cards[i] % CARDS_IN_SUITE;

        // If ace and first ace, indicate ace exists, after this aces count as 1
        if ((number == 0) && (ace == 0)){
            ace++;
            continue;
        }
        total += scores[number];
    }

    // With cards totalled, add aces
    if ((ace == 1) && ((total + 11) <= BLACKJACK)){
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

// Sends the contents of the null terminated buffer to all connected players
void sendToAllPlayers(char* buffer, Player* players, uint32_t player_count){
    for (uint32_t i = 0; i < player_count; i++)
        send(players[i].socket, buffer, strlen(buffer), 0);
}

// Picks a card, saves the value, calculates number and suite from card index in sorted deck to params
void pickCard(uint32_t* suite, uint32_t* number, uint32_t* next_card, uint32_t* deck, uint32_t index){
    *next_card = deck[index];
    *number = *next_card % CARDS_IN_SUITE;
    *suite = (uint32_t) ((*next_card - *number) / CARDS_IN_SUITE);
}

// The entry point from Init.S
int PayloadEntry()
{
    Player players[MAX_PLAYERS];
    Dealer dealer;
    uint32_t player_count = 0;
    uint32_t next_card_index = 0;

    uint32_t server_socket; // fds for client/server sockets
    uint32_t serv_addr[4]; // sockaddr for server
    uint32_t client_addr[4]; // sockaddr for client

    char buffer[256];

    uint32_t round = 1;

    // Construct the deck and shuffle it
    uint32_t deck[52];
    uint32_t number;
    uint32_t suite;
    uint32_t next_card;
    for (uint32_t i = 0; i < 52; i++)
        deck[i] = i;

    // Create UDP socket
    server_socket = socket(2, 1, 0);

     // Need this sleep to let other threads run - stupid watchdog
     sleep(50);

    // Manually construct the serv_addr struct in the memory
    for (uint32_t i = 0; i < 0x4; i++)
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
            players[player_count].funds = BASE_FUNDS;
            players[player_count].broke = 0;
            players[player_count].blackjack = 0;

            sprintf(buffer, "\n   ___  __         __     _          __\n  / _ )/ /__ _____/ /__  (_)__ _____/ /__\n / _  / / _ `/ __/  '_/ / / _ `/ __/  '_/\n/____/_/\\_,_/\\__/_/\\_\\_/ /\\_,_/\\__/_/\\_\\ \n                    |___/\n\n");
            send(client_socket, buffer, strlen(buffer), 0);

            // Say hello to connected client
            if (player_count == 0){
                sprintf(buffer, "Welcome player %d!\nEnter player count (including yourself)\n> ", player_count + 1);
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
                sendToAllPlayers(buffer, players, player_count);
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
        shuffle(deck, 52);
        next_card_index = 0;
        
        // Print intro to round
        sprintf(buffer, "\n\nAs it stands:\n");
        sendToAllPlayers(buffer, players, player_count);

        // Send all funds to all other players
        for (uint32_t i = 0; i < player_count; i++){
            sprintf(buffer, "- Player %d has $%d\n", i + 1, players[i].funds);
            sendToAllPlayers(buffer, players, player_count);
        }

        // Make sure all players are not bust anymore and clear cards
        for (uint32_t i = 0; i < player_count; i++){
            players[i].bust = 0;
            players[i].hand.card_count = 0;
            players[i].score = 0;
            players[i].blackjack = 0;
        }
        dealer.hand.card_count = 0;

        // First, each player places their bet
        for (uint32_t i = 0; i < player_count; i++){ // Player requesting from
            // Skip broke players go
            if (players[i].broke == 1)
                continue;

            // Notify other players
            for (uint32_t j = 0; j < player_count; j++){
                if (j == i){
                    // This is the player that is placing the bet
                    sprintf(buffer, "\nPlace your bet player %d...\n> ", i + 1);
                } else {
                    // This is the other players
                    sprintf(buffer, "\nPlayer %d is placing their bet\n", i + 1);
                }
                send(players[j].socket, buffer, strlen(buffer), 0);
            }

            while (1) {
                uint32_t recv_result = recv(players[i].socket, buffer, sizeof(buffer), 0);
                buffer[recv_result] = '\0';
                if (isIntegerAtStart(buffer) == 1){
                    uint32_t bet = strtoul(buffer, 10);
                    if (bet > players[i].funds)
                        bet = players[i].funds;

                    players[i].current_bet = bet;
                    sprintf(buffer, "Player %d has bet $%d\n", i + 1, players[i].current_bet);
                    sendToAllPlayers(buffer, players, player_count);
                    break;
                }
            }
        }

        // Now each player gets 2 cards
        for (uint32_t i = 0; i < player_count; i++){ // Player requesting from
            // Skip broke players go
            if (players[i].broke == 1)
                continue;

            sprintf(buffer, "\nPlayer %d cards:\n", i + 1);
            sendToAllPlayers(buffer, players, player_count);

            // Get 2 random cards from deck for player
            for (uint32_t j = 0; j < 2; j++){
                pickCard(&suite, &number, &next_card, deck, next_card_index);
                next_card_index++;

                // Set the card in players hand
                players[i].hand.cards[j] = next_card;
            }

            // Set players card count now that they have 2
            players[i].hand.card_count = 2;

            for (int k = 0; k < player_count; k++)
                createMultipleCardsAndSend(buffer, players[i].hand.cards, 2, players[k].socket);

            // Check that the player doesn't have a blackjack
            if (calculateScore(players[i].hand) == BLACKJACK){
                // Player has a blackjack
                players[i].blackjack = 1;

                // Notify all other players
                sprintf(buffer, "\nPlayer %d has blackjack!\n", i + 1);
                sendToAllPlayers(buffer, players, player_count);
            }
        }

        // Now get the dealers cards, 1 unhidden and 1 hidden
        sprintf(buffer, "\nDealers card:\n");
        sendToAllPlayers(buffer, players, player_count);

        // This is the unhidden one
        pickCard(&suite, &number, &next_card, deck, next_card_index);
        next_card_index++;
        
        // Send the result to all the other players
        // createSingleCard(buffer, number, suite);
        // sendToAllPlayers(buffer, players, player_count);

        dealer.hand.cards[0] = next_card;
        dealer.hand.card_count++;

        // Send the hidden card to everyone else
        for (int k = 0; k < player_count; k++)
            createMultipleCardsAndSend(buffer, dealer.hand.cards, dealer.hand.card_count, players[k].socket);

        // This is the hidden one
        next_card = deck[next_card_index];
        next_card_index++;

        dealer.hand.cards[1] = next_card;
        dealer.hand.card_count++;

        // Now iterate over the players stick or twist
        for (uint32_t i = 0; i < player_count; i++){
            // Skip players that either have no funds, or already have blackjack
            if ((players[i].broke == 1) || (players[i].blackjack == 1))
                continue;

            // Notify other players whos move it is
            sprintf(buffer, "\nPlayer %d's move, current hand:\n", i + 1);
            sendToAllPlayers(buffer, players, player_count);

            for (int k = 0; k < player_count; k++)
                createMultipleCardsAndSend(buffer, players[i].hand.cards, players[i].hand.card_count, players[k].socket);
            
            // Loop until player sticks or player busts
            while (1) {
                sprintf(buffer, "\nStick or twist?\n> ");
                send(players[i].socket, buffer, strlen(buffer), 0);
                uint32_t recv_result = recv(players[i].socket, buffer, sizeof(buffer), 0);
                if (recv_result > 0) {
                    buffer[recv_result] = 0x0;
                    if (*buffer == 's'){
                        // Stick
                        sprintf(buffer, "\nPlayer %d chose to stick\n", i + 1);
                        sendToAllPlayers(buffer, players, player_count);
                        
                        // Calculate final score and send to all players
                        players[i].score = calculateScore(players[i].hand);
                        sprintf(buffer, "\nPlayer %d final score: %d\n", i + 1, players[i].score);
                        sendToAllPlayers(buffer, players, player_count);
                        break;
                    } else if (*buffer == 't'){
                        // Twist
                        // Get another card
                        pickCard(&suite, &number, &next_card, deck, next_card_index);
                        next_card_index++;
                        
                        // Send the result to all the other players
                        // createSingleCard(buffer, number, suite);
                        // sendToAllPlayers(buffer, players, player_count);

                        players[i].hand.cards[players[i].hand.card_count] = next_card;
                        players[i].hand.card_count++;

                        sprintf(buffer, "\nPlayer %d's chose to twist, current hand:\n", i + 1);
                        sendToAllPlayers(buffer, players, player_count);

                        // Send updated hand to all players
                        for (int k = 0; k < player_count; k++)
                            createMultipleCardsAndSend(buffer, players[i].hand.cards, players[i].hand.card_count, players[k].socket);

                        // Check that new card hasn't made player go bust
                        if (calculateScore(players[i].hand) > BLACKJACK){
                            sprintf(buffer, "\nPlayer %d is bust!\n", i + 1);
                            sendToAllPlayers(buffer, players, player_count);
                            players[i].bust = 1;
                            break;
                        }
                    }
                }
            }
        }

        // Reveal hidden card in full hand
        sprintf(buffer, "\nAll players done...\n\nThe dealers full hand is:\n");
        sendToAllPlayers(buffer, players, player_count);
        // Send updated hand to all players
        for (int k = 0; k < player_count; k++)
            createMultipleCardsAndSend(buffer, dealer.hand.cards, dealer.hand.card_count, players[k].socket);

        number = dealer.hand.cards[1] % CARDS_IN_SUITE;
        suite = (uint32_t) ((dealer.hand.cards[1] - number) / CARDS_IN_SUITE);
        
        // Send the result to all the other players
        // createSingleCard(buffer, number, suite);
        // sendToAllPlayers(buffer, players, player_count);

        // Get the dealers current score and notify players
        uint32_t dealer_score = calculateScore(dealer.hand);
        // sprintf(buffer, "\nDealers current score: %d\n", dealer_score);
        // sendToAllPlayers(buffer, players, player_count);

        // Now determine if the dealer needs another card
        // Dealer must keep taking cards until total is 17 or more
        // If dealer has an ace and counting it as 11 would bring the total to 17 or more (but not over 21), dealer must stand
        // If multiple aces, first ace counts as 11 unles it busts the hand, subsequent aces count as 1
        uint8_t dealer_bust = 0;

        while(1){
            if (dealer_score < DEALER_TWIST_UNTIL){
                sprintf(buffer, "\nDealer is twisting\n");
                sendToAllPlayers(buffer, players, player_count);
            } else {
                sprintf(buffer, "\nDealer is sticking\n");
                sendToAllPlayers(buffer, players, player_count);

                sprintf(buffer, "\nDealers final score: %d\n", dealer_score);
                sendToAllPlayers(buffer, players, player_count);
                
                break;
            }

            // Take another card
            // This is the unhidden one
            pickCard(&suite, &number, &next_card, deck, next_card_index);
            next_card_index++;
            
            // // Send the result to all the other players
            // createSingleCard(buffer, number, suite);
            // sendToAllPlayers(buffer, players, player_count);

            // Add to dealers hand
            dealer.hand.cards[dealer.hand.card_count] = next_card;
            dealer.hand.card_count++;

            // Reveal hidden card in full hand
            sprintf(buffer, "\nDealers current hand:\n");
            sendToAllPlayers(buffer, players, player_count);
            // Send updated hand to all players
            for (int k = 0; k < player_count; k++)
                createMultipleCardsAndSend(buffer, dealer.hand.cards, dealer.hand.card_count, players[k].socket);

            // Check if bust
            dealer_score = calculateScore(dealer.hand);
            // sprintf(buffer, "\nDealers current score: %d\n", dealer_score);
            // sendToAllPlayers(buffer, players, player_count);

            // Check if dealer is bust
            if (dealer_score > BLACKJACK){
                sprintf(buffer, "Dealer is bust!\n");
                sendToAllPlayers(buffer, players, player_count);
                dealer_bust = 1;
                break;
            }
        }

        // Iterate over players and distribute winnings
        for (uint32_t i = 0; i < player_count; i++){
            // Skip broke players
            if (players[i].broke == 1)
                continue;

            // Handle blackjack
            if (players[i].blackjack == 1){
                sprintf(buffer, "\nYou won $%d!\n", players[i].current_bet/2);
                send(players[i].socket, buffer, strlen(buffer), 0);
                players[i].funds += players[i].current_bet / 2;
                continue;
            }

            if (((dealer_bust == 1) && (players[i].bust == 0)) || ((dealer_bust == 0) && (players[i].score > dealer_score))) {
                // If dealer bust and player not bust, they win
                sprintf(buffer, "\nYou won $%d!\n", players[i].current_bet);
                send(players[i].socket, buffer, strlen(buffer), 0);
                players[i].funds += players[i].current_bet;
            } else {
                // Otherwise, player loses their bet (unless they had a blackjack earlier)
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

        // Indicate that the next round is starting
        round++;
        sleep(500);
        sprintf(buffer, "\nRound %d!", round);
        sendToAllPlayers(buffer, players, player_count);
    }
    
    return 0;
}
