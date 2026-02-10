#define RED "\e[0;31m"
#define YEL "\e[0;33m"
#define CYN "\e[0;36m"
#define GRN "\e[0;32m"
#define RESET "\e[0m"
#define TRUE 1
#define FALSE 0
#define VALID 1
#define INVALID 0
#define CHECK_CIDR 1
#define DONT_CHECK_CIDR 0
#define SAME 1
#define DIFFERENT 0

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>

int verbose_mode  = FALSE;
typedef struct  
{
	uint8_t firstIP[4];
	uint8_t lastIP[4];
	uint8_t  netmask[4];
	uint8_t wildcard[4];
	uint64_t hosts;
	
	uint32_t firstIPdecimal;
	uint32_t lastIPdecimal;
} IP_SOLUTION ;

////////////////////////////////////////////////////////////////
int get_ipValidity(char *ip_string, uint8_t (*ip)[5], int check_cidr);
void get_ipFromComputer(uint8_t (*ip)[5]);
void user_help();
void solve_ip(uint8_t (*ip)[5], IP_SOLUTION *ip_solution);
void show_solution(IP_SOLUTION *ip_solution);
void question_user(IP_SOLUTION *ip_solution);
int compare_ip( uint8_t (*ip1)[5], uint8_t (*ip2)[4] );
uint64_t get_cidrFromRange( uint8_t (*ip1)[5], uint8_t (*ip2)[5]);
////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
	uint8_t ip[5]; // 4 octets + cidr value
	uint8_t ip_2[5]; // used only for --ip-range argument .
	int practice_mode = FALSE; // computer asks questions to user.  
	IP_SOLUTION ip_solution;
	
	// dealing with arguments....
	if (argc == 1){
		printf(RED"No arguments were passed.\n");
		printf(YEL"Try using the "CYN"--help"YEL" argument.\n"RESET);
		return 1;
	}
	
	for (int i = 1; i < argc; i++){
		// User needs help :
		if (strcmp(argv[i], "--help") == 0){
			user_help();
			return 0;
		}
		// User needs training :
		else if (strcmp(argv[i], "--practice") == 0){
			practice_mode = TRUE;
		}
		// User wants to see additional info on the given IP
		else if (strcmp(argv[i], "--verbose") == 0){
			verbose_mode = TRUE;
		}// Normal IP-CIDR solving : 
		else if (strcmp(argv[i], "--ip") == 0){
			if (argc > i+1){
				if (get_ipValidity( argv[i+1], &ip, CHECK_CIDR) == TRUE){ i++ ;}
				else{
					return 1;
				}
			}
			else {
				printf(RED"No IP address specified using "CYN"--ip"RED" argument.\n");
				printf(YEL"Example : subnetter --ip 192.168.0.0/24 \n"RESET);
				return 1;
			}
		}// IP Range solving :
		else if (strcmp(argv[i], "--ip-range") == 0){
			if (argc > i+2){ // check if two ip's are given after this argument: 
				if (get_ipValidity( argv[i+1], &ip, DONT_CHECK_CIDR) == TRUE){
					if (get_ipValidity( argv[i+2], &ip_2, DONT_CHECK_CIDR) == TRUE){
						// We calculate the cidr value (eg: /24) from the two ip using the function get_cidrFromRange()
						// and fed into ip[5] . Now ip have a valid IP with CIDR which is solved by the computer .
						ip[4] = get_cidrFromRange( &ip, &ip_2);
						i += 2;
						printf("IP-CIDR      : "CYN"%u.%u.%u.%u/%u"RESET, ip[0], ip[1], ip[2], ip[3], ip[4]);
					}else { return 1;}
				}else { return 1;}
			}
			else {
				printf(RED"Didn't find exactly two IP addresses to solve for after "CYN"--ip-range\n"RESET);
				printf(YEL"Example : subnetter --ip 192.168.1.0 192.168.1.255 \n"RESET);
				return 1;
			}
		}// Unknown argument :
		else{
			printf(RED"Unknown argument "CYN"%s\n", argv[i]);
			printf(YEL"If you tried to specify the IP, place it after "CYN"--ip"YEL" argument .\n"RESET);
			return 1;
		}
	}
	// finally that arguments hassle is over .... phew .....
	
	// main... :
	if (practice_mode)
	{
		get_ipFromComputer(&ip);
		solve_ip(&ip, &ip_solution);
		printf("Your IP to solve is "CYN"%u.%u.%u.%u/%u\n\n"RESET, ip[0], ip[1], ip[2], ip[3], ip[4]);
		question_user(&ip_solution);
	}
	else{
		solve_ip(&ip, &ip_solution);
		show_solution(&ip_solution);
	}
	
	return 0;
}
////////////////////////////////////////////////////////////////
int get_ipValidity(char *ip_string, uint8_t (*ip)[5], int check_cidr)
{
	uint32_t  a, b, c, d, e = 0;
	int8_t terms_no = (check_cidr) ? 5 : 4;
	char *cidr_string = (check_cidr) ? "/e" : "" ;
	// check IP validity 
	if (sscanf(ip_string, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &e) != terms_no)
	{
		ip_string[strcspn(ip_string, "\n")] = '\0' ;
		printf(RED"Invalid IP Entered.\n");
		printf("Check your IP format "CYN"'%s'\n"RESET, ip_string);
		printf(RED"Expected IP format "CYN"'a.b.c.d%s'\n"RESET, cidr_string);
		printf(YEL"      -> a, b, c, d are IP octets with values from 0 to 255\n"RESET);
		if (check_cidr){
			printf(YEL"      -> e is CIDR notation value ranging from 0 to 32\n"RESET);
		}
		return INVALID;
	}
	else if ( a > 255 || b > 255 || c > 255 || d > 255 || e > 32)
	{
		printf(RED"Invalid IP Entered.\n");
		printf(YEL"IP octet values cannot be greater than 255 .\n"RESET);
		if (check_cidr){
			printf(YEL"CIDR Value cannot be greater than 32. \n"RESET);
		}
		return INVALID;
	}
	else{
		// valid ip:
		(*ip)[0] = a;
		(*ip)[1] = b;
		(*ip)[2] = c;
		(*ip)[3] = d;
		(*ip)[4] = e;
	}
	return VALID;
}
////////////////////////////////////////////////////////////////
void get_ipFromComputer(uint8_t (*ip)[5])
{
	srand(time(NULL)); // Seed with the current time
	int8_t index = 0;
	while (index < 4)
	{
		uint8_t octet_value = rand() % 256; // 0 to 255
		(*ip)[index] = octet_value;
		index++ ;
	}
	uint8_t cidr_value = rand() % 33; // 0 to 32
	(*ip)[4] = cidr_value;
}
////////////////////////////////////////////////////////////////
void user_help()
{
	printf("The Subnetter tool will help you with your daily subnetting challenges.\n");
	printf("It can also help you practice subnetting by giving you new challenges. \n");
	printf("It can take in an IP with CIDR to find the following: \n");
	printf("         -> First IP of the Network\n");
	printf("         -> Last  IP of the Network\n");
	printf("         -> Subnet mask\n");
	printf("         -> Wildcard Bits\n");
	printf("         -> Number of Possible hosts\n");
	
	printf("ARGUMENTS:\n");
	printf(CYN"         --help"RESET"          -> print this help message.\n");
	printf(CYN"         --practice"RESET"      -> computer generates questions for you to practice.\n");
	printf(CYN"         --ip "YEL"x.x.x.x/y"RESET"  -> specify an ip-cidr to solve.\n");
	printf(   "                            EXAMPLE: subnetter --ip 192.168.1.0/24\n");
	printf(CYN"         --verbose"RESET"       -> Show output in verbose / show more details about the network.\n");
	printf(CYN"         --ip-range"RESET"      -> Specify two IP to solve.\n");
	printf(   "                            EXAMPLE: subnetter --ip-range 192.168.0.0 192.168.0.255\n");
	
}
////////////////////////////////////////////////////////////////
void solve_ip(uint8_t (*ip)[5], IP_SOLUTION *ip_solution)
{
	uint8_t lockedBits = (*ip)[4]; // CIDR value
	uint8_t unlockedBits = 32 - lockedBits; 
	
	uint8_t positionA = lockedBits % 8 ;
	uint8_t positionB = 8 - positionA ;
	uint8_t i = lockedBits / 8 ;
	
	// METHOD: 
	// locked bits refer to cidr value
	// unlocked bits are all other bits (ie. 32 - locked-bits). 
	
	// The first ip will be all the unlocked bits turned 0.
	// The last ip will be all the unlocked bits turned 1.
	// Subnet mask is like first ip, but all locked bits are turned 1 and unlocked turned 0
	// Wildcard bit is like last ip, but locked bits are turned 0 and nlocked bits are turned 1.
	// We all know No. of Hosts is (2 ** cidr-value) . Example for /24, Hosts = 2 ** 24
	
	// the following code may be complex at first and tricky with bit operations, but it WORKS !!
	// if you don't understand the code, try writing your own code with the above ideas and you might 
	// click why my code is like this or why this specific value for a varable or why is it necessary ...
	
	// finding first and last IP :
	// finding netmask and wildcard : 
	for (int j = 0; j < i; j++)
	{
		ip_solution->firstIP[j]   = (*ip)[j];
		ip_solution->lastIP[j]   = (*ip)[j];
		ip_solution->netmask[j]  = 255;
		ip_solution->wildcard[j] = 0;
	}
	if (i < 4){
		ip_solution->firstIP[i]   = (*ip)[i] & (0b11111111 << positionB);
		ip_solution->lastIP[i]   = (*ip)[i] | (0b11111111 >> positionA );
		ip_solution->netmask[i]  = (0b11111111 << positionB);
		ip_solution->wildcard[i] = (0b11111111 >> positionA);
	}
	for (i++ ; i < 4; i++)
	{
		ip_solution->firstIP[i]   = 0;
		ip_solution->lastIP[i]   = 255;
		ip_solution->netmask[i]  = 0;
		ip_solution->wildcard[i] = 255;
	}
	
	// finding hosts :
	ip_solution->hosts = pow(2, unlockedBits); // same as 2 ** CIDR-value
	
	// following for verbose mode :
	if (verbose_mode)
	{
		// make sure firstIPdecimal and lastIPdecimal are 32 bits long 
		ip_solution->firstIPdecimal = ((((((ip_solution->firstIP[0] << 8) | ip_solution->firstIP[1])
									  << 8) | ip_solution->firstIP[2]) << 8) | ip_solution->firstIP[3]);
		ip_solution->lastIPdecimal = ((((((ip_solution->lastIP[0] << 8) | ip_solution->lastIP[1])
									  << 8) | ip_solution->lastIP[2]) << 8) | ip_solution->lastIP[3]);
	}
}
////////////////////////////////////////////////////////////////
void show_solution(IP_SOLUTION *ip_solution)
{
	printf("\n");
	printf("First IP     : "CYN"%u.%u.%u.%u\n"RESET, ip_solution->firstIP[0], ip_solution->firstIP[1],
										   ip_solution->firstIP[2], ip_solution->firstIP[3]);
	printf("Last IP      : "CYN"%u.%u.%u.%u\n"RESET, ip_solution->lastIP[0], ip_solution->lastIP[1],
										   ip_solution->lastIP[2], ip_solution->lastIP[3]);	
	printf("Subnet Mask  : "CYN"%u.%u.%u.%u\n"RESET, ip_solution->netmask[0], ip_solution->netmask[1],
										   ip_solution->netmask[2], ip_solution->netmask[3]);
	printf("Wildcard Bits: "CYN"%u.%u.%u.%u\n"RESET, ip_solution->wildcard[0], ip_solution->wildcard[1],
										   ip_solution->wildcard[2], ip_solution->wildcard[3]);
	printf("No. of Hosts : "CYN"%lu\n"RESET, ip_solution->hosts);
	
	if (verbose_mode)
	{
		printf("\nFirst IP in Decimal: "CYN"%u\n"RESET, ip_solution->firstIPdecimal);
		printf("Last  IP in Decimal: "CYN"%u\n"RESET, ip_solution->lastIPdecimal);
	}
}
////////////////////////////////////////////////////////////////
void question_user(IP_SOLUTION *ip_solution)
{
	uint8_t ip[5]; 
	uint64_t hosts; 
	char ip_string[20]; 
	char *questions[4] = {"First IP", "Last IP ", "Subnet Mask"};
	uint8_t ((*solution_arr[4])[4]) = {&ip_solution->firstIP, &ip_solution->lastIP, &ip_solution->netmask};
	
	for (int i = 0; i < 3; i++ ){
		do {
			printf("Enter %s: ", questions[i]);
			fgets(ip_string, sizeof(ip_string), stdin);	
		} while (!get_ipValidity(ip_string, &ip, DONT_CHECK_CIDR)) ;
		
		// solution_arr[i] is itself an address , so no need to use & operator .
		if (compare_ip( &ip, solution_arr[i])){
			printf(GRN"CORRECT !\n"RESET);
		}else{
			printf(YEL"INCORRECT. Answer was "CYN"%u.%u.%u.%u\n"RESET, (*solution_arr[i])[0], (*solution_arr[i])[1],
																	   (*solution_arr[i])[2], (*solution_arr[i])[3]);
		}
	}
	
	while (TRUE){
		printf("Enter No. of Hosts: ");
		fgets(ip_string, sizeof(ip_string), stdin);
		if (sscanf(ip_string, "%lu", &hosts) != 1){
			printf(RED"Invalid Hosts value."YEL" Try Again.\n"RESET);
		}
		else{
			break;
		}
	}
	
	if (hosts == ip_solution->hosts){
		printf(GRN"CORRECT !\n"RESET);
	}
	else{
		printf(YEL"INCORRECT. The correct answer was "CYN"%lu\n"RESET, ip_solution->hosts);
	}
}
////////////////////////////////////////////////////////////////
int compare_ip( uint8_t (*ip1)[5], uint8_t (*ip2)[4] )
{
	// using (*ip1)[5] here instead of (*ip1)[4] for compatibility as
	// it is used such in question_user() for compatibility with get_ipValidity() .
	for (int i = 0; i < 4; i++)
	{
		if ((*ip1)[i] != (*ip2)[i]){
			return DIFFERENT ;
		}
	}
	return SAME ;
}
////////////////////////////////////////////////////////////////
uint64_t get_cidrFromRange( uint8_t (*ip1)[5], uint8_t (*ip2)[5]) 
// ip1 and ip2 length is 5 for compatibility with get_ipValidity().
{
	// Here, we will be finding the CIDR value by checking how many bits starting from left of 
	// each ip are same and then returning that value. We use some binary operations. 
	uint64_t cidr_value = 0;
	uint32_t compared_result; // in binary, represents which bits of ip1 and ip2 are same, 
							  // represented by a 1 and which are not represented by a 0. 
	uint8_t  position = 31;
	
	// we use XOR to find which are different represent 1 for different bits 
	compared_result = ((((((((*ip1)[0] ^ (*ip2)[0])  << 8) | ((*ip1)[1] ^ (*ip2)[1])) << 8) |
							 ((*ip1)[2] ^ (*ip2)[2])) << 8) | ((*ip1)[3] ^ (*ip2)[3])) ;
	
	for (; cidr_value <= 32; cidr_value++ )
	{
		if (compared_result & (1 << position)) {  // found bit 1 ( representing different bits)
			break; 
		}
		position-- ;
	}
	
	return cidr_value;
}
////////////////////////////////////////////////////////////////
