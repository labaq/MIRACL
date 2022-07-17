/*
** rigol ds2000 keygen / cybernet & the-eevblog-users
**
** to compile this you need MIRACL from https://github.com/CertiVox/MIRACL
** download the master.zip into a new folder and run
**
**    unzip -j -aa -L master.zip
**
** then run
**
**    bash linux
**
** to build the 32-bit miracle.a library
**
** then optionally fetch private key from EEVBlog and put into "private_key[]="
** below, do not prefix with 0x. excluding here will require the key at runtime.
**
**
** BUILD WITH:
**    gcc rikey.c -m32 -I./MIRACL ./MIRACL/miracl.a -o rikey
**
** adapt -I and path to miracl.a to your environment
**
** more info: http://www.eevblog.com/forum/testgear/sniffing-the-rigol's-internal-i2c-bus/
**
** run, supply your serial and wanted options, and enjoy!
** 
** tabs: 4 cols: 100 rev: 20130723_1_true
**
** additions and changes:
**   change: removed unused functions
**   change: run-time private key option
**   change: ecssign function clean-up (zombie28)
**   fix: code is beautified
**   fix: licenses are padded properly (Maalobs, true)
**   fix: lic2 prime check (anonymous, cybernet, studio25)
**   fix: unnecessary brute-force removed (studio25)
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "miracl.h"

#define RIGOL_DS2000

// START OF SETTINGS FOR ECC
#ifdef RIGOL_DS2000
unsigned char private_key[] = "8EEBD4D04C3771"; 	// fill me in (optional), B....

int           k_offset = 0; 		// optionally change ecssign starting offset
									// (changes lic1; makes different licenses)
/* do not change these */
unsigned char prime1[]  = "AEBF94CEE3E707";
unsigned char prime2[]  = "AEBF94D5C6AA71";
unsigned char curve_a[] = "2982";
unsigned char curve_b[] = "3408";
unsigned char point1[]  = "7A3E808599A525";
unsigned char point2[]  = "28BE7FAFD2A052";
#endif
// END OF SETTINGS FOR ECC

unsigned char vb[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R',
	'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'2', '3', '4', '5', '6', '7', '8', '9'
};

/*
** program help
*/
void show_help(char *cmd)
{
	char text_pk[10];
	strcpy(text_pk, strlen(private_key) ? "[privkey]" : "<privkey>");
	
	printf("\nUsage: %s <sn> <opts> %s\n\n", cmd, text_pk);
	printf("  <sn>       serial number of device (DS2A.........)\n");
	printf("  <opts>     device options, 4 characters, see below\n");
	printf("  %s  private key%s\n\n\n", text_pk, strlen(private_key) ? " (optional)" : "");
	
	printf("device options:\n\n");
	printf("  first character:  D = official, V = trial\n");
	printf("  second character: S\n");
	printf("  third character:  A = DS2000, H = DS4000\n");
	printf("  last character :  your options, use the following table to generate for DS2000:\n\n");

	printf("  --------- A B C D E F G H J K L M N P Q R S T U V W X Y Z 2 3 4 5 6 7 8 9\n");
	printf("  100MHz    ' ' ' ' ' ' ' ' * * * * * * * * ' ' ' ' ' ' ' ' * * * * * * * *\n");
	printf("  200MHz    ' ' ' ' ' ' ' ' ' ' ' ' ' ' ' ' * * * * * * * * * * * * * * * *\n");
	printf("  Memory56M ' ' ' ' * * * * ' ' ' ' * * * * ' ' ' ' * * * * ' ' ' ' * * * *\n");
	printf("  Decode    ' ' * * ' ' * * ' ' * * ' ' * * ' ' * * ' ' * * ' ' * * ' ' * *\n");
	printf("  Triggers  ' * ' * ' * ' * ' * ' * ' * ' * ' * ' * ' * ' * ' * ' * ' * ' *\n\n");
	printf("  For DS4000, try DSH9, VSH9 to enable all options.\n\n");
	printf("MAKE SURE YOUR FIRMWARE IS UP TO DATE BEFORE APPLYING ANY KEYS\n\n");
}

/*
** take serial and options make sha1 hash out of it
*/
static void hashing(unsigned char *opt_str, big hash)
{
	char *p;
	char h[20];
	int ch;
	sha sh;
	shs_init(&sh);
	p = opt_str;

	while(*p) {
		shs_process(&sh, *p);
		p++;
	}
    
    shs_hash(&sh, h);
    bytes_to_big(20, h, hash);
}

/*
** sign the secret message (serial + opts) with the private key
*/
void ecssign(char *serial, char *options, char *privk, char *lic1, char *lic2)
{
    mirsys(800, 16)->IOBASE = 16;

    sha sha1;
    shs_init(&sha1);
	
    char *ptr = serial;
    while(*ptr) shs_process(&sha1, *ptr++);
    ptr = options;
    while(*ptr) shs_process(&sha1, *ptr++);
    
	char h[20];
    shs_hash(&sha1, h);
    big hash = mirvar(0);
    bytes_to_big(20, h, hash);

    big a = mirvar(0);  instr(a, curve_a);
    big b = mirvar(0);  instr(b, curve_b);
    big p = mirvar(0);  instr(p, prime1);
    big q = mirvar(0);  instr(q, prime2);
    big Gx = mirvar(0); instr(Gx, point1);
    big Gy = mirvar(0); instr(Gy, point2);
    big d = mirvar(0);  instr(d, privk);
    big k = mirvar(0);
    big r = mirvar(0);
    big s = mirvar(0);
    big k1 = mirvar(0);
    big zero = mirvar(0);

    big f1 = mirvar(17);
    big f2 = mirvar(53);
    big f3 = mirvar(905461);
    big f4 = mirvar(60291817);
	
	incr(k, k_offset, k);

    epoint *G = epoint_init();
    epoint *kG = epoint_init();
    ecurve_init(a, b, p, MR_PROJECTIVE);
    epoint_set(Gx, Gy, 0, G);

    for(;;) {
        incr(k, 1, k);

        if(divisible(k, f1) || divisible(k, f2) || divisible(k, f3) || divisible(k, f4))
			continue;

        ecurve_mult(k, G, kG);
        epoint_get(kG, r, r);
        divide(r, q, q);
        
        if(mr_compare(r, zero) == 0)
            continue;

        xgcd(k, q, k1, k1, k1);
        mad(d, r, hash, q, q, s);
        mad(s, k1, k1, q, q, s);

        if(!divisible(s, f1) && !divisible(s, f2) && !divisible(s, f3) && !divisible(s, f4))
            break;
    } 

    cotstr(r, lic1);
    cotstr(s, lic2);
}

/*
** convert string to uppercase chars
*/
unsigned char * strtoupper(unsigned char *str)
{
	unsigned char *newstr, *p;
	p = newstr = (unsigned char*) strdup((char*)str);
	while ((*p++ = toupper(*p)));
	return newstr;
}

/*
** prepend a char to a string
*/
unsigned char * prepend(unsigned char *c, unsigned char *str)
{
    int i;

    for (i = strlen(str); i >= 0; i--) {
		str[i + 1] = str[i];
	}
    
    str[0] = *c;
	return c;
}

/*
** convert hex-ascii-string to rigol license format
*/
unsigned char * map_hex_to_rigol(unsigned char *code5)
{
	unsigned long long b = 0;
	unsigned char *out;
	int i = 0;
	
	out = calloc(5, 1);

	/* hex2dez */
	while (code5[i] != '\0') {
		if (code5[i] >= '0' && code5[i] <= '9') {
			b = b * 16 + code5[i] - '0';
		} else if (code5[i] >= 'A' && code5[i] <= 'F') {
			b = b * 16 + code5[i] - 'A' + 10;
		} else if (code5[i] >= 'a' && code5[i] <= 'f') {
			b = b * 16 + code5[i] - 'a' + 10;
		}
	
		i++;
	}    

	for (i = 3; ; i--) {
		out[i] = vb[b & 0x1F];
		if (i == 0) break;
		b >>= 5;
	}

	out[4] = '\0';
	return(out);
}

/*
** the world ends here
*/
int main(int argc, char *argv[0])
{
	unsigned char *options, *lic1_code, *lic2_code, *lic_all;
	unsigned char *out, *chunk, *temp, *final;
	unsigned char *lic1_key, *lic2_key, *priv_key;
	unsigned char *serial;
	int            i = 0, j = 0;

	if (!((argc == 3 && strlen(private_key)) || argc == 4)) {
		show_help(argv[0]);
		exit(-1);
	}
	
	serial = strtoupper((unsigned char*)argv[1]);
	options = strtoupper((unsigned char*)argv[2]);
	
	if (argc == 4) {
		priv_key = strtoupper((unsigned char*)argv[3]);	
	} else {
		priv_key = strtoupper((unsigned char*)private_key);	
	}
 
	if (strlen(priv_key) != 14) {
		printf("\nERROR: INVALID PRIVATE KEY LENGTH\n");
		show_help(argv[0]);
		exit(-1);
	}
	
	if (strlen(serial) < 13) {
		printf("\nERROR: INVALID SERIAL LENGTH\n");
		show_help(argv[0]);
		exit(-1);
	}
 
	if (strlen(options) != 4) {
		printf("\nERROR: INVALID OPTIONS LENGTH\n");
		show_help(argv[0]);
		exit(-1);
	}
	
	printf("private-key:      %s\n", priv_key);
	printf("serial:           %s\n", serial);
	printf("options:          %s\n", options);
 
	/* sign the message */
	lic1_code = calloc(64, 1);
	lic2_code = calloc(64, 1);
	
	ecssign(serial, options, priv_key, lic1_code, lic2_code);
		
	/* fix missing zeroes */
	while (strlen(lic1_code) < 14) {
		prepend("0", lic1_code);
	}
	while (strlen(lic2_code) < 14) {
		prepend("0", lic2_code);
	}
	
	printf("lic1-code:        %s\n", lic1_code);
	printf("lic2-code:        %s\n", lic2_code);

	lic_all = calloc(128, 1);
	temp = calloc(128, 1);
	chunk = calloc(6, 1);
	final = calloc(128, 1);
	lic1_key = calloc(20, 1);
	lic2_key = calloc(20, 1);
	
	strcpy(lic_all, lic1_code);
	strcat(lic_all, "0");
	strcat(lic_all, lic2_code);
	printf("target-code:      %s\n", lic_all);

	strcat(lic1_code, "0");
	
	while (i < strlen(lic1_code)) {
		memcpy(chunk, lic1_code + i, 5);
		out = map_hex_to_rigol(chunk);
	
		if (out) {
			strcat(temp, out);
		}
   
		i = i + 5;
	}
 
	strcpy(lic1_key, temp);

	// run for lic2_code
	strcpy(temp, "");
	
	i = 0;
	while (i < strlen(lic2_code)) {
		memcpy(chunk, lic2_code + i, 5);
		
		if (strlen(chunk) < 5) {
			for(j = 0; j < 5 - strlen(chunk); j++) {
				strcat(chunk, "0");
			}
		}
   
		out = map_hex_to_rigol(chunk);
   
		if (out) {
			strcat(temp, out);
		}
   
		i = i + 5;
	}
	
	strcpy(lic2_key, temp);
 
	strcpy(temp, lic1_key);
	strcat(temp, lic2_key);
 
	/* now add the options */
	memcpy(final,      temp     , 1);
	final[1] = options[0];
	memcpy(final +  2, temp +  1, 7);
	final[9] = options[1];
	memcpy(final + 10, temp +  8, 7);
	final[17] = options[2];
	memcpy(final + 18, temp + 15, 7);
	final[25] = options[3];
	memcpy(final + 26, temp + 22, 4);
	
	printf("----------------------------------------------------\n");
	printf("your-license-key: ");
	
	for(i = 0; i < strlen(final); i++) {
		if (i % 7 == 0 && i > 0) printf("-");
		printf("%c", final[i]);
	}
 
	printf("\n");
	printf("----------------------------------------------------\n");
}