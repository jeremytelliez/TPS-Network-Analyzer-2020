#include "analyseur.h"

int verbosity = 1;

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;
  int verb;
  switch (key)
    {
    case 'v':
      verb = atoi(arg);
      if(verb == 1 || verb == 2 || verb == 3)
        arguments->verbosity = verb;
      break;
    case 'f':
      arguments->filter = arg;
      break;
    case 'i':
      arguments->interface = arg;
      break;
    case 'o':
      arguments->input_file = arg;
      break;

    case ARGP_KEY_ARG:
      argp_usage (state);
      break;

    case ARGP_KEY_END:
      if (state->arg_num != 0)
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void handle_ipv4(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

  const struct iphdr *ip;              /* The IP header */
  int size_ip;                        /* Size of IP Header */
  char *addrBuf = malloc(SIZE_ADDR_CHAR);

  /* define/compute ip header offset */
	ip = (struct iphdr*)(packet + SIZE_ETHERNET);
	size_ip = (ip->ihl)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
  /* print protocol, source and destination IP addresses */
  if(verbosity == 1) {
    /* print source and destination IP addresses */
    printf("Protocol: IPv4\n");
  	printf("From: %s\n", inet_ntop(AF_INET,&(ip->saddr),addrBuf,SIZE_ADDR_CHAR));
  	printf("  To: %s\n", inet_ntop(AF_INET,&(ip->daddr),addrBuf,SIZE_ADDR_CHAR));
  } else if (verbosity == 2) {
    printf("Protocol: IPv4");
  	printf(" src: %s", inet_ntop(AF_INET,&(ip->saddr),addrBuf,SIZE_ADDR_CHAR));
  	printf(" dst: %s\n", inet_ntop(AF_INET,&(ip->daddr),addrBuf,SIZE_ADDR_CHAR));
  } else {
    printf(" IPv4");
  }

	/* determine protocol */
	switch(ip->protocol) {
		case IPPROTO_TCP:
      print_tcp(args,header,packet,size_ip);
			break;
		case IPPROTO_UDP:
      print_udp(args,header,packet,size_ip);
			return;

    case IPPROTO_IGMP:
      print_igmp(args,header,packet,size_ip);
  		return;

		case IPPROTO_ICMP:
      print_icmp(args,header,packet,size_ip);
			return;
		default:
			printf("    Protocol: unknown\n");
			return;
	}
}

void handle_ipv6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  return;
}

void handle_arp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  const struct arphdr *arp;              /* The IP header */
  arp = (struct arphdr*)(packet + SIZE_ETHERNET);

  if(verbosity == 1) {
    /* print source and destination IP addresses */
    printf("Protocol: ARP\n");
  	printf("Hardware Address format: %s\n", ntohs(arp->ar_op));
  	printf("Sender Harware Protocol: %s\n", );

    printf("Target Hardware Address: %s\n", );
  	printf("Target Harware Protocol: %s\n", );
  } else if (verbosity == 2) {
    printf("prot: ARP");
  	printf(" sender add: %s", inet_ntop(AF_INET,&(ip->saddr),addrBuf,SIZE_ADDR_CHAR));
  	printf(" target add: %s\n", inet_ntop(AF_INET,&(ip->daddr),addrBuf,SIZE_ADDR_CHAR));
    printf(" arp opcode: %d\n", ntohs(arp->ar_op));
  } else {
    printf(" ARP");
  }

  return;
}

void print_tcp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int size_ip){
  const struct iphdr *ip;              /* The IP header */
  const struct tcphdr *tcp;            /* The TCP header */
  const char *payload;                    /* Packet payload */
  int size_tcp;                         /* Size of TCP Header */
	int size_payload;

	/* define/compute tcp header offset */
	tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);

  ip = (struct iphdr*)(packet + SIZE_ETHERNET);

	size_tcp = tcp->th_off*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

  if(verbosity == 1){
    printf("   Protocol: TCP\n");
    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));
    /* define/compute tcp payload (segment) offset */
  	payload = (u_char *)(packet + ETH_HLEN + size_ip + size_tcp);

  	/* compute tcp payload (segment) size */
  	size_payload = ntohs(ip->tot_len) - (size_ip + size_tcp);

  	/*
  	 * Print payload data; it might be binary, so don't just
  	 * treat it as a string.
  	 */
  	if (size_payload > 0) {
  		printf("   Payload (%d bytes):\n", size_payload);
  		print_payload(payload, size_payload);
  	}
  } else if (verbosity == 2) {
    printf("    Protocol: TCP");
    printf("    Sport: %d", ntohs(tcp->th_sport));
    printf("    Dport: %d\n", ntohs(tcp->th_dport));
  } else {
    printf(" TCP");
  }


  return;
}

void print_udp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int size_ip){
  const struct udphdr *udp;              /* The IP header */
  udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
  if(verbosity == 1){
    printf("   Protocol: UDP\n");
    printf("   Src port: %d\n", ntohs(udp->source));
    printf("   Dst port: %d\n", ntohs(udp->dest));
  } else if (verbosity == 2) {
    printf("    Protocol: UDP");
    printf("    Sport: %d", ntohs(udp->source));
    printf("    Dport: %d\n", ntohs(udp->dest));
  } else {
    printf(" UDP");
  }

  return;
}

void print_icmp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int size_ip){

}

void print_igmp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int size_ip){

}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct ether_header *ethernet;  /* The ethernet header [1] */

  if(verbosity == 1) {
    printf("\nPacket number %d:\n", count);
  } else if (verbosity == 2) {
    printf("\nPacket %d:\n", count);
  } else {
    printf("%d: ", count);
  }
	count++;

	/* define ethernet header */
	ethernet = (struct ether_header*)(packet);

  switch(ntohs(ethernet->ether_type)) {
    case ETHERTYPE_IP:
      handle_ipv4(args,header,packet);
      printf("\n");
      break;
    case ETHERTYPE_IPV6:
      handle_ipv6(args,header,packet);
      printf("\n");
      break;
    case ETHERTYPE_ARP:
      handle_arp(args,header,packet);
      printf("\n");
      break;
    default:
      printf("Protocol: unknow\n");
      break;
  }
return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char* filter_exp = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 0;			/* number of packets to capture */

  struct arguments arguments;

  /* Default values. */
  arguments.interface = NULL;
  arguments.filter = NULL;
  arguments.input_file = NULL;
  arguments.verbosity = 0;

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

	/* check for capture device name on command-line */
	/*if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line *//*
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}*/

  if(arguments.interface == NULL){
    dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
  }
  if(arguments.filter != NULL)
    filter_exp = arguments.filter;

  if(arguments.verbosity != 0)
    verbosity = arguments.verbosity;



	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Filter expression: %s\n", filter_exp);

  if(arguments.input_file == NULL){
    /* open capture device */
    handle = pcap_open_live(dev, ETHERMTU, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
      exit(EXIT_FAILURE);
    }
  } else {

    handle = pcap_open_offline(arguments.input_file, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open file %s: %s\n", arguments.input_file, errbuf);
      exit(EXIT_FAILURE);
    }
  }


	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
