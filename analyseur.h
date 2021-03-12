#ifndef ANALYSEUR_H
#define ANALYSEUR_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <argp.h>


#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define SIZE_ADDR_CHAR 16

void
print_igmp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int size_ip);

void
print_udp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int size_ip);

void
print_icmp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int size_ip);

void
print_tcp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet, int size_ip);

void
handle_arp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
handle_ipv6(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
handle_ipv4(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

/* ARGP */
static char args_doc[] = "";

static char doc[] =
  "Analyseur de paquets -- un programme analysant des paquets";

static struct argp_option options[] = {
  {"verbose",  'v', "VERBOSITY",      0,  "Indicate the VERBOSITY level from 1...3" },
  {"filter",   'f', "FILTER",      0,  "specify a FILTER to pass to pcap" },
  {"interface",'i', "INTERFACE",      0,  "specify the INTERFACE to listen on" },
  {"output",   'o', "FILE", 0, "Output to FILE instead of standard output" },
  { 0 }
};

struct arguments
{
  int verbosity;
  char *input_file;
  char *filter;
  char *interface;
};

#endif // ANALYSEUR_H
