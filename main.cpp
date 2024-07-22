#include <stdio.h>
#include <stdlib.h>
#include <mysql.h>
#include <pcap.h>
#include <time.h>
#include "mysql_handler.h"
#include "packet_handler.h"
#include "readconfig.h"
#include <iostream>
#include <string.h>
using namespace std;

bool use_database=true;

std::string dbhost;
std::string dbname;
std::string dbuser;
std::string dbpasswd;

int main(int argc, char *argv[])
{
  ReadConfig readconfig;
  dbhost = readconfig.dbhost;
  dbname = readconfig.dbname;
  dbuser = readconfig.dbuser;
  dbpasswd = readconfig.dbpasswd;

  std::string str = readconfig.packet_filter;
  char packet_filter[str.length() + 1];
  strcpy(packet_filter, str.c_str());

  if (use_database==true)
  {
    int result_conndb = connectdb();
  }
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i = 0;
  int inum = 0;
  pcap_t *adhandle;
  struct bpf_program fcode;
  void packet_handler(u_char * dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data);

  if (pcap_findalldevs(&alldevs, errbuf) == -1)
  {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);
  }

  for (d = alldevs; d; d = d->next)
  {
    printf("%d. %s", ++i, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n");
  }

  inum = atoi(argv[1]);
  printf("\r\ninterface1: %d\r\n", inum);

  if (i == 0)
  {
    printf("\nNo interfaces found!\n");
    return -1;
  }

  if (inum < 1 || inum > i)
  {
    printf("\nAdapter number out of range.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
    ;

  if ((adhandle = pcap_open_live(d->name, 65536, 1, 100, errbuf)) == NULL)
  {
    fprintf(stderr, "\nUnable to open adapter.p\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  if (pcap_datalink(adhandle) != DLT_EN10MB)
  {
    fprintf(stderr, "\nEthernet only.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  if (pcap_compile(adhandle, &fcode, packet_filter, 1, 0xffffff) < 0)
  {
    fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  if (pcap_setfilter(adhandle, &fcode) < 0)
  {
    fprintf(stderr, "\nError setting the filter.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  printf("\nlistening on %s...\n", d->name);

  pcap_loop(adhandle, 0, packet_handler, NULL);
  pcap_freealldevs(alldevs);
  return 0;
}
