#ifndef PACKET_HANDLER_H_INCLUDED
#define PACKET_HANDLER_H_INCLUDED
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif // PACKET_HANDLER_H_INCLUDED
