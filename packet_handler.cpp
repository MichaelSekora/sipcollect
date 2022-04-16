#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <string.h>
#include <mysql.h>
#include "mysql_handler.h"
#include <unistd.h>
using namespace std;

extern MYSQL *conn;
extern bool mysqlpresent;
extern std::string dbname;

string query_part2 = "";
string query_part3 = ";";
int query_counter = 0;

typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

// IPv4 header
typedef struct ip_header
{
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flags_fo;
	u_char ttl;
	u_char proto;
	u_short crc;
	ip_address saddr;
	ip_address daddr;
	u_int op_pad;
} ip_header;

// UDP header
typedef struct udp_header
{
	u_short sport;
	u_short dport;
	u_short len;
	u_short crc;
} udp_header;

// TCP header
typedef struct tcp_header
{
	u_short sport;
	u_short dport;
	u_int sequence;
	u_int ack;
	u_char offset;
} tcp_header;

typedef struct udp_data
{
	u_char UDPdata_c;
} udp_data;

ip_header *ih;
udp_header *uh;
udp_data *UDPdata;
tcp_header *th;
ip_address srcaddr;
ip_address dstaddr;

char *concat(int count, ...)
{
	va_list ap;
	int i;

	size_t len = 1; // room for NULL
	va_start(ap, count);
	for (i = 0; i < count; i++)
		len += strlen(va_arg(ap, char *));
	va_end(ap);

	char *merged = (char *)calloc(sizeof(char), len + 1);
	size_t null_pos = 0;

	va_start(ap, count);
	for (i = 0; i < count; i++)
	{
		char *s = va_arg(ap, char *);
		strcpy(merged + null_pos, s);
		null_pos += strlen(s);
	}
	va_end(ap);
	return merged;
}

char *extractheader(char *haystack, char *needle)
{
	int y = 0;
	size_t h = 0;
	size_t p = 0;
	int match = 0;
	size_t callidcounter = 0;
	size_t callidstart = 0;
	size_t haylen = strlen(haystack);
	size_t neelen = strlen(needle);
	char needle1[500] = {0};
	size_t ne = 0;
	for (ne = 0; ne < strlen(needle); ne++)
	{
		needle1[ne] = needle[ne];
		if (needle[ne] > 64 && needle[ne] < 91)
		{
			needle1[ne] = (int)needle[ne] + 32;
		}
		if (needle[ne] > 96 && needle[ne] < 123)
		{
			needle1[ne] = (int)needle[ne] - 32;
		}
	}
	needle1[ne + 1] = '\0';

	char *resultstr1 = new char[1024];
	int i = 0;
	for (i = 0; i < 1024; i++)
	{
		resultstr1[i] = '\0';
	}

	size_t hayfor = haylen - (neelen + 1);
	if (haylen > neelen)
	{
		for (h = 0; h < hayfor; h++)
		{
			if (haystack[h] == '\n')
			{
				if (haystack[h + 1] == needle[1] || haystack[h + 1] == needle1[1])
				{
					match = 1;
					for (p = 0; p < neelen - 1; p++)
					{
						if (haystack[h + 1 + p] != needle[p + 1] && haystack[h + 1 + p] != needle1[p + 1])
						{
							match = 0;
							break;
						}
					}
					if (match == 1)
					{
						callidstart = h + neelen;
						if (haystack[h + neelen] == ' ')
						{
							callidstart = h + neelen + 1;
							if (haystack[h + neelen + 1] == ' ')
							{
								callidstart = h + neelen + 2;
								if (haystack[h + neelen + 2] == ' ')
								{
									callidstart = h + neelen + 3;
								}
							}
						}
						callidcounter = callidstart;
						while (haystack[callidcounter] != '\r' && haystack[callidcounter] != '\n' && y < 1020)
						{
							resultstr1[y] = haystack[callidcounter];
							callidcounter++;
							y++;
						}
						match = 0;
						break;
					}
				}
			}
		}
	}
	resultstr1[y] = '\0';
	return resultstr1;
}

void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	string query_part1 = "INSERT INTO " + dbname + ".sip (`callid`, `datetime`, \
  `srcip`, `srcport`, `dstip`, `dstport`, `content`) VALUES ";

	char udpstrtmp[65535];
	char udpstrtmp2[65535];
	struct tm *ltime;
	u_int ip_len;
	u_short sport, dport, len;
	time_t local_tv_sec;
	char timestr[64];
	char usec[76];
	int b = 0;
	while (b < 65535)
	{
		udpstrtmp[b] = '\0';
		udpstrtmp2[b] = '\0';
		b++;
	}

	local_tv_sec = header->ts.tv_sec;
	ltime = gmtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);

	snprintf(usec, sizeof usec, "%s.%06ld", timestr, header->ts.tv_usec);

	ih = (ip_header *)(pkt_data + 14); // length of ethernet header

	u_char ip_proto = ih->proto;

	/* retrieve the position of the udp/tcp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;

	int tcpudplen = 8;
	// get length of udp/tcp header and set tcpudplen (minimum 8)
	if (ip_proto == 6)
	{
		th = (tcp_header *)((u_char *)ih + ip_len);
		tcpudplen = (int)(th->offset >> 4) * 4;
		UDPdata = (udp_data *)((u_char *)th + tcpudplen);
		sport = ntohs(th->sport);
		dport = ntohs(th->dport);
		u_short tlen = ntohs(ih->tlen);
		len = tlen - ip_len - tcpudplen;
	}

	if (ip_proto == 17)
	{
		uh = (udp_header *)((u_char *)ih + ip_len);
		tcpudplen = 8;
		UDPdata = (udp_data *)((u_char *)uh + tcpudplen);
		sport = ntohs(uh->sport);
		dport = ntohs(uh->dport);
		len = ntohs(uh->len) - 8;
	}

	srcaddr = ih->saddr;
	dstaddr = ih->daddr;
	if (len < 1)
	{
		len = 0;
	}

	if (len > 0)
	{
		memcpy(udpstrtmp, UDPdata, len);
	}

	char *callid = extractheader(udpstrtmp, (char *)"\nCall-ID:");

	string srcip1 = to_string(srcaddr.byte1);
	string srcip2 = to_string(srcaddr.byte2);
	string srcip3 = to_string(srcaddr.byte3);
	string srcip4 = to_string(srcaddr.byte4);
	string dstip1 = to_string(dstaddr.byte1);
	string dstip2 = to_string(dstaddr.byte2);
	string dstip3 = to_string(dstaddr.byte3);
	string dstip4 = to_string(dstaddr.byte4);
	string srcip = srcip1 + "." + srcip2 + "." + srcip3 + "." + srcip4;
	string srcport = to_string(sport);
	string dstip = dstip1 + "." + dstip2 + "." + dstip3 + "." + dstip4;
	string dstport = to_string(dport);
	string datetime(usec);
	int conversion_result = mysql_real_escape_string(conn, udpstrtmp2, udpstrtmp, strlen(udpstrtmp));
	string content(udpstrtmp2);

	// cout << "\nCall-ID: " << callid;

	if (query_counter == 0)
	{
		query_part2 = "('" + string(callid) + "', '" + datetime + "', '" + srcip + "', '" + srcport + "', '" + dstip + "', '" + dstport + "', '" + content + "')";
	}
	else
	{
		query_part2 = query_part2 + ", " + "('" + callid + "', '" + datetime + "', '" + srcip + "', '" + srcport + "', '" + dstip + "', '" + dstport + "', '" + content + "')";
	}

	query_counter++;
	if (query_counter > 9)
	{

		string query_part123 = query_part1 + query_part2 + query_part3;

		int query_part123_size = query_part123.size();
		char *query = new char[query_part123_size + 1];
		query_part123.copy(query, query_part123_size + 1);
		query[query_part123_size] = '\0';
		MYSQL_RES *result;
		result = mysql_perform_query(conn, query);

		if (*mysql_error(conn))
		{
			printf("\n******\nmysql-error:%s\n", result);
			mysqlpresent = false;
			connectdb();
			sleep(5);
		}
		for (; mysql_next_result(conn) == 0;)
			/* do nothing */;
		mysql_free_result(result);
		query_counter = 0;
		delete[] query;
		free(result);
	}

	delete callid;
	callid = NULL;
}
