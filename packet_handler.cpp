#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <string.h>
#include <mysql.h>
#include "mysql_handler.h"
#include <unistd.h>
#include <bits/stdc++.h>
#include <ctime>

using namespace std;

extern MYSQL *conn;
extern bool use_database;
extern bool mysqlpresent;
extern std::string dbname;

string query_part2 = "";
string query_part3 = "; ";
int query_counter = 0;
map<u_short, string> sip_fragment;
map<u_short, u_int> sip_fragment_age;

bool wait_for_more = false;
int last_number_of_entries=0;
int counter_l=0;

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
	u_char flags;
	u_char fragment_offset;
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
// 8 byte

// TCP header
typedef struct tcp_header
{
	u_short sport;
	u_short dport;
	u_int sequence;
	u_int ack;
	u_char offset;
} tcp_header;
// 13 byte

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
	// maintain (delete) old entries from map sip_fragment
	u_int number_of_entries = sip_fragment.size();
	counter_l++;
	if (counter_l > 100 && number_of_entries > 20)
	{
		last_number_of_entries = number_of_entries;
		//printf("\n-------------------\n%u", number_of_entries);
		//for (auto it1 = sip_fragment.begin(); it1 != sip_fragment.end();)
		auto it1=sip_fragment.begin();
		u_int time_now2 = (int)time(nullptr);
		//for (int i77 = 0; i77 < 10; i77++)
    	for (auto it1 = sip_fragment.begin(); it1 != sip_fragment.end();)
		{
		
			//it1 = sip_fragment.begin();
			u_short ip_ident2 = it1->first;
        	u_int age = sip_fragment_age.at(ip_ident2);
			/*
			printf("\n%u  ", ip_ident2);
			printf("  %d", age);
			printf("  %d", time_now2);
			/**/
			if ((time_now2 - age) > 10)
			{
				//printf("\ndelete %u", ip_ident2);
				sip_fragment_age.erase(ip_ident2);
				sip_fragment.erase(ip_ident2);
				it1 = sip_fragment.begin();
				continue;
			}
			++it1;
    	}
		counter_l=0;
	}





	wait_for_more = false;
	string query_part1 = "INSERT INTO " + dbname + ".sip (`callid`, `datetime`, \
  `srcip`, `srcport`, `dstip`, `dstport`, `content`) VALUES ";

	char udpstrtmp[5000];
	char udpstrtmp2[5000];
	struct tm *ltime;
	u_int ip_len;
	u_char eth_type_part1;
	u_char eth_type_part2;
	u_short sport, dport, len, ip_identification;
	u_char ip_flags;
	u_char ip_fragment_offset;
	time_t local_tv_sec;
	char timestr[64];
	char usec[76];
	int b = 0;
	u_short tlen =0;

	memset(udpstrtmp, '\0', sizeof(udpstrtmp));
	memset(udpstrtmp2, '\0', sizeof(udpstrtmp2));

	local_tv_sec = header->ts.tv_sec;
	ltime = gmtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);

	snprintf(usec, sizeof usec, "%s.%06ld", timestr, header->ts.tv_usec);

	// check if type is VLAN ( 81 00 )
	eth_type_part1 = (u_char)(pkt_data + 12)[0];
	eth_type_part2 = (u_char)(pkt_data + 12)[1];

	// if (eth_type_part1 == '\x81' && eth_type_part2 == '\x00')
	if ((u_int)eth_type_part1 == 129 && (u_int)eth_type_part2 == 0)
	{
		ih = (ip_header *)(pkt_data + 18); // length of ethernet header
	}
	else
	{
		ih = (ip_header *)(pkt_data + 14); // length of ethernet header
	}

	// ih = IP4-Layer

	u_char ip_proto = ih->proto;

	ip_identification = ih->identification;
	ip_flags = ih->flags;
	ip_fragment_offset = ih->fragment_offset;

	/* retrieve the position of the udp/tcp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;

	int tcpudplen = 8;
	// get length of udp/tcp header and set tcpudplen (minimum 8)
	if (ip_proto == 6)
	{
		th = (tcp_header *)((u_char *)ih + ip_len);
		if (ip_fragment_offset == 0)
		{
			tcpudplen = (int)(th->offset >> 4) * 4;
		}
		else
		{
			tcpudplen = 0;
		}
		UDPdata = (udp_data *)((u_char *)th + tcpudplen);
		sport = ntohs(th->sport);
		dport = ntohs(th->dport);
		tlen = ntohs(ih->tlen);
		len = tlen - ip_len - tcpudplen;
	}

	if (ip_proto == 17)
	{
		uh = (udp_header *)((u_char *)ih + ip_len);
		if (ip_fragment_offset == 0)
		{
			tcpudplen = 8;
		}
		else
		{
			tcpudplen = 0;
		}

		UDPdata = (udp_data *)((u_char *)uh + tcpudplen);
		sport = ntohs(uh->sport);
		dport = ntohs(uh->dport);
		tlen = ntohs(ih->tlen);
		len = tlen - ip_len - 8;
	}

	srcaddr = ih->saddr;
	dstaddr = ih->daddr;
	if (len < 1)
	{
		len = 0;
	}

	if (len > 0 && len < 2400)
	{
		// ip flag, more fragments
		if ((1 & (ip_flags >> 5)))
		{
			memset(udpstrtmp, '\0', sizeof(udpstrtmp));
			memcpy(udpstrtmp, UDPdata, len);
			sip_fragment.insert({ip_identification, string(udpstrtmp)});
			size_t time_now = time(nullptr);
			sip_fragment_age.insert({ip_identification, (uint)time_now});

			/*
			printf ("\n=============================== udpstrtmp when more fragments ==========================\n");
			for(int i = 0; i < 2000; i++)
			{
					printf("%02x ", udpstrtmp[i]);
			}
			/**/
		}

		else
		{
			memset(udpstrtmp, '\0', sizeof(udpstrtmp));

			if (ip_fragment_offset > 0)
			{
				memcpy(udpstrtmp, UDPdata, len+8);
			}
			else
			{
				memcpy(udpstrtmp, UDPdata, len);
			}
			
			
			
			int i2 = 0;
			for (int i = 0; i < sizeof(udpstrtmp); i++)
			{
				if (udpstrtmp[i] < 128 && udpstrtmp[i] > -1)
				{
					udpstrtmp2[i2] = udpstrtmp[i];
					i2++;
				}
			}

			memset(udpstrtmp, '\0', sizeof(udpstrtmp));
			memcpy(udpstrtmp, udpstrtmp2, sizeof(udpstrtmp2));

			// check if fragment offset > 0 and previous packet exists
			if (ip_fragment_offset > 0)
			{
				string content_old = "";
   			try 
				{
      			content_old = sip_fragment.at(ip_identification);
   			} catch(const out_of_range &e) 
				{
					cout << "\nException at " << e.what() << endl;
					printf("\n===================================================================================\n");
					cout << "\nip identification:" << ip_identification;
					printf("\nip flags:%d", ip_flags);
					printf("\nip_fragment_offset:%d", ip_fragment_offset);
					printf("\nip len:%d", ip_len);
					printf("\nip proto:%d", ip_proto);
					printf("\ntlen:%d", tlen);
					printf("\nlen:%d", len);
					
				
					
					//printf ("\n===== udpstrtmp ==========================================================================\n");
					//for(int i = 0; i < 200; i++)
					//{
					//	printf("%02x ", udpstrtmp[i]);
					//}
      	
   			}


				//sip_fragment.erase(ip_identification);
				string content_tmp = content_old + string(udpstrtmp);
				memset(udpstrtmp, '\0', sizeof(udpstrtmp));
				strcpy(udpstrtmp, content_tmp.c_str());

				//printf ("\n===== udpstrtmp when more fragments ======================================================\n");
				//printf ("\n%s", udpstrtmp);
				//printf ("\n===== udpstrtmp ==========================================================================\n");
				//for(int i = 0; i < 2000; i++)
				//{
				//	printf("%02x ", udpstrtmp[i]);
				//}
      	
			}

			char *callid = extractheader(udpstrtmp, (char *)"\nCall-ID:");
			char callid_escaped[200];
			memset(callid_escaped, '\0', sizeof(callid_escaped));

			string callidstring(callid);
			u_int callid_len = callidstring.size();
			if (callid_len > 5)
			{
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

				char *content_escaped = new char[10001];
				memset(content_escaped, '\0', sizeof(content_escaped));
				if (use_database == true)
				{
					int result = mysql_real_escape_string(conn, content_escaped, udpstrtmp, strlen(udpstrtmp));
					result = mysql_real_escape_string(conn, callid_escaped, callid, strlen(callid));
				}
				else
				{
					memcpy(content_escaped, udpstrtmp, sizeof(udpstrtmp));
				}

				string content(content_escaped);
				delete content_escaped;

				if (use_database == true)
				{
					if (query_counter == 0)
					{
						query_part2 = "('" + string(callid_escaped) + "', '" + datetime + "', '" + srcip + "', '" + srcport + "', '" + dstip + "', '" + dstport + "', '" + content + "')";
					}
					else
					{
						query_part2 = query_part2 + ", " + "('" + string(callid_escaped) + "', '" + datetime + "', '" + srcip + "', '" + srcport + "', '" + dstip + "', '" + dstport + "', '" + content + "')";
					}

					query_counter++;

					if (query_counter > 10)
					{

						string query_part123 = query_part1 + query_part2 + query_part3;

						int query_part123_size = query_part123.length();
						char *query = new char[query_part123_size + 1];
						memset(query, 0, sizeof(query));
						strcpy(query, query_part123.c_str());

						MYSQL_RES *result;
						result = mysql_perform_query(conn, query);

						if (*mysql_error(conn))
						{

							printf("\n** ERROR BEGIN ********************************************************************************************************************************************************************************************\n");
							printf("\n******\nmysql-error:%s\n", result);
							printf("\n******\nquery:%s\n", query);
							printf("\n******\nquerypart123:%s\n", query_part123.c_str());
							printf("\n*************************************************\n");
							printf("\n******\ncontent:%s\n", content.c_str());
							printf("\n*************************************************\n");
							printf("\n******\nCall-ID:%s\n", callid_escaped);
							printf("\n*************************************************\n");

							printf("\n** ERROR END ********************************************************************************************************************************************************************************************\n");
							/*
							 */
							mysqlpresent = false;
							exit(1);
						}
						else

							for (; mysql_next_result(conn) == 0;)
								mysql_free_result(result);
						query_counter = 0;
						memset(query, '\0', sizeof(query));
						delete[] query;
						free(result);
					}
				}
			}
			delete callid;
			callid = NULL;
		}
	}
}
