#define HAVE_REMOTE
#define LINE_LEN 16
#include <pcap.h>

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main() {
	freopen("output.txt", "w", stdout);

	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i = 0;
	int res, max = 0;

	fp = pcap_open_offline("eth-9.pcap", errbuf);
	if (fp == NULL) return 0;
	int index = 0;
	u_char **ip;

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
		index++;

	ip = (u_char**)malloc(index * sizeof(u_char*));
	for (int i = 0; i < index; i++) {
		ip[i] = (u_char*)malloc(5 * sizeof(u_char));
	}

	printf("Package of %d ramcov\n\n", index);

	pcap_close(fp);

	fp = pcap_open_offline("eth-9.pcap", errbuf);
	index = 0;

	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{

		if (pkt_data[12] == 0x08 && pkt_data[13] == 0x06) {
			//ARP protocol

			if (pkt_data[21] == 1) {
				printf("ARP-Request, ");
				printf("IP Adresa: %d.%d.%d.%d, ",
					pkt_data[38],
					pkt_data[39],
					pkt_data[40],
					pkt_data[41]
				);
				printf(" MAC adresa: ???\n");
				printf("Zdrojova IP: %d.%d.%d.%d, ",
					pkt_data[28],
					pkt_data[29],
					pkt_data[30],
					pkt_data[31]
				);
				printf("Cielova IP: %d.%d.%d.%d \n",
					pkt_data[38],
					pkt_data[39],
					pkt_data[40],
					pkt_data[41]
					);
			}
			if (pkt_data[21] == 2) {
				printf("ARP-Reply, ");
				printf("IP Adresa: %d.%d.%d.%d, ",
					pkt_data[28],
					pkt_data[29],
					pkt_data[30],
					pkt_data[31]
				);
				printf(" MAC adresa: %x.%x.%x.%x.%x.%x \n",
					pkt_data[6],
					pkt_data[7],
					pkt_data[8],
					pkt_data[9],
					pkt_data[10],
					pkt_data[11]
				);
				printf("Zdrojova IP: %d.%d.%d.%d, ",
					pkt_data[28],
					pkt_data[29],
					pkt_data[30],
					pkt_data[31]
				);
				printf("Cielova IP: %d.%d.%d.%d \n",
					pkt_data[38],
					pkt_data[39],
					pkt_data[40],
					pkt_data[41]
				);
			}
		}
		if (pkt_data[23] == 1) {
			//ICMP
			
			//34
			switch (pkt_data[34]) {
				case 0: printf("Echo Reply"); break;
				case 3: printf("Destination Unreachable"); break;
				case 4: printf("Source Quench"); break;
				case 5: printf("Redirect"); break;
				case 8: printf("Echo"); break;
				case 9: printf("Router Advertisement"); break;
				case 10: printf("Router Selection"); break;
				case 11: printf("Time Exceeded"); break;
				case 12: printf("Parameter Problem"); break;
				case 13: printf("Timestamp"); break;
				case 14: printf("Timestamp Reply"); break;
				case 15: printf("Information Request"); break;
				case 16: printf("Information Reply"); break;
				case 17: printf("Address Mask Request"); break;
				case 18: printf("Address Mask Reply"); break;
				case 30: printf("Tracerouter"); break;
				default: printf("not found"); break;
			}
			printf("\n");
		}

		printf("ramec %d.\n", index + 1);
/*
		das = write(0, 6, pkt_data);
		ssa = write(6, 12, pkt_data);
		type = write(12, 16, pkt_data);
*/

		printf("dlzka ramca poskytnuta pcap API:   %ld\n", header->len);
		printf("dlzka ramca prenasaneho po mediu:  %ld\n", header->len + 4);
/*
		print('t', type, false);
		print('s', ssa, false);
		print('d', das, false);

		print('t', type, true);
*/

		//here type
		
		if (pkt_data[12] >= 0x05) {
				printf("Ethernet II \n");
		}
		else {
			if (pkt_data[14] == 0xFF && pkt_data[15] == 0xFF) {
				printf("IEEE 802.3 RAW");
			}
			if (pkt_data[15] == 0xAA) {
				printf("IEEE 802.3 LLC + SNAP");
			}
			if (pkt_data[14] != 0xff && pkt_data[15] != 0xff || pkt_data[15] != 0xaa) {
				printf("IEEE 802.3 LLC");
			}
			printf("\n");
		}

		printf("Zdrojova MAC adresa: %.2x %.2x %.2x %.2x %.2x %.2x",
			pkt_data[6],
			pkt_data[7],
			pkt_data[8],
			pkt_data[9],
			pkt_data[10],
			pkt_data[11]
		);

		printf("\n");

		printf("Cielova MAC adresa: %.2x %.2x %.2x %.2x %.2x %.2x",
			pkt_data[0],
			pkt_data[1],
			pkt_data[2],
			pkt_data[3],
			pkt_data[4],
			pkt_data[5]
		);

		printf("\n");

		if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00) {
			ip[index][0] = pkt_data[26];
			ip[index][1] = pkt_data[27];
			ip[index][2] = pkt_data[28];
			ip[index][3] = pkt_data[29];

			ip[index][4] = header->len;

			if (ip[index][4] > max)
				max = ip[index][4];
		}

		if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00 && pkt_data[23] == 17) {
		//	37 38
			
			if ((pkt_data[36] * 16 * 16 + pkt_data[37]) == 69) {
				printf("UDP\nTFTP\n");
			}
		}

		if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00 && pkt_data[23] == 0x06) {
			printf("IPv4\n");
			
			printf("zdrojova IP adresa: %d.%d.%d.%d\n",
				pkt_data[26],
				pkt_data[27],
				pkt_data[28],
				pkt_data[29]
				);
			printf("cielova IP adresa: %d.%d.%d.%d\n",
				pkt_data[30],
				pkt_data[31],
				pkt_data[32],
				pkt_data[33]
			);

			printf("TCP\n");

			int port = pkt_data[36] * 16 * 16 + pkt_data[37];

			printf("zdrojovy port: %d\n", 
				pkt_data[34] * 16 * 16 + pkt_data[35]
			);
			printf("cielovy port: %d\n",
				port
			);


			printf("Port: ");
			switch (port) {
				case 20: printf("ftp-data"); break;
				case 21: printf("ftp-control"); break;
				case 22: printf("ssh"); break;
				case 23: printf("telnet"); break;
				case 80: printf("http"); break;
				case 443: printf("https (ssl)"); break;
				default: printf("not found"); break;
			}
		}
		

		printf("\n\n");

		/* Print the packet */
		for (i = 1; (i < header->caplen + 1); i++)
		{
			printf("%.2x ", pkt_data[i - 1]);
			if (i % 8 == 0)
				printf(" ");
			if ((i % LINE_LEN) == 0) printf("\n");
		}
		printf("\n\n");

		printf("\n");
		index++;
	}

	printf("IP:\n");
	for (int i = 0; i < index; i++) {
		printf("#%d   %d.%d.%d.%d\n",
			i + 1,
			ip[i][0],
			ip[i][1],
			ip[i][2],
			ip[i][3]
		);
	}
	if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00)
	{
		printf("\nAdresa uzla s najvacsim poctom odvysielanych bajtov:\n");
		for (int i = 0; i < index; i++) {
			if (ip[i][4] == max)
				printf("#%d   %d.%d.%d.%d    %d bajtov\n",
					i + 1,
					ip[i][0],
					ip[i][1],
					ip[i][2],
					ip[i][3],
					ip[i][4]
				);
		}
	}

	return 1;
}

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	u_int i = 0;

	/*
	 * Unused variable
	 */
	(VOID)temp1;

	/* print pkt timestamp and pkt len */
	printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

	/* Print the packet */
	for (i = 1; (i < header->caplen + 1); i++)
	{
		printf("%.2x ", pkt_data[i - 1]);
		if ((i % LINE_LEN) == 0) printf("\n");
	}

	printf("\n\n");
}
