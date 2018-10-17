#define HAVE_REMOTE
#define LINE_LEN 16
#include <pcap.h>

int max = 0, komunikacia_number = 0;

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);
int vsetky_ramce(u_char **ip, char socket_name[], int *bajts);

int uniq_elements(u_char **arr, int n, int *bajts) {
	for (int i = 0; i < n; i++) {
		for (int j = i + 1; j < n; j++) {

			if (
				arr[j][0] == arr[i][0] &&
				arr[j][1] == arr[i][1] &&
				arr[j][2] == arr[i][2] &&
				arr[j][3] == arr[i][3]) {

				for (int x = j; x < n - 1; x++) {
					arr[x][0] = arr[x + 1][0];
					arr[x][1] = arr[x + 1][1];
					arr[x][2] = arr[x + 1][2];
					arr[x][3] = arr[x + 1][3];
					bajts[x] = (bajts[x] > bajts[x + 1]) ? bajts[x] : bajts[x + 1];
				}
				n--;
			}
			if (
				arr[j][0] == arr[i][0] &&
				arr[j][1] == arr[i][1] &&
				arr[j][2] == arr[i][2] &&
				arr[j][3] == arr[i][3])
				j--;
		}
	}

	return n;
}

int arp(const u_char *pkt_data) {
	komunikacia_number++;
	if (pkt_data[12] == 0x08 && pkt_data[13] == 0x06) {
		//ARP protocol

		if (pkt_data[21] == 1) {
			printf("Komunikacia #%d: \n", komunikacia_number);
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

	return 0;
}

int icmp(const u_char *pkt_data) {
	if (pkt_data[23] == 1) {
		//ICMP
		printf("ICMP: ");

		//34
		switch (pkt_data[34]) {
		case 0: printf("Echo Reply"); break;
		case 3: printf("Destination Unreachable ");
			switch (pkt_data[35]) {
			case 0: printf("Net Unreachable"); break;
			case 1: printf("Host Unreachable"); break;
			case 2: printf("Protocol Unreachable"); break;
			case 3: printf("Port Unreachable"); break;
			case 4: printf("Fragmentation Needed & DF Set"); break;
			case 5: printf("Source Route Failed"); break;
			case 6: printf("Destination Network Unknown"); break;
			case 7: printf("Destination Host Unknown"); break;
			case 8: printf("Source Host Isolated"); break;
			case 9: printf("Network Administratively Prohibited"); break;
			case 10: printf("Host Administratively Prohibited"); break;
			case 11: printf("Network Unreachable for TOS"); break;
			case 12: printf("Host Unreachable for TOS"); break;
			case 13: printf("Communication Administratively Prohibited"); break;
			}
			break;
		case 4: printf("Source Quench"); break;
		case 5: printf("Redirect");
			switch (pkt_data[35]) {
			case 0: printf("Redirect Datagram for the Network"); break;
			case 1: printf("Redirect Datagram for the Host"); break;
			case 2: printf("Redirect Datagram for the TOS & Network"); break;
			case 3: printf("Redirect Datagram for the TOS & Host"); break;
			}
			break;
		case 8: printf("Echo"); break;
		case 9: printf("Router Advertisement"); break;
		case 10: printf("Router Selection"); break;
		case 11: printf("Time Exceeded"); break;
			switch (pkt_data[35]) {
			case 0: printf("Time to Live exceeded in Transit"); break;
			case 1: printf("Fragment Reassembly Time Exceeded"); break;
			}
			break;
		case 12: printf("Parameter Problem");
			switch (pkt_data[35]) {
			case 0: printf("Pointer indicates the error"); break;
			case 1: printf("Missing a Required Option"); break;
			case 2: printf("Bad Length"); break;
			}
			break;
		case 13: printf("Timestamp"); break;
		case 14: printf("Timestamp Reply"); break;
		case 15: printf("Information Request"); break;
		case 16: printf("Information Reply"); break;
		case 17: printf("Address Mask Request"); break;
		case 18: printf("Address Mask Reply"); break;
		case 30: printf("Tracerouter"); break;
		}
		printf("\n");
	}

	return 0;
}

int type(const u_char *pkt_data) {
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

	return 0;
}

int mac(const u_char *pkt_data) {
	printf("Zdrojova MAC adresa: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		pkt_data[6],
		pkt_data[7],
		pkt_data[8],
		pkt_data[9],
		pkt_data[10],
		pkt_data[11]
	);

	printf("\n");

	printf("Cielova MAC adresa: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		pkt_data[0],
		pkt_data[1],
		pkt_data[2],
		pkt_data[3],
		pkt_data[4],
		pkt_data[5]
	);

	printf("\n");

	return 0;
}

int write_ip(const u_char *pkt_data, u_char **ip, int index, int header_length, int *bajts) {
	if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00) {
		ip[index][0] = pkt_data[26];
		ip[index][1] = pkt_data[27];
		ip[index][2] = pkt_data[28];
		ip[index][3] = pkt_data[29];

		bajts[index] = header_length;
	}
	if (pkt_data[12] == 0x08 && pkt_data[13] == 0x06) {
			ip[index][0] = pkt_data[28];
			ip[index][1] = pkt_data[29];
			ip[index][2] = pkt_data[30];
			ip[index][3] = pkt_data[31];

			bajts[index] = header_length;
	}

	if (bajts[index] > max)
		max = bajts[index];

	return 0;
}

int udp(const u_char *pkt_data) {
	if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00 && pkt_data[23] == 17) {
		//	37 38

		if ((pkt_data[36] * 16 * 16 + pkt_data[37]) == 69) {
			printf("UDP\nTFTP\n");
		}
	}

	return 0;
}

int ipv4(const u_char *pkt_data) {
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
		case 20: printf("FTP-data"); break;
		case 21: printf("FTP-control"); break;
		case 22: printf("SSH"); break;
		case 23: printf("TELNET"); break;
		case 80: printf("HTTP"); break;
		case 443: printf("HTTPS (SSL)"); break;
		default: printf("%d", port); break;
		}
	}

	printf("\n\n");

	return 0;
}

int print_packet(const u_char *pkt_data, int header_cap_length) {
	for (int i = 1; (i < header_cap_length + 1); i++)
	{
		printf("%.2x ", pkt_data[i - 1]);
		if (i % 8 == 0)
			printf(" ");
		if ((i % LINE_LEN) == 0) printf("\n");
	}
	printf("\n\n");

	printf("\n");

	return 0;
}

int print_ip(const u_char *pkt_data, u_char **ip, int index, int *bajts) {
	printf("IP:\n");
	for (int i = 0; i < index; i++) {
		printf("#%d   %d.%d.%d.%d %d bajtov\n",
			i + 1,
			ip[i][0],
			ip[i][1],
			ip[i][2],
			ip[i][3],
			bajts[i]
		);
	}
	if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00)
	{
		printf("\nAdresa uzla s najvacsim poctom odvysielanych bajtov:\n");
		max = 0;
		for (int i = 0; i < index; i++) {
			if (bajts[i] > max)
				max = bajts[i];
		}
		for (int i = 0; i < index; i++) {
			if (bajts[i] == max)
				printf("#%d   %d.%d.%d.%d    %d bajtov\n",
					i + 1,
					ip[i][0],
					ip[i][1],
					ip[i][2],
					ip[i][3],
					bajts[i]
				);
		}
	}

	return 0;
}

int number_and_length_of_socket(int index, int header_length) {

	printf("ramec %d.\n", index + 1);
	printf("dlzka ramca poskytnuta pcap API:   %ld\n", header_length);
	printf("dlzka ramca prenasaneho po mediu:  %ld\n", header_length + 4);

	return 0;
}

void print_menu() {

	printf("List of commands: \n");
	printf("a - HTTP\n");
	printf("b - HTTPS\n");
	printf("c - TELNET\n");
	printf("d - SSH\n");
	printf("e - FTP riadiace\n");
	printf("f - FTP datove\n");
	printf("g - Vsetky TFTP\n");
	printf("h - Vsetky ICMP\n");
	printf("i - Vsetky ARP dvojice (request  - reply)\n\n");

	printf("x - !!!Close program!!!\n");

	printf("\n");
}

int select_command(char socket_name[], u_char **ip, int bajts[]) {
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *fp = pcap_open_offline(socket_name, errbuf);
	char command = '0';
	int res;
	int protocol = 0;


	int index = 0;

		printf("\n\n");
		index = 0;

		while (command != 'x') {

			freopen("CON", "w", stdout);
			printf("Enter command: ");
			freopen("output.txt", "a", stdout);
			scanf(" %c", &command);

			switch (command) {
			case 'a': protocol = 80; printf("HTTP:\n\n"); break;
			case 'b': protocol = 443; printf("HTTPS (SSL):\n\n"); break;
			case 'c': protocol = 23; printf("TELNET:\n\n"); break;
			case 'd': protocol = 22; printf("SSH:\n\n"); break;
			case 'e': protocol = 21; printf("FTP-CONTROL:\n\n"); break;
			case 'f': protocol = 20; printf("FTP-DATA:\n\n"); break;
			case 'g': protocol = 69; printf("TFTP:\n\n"); break;
			case 'h': printf("ICMP:\n\n"); break;
			case 'i': printf("ARP:\n\n"); break;
//			case 'j': index = vsetky_ramce(ip, socket_name, bajts); break;
			}

			int port;

			while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
			{
				if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00 && pkt_data[23] == 0x06) {
					//if ipv4 and tcp
					port = pkt_data[36] * 16 * 16 + pkt_data[37];
					if (port == protocol) {
						number_and_length_of_socket(index, header->len);
						type(pkt_data);
						ipv4(pkt_data);
						print_packet(pkt_data, header->caplen);
					}
				}
				if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00 && pkt_data[23] == 17) {
					//if ipv4 and udp and TFTP
					port = pkt_data[34] * 16 * 16 + pkt_data[35];
					if (port == protocol) {
						number_and_length_of_socket(index, header->len);
						printf("Source Port: %d\n", port);
						printf("Destination Port: %d\n", pkt_data[36] * 16 * 16 + pkt_data[37]);
						type(pkt_data);
						ipv4(pkt_data);
						print_packet(pkt_data, header->caplen);
					}
				}
				if (pkt_data[12] == 0x08 && pkt_data[13] == 0x06 && command == 'i') {
					//if ARP
						number_and_length_of_socket(index, header->len);
						arp(pkt_data);
						type(pkt_data);
						ipv4(pkt_data);
						print_packet(pkt_data, header->caplen);
				}
				if (pkt_data[12] == 0x08 && pkt_data[13] == 0x00 && pkt_data[23] == 1 && command == 'h') {
					//if ICMP
					number_and_length_of_socket(index, header->len);
					icmp(pkt_data);
					type(pkt_data);
					ipv4(pkt_data);
					print_packet(pkt_data, header->caplen);
				}
				index++;
			}
			pcap_close(fp);
			fp = pcap_open_offline(socket_name, errbuf);
		}


	index = vsetky_ramce(ip, socket_name, bajts);
	return index;
}

int vsetky_ramce(u_char **ip, char socket_name[], int bajts[]) {
	char errbuf[PCAP_ERRBUF_SIZE], source[PCAP_BUF_SIZE];
	pcap_t *fp = pcap_open_offline(socket_name, errbuf);
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i = 0;
	int res, index = 0;

	printf("All the packets:\n\n");

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		//ARP dvoice
		arp(pkt_data);

		//ICMP
		icmp(pkt_data);

		//number and length of socket
		number_and_length_of_socket(index, header->len);

		//type	
		type(pkt_data);

		//MAC address
		mac(pkt_data);

		//write IP
		write_ip(pkt_data, ip, index, header->len, bajts);

		//UDP
		udp(pkt_data);

		//ipv4, tcp
		ipv4(pkt_data);

		// print the packet
		print_packet(pkt_data, header->caplen);

		index++;
	}

	return index;
}

int start_analize(char socket_name[]) {
	char errbuf[PCAP_ERRBUF_SIZE], source[PCAP_BUF_SIZE];
	pcap_t *fp;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i = 0;
	int res, index = 0, komunikacia_number = 1;

	//create ip array
	fp = pcap_open_offline(socket_name, errbuf);
	if (fp == NULL) return 0;
	u_char **ip;

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
		index++;

	ip = (u_char**)malloc(index * sizeof(u_char*));
	for (int i = 0; i < index; i++) {
		ip[i] = (u_char*)malloc(5 * sizeof(u_char));
	}

	int *bajts = (int*)malloc(index * sizeof(int));

	printf("Package of %d ramcov\n\n", index);

	pcap_close(fp);

	fp = pcap_open_offline(socket_name, errbuf);
	index = 0;

	//select command what to print
	index = select_command(socket_name, ip, bajts);

	//delete repeating ips
	index = uniq_elements(ip, index, bajts);

	//print ips
	print_ip(pkt_data, ip, index, bajts);
}

int main() {
	printf("Results will be written to file \"output.txt\"\n");
	printf("After closing the program all the sockets will be printed.\n");
	print_menu();

	freopen("output.txt", "w", stdout);

	start_analize("pcap/eth-2.pcap");

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
