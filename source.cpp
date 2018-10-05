#define HAVE_REMOTE
#define LINE_LEN 16
#include <pcap.h>

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);

u_char *write(u_int begin, u_int end, const u_char *arr) {


	u_char *str = (u_char*)malloc((end - begin) * sizeof(u_char));
	for (u_int i = begin; i < end; i++) {
		str[i] = arr[i];
	}

	return str;
}

void print(char c, u_char *arr) {
	u_int begin, end;

	switch (c) {
		case 'd': printf("Destination address: "); begin = 0; end = 6; break;
		case 's': printf("Source address:      "); begin = 6; end = 12; break;
		case 't': printf("EtherType:           "); begin = 12; end = 14; break;
		default: printf("Stas ty dibil blyat napishi normalnyj kod!!\n");
	}

	for (u_int i = begin; i < end; i++) {
		printf("%.2x ", arr[i]);
	}

	if (end == 14) {
		printf("(");
		if (arr[12] == 2 && arr[13] == 0)
			printf("XEROX PUP");
		if (arr[12] == 2 && arr[13] == 1)
			printf("PUP Addr Trans");
		if (arr[12] == 8 && arr[13] == 0)
			printf("IPv4");
		if (arr[12] == 8 && arr[13] == 1)
			printf("X.75 Internet");
		if (arr[12] == 8 && arr[13] == 5)
			printf("X.25 Level 3");
		if (arr[12] == 8 && arr[13] == 6)
			printf("ARP");
		if (arr[12] == 128 && arr[13] == 53)
			printf("Reverse ARP");
		if (arr[12] == 128 && arr[13] == 155)
			printf("Appletalk");
		if (arr[12] == 128 && arr[13] == 243)
			printf("Appletalk AARP (Kinetics)");
		if (arr[12] == 129 && arr[13] == 0)
			printf("IEEE 802.1Q VLAN-tagged frames");
		if (arr[12] == 129 && arr[13] == 55)
			printf("Novell IPX");
		if (arr[12] == 134 && arr[13] == 221)
			printf("IPv6");
		if (arr[12] == 136 && arr[13] == 11)
			printf("PPP");
		if (arr[12] == 136 && arr[13] == 0x47)
			printf("MPLS");
		if (arr[12] == 0x88 && arr[13] == 0x48)
			printf("MPLS with upstream-assigned label");
		if (arr[12] == 0x88 && arr[13] == 0x63)
			printf("PPPoE Diskovery Stage");
		if (arr[12] == 0x88 && arr[13] == 0x64)
			printf("PPPoE Session Stage");
		if (arr[12] == 0x00 && arr[13] == 0x26)
			printf("LEAF-2");
		if (arr[12] == 0x00 && arr[13] == 0x27)
			printf("RDP");

		if (arr[12] >= 0x05 && arr[13] >= 0xDC)
			printf("Length: %x%x\n", arr[12], arr[13]);


		printf(")\n");
	}

	printf("\n");
}

int main() {
	freopen("output.txt", "w", stdout);

	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i = 0;
	int res;

	fp = pcap_open_offline("trace-6.pcap", errbuf);
	if (fp == NULL) return 0;

//	pcap_loop(fp, 0, dispatcher_handler, NULL);
	int index = 1;

	u_char *das, *ssa, *type;

	while (res = pcap_next_ex(fp, &header, &pkt_data) > 0)
	{
		printf("%d.\n", index);

		/* Print the packet */
		for (i = 1; (i < header->caplen + 1); i++)
		{
			printf("%.2x ", pkt_data[i - 1]);
			if (i % 8 == 0)
				printf(" ");
			if ((i % LINE_LEN) == 0) printf("\n");
		}
		printf("\n\n");

		das = write(0, 6, pkt_data);
		ssa = write(6, 12, pkt_data);
		type = write(12, 14, pkt_data);

		printf("Length: %ld\n", header->len);
		print('d', das);
		print('s', ssa);
		print('t', type);

		printf("\n\n");
		index++;
	}

	return 0;
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
