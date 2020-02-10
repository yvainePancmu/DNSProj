#include<stdio.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<string.h>
#include<assert.h>
#include "myfunctions.h"
struct in_addr addr;
struct sockaddr_in client;
struct sockaddr_in *sock;
char buf[300];
char buffer[300];
char* web;
int myip = 0xdcb56fbc;
char *ipp;

struct DNS_RR answer;
struct DNSHeader *h;

char *file(char *bb, int type) {
    char *b = strcat(bb, type_itoa[type]);
    printf("b is %s", b);

    typedef struct address {
        char a1[20];
        char a2[20];
        char a3[20];
        char a4[20];
        char a5[20];
    } add;
    char *ptr[30];
    char *ptr1[30];
    int i = 0;
    ptr[0] = strtok(b, " ");
    ptr[1] = strtok(NULL, " ");
    FILE * r = fopen("4.txt", "r");
    assert(r != NULL);
    add a[128];
    static char ss[50];
    ptr1[0] = strtok(ptr[0], ".");
    ptr1[1] = strtok(NULL, ".");
    ptr1[2] = strtok(NULL, ".");
    printf("%s %s\n", ptr1[1], ptr1[2]);
    char *ssss[10];
    while (fscanf(r, "%s %s %s %s %s", a[i].a1, a[i].a2, a[i].a3, a[i].a4, a[i].a5) != EOF) {
        printf("%s\n", a[i].a1);
        ssss[0] = strtok(a[i].a1, ".");
        printf("%s\n", ssss[0]);
        ssss[1] = strtok(NULL, ".");
        printf("%s\n", ssss[1]);
        if (strcmp(ssss[0], ptr1[1]) == 0 && strcmp(ssss[1], ptr1[2]) == 0) {
            printf("got it!\n");
            strcpy(ss, a[i].a5);
            printf("%s\n", ss);
            break;
        } else
            i++;
    }
    fclose(r);
    return ss;
}

char * NormalDomain(char *s) {
    char *s1 = (char*) malloc(50);
    memcpy(s1, s, strlen(s));
    char *p = s1 + strlen(s) - 1;
    for (; p > s1; p--) {
        if (*p < 20 && *p >= 0)
            *p = '.';
    }
    printf("the normal domain name is %s\n", s1);
    return s1;
}

void initAnswer(struct DNS_RR *rr, int type) {
    if (flag == 0) {
        rr->type = 2;
        rr->myclass = 1;
        rr->ttl = 0x63;
        rr->data_len = 5;
        rr->cname = "\x02ns\x04root\x06server"; //�˴�ÿ�������������ֲ�һ�� 

        rr->rdata = ip_atoi(ipp);
    } else {
        if (type == 1) {
            rr->type = 1;
            rr->myclass = 1;
            rr->ttl = 0x63;
            rr->data_len = 4;
            rr->rdata = myip;
        }
        if (type == 5) {
            rr->type = 5;
            rr->myclass = 1;
            rr->ttl = 0x63;
            rr->data_len = 9;
            rr->cname = "qiandu"; //�˴���Ҫ�ĳɻ������ 
        }
        if (type == 15) {
            rr->type = 15;
            rr->myclass = 1;
            rr->ttl = 0x63;
            rr->data_len = 9;
            rr->cname = "mail"; //�˴�ǰ׺�������mail��Ҫ�ĳ��� 
            rr->pre = 6;
            rr->rdata = myip;
        }
        if (type == 12) {
            rr->type = 12;
            rr->myclass = 1;
            rr->ttl = 0x63; //�˴����Ȳ��̶� 
            rr->data_len = 11;
            rr->cname = "\x03www\x02qq\x03net";

        }
    }
}

void initHeader(struct DNSHeader *header, int type) {
    if (flag == 0) {
        header->id = 11;
        header->tag = 0x100;
        header->queryCount = 1;
        header->answerCount = 0;
        header->autCount = 1;
        header->URL_a = web;
        header->queryClass = 1;
        header->queryType = 2; //NS
        header->addCount = 1;
    } else {
        header->id = 11;
        header->tag = 0x100;
        header->queryCount = 1;
        header->answerCount = 1;
        header->autCount = 0;

        header->URL_a = web;
        header->queryClass = 1;
        if (type == 1) {
            header->queryType = 1;
            header->addCount = 0;
        } //A
        if (type == 5) {
            header->queryType = 5; //CNAME
            header->addCount = 0;
        }
        if (type == 15) {
            header->queryType = 15; //CNAME
            header->addCount = 1;
        }
        if (type == 12) {
            header->queryType = 12;
            header->addCount = 0;
        }
    }

}

int main() {
    struct sockaddr_in s1;
    sock = &s1;
    int s = socket(PF_INET, SOCK_DGRAM, 0);
    unsigned short p = 53;
    if (s < 0)
        printf("create error\n");
    memset(sock, 0, sizeof (*sock));
    sock->sin_family = AF_INET;
    sock->sin_port = htons(p);
    sock->sin_addr.s_addr = inet_addr("127.0.0.3");
    if (bind(s, (struct sockaddr*) sock, sizeof (*sock)) < 0)
        printf("bind error\n");
    printf("waiting for data\n");
    while (1) {
        unsigned int len = sizeof (client);
        int size = recvfrom(s, buf, 299, 0, (struct sockaddr*) &client, &len);
        h = ArraytoDNSHeader(buf); //�ڴ�֮�������query���� 
        printf("tag is %d\n", h->tag);
        web = h->URL_a;
        char * normalweb = NormalDomain(web);
        ipp = file(normalweb, h->queryType);
        reverseDomain(web);
        printf("the domain name is %s\n", web);
        printf("the address of client is %s\n", inet_ntoa(client.sin_addr));
        initHeader(&header, h->queryType);
        initAnswer(&answer, h->queryType);
        MyPart(web);
        int size2 = DNSAnswer_toArray(buffer, &header, &answer, h->queryType);
        printf("the ip you require is %s", ipp);
        if (sendto(s, buffer, size2, 0, (struct sockaddr*) &client, sizeof (client)))
            printf("ok\n");
        memset(buffer, 0, sizeof (buffer));
        memset(buf, 0, sizeof (buf));
    }
    getchar();
    return 0;
}


