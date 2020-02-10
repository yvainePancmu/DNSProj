#include<stdio.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<string.h>
#include<assert.h>

#ifndef MYFUNCTIONS_H
#define MYFUNCTIONS_H
int first, second, third, flag = 0;
struct DNSHeader header;
char *ptr;

void MyPart(char *s) {
    int a[3];
    char *start = s;
    int i = 0;
    for (start = s; start < s + strlen(s); start++) {

        if (*start < 20 && *start >= 0) {
            a[i] = *start;
            i++;
        }
    }
    first = a[0] + 1;
    second = a[1] + 1;
    third = a[2] + 1;
    printf("%d %d %d", first, second, third);
}

unsigned int ip_atoi(char* inarr) {
    char* arr = malloc(strlen(inarr) + 1);
    memcpy(arr, inarr, strlen(inarr) + 1);
    int last = 0;
    unsigned int result = 0;
    unsigned int offset = 0x1000000;
    int i = 0;
    int p = strlen(arr);

    for (; i < p; i++) {
        if (arr[i] == '.') {
            arr[i] = 0;

            int m = atoi(arr + last) * offset;
            printf("%x\n", m);
            result += m;
            offset /= 0x100;
            last = i + 1;
        }
    }

    result += atoi(arr + last) * offset;
    free(arr);
    return result;
}
char *type_itoa[] = {"", " A", "2", "3", "4", " CNAME", "6", "7", "8",
    "9", "10", "11", "12", "13", "14", " MX"};

struct DNSHeader {
    unsigned short id;
    unsigned short tag;
    unsigned short queryCount;
    unsigned short answerCount;
    unsigned short autCount;
    unsigned short addCount;


    char *URL_a;
    unsigned short queryType;
    unsigned short queryClass;
};

struct DNS_RR {
    //unsigned char *name; 
    unsigned short type;
    unsigned short myclass;
    unsigned int ttl;
    unsigned short data_len;
    //	unsigned char *rdata; 
    unsigned int rdata;
    char *ip;
    unsigned short pre;
    unsigned char* cname;
    unsigned char* mx;
    char* name;
};

struct DNSHeader* ArraytoDNSHeader(char *input) {
    struct DNSHeader *h = (struct DNSHeader*) malloc(sizeof (struct DNSHeader));
    char * data = input;
    h->id = ntohs(*(unsigned short*) data);
    data += 2;
    h->tag = ntohs(*(unsigned short*) data);
    data += 2;
    h->queryCount = ntohs(*(unsigned short*) data);
    data += 2;
    h->answerCount = ntohs(*(unsigned short*) data);
    data += 2;
    h->autCount = ntohs(*(unsigned short*) data);
    data += 2;
    h->addCount = ntohs(*(unsigned short*) data);
    data += 2;
    h->URL_a = malloc(50);
    memcpy(h->URL_a, data, strlen(data) + 1);
    data += strlen(data) + 1;
    h->queryType = ntohs(*(unsigned short*) data);
    data += 2;
    h->queryClass = ntohs(*(unsigned short*) data);
    data += 2;


    return h;
}

int DNSAnswer_toArray(char* indata, struct DNSHeader *header, struct DNS_RR *rr, int type) { // query��answerһ��Ž�buf 
    // indata = (char*)malloc(sizeof(unsigned short) * 6);

    char * data = indata;
    *((unsigned short*) data) = htons(header->id);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->tag);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->queryCount);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->answerCount);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->autCount);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->addCount);
    data = data + sizeof (unsigned short);



    char *baidu = data;
    memcpy(data, header->URL_a, strlen(header->URL_a) + 1);
    data = data + strlen(header->URL_a) + 1;
    *((unsigned short*) data) = htons(header->queryType);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->queryClass);
    data = data + sizeof (unsigned short);

    // memcpy(data,rr->name,strlen(rr->name));
    *((unsigned short*) data) = htons(baidu - indata + 0xc000);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(rr->type);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(rr->myclass);
    data = data + sizeof (unsigned short);
    *((unsigned int*) data) = htons(rr->ttl);
    data = data + sizeof (unsigned int);
    if (flag == 0) {
        *((unsigned short*) data) = htons(rr->data_len);
        data = data + sizeof (unsigned short);
        char *dns = data;
        memcpy(data, "\x02ns", 3);
        data += 3;
        *((unsigned short*) data) = htons(baidu - indata + 0xc000);
        data = data + sizeof (unsigned short);
        //memcpy(data,"\x02ns\x04root\x06server",15);
        //data+=15;
        *((unsigned short*) data) = htons(dns - indata + 0xc000);
        data = data + sizeof (unsigned short);
        *((unsigned short*) data) = htons(1); //A
        data = data + sizeof (unsigned short);
        *((unsigned short*) data) = htons(1); //IN
        data = data + sizeof (unsigned short);
        *((unsigned int*) data) = htons(rr->ttl);
        data = data + sizeof (unsigned int);
        *((unsigned short*) data) = htons(4); //data length
        data = data + sizeof (unsigned short);
        *((unsigned int*) data) = htonl(rr->rdata);
        data = data + 4;
        return data - indata;
    } else {
        if (type == 12) {
            *((unsigned short*) data) = htons(rr->data_len);
            data = data + sizeof (unsigned short);
            memcpy(data, rr->cname, rr->data_len);
            data = data + strlen(rr->cname);
            return data - indata;
        }
        if (type == 15) {
            *((unsigned short*) data) = htons(rr->data_len);
            data = data + sizeof (unsigned short);
            *((unsigned short*) data) = htons(rr->pre);
            data = data + sizeof (unsigned short);
            char *second = data;
            *data = strlen(rr->cname);
            data = data + 1;
            memcpy(data, rr->cname, strlen(rr->cname));
            data = data + strlen(rr->cname);
            *((unsigned short*) data) = htons(baidu - indata + 0xc000);
            data = data + sizeof (unsigned short);
            //Additional part
            *((unsigned short*) data) = htons(second - indata + 0xc000);
            data = data + sizeof (unsigned short);
            *((unsigned short*) data) = htons(1); //type
            data = data + sizeof (unsigned short);
            *((unsigned short*) data) = htons(rr->myclass);
            data = data + sizeof (unsigned short);
            *((unsigned int*) data) = htons(rr->ttl);
            data = data + sizeof (unsigned int);
            *((unsigned short*) data) = htons(4); //datalength
            data = data + sizeof (unsigned short);
            *((unsigned int*) data) = htonl(rr->rdata);
            data = data + 4;
            return data - indata;
        }
        if (type == 5) {
            *((unsigned short*) data) = htons(rr->data_len);
            data = data + sizeof (unsigned short);
            char *end = baidu + first;

            *data = strlen(rr->cname);
            data = data + 1;
            memcpy(data, rr->cname, rr->data_len);
            data = data + strlen(rr->cname);
            *((unsigned short*) data) = htons(end - indata + 0xc000);
            data = data + sizeof (unsigned short);
            return data - indata;
        }
        if (type == 1) {
            *((unsigned short*) data) = htons(rr->data_len);
            data = data + sizeof (unsigned short);
            *((unsigned int*) data) = htonl(rr->rdata);
            data = data + 4;
            return data - indata;
        }
    }
}

int DNSHeader_toArray(char* indata, struct DNSHeader *header, int type) { //indata��ʵ��outdata 
    // indata = (char*)malloc(sizeof(unsigned short) * 6);
    char * data = indata;
    *((unsigned short*) data) = htons(0);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->id);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->tag);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->queryCount);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->answerCount);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->autCount);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->addCount);
    data = data + sizeof (unsigned short);

    memcpy(data, header->URL_a, strlen(header->URL_a) + 1);
    data = data + strlen(header->URL_a) + 1;
    if (type == 4) {
        memcpy(data, ptr, strlen(ptr));
        data += strlen(ptr) + 1;
    }
    *((unsigned short*) data) = htons(header->queryType);
    data = data + sizeof (unsigned short);
    *((unsigned short*) data) = htons(header->queryClass);
    data = data + sizeof (unsigned short);
    //  tcplength=data-indata;
    *(unsigned short*) indata = htons((unsigned short) (data - indata - 2));
    return data - indata;

}

char* parseWeb(char* input) {

    char* output = (char*) malloc(50);
    memcpy(output + 1, input, strlen(input) + 1);
    char* e = output + strlen(input);
    int i = 0;
    for (; e > output; e--) {
        if (*e != '.') {
            i++;
        } else {
            *e = i;
            i = 0;
        }
    }
    // strend == parsed
    *e = i;
    return output;
}

char *reverseDomain(char * input) {
    char * output = (char*) malloc(strlen(input));
    char * i = input;
    char * j = output;
    char** d = (char**) malloc(sizeof (char*)*4);
    int d1 = 1;
    d[0] = input - 1;
    for (; i < input + strlen(input); i++) {
        if (*i == '.') {
            d[d1] = i;
            d1++;
        }
    }
    int i = 3;
    for (; i >= 0; i--) {
        i = d[i] + 1;
        while (*i != '.' && *i != '\0') {
            *j = *i;
            j++;
            i++;
        }
        *j = '.';
        j++;
    }
    j--;
    *j = '\0';
    return output;
}

struct DNS_RR* ArraytoDNSAnswer(char *input, int type) {
    struct DNS_RR *r = (struct DNS_RR*) malloc(sizeof (struct DNS_RR));
    struct DNSHeader *h = (struct DNSHeader*) malloc(sizeof (struct DNSHeader));
    char * data = input;
    data += 2;
    h->id = ntohs(*(unsigned short*) data);
    data += 2;
    h->tag = ntohs(*(unsigned short*) data);
    data += 2;
    h->queryCount = ntohs(*(unsigned short*) data);
    data += 2;
    h->answerCount = ntohs(*(unsigned short*) data);
    data += 2;
    h->autCount = ntohs(*(unsigned short*) data);
    data += 2;
    h->addCount = ntohs(*(unsigned short*) data);
    data += 2;
    h->URL_a = malloc(50);
    memcpy(h->URL_a, data, strlen(data) + 1);
    data += strlen(data) + 1;
    h->queryType = ntohs(*(unsigned short*) data);
    data += 2;
    h->queryClass = ntohs(*(unsigned short*) data);
    data += 4;


    r->type = ntohs(*(unsigned short*) data);
    data += 2;
    r->myclass = ntohs(*(unsigned short*) data);
    data += 2;
    r->ttl = ntohl(*(unsigned int*) data);
    data += 4;
    r->data_len = ntohs(*(unsigned short*) data);
    data += 2;
    if (h->answerCount == 0) {
        data += r->data_len;
        data += 12;
        struct in_addr a;
        unsigned int ip = (*(unsigned int*) data);
        a.s_addr = ip;
        r->ip = inet_ntoa(a);
    } else {
        if (type == 1) {
            struct in_addr a;
            unsigned int ip = (*(unsigned int*) data);
            a.s_addr = ip;
            r->ip = inet_ntoa(a);

        }
        if (type == 2) {
            data += 1;
            r->cname = (char*) malloc(40);
            r->name = (char*) malloc(40);
            char *s = (char*) malloc(10);
            memcpy(r->cname, data, r->data_len - 3);
            data += r->data_len - 3;
            memcpy(s, data, 2);
            data = input + *(s + 1);
            memcpy(r->name, data, strlen(header.URL_a) + 1);
        }
        if (type == 3) {
            r->pre = ntohs(*(unsigned short*) data);
            data += 2;
            r->mx = (char*) malloc(50);
            memcpy(r->mx, data, r->data_len - 4);
            data += r->data_len - 4;
            data += 14;
            struct in_addr a;
            unsigned int ip = (*(unsigned int*) data);
            a.s_addr = ip;
            r->ip = inet_ntoa(a);
        }
    }
    return r;
}

#endif

