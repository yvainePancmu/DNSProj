#include<stdio.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<string.h>
#include<assert.h>
struct in_addr addr;
struct sockaddr_in client;
struct sockaddr_in *sock;
char buf[300];
char buffer[300];
char* web;
char *typebook[]= {""," A","2","3","4"," CNAME","6","7","8","9","10","11","12","13","14"," MX"};
int first,second,third,flag=0;
struct DNSHeader
{
    unsigned short id;
    unsigned short tag;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;


    char *web;
    unsigned short qtype;
    unsigned short qclass;
};
struct DNS_RR
{
//unsigned char *name;
    unsigned short type;
    unsigned short iclass;
    unsigned int ttl;
    unsigned short data_len;
    //	unsigned char *rdata;
    unsigned int rdata;
    unsigned short pre;
    unsigned char* cname;
};
int myip=0xdcb56fbc;
char *ipp;
struct DNSHeader header;
struct DNS_RR answer;
struct DNSHeader *h;

void Segement(char *s)
{
    int a[3];
    char *start=s;
    int i=0;
    for(start=s; start<s+strlen(s); start++)
    {

        if(*start<20&&*start>=0)
        {
            a[i]=*start;
            i++;
        }
    }
    first=a[0]+1;
    second=a[1]+1;
    third=a[2]+1;
    printf("%d %d %d",first,second,third);
}
char *reverDomain(char * orig)
{
    char *buffer=(char*)malloc(strlen(orig));
    char *reading=orig+strlen(orig);
    char *last=reading;
    char *writing=buffer;
    reading--;
    for(; reading>=orig; reading--)
    {
        if(*reading<' '||*reading>=0||*reading=='.')
        {
            memcpy(writing,reading,last-reading);
            writing+=last-reading;
            last=reading;
        }
    }
    *writing=0;
    printf("the rever domian name is %s\n",buffer);
    return buffer;
}
char *file(char *bb,int type)
{
    char *b=strcat(bb,typebook[type]);
    typedef struct address
    {
        char a1[20];
        char a2[20];
        char a3[20];
        char a4[20];
        char a5[20];
    } add;
    char *ptr[30];
    char *ptr1[30];
    int i=0;
    int j=0;
    ptr[0]=strtok(b," ");
    ptr[1]=strtok(NULL," ");
    FILE * r=fopen("3.txt","r");
    FILE * r1=fopen("3a.txt","a");
    assert(r!=NULL);
    add a[128];
    static char ss[50];
    ptr1[j]=strtok(ptr[0],".");
    printf("%s\n",ptr1[j]);
    for(j=0; j<2; j++)
    {
        ptr1[j]=strtok(NULL,".");
        printf("%s\n",ptr1[j]);
    }
    while(fscanf(r,"%s %s %s %s %s",a[i].a1,a[i].a2,a[i].a3,a[i].a4,a[i].a5)!=EOF)
    {
        if(strcmp(a[i].a1,ptr1[1])==0)
        {
            printf("got it!");
            strcpy(ss,a[i].a5);
            printf("%s\n",ss);
            fprintf(r1,"%s %s %s\n",bb,a[i].a4,a[i].a5);
            break;
        }
        else
        {
            //if(i==3){
            //printf("the domain name you input is not exist!!!!\n");
            //		exit(0);
            //	}
            i++;
        }
    }
    fclose(r);
    fclose(r1);
    return ss;
}
char * NormalDomain(char *s)
{
    char *s1=(char*)malloc(50);
    memcpy(s1,s,strlen(s));
    char *p=s1+strlen(s)-1;
    for(; p>s1; p--)
    {
        if(*p<20&&*p>=0)
            *p='.';
    }
    printf("the normal domain name is %s\n",s1);
    return s1;
}
unsigned int IpHex(char* inarr)
{
    char* arr = malloc(strlen(inarr)+1);
    memcpy(arr, inarr, strlen(inarr)+1);
    int last = 0;
    unsigned int result = 0;
    unsigned int offset = 0x1000000;
    int i = 0;
    int p = strlen(arr);

    for(; i < p; i++)
    {
        if(arr[i] == '.')
        {
            arr[i] = 0;

            int m =  atoi(arr + last) * offset;
            printf("%x\n", m);
            result += m;
            offset /= 0x100;
            last = i + 1;
        }
    }

    result += atoi(arr +  last) * offset;
    free(arr);
    return result;
}
void initAnswer(struct DNS_RR *rr,int type)
{
    if(flag==0)
    {
        rr->type=2;
        rr->iclass=1;
        rr->ttl=0x63;
        rr->data_len=5;
        rr->cname="\x02ns\x04root\x06server";         //此处每个服务器的名字不一样

        rr->rdata=IpHex(ipp);
    }
    else
    {
        if(type==1)
        {
            rr->type=1;
            rr->iclass=1;
            rr->ttl=0x63;
            rr->data_len=4;
            rr->rdata=myip;
        }
        if(type==5)
        {
            rr->type=5;
            rr->iclass=1;
            rr->ttl=0x63;
            rr->data_len=9;
            rr->cname="qiandu";	               //此处需要改成活的数据
        }
        if(type==15)
        {
            rr->type=15;
            rr->iclass=1;
            rr->ttl=0x63;
            rr->data_len=9;
            rr->cname="mail";                       //此处前缀如果不是mail需要改长度
            rr->pre=6;
            rr->rdata=myip;
        }
        if(type==12)
        {
            rr->type=12;
            rr->iclass=1;
            rr->ttl=0x63;	                    //此处长度不固定
            rr->data_len=11;
            rr->cname="\x03www\x02qq\x03net";

        }
    }
}
void initHeader(struct DNSHeader *header,int type)
{
    if(flag==0)
    {
        header->id=11;
        header->tag=0x100;
        header->queryNum=1;
        header->answerNum=0;
        header->authorNum=1;
        header->web=web;
        header->qclass=1;
        header->qtype=2;     //NS
        header->addNum=1;
    }
    else
    {
        header->id=11;
        header->tag=0x100;
        header->queryNum=1;
        header->answerNum=1;
        header->authorNum=0;

        header->web=web;
        header->qclass=1;
        if(type==1)
        {
            header->qtype=1;
            header->addNum=0;
        } //A
        if(type==5)
        {
            header->qtype=5;     //CNAME
            header->addNum=0;
        }
        if(type==15)
        {
            header->qtype=15;     //CNAME
            header->addNum=1;
        }
        if(type==12)
        {
            header->qtype=12;
            header->addNum=0;
        }
    }

}
struct DNSHeader* ArraytoDNSHeader(char *input)
{
    struct	DNSHeader *h=(struct DNSHeader*)malloc(sizeof(struct DNSHeader));
    char * data = input;
    h->id=ntohs(*(unsigned short*)data);
    data+=2;
    h->tag=ntohs(*(unsigned short*)data);
    data+=2;
    h->queryNum=ntohs(*(unsigned short*)data);
    data+=2;
    h->answerNum=ntohs(*(unsigned short*)data);
    data+=2;
    h->authorNum=ntohs(*(unsigned short*)data);
    data+=2;
    h->addNum=ntohs(*(unsigned short*)data);
    data+=2;
    h->web=malloc(50);
    memcpy(h->web,data,strlen(data)+1);
    data+=strlen(data)+1;
    h->qtype=ntohs(*(unsigned short*)data);
    data+=2;
    h->qclass=ntohs(*(unsigned short*)data);
    data+=2;


    return h;
}
int DNSAnswer_toArray(char* indata,struct DNSHeader *header,struct DNS_RR *rr,int type)            // query，answer一起放进buf
{
    // indata = (char*)malloc(sizeof(unsigned short) * 6);

    char * data = indata;
    *((unsigned short*)data)=htons(header->id);
    data = data + sizeof(unsigned short);
    *((unsigned short*)data)=htons(header->tag);
    data = data + sizeof(unsigned short);
    *((unsigned short*)data)=htons(header->queryNum);
    data = data + sizeof(unsigned short);
    *((unsigned short*)data)=htons(header->answerNum);
    data = data + sizeof(unsigned short);
    *((unsigned short*)data)=htons(header->authorNum);
    data = data + sizeof(unsigned short);
    *((unsigned short*)data)=htons(header->addNum);
    data = data + sizeof(unsigned short);



    char *baidu=data;
    memcpy(data,header->web,strlen(header->web)+1);
    data=data+strlen(header->web)+1;
    *((unsigned short*)data)=htons(header->qtype);
    data = data + sizeof(unsigned short);
    *((unsigned short*)data)=htons(header->qclass);
    data=data+sizeof(unsigned short);

    // memcpy(data,rr->name,strlen(rr->name));
    *((unsigned short*)data)=htons(baidu-indata+0xc000);
    data=data+sizeof(unsigned short);
    *((unsigned short*)data)=htons(rr->type);
    data=data+sizeof(unsigned short);
    *((unsigned short*)data)=htons(rr->iclass);
    data=data+sizeof(unsigned short);
    *((unsigned int*)data)=htons(rr->ttl);
    data=data+sizeof(unsigned int);
    if(flag==0)
    {
        *((unsigned short*)data)=htons(rr->data_len);
        data=data+sizeof(unsigned short);
        char *dns=data;
        memcpy(data,"\x02ns",3);
        data+=3;
        *((unsigned short*)data)=htons(baidu-indata+0xc000);
        data=data+sizeof(unsigned short);
//memcpy(data,"\x02ns\x04root\x06server",15);
//data+=15;
        *((unsigned short*)data)=htons(dns-indata+0xc000);
        data=data+sizeof(unsigned short);
        *((unsigned short*)data)=htons(1);    //A
        data=data+sizeof(unsigned short);
        *((unsigned short*)data)=htons(1);      //IN
        data=data+sizeof(unsigned short);
        *((unsigned int*)data)=htons(rr->ttl);
        data=data+sizeof(unsigned int);
        *((unsigned short*)data)=htons(4);     //data length
        data=data+sizeof(unsigned short);
        *((unsigned int*)data)=htonl(rr->rdata);
        data=data+4;
        return data-indata;
    }
    else
    {
        if(type==12)
        {
            *((unsigned short*)data)=htons(rr->data_len);
            data=data+sizeof(unsigned short);
            memcpy(data,rr->cname,rr->data_len);
            data=data+strlen(rr->cname);
            return data-indata;
        }
        if(type==15)
        {
            *((unsigned short*)data)=htons(rr->data_len);
            data=data+sizeof(unsigned short);
            *((unsigned short*)data)=htons(rr->pre);
            data=data+sizeof(unsigned short);
            char *second=data;
            *data=strlen(rr->cname);
            data=data+1;
            memcpy(data,rr->cname,strlen(rr->cname));
            data=data+strlen(rr->cname);
            *((unsigned short*)data)=htons(baidu-indata+0xc000);
            data=data+sizeof(unsigned short);
            //Additional part
            *((unsigned short*)data)=htons(second-indata+0xc000);
            data=data+sizeof(unsigned short);
            *((unsigned short*)data)=htons(1);//type
            data=data+sizeof(unsigned short);
            *((unsigned short*)data)=htons(rr->iclass);
            data=data+sizeof(unsigned short);
            *((unsigned int*)data)=htons(rr->ttl);
            data=data+sizeof(unsigned int);
            *((unsigned short*)data)=htons(4);  //datalength
            data=data+sizeof(unsigned short);
            *((unsigned int*)data)=htonl(rr->rdata);
            data=data+4;
            return data-indata;
        }
        if(type==5)
        {
            *((unsigned short*)data)=htons(rr->data_len);
            data=data+sizeof(unsigned short);
            char *end=baidu+first;

            *data=strlen(rr->cname);
            data=data+1;
            memcpy(data,rr->cname,rr->data_len);
            data=data+strlen(rr->cname);
            *((unsigned short*)data)=htons(end-indata+0xc000);
            data=data+sizeof(unsigned short);
            return data-indata;
        }
        if(type==1)
        {
            *((unsigned short*)data)=htons(rr->data_len);
            data=data+sizeof(unsigned short);
            *((unsigned int*)data)=htonl(rr->rdata);
            data=data+4;
            return data-indata;
        }
    }
}
int main()
{
    struct sockaddr_in s1;
    sock=&s1;
    int s=socket(PF_INET,SOCK_DGRAM,0);
    unsigned short p=53;
    if(s<0)
        printf("create error\n");
    memset(sock,0,sizeof(*sock));
    sock->sin_family=AF_INET;
    sock->sin_port=htons(p);
    sock->sin_addr.s_addr=inet_addr("127.0.0.2");
    if(bind(s,(struct sockaddr*)sock,sizeof(*sock))<0)
        printf("bind error\n");
    printf("waiting for data\n");
    while(1)
    {
        unsigned int len=sizeof(client);
        int size=recvfrom(s,buf,299,0,(struct sockaddr*)&client,&len);
        h=ArraytoDNSHeader(buf);                  //在此之后便能用query包了
        printf("tag is %d\n",h->tag);
        web=h->web;
        char * normalweb=NormalDomain(web);
        ipp=file(normalweb,h->qtype);
        reverDomain(web);
        printf("the domain name is %s\n",web);
        printf("the address of client is %s\n",inet_ntoa(client.sin_addr));
        initHeader(&header,h->qtype);
        initAnswer(&answer,h->qtype);
        Segement(web);
        int size2=DNSAnswer_toArray(buffer,&header,&answer,h->qtype);
        printf("the ip you require is %s",ipp);
        if(sendto(s,buffer,size2,0,(struct sockaddr*)&client,sizeof(client)))
            printf("ok\n");
        memset(buffer,0,sizeof(buffer));
        memset(buf,0,sizeof(buf));
    }
    getchar();
    return 0;
}


