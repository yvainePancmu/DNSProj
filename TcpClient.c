#include<stdio.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<string.h>
#include<malloc.h> 
char buf[200];
struct sockaddr_in sd;
struct sockaddr s;
char * serip;
char* word;
char buffer[100];
char *web;
char *ptr;
struct sockaddr_in client;
struct DNSHeader{
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
struct DNS_RR {     
//unsigned char *name; 
    unsigned short type;     
	   unsigned short iclass; 
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
struct DNSHeader header;
struct DNS_RR *r;
void init(struct DNSHeader *header,int type){

    header->id=11;
    header->tag=0x100;
    header->queryNum=1;
    header->answerNum=0;
    header->authorNum=0;
    header->addNum=0;
    header->qclass=1;
    if(type==1) {
    header->qtype=1;
     header->web=web;
    }
    if(type==2){
    header->qtype=5; 
	 header->web=web;} //CNAME
if(type==3) {
      header->web=web;                 //MX
header->qtype=15; 
}      //PTR
if(type==4){
	header->qtype=12;
	header->web=ptr;
}
}  
int DNSHeader_toArray(char* indata,struct DNSHeader *header,int type){            //indata其实是outdata 
	// indata = (char*)malloc(sizeof(unsigned short) * 6);
        char * data = indata;
    *((unsigned short*)data)=htons(0);
data=data+sizeof(unsigned short);
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

  memcpy(data,header->web,strlen(header->web)+1);
data=data+strlen(header->web)+1;
//if(type==4){
//	memcpy(data,ptr,strlen(ptr));
//	data+=strlen(ptr)+1;
//}
    *((unsigned short*)data)=htons(header->qtype);
    data = data + sizeof(unsigned short);
     *((unsigned short*)data)=htons(header->qclass);
    data=data+sizeof(unsigned short);
   //  tcplength=data-indata;
*(unsigned short*)indata=htons((unsigned short)(data-indata-2));
    return data-indata;
	
}
char * NormalDomain(char *s){
char *s1=(char*)malloc(50);
memcpy(s1,s,strlen(s));
char *p=s1+strlen(s)-1;
for(;p>s1;p--){
if(*p<20&&*p>=0)
*p='.';
}
printf("the normal domain name is %s\n",s1);
return s1;
}
char* website(char* input)
{
    // w w w . b a i....

    //parsed = _ w w w . b a i d u . c o m \0

    //int mylen = strlen(input);
    char* parsed = (char*)malloc(50);
    memcpy(parsed + 1, input, strlen(input) + 1);
    char* strend = parsed + strlen(input);
    int counter = 0;
    for(; strend > parsed; strend--)
    {
        if (*strend != '.')
        {
            counter++;
        }
        else
        {
            *strend = counter;
            counter = 0;
        }
    }
    // strend == parsed
    *strend = counter;
    return parsed;
}
char *reverDomain(char * orig){
    char * buffer = (char*)malloc(strlen(orig));
    char * reading = orig;
    char * writing = buffer;
    char** dots = (char**)malloc(sizeof(char*)*4);
    int dotnow = 1;
    dots[0] = orig-1;
    for(; reading<orig+strlen(orig);reading++)
    {
        if(*reading == '.')
        {
            dots[dotnow] = reading;
            dotnow++;
        }
    }
int i=3;
    for(; i >= 0; i--)
    {
        reading = dots[i]+1;
        while(*reading != '.' && *reading != '\0')
        {
            *writing = *reading;
            writing++;
            reading++;
        }
        *writing = '.';
        writing++;
    }
    writing--;
    *writing = '\0';
    return buffer;
}
struct DNS_RR* ArraytoDNSAnswer(char *input,int type){
struct	DNS_RR *r=(struct DNS_RR*)malloc(sizeof(struct DNS_RR));
struct	DNSHeader *h=(struct DNSHeader*)malloc(sizeof(struct DNSHeader));
 char * data = input;
 data+=2;
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
  data+=4;


  r->type=ntohs(*(unsigned short*)data);
  data+=2;
  r->iclass=ntohs(*(unsigned short*)data);
  data+=2;
   r->ttl=ntohl(*(unsigned int*)data);
  data+=4;
   r->data_len=ntohs(*(unsigned short*)data);
  data+=2;
  if(h->answerNum==0){
	data+=r->data_len;
	data+=12;
		struct in_addr a;
       unsigned int  ip =(*(unsigned int*)data);
  a.s_addr=ip;
      r->ip=inet_ntoa(a);
}

else{
  if(type==1){
  	struct in_addr a;
       unsigned int  ip =(*(unsigned int*)data);
  a.s_addr=ip;
      r->ip=inet_ntoa(a);
  
  }
  if(type==2){
data+=1;
r->cname=(char*)malloc(40);
r->name=(char*)malloc(40);
char *s=(char*)malloc(10);
  memcpy(r->cname,data,r->data_len-3);
data+=r->data_len-3;
memcpy(s,data,2);
  	data=input+*(s+1)+2;
//memcpy(r->name,data,strlen(header.web)+1);
memcpy(r->name,data,15);
  }
  if(type==3){
  	  	r->pre=ntohs(*(unsigned short*)data);
  	data+=2;
r->mx=(char*)malloc(50);
  	memcpy(r->mx,data,r->data_len-4);
  	data+=r->data_len-4;
data+=14;
struct in_addr a;
unsigned int ip=(*(unsigned int*)data);
a.s_addr=ip;
r->ip=inet_ntoa(a);
  }
}
	return r;
}
int main(int argc,char* argv[]){
unsigned short p=53;
serip=argv[1];
char *arg=argv[2];
int t=atoi(argv[3]);
char arr[20];
web=website(arg);
if(t==4){
   char* pp=reverDomain(arg);             //先把ip倒过来
 memcpy(arr,pp,strlen(pp)+1);
 char s2[20]=".in-addr.arap";
char *pp2=strcat(arr,s2);
ptr=website(pp2);
printf("ptr is %s\n",pp2); 
}
init(&header,t);
memset(&sd,0,sizeof(sd));
sd.sin_family=AF_INET;
sd.sin_port=htons(p);
sd.sin_addr.s_addr=inet_addr(serip);
int ss=socket(PF_INET,SOCK_STREAM,0);
if(ss<0)
printf("sock create error\n");
if(connect(ss,(struct sockaddr*)&sd,sizeof(sd))<0)
printf("connected error\n") ;
//int length=strlen(word);
int size=DNSHeader_toArray(buffer,&header,t);
//int size=sendto(ss,word,length,0,(struct sockaddr*)&sd,sizeof(sd));
send(ss,buffer,size,0);
int len=sizeof(client);
recv(ss,buf,200,0);
r=ArraytoDNSAnswer(buf,t);
if(t==1){
	printf("Question:\n");
	printf("Name:  %s\n",arg);
	printf("Type:A\n");
if(strcmp(r->ip,"0.0.0.0")==0){
printf("the domian is not exist\n");
exit(0);
}
        printf("the des ip is %s\n",r->ip);
}
if(t==2){
printf("Question:\n");
	printf("Name:  %s\n",arg);
	printf("Type:CNAME\n");	
        printf("the primary name is %s.%s\n",r->cname,r->name);
//   printf("I wish you can do %s\n",NormalDomain(r->name));
}

if(t==3){
printf("Question:\n");
	printf("Name:  %s\n",arg);
	printf("Type:MX\n");
       printf("mail exchanger is %s %s\n",r->mx,arg);
       printf("ip is %s\n",r->ip);
}
if(t==4){
printf("Question:\n");
	printf("Name:  %s\n",arg);
	printf("Type:PTR\n");	
}

return 0;
}




