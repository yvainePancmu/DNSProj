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
struct sockaddr_in cliaddr;
struct sockaddr_in *sock;
struct sockaddr_in sd;
struct sockaddr_in client2;
char buffrom[200];
char bufto[200];
char buf[300];
char check[50];
char buf2[200];
char buffer[300]; 
char check2[50];
char buffanswer[200];
char* web;
//char mail1[30];
char *anther;
int size3,ack=0;
char *typebook[]={""," A","2","3","4"," CNAME","6","7","8","9","10","11","12","13","14"," MX"};
int first,second,third;
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
unsigned char* mx;
unsigned char* name;
		unsigned short pre; 
			unsigned char* cname;
		};
int myip=0xdcb56fbc;
char *ipp;
struct DNSHeader header;
struct DNS_RR answer;
struct DNSHeader *h;
struct DNS_RR *r;
void Segement(char *s){
	int a[3];
 char *start=s;
 int i=0;
 for(start=s;start<s+strlen(s);start++){
 	
 	if(*start<20&&*start>=0){
	 	a[i]=*start;
	 	i++;
	 }
 }	
first=a[0]+1;
second=a[1]+1;
third=a[2]+1;	
printf("%d %d %d",first,second,third);	
} 
char *reverDomain(char * orig){
char *buffer=(char*)malloc(strlen(orig));
char *reading=orig+strlen(orig);
char *last=reading;
char *writing=buffer;
reading--;
for(;reading>=orig;reading--){
if(*reading<' '||*reading>=0||*reading=='.')
{
memcpy(writing,reading,last-reading);
writing+=last-reading;
last=reading;}
}
*writing=0;
printf("the rever domian name is %s\n",buffer);
return buffer;
}

char *file(char *bb,int type){
char *b=strcat(bb,typebook[type]);
printf("b is %s\n",b);
	typedef struct address{
	    char a1[30];
        char a2[20];
        char a3[30];
    }add;
	char *ptr[30];
	int i=0;
	int bbb=0;
	int kk=0;
	ptr[0]=strtok(b," ");
printf("1 is %s\n",ptr[0]);
	ptr[1]=strtok(NULL," ");
printf("2 is %s\n",ptr[1]);
    FILE * r=fopen("1.txt","r");
    FILE * r1=fopen("1.txt","r");
    while(!feof(r1)){
    	bbb=fgetc(r1);
    	if(bbb=='\n')
    	kk++;
    }
  //  printf("%d\n",kk);
    assert(r!=NULL);
    add a[128];
	static char ss[50];
char *ssss[10];
    while(fscanf(r,"%s %s %s",a[i].a1,a[i].a2,a[i].a3)!=EOF)
   {
printf("1 is %s 2 is %s\n",a[i].a1,a[i].a2);
        if(strcmp(a[i].a1,ptr[0])==0&&strcmp(a[i].a2,ptr[1])==0){
			printf("got it!\n");
//                         strcpy(mail1,a[i].a3);
                        if(strcmp(ptr[1],"MX")==0||strcmp(ptr[1],"CNAME")==0){
                         ssss[0]=strtok(a[i].a3,".");
                         printf("%s\n",ssss[0]);
                         strcpy(ss,ssss[0]);
                          printf("%s\n",ss);
                         i=-1;
                         break;
                        }else{
			strcpy(ss,a[i].a3);
	//		printf("%s\n",ss);
                        i=-1;
			break;
                         }
		}else{
			i++;
			if(i==kk){
				printf("meiyou!\n");
				strcpy(ss,"mei");
				break;
			}
		}
    }  
    if(i==0){
        printf("meiyou!\n");
        strcpy(ss,"mei");
     }
    fclose(r); 
    fclose(r1);
	return ss;
}
char * NormalDomain(char *s){
char *s1=(char*)malloc(50);
memcpy(s1,s+1,strlen(s)-1);
char *p=s1+strlen(s)-2;
for(;p>s1;p--){
if(*p<20&&*p>=0)
*p='.';
}
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

void initAnswer(struct DNS_RR *rr,int type){
  /*	if(flag==0){
		rr->type=2;
		rr->iclass=1;
		rr->ttl=0x63;
		rr->data_len=5;
		rr->cname="\x02ns\x04root\x06server";
		
                rr->rdata=IpHex(ipp);
	}*/
	if(type==1){
	rr->type=1;
	rr->iclass=1;
	rr->ttl=0x63;
	rr->data_len=4;
	rr->rdata=IpHex(check);
		}
		if(type==5){
			rr->type=5;
	rr->iclass=1;
	rr->ttl=0x63;
	rr->data_len=strlen(check)+3;
rr->cname=check;	
		}
		if(type==15){
				rr->type=15;
	rr->iclass=1;
	rr->ttl=0x63;
	rr->data_len=strlen(check)+5;
	rr->cname=check;
	rr->pre=6;
	rr->rdata=IpHex(check2);		
		}
}
void initHeader(struct DNSHeader *header,int type){
	/*if(flag==0){
	 header->id=11;
    header->tag=0x100;
    header->queryNum=1;
    header->answerNum=0;
    header->authorNum=1;
    header->web=web;
    header->qclass=1;     
    header->qtype=2;     //NS
	header->addNum=1;  	
	}*/
   
    header->id=11;
    header->tag=0x100;
    header->queryNum=1;
    header->answerNum=1;
    header->authorNum=0;
    
    header->web=web;
    header->qclass=1;
    if(type==1) { 
    header->qtype=1;
	header->addNum=0;  
	} //A
    if(type==5){ 
    header->qtype=5;     //CNAME
header->addNum=0;
		}
		if(type==15){
			 header->qtype=15;     //CNAME
header->addNum=1;
		} 	
   
   
} 
struct DNS_RR* ArraytoDNSAnswer(char *input,int type){
struct	DNS_RR *r=(struct DNS_RR*)malloc(sizeof(struct DNS_RR));
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
ack=0;
	data+=r->data_len;
	data+=12;
		struct in_addr a;
       unsigned int  ip =(*(unsigned int*)data);
  a.s_addr=ip;
      r->ip=inet_ntoa(a);
}

else{
ack=1;
  if(type==1){
  	struct in_addr a;
       unsigned int  ip =(*(unsigned int*)data);
  a.s_addr=ip;
      r->ip=inet_ntoa(a);
  
  }
  if(type==5){
data+=1;
r->cname=(char*)malloc(40);
r->name=(char*)malloc(40);
char *s=(char*)malloc(10);
  memcpy(r->cname,data,r->data_len-3);
data+=r->data_len-3;
memcpy(s,data,2);
  	data=input+*(s+1);
memcpy(r->name,data,15);
  }
  if(type==15){
  	r->pre=ntohs(*(unsigned short*)data);
  	data+=2;
r->mx=(char*)malloc(50);
data+=1;
  	memcpy(r->mx,data,r->data_len-5);
  	data+=r->data_len-5;
data+=14;
struct in_addr a;
unsigned int ip=(*(unsigned int*)data);
a.s_addr=ip;
r->ip=inet_ntoa(a);
  }
}
	return r;
}
struct DNSHeader* ArraytoDNSHeader(char *input){
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
  data+=2;
  
  
	return h;
}
//void filewrite(char *bb,int type,char *ip){
  //  FILE * r=fopen("1.txt","a");
    //fprintf(r,"%s %s %s\n",bb,typebook[type],ip);
    //fclose(r); 
//}
void *file1(char *bb,int type,char *ip){
//char *b=(char*)malloc(50);
//*b=0;
char *b=strcat(bb,typebook[type]);
printf("thish is %s\n",b);
    FILE *r1=fopen("1.txt","a");
printf("%s\n",b);
printf("%s\n",ip);
    fprintf(r1,"%s %s\n",b,ip);  
     fclose(r1);
}
int DNSAnswer_toArray(char* indata,struct DNSHeader *header,struct DNS_RR *rr,int type){           // query，answer一起放进buf 
	// indata = (char*)malloc(sizeof(unsigned short) * 6);

	
        char * data = indata;
          *((unsigned short*)data)=htons(0);
    data = data + sizeof(unsigned short);
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
   
  
   
   char *baidu=data-2;
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
/*    if(flag==0){
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
   *((unsigned short*)indata)=htons((unsigned short)(indata-data-2));
    return data-indata;
   }*/
   // else{
if(type==12){
}
    if(type==15){
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
*((unsigned short*)indata)=htons((unsigned short)(indata-data-2));
    return data-indata;	
    }
    if(type==5){	
     *((unsigned short*)data)=htons(rr->data_len);
     data=data+sizeof(unsigned short);
char *end=baidu+first;

   *data=strlen(rr->cname);
  data=data+1;
  memcpy(data,rr->cname,rr->data_len);
  data=data+strlen(rr->cname);
   *((unsigned short*)data)=htons(end-indata+0xc000);
   data=data+sizeof(unsigned short);
*((unsigned short*)indata)=htons((unsigned short)(indata-data-2));
    return data-indata;
    }
    if(type==1){
    	  *((unsigned short*)data)=htons(rr->data_len);
     data=data+sizeof(unsigned short);
    *((unsigned int*)data)=htonl(rr->rdata);
    data=data+4;

    *((unsigned short*)indata)=htons((unsigned short)(data-indata-2));
    return data-indata;
    }
	//}
}
int main(){
struct sockaddr_in s1;
//int qlength=100;
sock=&s1;
int s=socket(PF_INET,SOCK_STREAM,0);
unsigned short p=53;
if(s<0)
printf("create error\n");
memset(sock,0,sizeof(*sock));
sock->sin_family=AF_INET;
sock->sin_port=htons(p);
sock->sin_addr.s_addr=inet_addr("127.0.0.4");
if(bind(s,(struct sockaddr*)sock,sizeof(*sock))<0)
printf("bind error\n");
int con=listen (s,50);
	if(con<0)
 	printf("connect failed\n");
printf("localserver waiting for data\n");
		unsigned int len2=sizeof(cliaddr);
		int newsock=accept (s, (struct sockaddr*)&cliaddr, &len2);
if(newsock<0)
printf("accept failed\n");
unsigned int len=sizeof(client);
//while(1){ 
int size=recv(newsock,buf,299,0);
h=ArraytoDNSHeader(buf);                //在此之后便能用query包了 
//printf("tag is %d\n",h->tag);
//printf("type is %d\n",h->qtype); 
web=h->web;
printf("web is the length is %d %s\n",strlen(web),web);
char *c=NormalDomain(web);
printf("this is %s\n",c);
strcpy(check,file(NormalDomain(web),h->qtype)) ;
if(strcmp(check,"mei")!=0){
if(h->qtype==15){
strcpy(check2,file(check,1));
}
initHeader(&header,h->qtype);
initAnswer(&answer,h->qtype);
int size2=DNSAnswer_toArray(buffer,&header,&answer,h->qtype);
printf("the ip you require is %s",ipp);
send(newsock,buffer,size2,0);
exit(0); 	
}
//else{
printf("the check is %s\n",check);
int i=0;
//char *ip=(char*)malloc(30);
char *ip="127.0.0.2";
memcpy(buf2,buf+2,size-2);   
while(ack<1){  //将TCP请求转换为UDP装在buf2            //截断tcp请求的前两位并考到buf2作为udp转发 
int ss=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
 memset(&sd,0,sizeof(sd));
memset(buffrom,0,sizeof(buffrom));
sd.sin_family=AF_INET;
sd.sin_port=htons(53);
sd.sin_addr.s_addr=inet_addr(ip);
 sendto(ss,buf2,size-2,0,(struct sockaddr*)&sd,sizeof(sd));
int len=sizeof(client2);
 size3=recvfrom(ss,buffrom,199,0,(struct sockaddr*)&client2,&len);
r=ArraytoDNSAnswer(buffrom,h->qtype);
ip=r->ip;
if(strcmp(r->ip,"0.0.0.0")==0)
{
printf("domain is not exist\n");
exit(0);
}
printf("trace is %s\n",ip);
i++;
}
//printf("mail is %s\n",r->mx);
if(h->qtype==1)
file1(NormalDomain(web),h->qtype,r->ip);
if(h->qtype==5){
file1(NormalDomain(web),h->qtype,r->cname);
}
if(h->qtype==15){
//char *s=NormalDomain(web);

file1(c,h->qtype,r->mx);
file1(r->mx,1,r->ip);
printf("web is %s %s \n",web,NormalDomain(web));
}
anther=(char*)malloc(size3+2);
*((unsigned short*)anther)=htons(size3);
memcpy(anther+2,buffrom,size3); 
send(newsock,anther,size3+2,0); 
close(s);
close(newsock);
//}       //以TCP形式发送回客户端 
return 0;
}


