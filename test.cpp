#include<iostream>
#include<pcap.h>
#include<string.h>
#include <algorithm>
#include<string>
#include<sstream>
using namespace std;
char errbuf[512];
size_t mac_addr = 6;
typedef unsigned char   u_char;
string dectohex(int i);
string utos(u_char u_c);
void struse(const u_char* p, u_char* q, int begin, int l);
int main()
{
    struct pcap_pkthdr pkthdr;
    pcap_t* pcap_str = pcap_open_offline("./nd_packet.cap", errbuf);
    if (!pcap_str)
    {
        printf("error file format\n");
    }
    size_t num = 0;
    
    const u_char* pkt_buff = pcap_next(pcap_str, &pkthdr);
    if (!pkt_buff)
    {
        printf("file read over\n");
        return 0;
    }
    //取源mac地址，目的mac地址
    u_char srcmac[7];
    memset(srcmac,0,7);
    struse(pkt_buff,srcmac,num,6);
    string srcmacstr;
    for(int i=0;i<6;i++)
    {
        srcmacstr=srcmacstr+dectohex((int)srcmac[i])+":";
    }
    srcmacstr.erase(srcmacstr.end()-1);
    cout<<"源mac地址为:"<<srcmacstr<<endl;

    u_char desmac[7];
    memset(desmac,0,7);
    struse(pkt_buff,desmac,num+6,6);
    string desmacstr;
    for(int i=0;i<6;i++)
    {
        desmacstr=desmacstr+dectohex((int)desmac[i])+":";
    }
    desmacstr.erase(desmacstr.end()-1);
    cout<<"目的mac地址为："<<desmacstr<<endl;

    num = num + mac_addr + mac_addr;

    //获取协议类型为IP协议
    u_char q[3];
    memset(q,0,3);
    struse(pkt_buff,q, num, 2);
    //这里不做校验判断了
    num=num+2;
    //获取IP数据报头部长度,获取应用层起始位置，获取应用层协议
    u_char ipheadlength[1];
    memset(ipheadlength,0,1);
    struse(pkt_buff,ipheadlength,num,1);
    //printf("%d\n",(ipheadlength[0]&15)*4);
    int tcpbegin=(ipheadlength[0]&15)*4+num;
    u_char pro[2];
    struse(pkt_buff,pro,num+9,1);
    //printf("%d\n",pro[0]);
    if(pro[0]==6)
    {
        cout<<"传输层协议为TCP,";
        //在这里得出序列号
        u_char seq[5];
        memset(seq,0,5);
        struse(pkt_buff,seq,tcpbegin+4,4);
        //printf("%d\n",seq[0]);
        unsigned int seqnum=seq[3] | seq[2]<<8|seq[1]<<16 | seq[0]<<24;
        cout<<"序列号为"<<seqnum<<endl;

    }
    if(pro[0]==17)
    {
        cout<<"传输层协议为UDP";
    }
    
    //获取源IP地址,目的IP地址
    u_char srcip[5];
    memset(srcip,0,5);
    struse(pkt_buff,srcip,num+12,4);
    string srcipstr;
    for(int i=0;i<4;i++)
    {
        srcipstr=srcipstr+utos(srcip[i])+'.';
    }
    srcipstr.erase(srcipstr.end()-1);
    cout<<"源IP地址为："<<srcipstr<<endl;
    u_char desip[5];
    memset(desip,0,5);
    struse(pkt_buff,desip,num+16,4);
    string desipstr;
    for(int i=0;i<4;i++)
    {
        desipstr=desipstr+utos(desip[i])+'.';
    }
    desipstr.erase(desipstr.end()-1);
    cout<<"目的IP地址为："<<desipstr<<endl;
    
    //获取源端口号，目的端口号
    u_char srcport[3];
    memset(srcport,0,3);
    struse(pkt_buff,srcport,tcpbegin,2);
    int srcportvalue = (int)((unsigned char)srcport[1] | (unsigned char)srcport[0]<<8);
    cout<<"源端口号为："<<srcportvalue<<endl;
    u_char desport[3];
    memset(desport,0,3);
    struse(pkt_buff,desport,tcpbegin+2,2);
    int desportvalue = (int)((unsigned char)desport[1] | (unsigned char)desport[0]<<8);
    cout<<"目的端口号为："<<desportvalue<<endl;
}
void struse(const u_char* p,u_char* q ,int begin, int l)
{
    for (int i = 0; i < l; i++)
    {
        q[i] = p[i + begin];
    }
}
//u_char转化为字符串
string utos(u_char u_c)
{
    int temp=(int)u_c;
    string ans;
    while(temp)
    {
        int tt=temp%10;
        char ttc=tt+'0';
        ans=ans+ttc;
        temp=temp/10;
    }
    reverse(ans.begin(),ans.end());
    return ans;
}
string dectohex(int i) //将int转成16进制字符串
{
	stringstream ioss; 
	string s_temp; 
	ioss << hex << i;
	ioss >> s_temp;
	return s_temp;
}
