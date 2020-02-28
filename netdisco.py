import sys,getopt,psutil,re,nmap

#sys module is used to get arguments from command line 

#getopt module is used to parse arguments passed through command line

#psutil module is used to get network details of current system

#re module is used to find ipaddres and netmask of selected interface



def help():
    print("\n\nnetdisco -i <interface>\n\n")
    print("-i  :specify interface")
    print("-h  :show help")
    print("-t  :specify target ")
    print("\n\nExample:\n    python netdisco.py -i wlan0\n    python netdisco.py -i Wi-Fi")
    print("    python netdisco.py -i wlan0 -t 198.168.0.55(find if specific ip is alive or not)")

def scanWnmap(ipaddr):
    nm=nmap.PortScanner()
    mn=nm.scan(hosts=ipaddr,arguments='-n -PA -PS -PE -sP ')
    hosts = [(i, nm[i]['status']['state']) for i in nm.all_hosts()]

    #print("\n")
   # print("Total No. of hosts:", mn['nmap']['scanstats']['totalhosts'])
   # print("No. of hosts up:", mn['nmap']['scanstats']['uphosts'])
   # print("No. of hosts down:", mn['nmap']['scanstats']['downhosts'])
    #print("\n")
    
    #print("Alive Hosts\tStatus\t\tMAC Address\t\t\tMAC Vendor")
    for alive_host, status in hosts:
        if(status.lower()=='up'):
            print('{0}\t{1}\t\t{2}\t\t{3}'.format(alive_host,status,
                                                  "".join([macaddr for macaddr,macven in mn['scan'][alive_host]['vendor'].items()]),
                                                  "".join([macven for macaddr,macven in mn['scan'][alive_host]['vendor'].items()])))


def findip(interface):#finds ip and netmask of specified interface
    try:
        psu=str(psutil.net_if_addrs()[interface][:2])
    except:
        print("\n\nNo such interface available")
        exit()
   # print(psu)
    ip_addr,*netmask=re.findall('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',psu)
    del psu
    netmask=netmask[0]
    return ip_addr,netmask

def findipTscan(ip_addr,netmask):#finds ip range to scan cidr /24,/16
    ip_addr=ip_addr.split('.')
    netmask=netmask.split('.')

    ipaddr=''
    #wildcard=''#if netmask is 255.255.255.0 then wildcard will be 0.0.0.255
    binnetmask=''
    length=len(netmask)

    for i in range(length):
        ipaddr+=str(int(ip_addr[i]) & int(netmask[i]))
        #wildcard+=str(int(netmask[i]) ^ 255))
        binnetmask+=bin(int(netmask[i]))
        if(i<length-1):
            ipaddr+='.'
    binnetmask=binnetmask.count('1')
    return ipaddr,binnetmask


def scan(ipaddr,binnetmask=32):
    print("\nScanning..."+"\""+ipaddr+'/'+str(binnetmask)+"\"\n")
    print("Alive Hosts\tStatus\t\tMAC Address\t\t\tMAC Vendor")
    if int(binnetmask)>=24:
        ipaddr+='/'+str(binnetmask)
        scanWnmap(ipaddr)
    else:
        ipaddr+='/'+'24'
        i=2**(8-int(binnetmask)%8)#find host in 3 rd octate if any (in else part)
        while i!=-1:
            #print(ipaddr)
            scanWnmap(ipaddr)
            ipaddr=ipaddr.split('.')
            ipaddr[2]=str(int(ipaddr[2])+1)
            ipaddr=".".join(ipaddr)
            i=i-1
          
def mainNet(interface):

    #findip will grab systems ipaddress and netmask and assign them respectively
    ip_addr,netmask=findip(interface)
    
    print("\n\nSystem Details:")
    print("\nIP ADDRESS: ",ip_addr)
    print("NETMASK: ",netmask)

    #ipaddr:only network part of ip_addr
    #binnetmask:it will help us to calculate cidr of ip_addr(192.168.1.0/(24)) this 24 will automatically be calculated
    ipaddr,binnetmask=findipTscan(ip_addr,netmask)
    

    del ip_addr,netmask
    scan(ipaddr,binnetmask)
    
def target(ipaddr,interface):

    ip_addr,netmask=findip(interface)
    ip,binnetmask=findipTscan(ip_addr,netmask)

    #here we will compare if target ip is in the range of specified interface
    print("\n\nSystem Details:")
    print("\nIP ADDRESS: ",ip_addr)
    print("NETMASK: ",netmask)
    print("IP TO SCAN:",ipaddr)
    del ip_addr,netmask
    
    ip=ip.split('.')
    ipaddr=ipaddr.split('.')

    i=binnetmask//8-1

    while i>0:
        if(ip[i]==ipaddr[i]):
            i=i-1
            continue
        else:
            print('\nSpecified IPaddress Does Not Match Specified Interface\'s IP address')
            exit()
        
    ipaddr='.'.join(ipaddr)
    if '/' in ipaddr:
        scan(ipaddr[:-3],ipaddr[-2:])
    else:
        scan(ipaddr)


#EXECTION starts from here
#getting all arguments except file name

cmdargv=sys.argv[1:]

#print(cmdargv)

try:
    options,argvs=getopt.getopt(cmdargv,'hi:t:',['help','target'])
    op=dict(options)
except:
    help()
    exit()    
interface=None
for opt,arg in options:
    #print(opt,arg)
    if(opt=='-h' or opt=='--help'):
        help()
    elif(opt=='-t' or opt=='--target'):
        try:
            if(op['-i']):
                target(arg,op['-i'])
        except Exception as e:
            print("\nSpecify interface:",e)
    elif(opt=='-i'):
        try:
            if(op['-t']):
                continue
        except:
            pass
        mainNet(arg)

    else:
        help()
    exit()
        
#print(options)
#print(argvs)
