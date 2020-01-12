import math
from urllib.parse import urlparse

domaintokencount=0
SymbolCountDomain=0
QueryDigitCount=0
url="https://images.pexels.com/photos/414612/pexels-photo-414612.jpeg?auto=compress&cs=tinysrgb&dpr=1&w=500"#"http://aneisig.es/vx/hstart.php?id=664&logon=141 "##"https://www.youtube.com/watch?v=dGwau9Vcc0o"#"http://aneisig.es/vx/hstart.php?id=664&logon=141 "#"https://www.google.com/search?q=seach&oq=seach&aqs=chrome..69i57.1308j0j1&sourceid=chrome&ie=UTF-8"#"http://sci-hub.se/https://www.researchgate.net/publication/30836520788_Detecting_Malicious_URLs_Using_Lexical_Analysis"    #input()    
symbols="://.:/?=,;()]+"
for i in range(0,len(url)):
    if (url[4]=='s'):
        url=url.replace('https://','')
    else:
        url=url.replace('http://','')

print (url)        

for i in range(len(url)):
    if url[i]=='/':
        pos=i
        break
    else:
        domain=url
        pos=len(url)
domain=url[0:pos]
print (domain)

o = urlparse(url)
print ("Path",o.path)



o = urlparse(url)
print ("Query",o.query)

digits="0123456789"
alphabets="abcdefghijklmnopqrstuvwxyz"
nodig=0
for i in url:
    if i in digits:
        nodig+=1
numrate=nodig/len(url)        
print ("Number_Rate",numrate)

temp_url=url.lower()
en_sum=0 

for i in alphabets:
    if i in temp_url:
        p=temp_url.count(i)/len(temp_url)
        en=-p*math.log10(p)
        en_sum+=en        
print ("Entropy",en_sum)

argpathratio=len(o.query)/len(o.path)
print ("argpathratio",argpathratio)

argurlratio= len(o.query)/len(url)
print ("argurlratio",argurlratio)

argdomainratio=len(o.query)/len(domain)
print ("argdomainratio",argdomainratio)

domainUrlRatio=len(domain)/len(url)
print ("domainUrlRatio",domainUrlRatio)

pathDomainRatio=len(o.path)/len(domain)
print ("pathDomainRatio",pathDomainRatio)

pathUrlRatio =len(o.path)/len(url)
print ("pathUrlRatio",pathUrlRatio)

for i in domain:
    if i in symbols:
        SymbolCountDomain+=1
print ("SymbolCountDomain",SymbolCountDomain)

for i in o.query:
    if i in digits:
        QueryDigitCount+=1
print ("QueryDigitCount",QueryDigitCount)

for i in range(len(domain)):
    if domain[i]=='.':
        pos=i
        break
tld=domain[pos:len(domain)]
print ("tld",tld," length",len(tld)-1)        

for i in domain:
    if i=='.':
        domaintokencount+=1
print ("domaintokencount",domaintokencount+1)        



for i in range(len(o.path)):
    
    if o.path[i]=='/':
        pos=i
filename=o.path[pos+1:len(o.path)]        
print ("filename",filename)

for i in range(len(o.path)):
    if o.path[i]=='/':
        pos1=i
        break
dirname=o.path[pos1+1:len(o.path)-len(filename)-1]        
print ("dirname",dirname)
    

"""alpha=0
dig=0
spchar=0


for i in temp_url:
    if i>='a' and i<='z':
        alpha+=1
    elif int(i)>=0 and int(i)<=9:
        dig+=1
    else:
        spchar+=1
            """