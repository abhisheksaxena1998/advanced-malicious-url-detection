import math
from urllib.parse import urlparse
URL_DigitCount=0
domaintokencount=0
SymbolCountDomain=0
QueryDigitCount=0
spcharUrl=0
url="https://images.pexels.com/photos/414612/pexels-photo-414612.jpeg?auto=compress&cs=tinysrgb&dpr=1&w=500"#"http://aneisig.es/vx/hstart.php?id=664&logon=141 "##"https://www.youtube.com/watch?v=dGwau9Vcc0o"#"http://aneisig.es/vx/hstart.php?id=664&logon=141 "#"https://www.google.com/search?q=seach&oq=seach&aqs=chrome..69i57.1308j0j1&sourceid=chrome&ie=UTF-8"#"http://sci-hub.se/https://www.researchgate.net/publication/30836520788_Detecting_Malicious_URLs_Using_Lexical_Analysis"    #input()    
symbols="://.:/?=,;()]+@"
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
pathlength=len(o.path)
print ("pathlength",pathlength)



o = urlparse(url)
print ("Query",o.query)
QueryLength=len(o.query)
print ("QueryLength",QueryLength)

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
domaintokencount+=1        
print ("domaintokencount",domaintokencount)        



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

nodig1=0
for i in domain:
    if i in digits:
        nodig1+=1
numrate_domain=nodig1/len(domain)        
print ("Number_Rate_domain",numrate_domain)

nodig2=0
for i in dirname:
    if i in digits:
        nodig2+=1
numrate_dir=nodig2/len(dirname)        
print ("Number_Rate_dir",numrate_dir)


nodig3=0
for i in filename:
    if i in digits:
        nodig3+=1
numrate_filename=nodig3/len(filename)        
print ("Number_Rate_filename",numrate_filename)

nodig4=0
for i in url:
    if i in digits:
        nodig4+=1
numrate_url=nodig4/len(url)        
print ("Number_Rate_url",numrate_url)

urlLen=len(url)
print ("urlLen",urlLen)
domainLen=len(domain)
print ("domainLen",domainLen)
ﬁleNameLen=len(filename)
print ("ﬁleNameLen",ﬁleNameLen)
path=o.path
tpath=path.replace("//"," ")
tpath=tpath.replace("/"," ")
tpath=tpath.replace("."," ")
tpath=tpath.replace("://"," ")
pathtokens=tpath.count(" ")+1   
for i in range(pathtokens-1):
    tpath=tpath.replace(" ","")
print (tpath)    

print ("pathtokens",pathtokens)
print ("lengthpath",len(tpath))
avergaepathtokenlen=len(tpath)/pathtokens
print ("avergaepathtokenlen",avergaepathtokenlen)

for i in url:
    if i in symbols:
        spcharUrl+=1
print ("spcharUrl",spcharUrl)      

averagedomaintokenlen=(len(domain)-domain.count("."))/domaintokencount
print ("avergaedomaintokencount",averagedomaintokenlen)

longdomaintokenlen=len(domain)-domain.count(".")
print ("longdomaintokenlen",longdomaintokenlen)

for i in range(len(dirname)):
    if dirname[i]=="/":
        pos=i
        break
subdir=dirname[pos+1:len(dirname)]
print ("subdir",subdir)        
subdirlen=len(subdir)
print ("subdirlen",subdirlen)
print (filename)
for i in range(len(filename)):
    if filename[i]=='.':
        pos=i
        break
extension=filename[pos+1:len(filename)]
print ("extension",extension)
extlen=len(extension)
print ("extlen",extlen)   

if extension=="exe":
    isexe=1
else:
    isexe=0
print ("isexe",isexe)        

nodotsurl=0
for i in url:
    if i==".":
        nodotsurl+=1
print ("nodotsurl",nodotsurl)     

for i in url:
    if i in digits:
        URL_DigitCount+=1
print ("URL_DigitCount",URL_DigitCount)     

host_DigitCount=0
for i in domain:
    if i in digits:
        host_DigitCount+=1
print ("host_DigitCount",host_DigitCount)        


Directory_DigitCount=0
for i in dirname:
    if i in digits:
        Directory_DigitCount+=1
print ("Directory_DigitCount",Directory_DigitCount)        

File_name_DigitCount=0
for i in filename:
    if i in digits:
        File_name_DigitCount+=1

print ("File_name_DigitCount",File_name_DigitCount)

extensiondigitcount=0
for i in extension:
    if i in digits:
        extensiondigitcount+=1
print ("extensiondigitcount",extensiondigitcount)        

querydigitcount=0
for i in o.query:
    if i in digits:
        querydigitcount+=1
if querydigitcount==0:
    querydigitcount=-1        
print ("querydigitcount",querydigitcount)     

urlalphabetcount=0
for i in url:
    if i in alphabets:
        urlalphabetcount+=1
print ("urllettercount",urlalphabetcount)     

domainlettercount=0
for i in domain:
    if i in alphabets:
        domainlettercount+=1
print ("domainlettercount",domainlettercount)     

Directory_LetterCount=0
for i in dirname:
    if i in alphabets:
        Directory_LetterCount+=1
print ("Directory_LetterCount",Directory_LetterCount)     

Filename_LetterCount=0
for i in filename:
    if i in alphabets:
        Filename_LetterCount+=1
print ("Filename_LetterCount",Filename_LetterCount)     

Extension_LetterCount=0
for i in extension:
    if i in alphabets:
        Extension_LetterCount+=1
print ("Extension_LetterCount",Extension_LetterCount)     

Query_LetterCount=0
for i in o.query:
    if i in alphabets:
        Query_LetterCount+=1
if Query_LetterCount==0:
    Query_LetterCount=-1        
print ("Query_LetterCount",Query_LetterCount)     

lendom=[]
for i in (domain.split(".")):
    lendom.append(len(i))
Domain_LongestWordLength=max(lendom)
print ("Domain_LongestWordLength",Domain_LongestWordLength)

subdirlongestwordlen=len(subdir)
print ("subdirlongestwordlen",subdirlongestwordlen)

"""delimeterindomain=0
for i in domain:
    if i in symbols:
        delimeterindomain+=1
print ("delimeterindomain",delimeterindomain)     """


nodig69=0
for i in extension:
    if i in digits:
        nodig69+=1
numrate_extension=nodig69/len(extension)        
print ("numrate_extension",numrate_extension)

x=0
symbolcounturl=0
for i in temp_url:
    if i>="a" and i<="z" or i>="0" and i<="9":
        x+=1
    else:
        symbolcounturl+=1
print ("symbolcounturl",symbolcounturl)        
            
symbolcountdom=0
for i in domain:
    if i>="a" and i<="z" or i>="0" and i<="9":
        x+=1
    else:
        symbolcountdom+=1
print ("symbolcountdom",symbolcountdom)      

symbolcountdir=0
for i in dirname:
    if i>="a" and i<="z" or i>="0" and i<="9":
        x+=1
    else:
        symbolcountdir+=1
print ("symbolcountdir",symbolcountdir)      

symbolcountfile=0
for i in filename:
    if i>="a" and i<="z" or i>="0" and i<="9":
        x+=1
    else:
        symbolcountfile+=1
print ("symbolcountfile",symbolcountfile)      

symbolcountext=0
for i in extension:
    if i>="a" and i<="z" or i>="0" and i<="9":
        x+=1
    else:
        symbolcountext+=1
print ("symbolcountext",symbolcountext)      

en_dom=0 
for i in alphabets:
    if i in domain:
        p=domain.count(i)/len(domain)
        en=-p*math.log10(p)
        en_dom+=en        
print ("Entropy_dom",en_dom)


en_dir=0 
for i in alphabets:
    if i in dirname:
        p=dirname.count(i)/len(dirname)
        en=-p*math.log10(p)
        en_dir+=en        
print ("Entropy_dir",en_dir)

en_file=0 
for i in alphabets:
    if i in filename:
        p=filename.count(i)/len(filename)
        en=-p*math.log10(p)
        en_file+=en        
print ("Entropy_file",en_file)

en_ext=0 
for i in alphabets:
    if i in extension:
        p=extension.count(i)/len(extension)
        en=-p*math.log10(p)
        en_ext+=en        
print ("Entropy_ext",en_ext)



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