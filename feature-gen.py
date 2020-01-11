import math

url="https://sci-hub.se/https://www.researchgate.net/publication/30836520788_Detecting_Malicious_URLs_Using_Lexical_Analysis"    #input()

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