#include<bits/stdc++.h>
#define MAX_LENGTH 13
#define MAX_CT 10000

using namespace std;

unsigned char key[MAX_LENGTH];
unsigned char ct[MAX_CT] = {0};
bool isTarChar[256];

void inintTarChar()
{
    //大小写字母、标点、空格对应1,其余为0
    memset(isTarChar,0,sizeof(isTarChar));
    for (int i = 'A'; i <= 'Z'; i++)
        isTarChar[i] = 1;
    for (int i = 'a'; i <= 'z'; i++)
        isTarChar[i] = 1;
    isTarChar[','] = 1;
    isTarChar['.'] = 1;
    isTarChar[' '] = 1;
}

size_t readFile()
{
    size_t i=0;
    FILE *cipherFile=fopen("ctext.txt","r");
    if(cipherFile == NULL)  return 0;
    while(fscanf(cipherFile,"%02X",&ct[i++])!=EOF) {}
    fclose(cipherFile);
    return i - 1;   //会多读入个0x00
}

int brute_force_crack(size_t ctsize,int keyLen)
{
    //std::cout<<"Try keyLen = "<<keyLen<<std::endl;
    long long i,j,pass=0;
    unsigned char k;
    for(i=0;i<keyLen;i++)
    {
        //printf("i=%d\n",i);
        for(k=0x00;;k++) //unsigned char 会溢出 --> 255+1=0
        {
            //printf("k=%d ",k);
            for(j=i;j<ctsize;j+=keyLen)
            {
                //cout << char(k^ct[j]) << endl;
                if(!(isTarChar[k^ct[j]]))   break;
            }
            if(j>=ctsize)
            {
                key[pass++]=k;  
                break;
            }
            if(k==0xFF)    break;
        }
    }
    if(pass>=keyLen)
    {
        cout<<"Key = ";
        for (int i = 0; i < keyLen; i++){
            printf("%02x", key[i]);
        }
        return 0;
    }
    return 1;
}

void writeFile(size_t ctsize,int keyLen)
{
    FILE *fpOut=fopen("ptext.txt","w");
    if(fpOut==NULL) printf("Error: can't write into ptext.txt.\n");
    long long i;
    for(i=0;i<ctsize;i++)
    {
        fprintf(fpOut,"%c",ct[i]^key[i%keyLen]);
    }
    fclose(fpOut);
}

int main()
{
    inintTarChar();
    const size_t ctsize = readFile();
    int keyLen;
    for(keyLen=1;keyLen<=13;keyLen++)
    {
        if(!(brute_force_crack(ctsize,keyLen)))
            break;
    }
    writeFile(ctsize,keyLen);
    return 0;
}
