#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define opBufSz 32

#define decodeSIB()                 \
    base = r32[*b&0x07];            \
    indx = r32[(*b&0x38)>>3];       \
    scale = ((*b&0xc0)>>6)*2;       \
    if(scale && !indx){             \
        puts("Invalid SIB byte.");  \
        exit(-1);                   \
    }

#define setG()                              \
    reg = (*b&0x38)>>3;                     \
    if(!Gsz){                               \
    } else if(Gsz == 1){                    \
        G = r8[reg];                        \
    } else if(Gsz == 2){                    \
        G = r16[reg];                       \
    } else if(Gsz == 3){                    \
        G = r32[reg];                       \
    } else if(Gsz == 4){                    \
        if(reg < 8){                        \
            G = rseg[reg];                  \
        } else{                             \
            puts("Invalid Mod R/M byte.");  \
            exit(-1);                       \
        }                                   \
    } else{                                 \
        puts("Invalid Mod R/M byte.");      \
        exit(-1);                           \
    }

unsigned char *f_entry;
unsigned int entry;
char *r8[] = {"al","cl","dl","bl","ah","ch","dh","bh"};
char *r16[] = {"ax","cx","dx","bx","sp","bp","si","di"};
char *r32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};
char *rseg[] = {"ds","es","fs","gs","ss","cs","ip"};

//order- 1: E/E, G | 0: G, E         //convert to enums
//Gsz-    0: none | 1: b | 2: w | 3: dw
int decodeModSM(unsigned char *a, char *op, int order, int Gsz, int Esz){
    int len = 0;
    int reg = 0;
    int scale = 0;
    unsigned char *b = a;
    char *E, *G, *indx, *base, *disp = "\0"; 
    char ebuf[32] = {0};
    
    setG();
    
    //set E
    if(Esz){ //use 16-bit addressing forms
        switch(*b&0xc7){
            case 0x00:
                E = "[bx+si]";
                break;
            case 0x01:
                E = "[bx+di]";
                break;
            case 0x02:
                E = "[bp+si]";
                break;
            case 0x03:
                E = "[bp+di]";
                break;
            case 0x04:
                E = "[si]";
                break;
            case 0x05:
                E = "[di]";
                break;
            case 0x06:
                snprintf(ebuf, sizeof(ebuf), "ds:%p", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x07:
                E = "[bx]";
                break;
            case 0x40:
                snprintf(ebuf, sizeof(ebuf), "[bx+si+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x41:
                snprintf(ebuf, sizeof(ebuf), "[bx+di+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x42:
                snprintf(ebuf, sizeof(ebuf), "[bp+si+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x43:
                snprintf(ebuf, sizeof(ebuf), "[bp+di+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x44:
                snprintf(ebuf, sizeof(ebuf), "[si+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x45:
                snprintf(ebuf, sizeof(ebuf), "[di+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x46:
                snprintf(ebuf, sizeof(ebuf), "[bp+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x47:
                snprintf(ebuf, sizeof(ebuf), "[bx+%p]", *(char *)++b); 
                E = ebuf;
            case 0x80:
                snprintf(ebuf, sizeof(ebuf), "[bx+si+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x81:
                snprintf(ebuf, sizeof(ebuf), "[bx+di+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x82:
                snprintf(ebuf, sizeof(ebuf), "[bp+si+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x83:
                snprintf(ebuf, sizeof(ebuf), "[bp+di+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x84:
                snprintf(ebuf, sizeof(ebuf), "[si+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x85:
                snprintf(ebuf, sizeof(ebuf), "[di+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x86:
                snprintf(ebuf, sizeof(ebuf), "[bp+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x87:
                snprintf(ebuf, sizeof(ebuf), "[bx+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0xc0:
                E = "al";
                break;
            case 0xc1:
                E = "cl";
                break;
            case 0xc2:
                E = "dl";
                break;
            case 0xc3:
                E = "bl";
                break;
            case 0xc4:
                E = "ah";
                break;
            case 0xc5:
                E = "ch";
                break;
            case 0xc6:
                E = "dh";
                break;
            case 0xc7:
                E = "bh";
                break;
            default:
                puts("Invalid Mod R/M byte.");
                exit(-1);
        }   
    } else{ //use 32-bit addressing forms
        switch(*b&0xc7){
            case 0x00:
                E = "[eax]";
                break;
            case 0x01:
                E = "[ecx]";
                break;
            case 0x02:
                E = "[edx]";
                break;
            case 0x03:
                E = "[ebx]";
                break;
            case 0x04:
                ++b;
                decodeSIB();
                if(!indx){
                    snprintf(ebuf, sizeof(ebuf), "[%s]", base);
                } else if(!base){
                    if(!scale){
                        snprintf(ebuf, sizeof(ebuf), "[%s]", indx);
                    } else{
                        snprintf(ebuf, sizeof(ebuf), "[%s*%i]", indx, scale);
                    }
                } else if(!scale){
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s]", base, indx);
                } else{
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s*%i]", base, indx, scale);
                }
                E = ebuf;
                break;
            case 0x05:
                snprintf(ebuf, sizeof(ebuf), "ds:%p", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x06:
                E = "[esi]";
                break;
            case 0x07:
                E = "[edi]";
                break;
             case 0x40:
                snprintf(ebuf, sizeof(ebuf), "[eax+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x41:
                snprintf(ebuf, sizeof(ebuf), "[ecx+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x42:
                snprintf(ebuf, sizeof(ebuf), "[edx+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x43:
                snprintf(ebuf, sizeof(ebuf), "[ebx+%p]", *(char *)++b); 
                E = ebuf;
            case 0x44:
                ++b;
                decodeSIB(); 
                if(!indx){
                    snprintf(ebuf, sizeof(ebuf), "[%s", base);
                } else if(!base){
                    if(!scale){
                        snprintf(ebuf, sizeof(ebuf), "[%s", indx);
                    } else{
                        snprintf(ebuf, sizeof(ebuf), "[%s*%i", indx, scale);
                    }
                } else if(!scale){
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s", base, indx);
                } else{
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s*%i", base, indx, scale);
                }
                len = strlen(ebuf);
                snprintf(ebuf+len, sizeof(ebuf)-len, "+%p]", *(char *)++b);
                E = ebuf;
                break;
            case 0x45:
                snprintf(ebuf, sizeof(ebuf), "[ebp+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x46:
                snprintf(ebuf, sizeof(ebuf), "[esi+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x47:
                snprintf(ebuf, sizeof(ebuf), "[edi+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x80:
                snprintf(ebuf, sizeof(ebuf), "[eax+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x81:
                snprintf(ebuf, sizeof(ebuf), "[ecx+%p]", *(int *)++b); 
                E = ebuf;
                break;
            case 0x82:
                snprintf(ebuf, sizeof(ebuf), "[edx+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x83:
                snprintf(ebuf, sizeof(ebuf), "[ebx+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
             case 0x84:
                ++b;
                decodeSIB(); 
                if(!indx){
                    snprintf(ebuf, sizeof(ebuf), "[%s", base);
                } else if(!base){
                    if(!scale){
                        snprintf(ebuf, sizeof(ebuf), "[%s", indx);
                    } else{
                        snprintf(ebuf, sizeof(ebuf), "[%s*%i", indx, scale);
                    }
                } else if(!scale){
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s", base, indx);
                } else{
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s*%i", base, indx, scale);
                }
                len = strlen(ebuf);
                snprintf(ebuf+len, sizeof(ebuf)-len, "+%p]", *(int *)++b);
                b += 3;
                E = ebuf;
                break;
           case 0x85:
                snprintf(ebuf, sizeof(ebuf), "[ebp+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x86:
                snprintf(ebuf, sizeof(ebuf), "[esi+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x87:
                snprintf(ebuf, sizeof(ebuf), "[edi+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
           case 0xc0:
                E = Esz == 1 ? "ax": "eax";
                break;
            case 0xc1:
                E = Esz == 1 ? "cx": "ecx";
                break;
            case 0xc2:
                E = Esz == 1 ? "dx": "edx";
                break;
            case 0xc3:
                E = Esz == 1 ? "bx": "ebx";
                break;
            case 0xc4:
                E = Esz == 1 ? "sp": "esp";
                break;
            case 0xc5:
                E = Esz == 1 ? "bp": "ebp";
                break;
            case 0xc6:
                E = Esz == 1 ? "si": "esi";
                break;
            case 0xc7:
                E = Esz == 1 ? "di": "edi";
                break;
            default:
                puts("Invalid Mod R/M byte.");
                exit(-1);
        }
    }

    if(order){
        snprintf(op, opBufSz, "%s", E);
        len = strlen(op);
        if(Gsz){
            snprintf(op+len, opBufSz-len, ", %s", G);
        }
    } else{
        snprintf(op, opBufSz, "%s, ", G);
        len = strlen(op);
        snprintf(op+len, opBufSz-len, "%s", E);
    }
    return b-a;
}

int decodeModSM_float(unsigned char *a, char *op, int order, int Gsz, int Esz){
    int len = 0;
    int reg = 0;
    int scale = 0;
    unsigned char *b = a;
    char *E, *G, *indx, *base, *disp = "\0"; 
    char ebuf[32] = {0};
    
    setG();
    
    //set E
    if(Esz){ //use 16-bit addressing forms
        switch(*b&0xc7){
            case 0x00:
                E = "[bx+si]";
                break;
            case 0x01:
                E = "[bx+di]";
                break;
            case 0x02:
                E = "[bp+si]";
                break;
            case 0x03:
                E = "[bp+di]";
                break;
            case 0x04:
                E = "[si]";
                break;
            case 0x05:
                E = "[di]";
                break;
            case 0x06:
                snprintf(ebuf, sizeof(ebuf), "ds:%p", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x07:
                E = "[bx]";
                break;
            case 0x40:
                snprintf(ebuf, sizeof(ebuf), "[bx+si+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x41:
                snprintf(ebuf, sizeof(ebuf), "[bx+di+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x42:
                snprintf(ebuf, sizeof(ebuf), "[bp+si+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x43:
                snprintf(ebuf, sizeof(ebuf), "[bp+di+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x44:
                snprintf(ebuf, sizeof(ebuf), "[si+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x45:
                snprintf(ebuf, sizeof(ebuf), "[di+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x46:
                snprintf(ebuf, sizeof(ebuf), "[bp+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x47:
                snprintf(ebuf, sizeof(ebuf), "[bx+%p]", *(char *)++b); 
                E = ebuf;
            case 0x80:
                snprintf(ebuf, sizeof(ebuf), "[bx+si+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x81:
                snprintf(ebuf, sizeof(ebuf), "[bx+di+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x82:
                snprintf(ebuf, sizeof(ebuf), "[bp+si+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x83:
                snprintf(ebuf, sizeof(ebuf), "[bp+di+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x84:
                snprintf(ebuf, sizeof(ebuf), "[si+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x85:
                snprintf(ebuf, sizeof(ebuf), "[di+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x86:
                snprintf(ebuf, sizeof(ebuf), "[bp+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x87:
                snprintf(ebuf, sizeof(ebuf), "[bx+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0xc0:
                E = "st(0)";
                break;
            case 0xc1:
                E = "st(1)";
                break;
            case 0xc2:
                E = "st(2)";
                break;
            case 0xc3:
                E = "st(3)";
                break;
            case 0xc4:
                E = "st(4)";
                break;
            case 0xc5:
                E = "st(5)";
                break;
            case 0xc6:
                E = "st(6)";
                break;
            case 0xc7:
                E = "st(7)";
                break;
            default:
                puts("Invalid Mod R/M byte.");
                exit(-1);
        }   
    } else{ //use 32-bit addressing forms
        switch(*b&0xc7){
            case 0x00:
                E = "[eax]";
                break;
            case 0x01:
                E = "[ecx]";
                break;
            case 0x02:
                E = "[edx]";
                break;
            case 0x03:
                E = "[ebx]";
                break;
            case 0x04:
                ++b;
                decodeSIB();
                if(!indx){
                    snprintf(ebuf, sizeof(ebuf), "[%s]", base);
                } else if(!base){
                    if(!scale){
                        snprintf(ebuf, sizeof(ebuf), "[%s]", indx);
                    } else{
                        snprintf(ebuf, sizeof(ebuf), "[%s*%i]", indx, scale);
                    }
                } else if(!scale){
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s]", base, indx);
                } else{
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s*%i]", base, indx, scale);
                }
                E = ebuf;
                break;
            case 0x05:
                snprintf(ebuf, sizeof(ebuf), "ds:%p", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x06:
                E = "[esi]";
                break;
            case 0x07:
                E = "[edi]";
                break;
             case 0x40:
                snprintf(ebuf, sizeof(ebuf), "[eax+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x41:
                snprintf(ebuf, sizeof(ebuf), "[ecx+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x42:
                snprintf(ebuf, sizeof(ebuf), "[edx+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x43:
                snprintf(ebuf, sizeof(ebuf), "[ebx+%p]", *(char *)++b); 
                E = ebuf;
            case 0x44:
                ++b;
                decodeSIB(); 
                if(!indx){
                    snprintf(ebuf, sizeof(ebuf), "[%s", base);
                } else if(!base){
                    if(!scale){
                        snprintf(ebuf, sizeof(ebuf), "[%s", indx);
                    } else{
                        snprintf(ebuf, sizeof(ebuf), "[%s*%i", indx, scale);
                    }
                } else if(!scale){
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s", base, indx);
                } else{
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s*%i", base, indx, scale);
                }
                len = strlen(ebuf);
                snprintf(ebuf+len, sizeof(ebuf)-len, "+%p]", *(char *)++b);
                E = ebuf;
                break;
            case 0x45:
                snprintf(ebuf, sizeof(ebuf), "[ebp+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x46:
                snprintf(ebuf, sizeof(ebuf), "[esi+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x47:
                snprintf(ebuf, sizeof(ebuf), "[edi+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x80:
                snprintf(ebuf, sizeof(ebuf), "[eax+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x81:
                snprintf(ebuf, sizeof(ebuf), "[ecx+%p]", *(int *)++b); 
                E = ebuf;
                break;
            case 0x82:
                snprintf(ebuf, sizeof(ebuf), "[edx+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x83:
                snprintf(ebuf, sizeof(ebuf), "[ebx+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
             case 0x84:
                ++b;
                decodeSIB(); 
                if(!indx){
                    snprintf(ebuf, sizeof(ebuf), "[%s", base);
                } else if(!base){
                    if(!scale){
                        snprintf(ebuf, sizeof(ebuf), "[%s", indx);
                    } else{
                        snprintf(ebuf, sizeof(ebuf), "[%s*%i", indx, scale);
                    }
                } else if(!scale){
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s", base, indx);
                } else{
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s*%i", base, indx, scale);
                }
                len = strlen(ebuf);
                snprintf(ebuf+len, sizeof(ebuf)-len, "+%p]", *(int *)++b);
                b += 3;
                E = ebuf;
                break;
           case 0x85:
                snprintf(ebuf, sizeof(ebuf), "[ebp+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x86:
                snprintf(ebuf, sizeof(ebuf), "[esi+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x87:
                snprintf(ebuf, sizeof(ebuf), "[edi+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
           case 0xc0:
                E = "st(0)";
                break;
            case 0xc1:
                E = "st(1)";
                break;
            case 0xc2:
                E = "st(2)";
                break;
            case 0xc3:
                E = "st(3)";
                break;
            case 0xc4:
                E = "st(4)";
                break;
            case 0xc5:
                E = "st(5)";
                break;
            case 0xc6:
                E = "st(6)";
                break;
            case 0xc7:
                E = "st(7)";
                break;
            default:
                puts("Invalid Mod R/M byte.");
                exit(-1);
        }
    }

    if(order){
        snprintf(op, opBufSz, "%s", E);
        len = strlen(op);
        if(Gsz){
            snprintf(op+len, opBufSz-len, ", %s", G);
        }
    } else{
        snprintf(op, opBufSz, "%s, ", G);
        len = strlen(op);
        snprintf(op+len, opBufSz-len, "%s", E);
    }
    return b-a;
}

int decodeModSM_memonly(unsigned char *a, char *op, int order, int Gsz, int Esz){
    int len = 0;
    int reg = 0;
    int scale = 0;
    unsigned char *b = a;
    char *E, *G, *indx, *base, *disp = "\0"; 
    char ebuf[32] = {0};
    
    setG();
    
    //set E
    if(Esz){ //use 16-bit addressing forms
        switch(*b&0xc7){
            case 0x00:
                E = "[bx+si]";
                break;
            case 0x01:
                E = "[bx+di]";
                break;
            case 0x02:
                E = "[bp+si]";
                break;
            case 0x03:
                E = "[bp+di]";
                break;
            case 0x04:
                E = "[si]";
                break;
            case 0x05:
                E = "[di]";
                break;
            case 0x06:
                snprintf(ebuf, sizeof(ebuf), "ds:%p", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x07:
                E = "[bx]";
                break;
            case 0x40:
                snprintf(ebuf, sizeof(ebuf), "[bx+si+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x41:
                snprintf(ebuf, sizeof(ebuf), "[bx+di+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x42:
                snprintf(ebuf, sizeof(ebuf), "[bp+si+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x43:
                snprintf(ebuf, sizeof(ebuf), "[bp+di+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x44:
                snprintf(ebuf, sizeof(ebuf), "[si+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x45:
                snprintf(ebuf, sizeof(ebuf), "[di+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x46:
                snprintf(ebuf, sizeof(ebuf), "[bp+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x47:
                snprintf(ebuf, sizeof(ebuf), "[bx+%p]", *(char *)++b); 
                E = ebuf;
            case 0x80:
                snprintf(ebuf, sizeof(ebuf), "[bx+si+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x81:
                snprintf(ebuf, sizeof(ebuf), "[bx+di+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x82:
                snprintf(ebuf, sizeof(ebuf), "[bp+si+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x83:
                snprintf(ebuf, sizeof(ebuf), "[bp+di+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x84:
                snprintf(ebuf, sizeof(ebuf), "[si+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x85:
                snprintf(ebuf, sizeof(ebuf), "[di+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x86:
                snprintf(ebuf, sizeof(ebuf), "[bp+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            case 0x87:
                snprintf(ebuf, sizeof(ebuf), "[bx+%p]", *(short *)++b); 
                E = ebuf;
                ++b;
                break;
            default:
                puts("Invalid Mod R/M byte.");
                exit(-1);
        }   
    } else{ //use 32-bit addressing forms
        switch(*b&0xc7){
            case 0x00:
                E = "[eax]";
                break;
            case 0x01:
                E = "[ecx]";
                break;
            case 0x02:
                E = "[edx]";
                break;
            case 0x03:
                E = "[ebx]";
                break;
            case 0x04:
                ++b;
                decodeSIB();
                if(!indx){
                    snprintf(ebuf, sizeof(ebuf), "[%s]", base);
                } else if(!base){
                    if(!scale){
                        snprintf(ebuf, sizeof(ebuf), "[%s]", indx);
                    } else{
                        snprintf(ebuf, sizeof(ebuf), "[%s*%i]", indx, scale);
                    }
                } else if(!scale){
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s]", base, indx);
                } else{
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s*%i]", base, indx, scale);
                }
                E = ebuf;
                break;
            case 0x05:
                snprintf(ebuf, sizeof(ebuf), "ds:%p", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x06:
                E = "[esi]";
                break;
            case 0x07:
                E = "[edi]";
                break;
             case 0x40:
                snprintf(ebuf, sizeof(ebuf), "[eax+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x41:
                snprintf(ebuf, sizeof(ebuf), "[ecx+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x42:
                snprintf(ebuf, sizeof(ebuf), "[edx+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x43:
                snprintf(ebuf, sizeof(ebuf), "[ebx+%p]", *(char *)++b); 
                E = ebuf;
            case 0x44:
                ++b;
                decodeSIB(); 
                if(!indx){
                    snprintf(ebuf, sizeof(ebuf), "[%s", base);
                } else if(!base){
                    if(!scale){
                        snprintf(ebuf, sizeof(ebuf), "[%s", indx);
                    } else{
                        snprintf(ebuf, sizeof(ebuf), "[%s*%i", indx, scale);
                    }
                } else if(!scale){
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s", base, indx);
                } else{
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s*%i", base, indx, scale);
                }
                len = strlen(ebuf);
                snprintf(ebuf+len, sizeof(ebuf)-len, "+%p]", *(char *)++b);
                E = ebuf;
                break;
            case 0x45:
                snprintf(ebuf, sizeof(ebuf), "[ebp+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x46:
                snprintf(ebuf, sizeof(ebuf), "[esi+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x47:
                snprintf(ebuf, sizeof(ebuf), "[edi+%p]", *(char *)++b); 
                E = ebuf;
                break;
            case 0x80:
                snprintf(ebuf, sizeof(ebuf), "[eax+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x81:
                snprintf(ebuf, sizeof(ebuf), "[ecx+%p]", *(int *)++b); 
                E = ebuf;
                break;
            case 0x82:
                snprintf(ebuf, sizeof(ebuf), "[edx+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x83:
                snprintf(ebuf, sizeof(ebuf), "[ebx+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
             case 0x84:
                ++b;
                decodeSIB(); 
                if(!indx){
                    snprintf(ebuf, sizeof(ebuf), "[%s", base);
                } else if(!base){
                    if(!scale){
                        snprintf(ebuf, sizeof(ebuf), "[%s", indx);
                    } else{
                        snprintf(ebuf, sizeof(ebuf), "[%s*%i", indx, scale);
                    }
                } else if(!scale){
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s", base, indx);
                } else{
                    snprintf(ebuf, sizeof(ebuf), "[%s+%s*%i", base, indx, scale);
                }
                len = strlen(ebuf);
                snprintf(ebuf+len, sizeof(ebuf)-len, "+%p]", *(int *)++b);
                b += 3;
                E = ebuf;
                break;
           case 0x85:
                snprintf(ebuf, sizeof(ebuf), "[ebp+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x86:
                snprintf(ebuf, sizeof(ebuf), "[esi+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            case 0x87:
                snprintf(ebuf, sizeof(ebuf), "[edi+%p]", *(int *)++b); 
                E = ebuf;
                b += 3;
                break;
            default:
                puts("Invalid Mod R/M byte.");
                exit(-1);
        }
    }

    if(order){
        snprintf(op, opBufSz, "%s", E);
        len = strlen(op);
        if(Gsz){
            snprintf(op+len, opBufSz-len, ", %s", G);
        }
    } else{
        snprintf(op, opBufSz, "%s, ", G);
        len = strlen(op);
        snprintf(op+len, opBufSz-len, "%s", E);
    }
    return b-a;
}

int decode(unsigned char *a){
    unsigned char *b = a;
    int len = 0;
    int flip_addr_sz = 0;
    int flip_imm_sz = 0;
    int EG = 1; //specifices operand order for MOD R/M instructions
    int B  = 1; //specifies operand size for MOD R/M instructions
    char *s, *prefix, *seg_oride = "\0";
    char op1[opBufSz] = {0};
    
    //check for instruction prefix
    if(*b == 0xf3){
        prefix = "rep";
        ++b;
    } else if(*b == 0xf2){
        prefix = "repnz";
        ++b;
    } else if(*b == 0xf0){
        prefix = "lock";
        ++b;
    } 

    //check for addr/opperand size prefix
    if(*b == 0x67){
        flip_addr_sz = 1;
        ++b;
    }
    if (*b == 0x66){
        flip_imm_sz = 1;
        ++b;
    }
    //check for segment override
    switch(*b){
        case 0x2e:
            seg_oride = "cs";
            ++b;
            break;
        case 0x36:
            seg_oride = "ss";
            ++b;
            break;
        case 0x3e:
            seg_oride = "ds";
            ++b;
            break;
        case 0x26:
            seg_oride = "es";
            ++b;
            break;
        case 0x64:
            seg_oride = "fs";
            ++b;
            break;
        case 0x65:
            seg_oride = "gs";
            ++b;
    }

    if(*b == 0x0f){ //extended opcodes

        puts("Extended opcodes not implimented.\n");
        exit(-1);
    
    } else{
        
        switch(*b){
            case 0x00:
                s = "add";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x01:
                s = "add";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x02:
                s = "add";
                b += decodeModSM(++b, op1, 0, 1, flip_addr_sz);
                break;
            case 0x03:
                s = "add";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x04:
                s = "add";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0x05:
                s = "add";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x06:
                s = "push    es";
                break;
            case 0x07:
                s = "pop     es";
                break;
            case 0x08:
                s = "or";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x09:
                s = "or";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x0a:
                s = "or";
                b += decodeModSM(++b, op1, 0, 1, flip_addr_sz);
                break;
            case 0x0b:
                s = "or";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x0c:
                s = "or";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0x0d:
                s = "or";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x0e:
                s = "push    cs";
                break;
            case 0x10:
                s = "adc";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x11:
                s = "adc";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x12:
                s = "adc";
                b += decodeModSM(++b, op1, 0, 1, flip_addr_sz);
                break;
            case 0x13:
                s = "adc";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x14:
                s = "adc";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0x15:
                s = "adc";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x16:
                s = "push    ss";
                break;
            case 0x17:
                s = "pop     ss";
                break;
            case 0x18:
                s = "sbb";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x19:
                s = "sbb";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x1a:
                s = "sbb";
                b += decodeModSM(++b, op1, 0, 1, flip_addr_sz);
                break;
            case 0x1b:
                s = "sbb";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x1c:
                s = "sbb";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0x1d:
                s = "sbb";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x1e:
                s = "push    ds";
                break;
            case 0x1f:
                s = "pop     ds";
                break;
            case 0x20:
                s = "and";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x21:
                s = "and";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x22:
                s = "and";
                b += decodeModSM(++b, op1, 0, 1, flip_addr_sz);
                break;
            case 0x23:
                s = "and";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x24:
                s = "and";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0x25:
                s = "and";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x27:
                s = "daa";
                break;
            case 0x28:
                s = "sub";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x29:
                s = "sub";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x2a:
                s = "sub";
                b += decodeModSM(++b, op1, 0, 1, flip_addr_sz);
                break;
            case 0x2b:
                s = "sub";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x2c:
                s = "sub";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0x2d:
                s = "sub";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x2f:
                s = "das";
                break;
            case 0x30:
                s = "xor";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x31:
                s = "xor";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x32:
                s = "xor";
                b += decodeModSM(++b, op1, 0, 1, flip_addr_sz);
                break;
            case 0x33:
                s = "xor";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x34:
                s = "xor";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0x35:
                s = "xor";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x37:
                s = "aaa";
                break;
            case 0x38:
                s = "cmp";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x39:
                s = "cmp";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x3a:
                s = "cmp";
                b += decodeModSM(++b, op1, 0, 1, flip_addr_sz);
                break;
            case 0x3b:
                s = "cmp";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x3c:
                s = "cmp";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0x3d:
                s = "cmp";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x3f:
                s = "aas";
                break;
            case 0x40:
                s = flip_imm_sz ? "inc     ax": "inc     eax";
                break;
            case 0x41:
                s = flip_imm_sz ? "inc     cx": "inc     ecx";
                break;
            case 0x42:
                s = flip_imm_sz ? "inc     dx": "inc     edx";
                break;
            case 0x43:
                s = flip_imm_sz ? "inc     bx": "inc     ebx";
                break;
            case 0x44:
                s = flip_imm_sz ? "inc     sp": "inc     esp";
                break;
            case 0x45:
                s = flip_imm_sz ? "inc     bp": "inc     ebp";
                break;
            case 0x46:
                s = flip_imm_sz ? "inc     si": "inc     esi";
                break;
            case 0x47:
                s = flip_imm_sz ? "inc     di": "inc     edi";
                break;
            case 0x48:
                s = flip_imm_sz ? "dec     ax": "dec     eax";
                break;
            case 0x49:
                s = flip_imm_sz ? "dec     cx": "dec     ecx";
                break;
            case 0x4a:
                s = flip_imm_sz ? "dec     dx": "dec     edx";
                break;
            case 0x4b:
                s = flip_imm_sz ? "dec     bx": "dec     ebx";
                break;
            case 0x4c:
                s = flip_imm_sz ? "dec     sp": "dec     esp";
                break;
            case 0x4d:
                s = flip_imm_sz ? "dec     bp": "dec     ebp";
                break;
            case 0x4e:
                s = flip_imm_sz ? "dec     si": "dec     esi";
                break;
            case 0x4f:
                s = flip_imm_sz ? "dec     di": "dec     edi";
                break;
            case 0x50:
                s = flip_imm_sz ? "push    ax": "push    eax";
                break;
            case 0x51:
                s = flip_imm_sz ? "push    cx": "push    ecx";
                break;
            case 0x52:
                s = flip_imm_sz ? "push    dx": "push    edx";
                break;
            case 0x53:
                s = flip_imm_sz ? "push    bx": "push    ebx";
                break;
            case 0x54:
                s = flip_imm_sz ? "push    sp": "push    esp";
                break;
            case 0x55:
                s = flip_imm_sz ? "push    bp": "push    ebp";
                break;
            case 0x56:
                s = flip_imm_sz ? "push    si": "push    esi";
                break;
            case 0x57:
                s = flip_imm_sz ? "push    di": "push    edi";
                break;
            case 0x58:
                s = flip_imm_sz ? "pop     ax": "pop     eax";
                break;
            case 0x59:
                s = flip_imm_sz ? "pop     cx": "pop     ecx";
                break;
            case 0x5a:
                s = flip_imm_sz ? "pop     dx": "pop     edx";
                break;
            case 0x5b:
                s = flip_imm_sz ? "pop     bx": "pop     ebx";
                break;
            case 0x5c:
                s = flip_imm_sz ? "pop     sp": "pop     esp";
                break;
            case 0x5d:
                s = flip_imm_sz ? "pop     bp": "pop     ebp";
                break;
            case 0x5e:
                s = flip_imm_sz ? "pop     si": "pop     esi";
                break;
            case 0x5f:
                s = flip_imm_sz ? "pop     di": "pop     edi";
                break;
            case 0x60:
                s = flip_imm_sz ? "pushaw": "pusha";
                break;
            case 0x61:
                s = flip_imm_sz ? "popaw": "popa";
                break;
            case 0x63:
                s = "arpl";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x68:
                s = "push";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "%p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "%p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x69:
                s = "imul";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                len = strlen(op1);
                if(flip_imm_sz){
                    snprintf(op1+len, sizeof(op1)-len, ", %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1+len, sizeof(op1)-len, ", %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0x6a:
                s = "push";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)*b);
            case 0x6b:
                s = "imul";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", %p", *(char *)++b);
               break;
            case 0x6c:
                s = flip_addr_sz ? "ins     bytes ptr es:[di], dx": "insb";
                break;
            case 0x6d:
                if(flip_addr_sz){
                    s = flip_imm_sz ? "ins     word ptr es:[di], dx": "ins     dword ptr es:[di], dx";
                } else{
                    s = flip_imm_sz ? "insw": "insd";
                }
                break;
            case 0x6e:
                s = flip_addr_sz ? "outs    dx, byte ptr [si]": "outsb";
                break;
            case 0x6f:
                if(flip_addr_sz){
                    s = flip_imm_sz ? "outs    dx, word ptr [si]": "outs    dx, dword ptr [si]";
                } else{
                    s = flip_imm_sz ? "outsw": "outsd";
                }
                break;
            case 0x70:
                s = "jo";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x71:
                s = "jno";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x72:
                s = "jb";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x73:
                s = "jnb";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x74:
                s = "jz";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x75:
                s = "jnz";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x76:
                s = "jbe";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x77:
                s = "ja";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x78:
                s = "js";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x79:
                s = "jns";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x7a:
                s = "jp";
                ++b;
                break;
            case 0x7b:
                s = "jnp";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x7c:
                s = "jl";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x7d:
                s = "jnl";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x7e:
                s = "jle";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x7f:
                s = "jnle";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0x80:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "add";
                        break;
                    case 1:
                        s = "or";
                        break;
                    case 2:
                        s = "adc";
                        break;
                    case 3:
                        s = "sbb";
                        break;
                    case 4:
                        s = "and";
                        break;
                    case 5:
                        s = "sub";
                        break;
                    case 6:
                        s = "xor";
                        break;
                    case 7:
                        s = "cmp";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", %p", *(char *)++b);
                break;
             case 0x81:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                 switch((*b&0x38)/8){
                    case 0:
                        s = "add";
                        break;
                    case 1:
                        s = "or";
                        break;
                    case 2:
                        s = "adc";
                        break;
                    case 3:
                        s = "sbb";
                        break;
                    case 4:
                        s = "and";
                        break;
                    case 5:
                        s = "sub";
                        break;
                    case 6:
                        s = "xor";
                        break;
                    case 7:
                        s = "cmp";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                len = strlen(op1);
                if(flip_imm_sz){
                    snprintf(op1+len, sizeof(op1)-len, ", %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1+len, sizeof(op1)-len, ", %p", *(int *)++b);
                    b += 3;
                }
                break;
           case 0x82:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "add";
                        break;
                    case 1:
                        s = "or";
                        break;
                    case 2:
                        s = "adc";
                        break;
                    case 3:
                        s = "sbb";
                        break;
                    case 4:
                        s = "and";
                        break;
                    case 5:
                        s = "sub";
                        break;
                    case 6:
                        s = "xor";
                        break;
                    case 7:
                        s = "cmp";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
               len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", %p", *(char *)++b);
                break;
           case 0x83:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "add";
                        break;
                    case 1:
                        s = "or";
                        break;
                    case 2:
                        s = "adc";
                        break;
                    case 3:
                        s = "sbb";
                        break;
                    case 4:
                        s = "and";
                        break;
                    case 5:
                        s = "sub";
                        break;
                    case 6:
                        s = "xor";
                        break;
                    case 7:
                        s = "cmp";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", %p", *(char *)++b);
                break;
            case 0x84:
                s = "test";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x85:
                s = "test";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x86:
                s = "xchg";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x87:
                s = "xchg";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x88:
                s = "mov";
                b += decodeModSM(++b, op1, 1, 1, flip_addr_sz);
                break;
            case 0x89:
                s = "mov";
                b += decodeModSM(++b, op1, 1, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x8a:
                s = "mov";
                b += decodeModSM(++b, op1, 0, 1, flip_addr_sz);
                break;
            case 0x8b:
                s = "mov";
                b += decodeModSM(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x8c:
                s = "mov";
                b += decodeModSM(++b, op1, 1, 4, flip_addr_sz);
                break;
            case 0x8d: 
                s = "lea";
                b += decodeModSM_memonly(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0x8e:
                s = "mov";
                b += decodeModSM(++b, op1, 0, 4, flip_addr_sz);
                break;
            case 0x8f:
                s = "pop";
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                break;
            case 0x90:
                s = flip_imm_sz ? "xchg    ax, ax": "nop";
                break;
            case 0x91:
                s = flip_imm_sz ? "xchg    ax, cx": "xchg    eax, ecx";
                break;
            case 0x92:
                s = flip_imm_sz ? "xchg    ax, dx": "xchg    eax, edx";
                break;
            case 0x93:
                s = flip_imm_sz ? "xchg    ax, bx": "xchg    eax, ebx";
                break;
            case 0x94:
                s = flip_imm_sz ? "xchg    ax, sp": "xchg    eax, esp";
                break;
            case 0x95:
                s = flip_imm_sz ? "xchg    ax, bp": "xchg    eax, ebp";
                break;
            case 0x96:
                s = flip_imm_sz ? "xchg    ax, si": "xchg    eax, esi";
                break;
            case 0x97:
                s = flip_imm_sz ? "xchg    ax, di": "xchg    eax, edi";
                break;
            case 0x98:
                s = flip_imm_sz ? "cbw": "cwde";
                break;
            case 0x99:
                s = flip_imm_sz ? "cwd": "cdq";
                break;
            case 0x9a:
                s = "call";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "%p:%p", *(short *)(b+2), *(short *)++b);
                    b += 3;                
                } else{
                    snprintf(op1, sizeof(op1), "far ptr %p:%p", *(short *)(b+4), *(int *)++b);
                    b += 5;
                }
                break;
            case 0x9b:
                s = "wait";
                break;
            case 0x9c:
                s = flip_imm_sz ? "pushfw": "pushf";
                break;
            case 0x9d:
                s = flip_imm_sz ? "popfw": "popf";
                break;
            case 0x9e:
                s = "sahf";
                break;
            case 0x9f:
                s = "lahf";
                break;
            case 0xa0:
                s = "mov";
                snprintf(op1, sizeof(op1), "al, ds:%p", *(int *)++b); //add seg oride
                b += 3;
                break;
            case 0xa1:
                s = "mov";
                snprintf(op1, sizeof(op1), flip_imm_sz ? "ax, ds:%p": "eax, ds:%p", *(int *)++b); //add seg oride
                b += 3;
                break;
            case 0xa2:
                s = "mov";
                snprintf(op1, sizeof(op1), "ds:%p, al", *(int *)++b); //add seg oride
                b += 3;
                break;
            case 0xa3:
                s = "mov";
                snprintf(op1, sizeof(op1), flip_imm_sz ? "ds:%p, ax": "ds:%p, eax", *(int *)++b); //add seg oride
                b += 3;
                break;
            case 0xa4:
                s = flip_addr_sz ? "movs    byte ptr es:[di], byte ptr [si]": "movsb";
                break;
            case 0xa5:
                if(flip_addr_sz){
                    s = flip_imm_sz ? "movs    word ptr es:[di], word ptr [si]": "movs    dword ptr es:[di], dword ptr [si]";
                } else{
                    s = flip_imm_sz ? "movsw": "movsd";
                }
                break;
            case 0xa6:
                s = flip_addr_sz ? "cmps    byte ptr [si], byte ptr es:[di]": "cmpsb";
                break;
            case 0xa7:
                if(flip_addr_sz){
                    s = flip_imm_sz ? "movs    word ptr [si], word ptr es:[di]": "movs    dword ptr [si], dword ptr es:[di]";
                } else{
                    s = flip_imm_sz ? "cmpsw": "cmpsd";
                }
                break;
            case 0xa8:
                s = "test";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0xa9:
                s = "test";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    b += 3;
                }
                break;
            case 0xaa:
                s = flip_addr_sz ? "stos    byte ptr es:[di]": "stosb";
                break;
            case 0xab:
                if(flip_addr_sz){
                    s = flip_imm_sz ? "stos    word ptr es:[di]": "stos    dword ptr es:[di]";
                } else{
                    s = flip_imm_sz ? "stosw": "stosd";
                }
                break;
            case 0xac:
                s = flip_addr_sz ? "lods    byte ptr [si]": "lodsb";
                break;
            case 0xad:
                if(flip_addr_sz){
                    s = flip_imm_sz ? "lods    word ptr [si]": "lods    dword ptr [si]";
                } else{
                    s = flip_imm_sz ? "lodsw": "lodsd";
                }
                break;
            case 0xae:
                s = flip_addr_sz ? "scas    byte ptr es:[di]": "scasb";
                break;
            case 0xaf:
                if(flip_addr_sz){
                    s = flip_imm_sz ? "scas    word ptr es:[di]": "scas    dword ptr es:[di]";
                } else{
                    s = flip_imm_sz ? "scasw": "scasd";
                }
                break;
            case 0xb0:
                s = "mov";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0xb1:
                s = "mov";
                ++b;
                snprintf(op1, sizeof(op1), "cl, %p", (void *)*b);
                break;
            case 0xb2:
                s = "mov";
                ++b;
                snprintf(op1, sizeof(op1), "dl, %p", (void *)*b);
                break;
            case 0xb3:
                s = "mov";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0xb4:
                s = "mov";
                ++b;
                snprintf(op1, sizeof(op1), "ah, %p", (void *)*b);
                break;
            case 0xb5:
                s = "mov";
                ++b;
                snprintf(op1, sizeof(op1), "ch, %p", (void *)*b);
                break;
            case 0xb6:
                s = "mov";
                ++b;
                snprintf(op1, sizeof(op1), "dh, %p", (void *)*b);
                break;
            case 0xb7:
                s = "mov";
                ++b;
                snprintf(op1, sizeof(op1), "bh, %p", (void *)*b);
                break;
            case 0xb8:
                s = "mov";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "ax, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "eax, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0xb9:
                s = "mov";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "cx, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "ecx, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0xba:
                s = "mov";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "dx, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "edx, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0xbb:
                s = "mov";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "bx, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "ebx, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0xbc:
                s = "mov";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "sp, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "esp, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0xbd:
                s = "mov";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "bp, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "ebp, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0xbe:
                s = "mov";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "si, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "esi, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0xbf:
                s = "mov";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "di, %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "edi, %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0xc0:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "rol";
                        break;
                    case 1:
                        s = "ror";
                        break;
                    case 2:
                        s = "rcl";
                        break;
                    case 3:
                        s = "rcr";
                        break;
                    case 4:
                        s = "shl";
                        break;
                    case 5:
                        s = "shr";
                        break;
                    case 6:
                        s = "shl";
                        break;
                    case 7:
                        s = "sar";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", %p", *(char *)++b);
                break;
            case 0xc1:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "rol";
                        break;
                    case 1:
                        s = "ror";
                        break;
                    case 2:
                        s = "rcl";
                        break;
                    case 3:
                        s = "rcr";
                        break;
                    case 4:
                        s = "shl";
                        break;
                    case 5:
                        s = "shr";
                        break;
                    case 6:
                        s = "shl";
                        break;
                    case 7:
                        s = "sar";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", %p", *(char *)++b);
                break;
           case 0xc2:
                s = "retn";
                snprintf(op1, sizeof(op1), "%p", *(short *)++b);
                ++b;
                break;
            case 0xc3:
                s = "retn";
                break;
            case 0xc4: //add mandatory segment selection
                s = "les";
                b += decodeModSM_memonly(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0xc5: //add mandatory segment selection
                s = "lds";
                b += decodeModSM_memonly(++b, op1, 0, flip_imm_sz ? 2: 3, flip_addr_sz);
                break;
            case 0xc6:
                s = "mov";
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", %p", *(char *)++b);
                break;
            case 0xc7:
                s = "mov";
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                len = strlen(op1);
                if(flip_imm_sz){
                    snprintf(op1+len, sizeof(op1)-len, ", %p", *(short *)++b);
                    ++b;
                } else{
                    snprintf(op1+len, sizeof(op1)-len, ", %p", *(int *)++b);
                    b += 3;
                }
                break;
            case 0xc8:
                s = "enter";
                snprintf(op1, sizeof(op1), "%p, %p", *(short *)(b+1), *(char *)(b+3));
                b += 3;
                break;
            case 0xc9:
                s = "leave";
                break;
            case 0xca:
                s = "retf";
                snprintf(op1, sizeof(op1), "%p", *(short *)++b);
                ++b;
                break;
            case 0xcb:
                s = "retf";
                break;
            case 0xcc:
                s = "int     3";
                break;
            case 0xcd:
                s = "int";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)*b);
                break;
            case 0xce:
                s = "into";
                break;
            case 0xcf:
                s = "iret";
                break;
            case 0xd0:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "rol";
                        break;
                    case 1:
                        s = "ror";
                        break;
                    case 2:
                        s = "rcl";
                        break;
                    case 3:
                        s = "rcr";
                        break;
                    case 4:
                        s = "shl";
                        break;
                    case 5:
                        s = "shr";
                        break;
                    case 6:
                        s = "shl";
                        break;
                    case 7:
                        s = "sar";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", 1");
                break;
            case 0xd1:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "rol";
                        break;
                    case 1:
                        s = "ror";
                        break;
                    case 2:
                        s = "rcl";
                        break;
                    case 3:
                        s = "rcr";
                        break;
                    case 4:
                        s = "shl";
                        break;
                    case 5:
                        s = "shr";
                        break;
                    case 6:
                        s = "shl";
                        break;
                    case 7:
                        s = "sar";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", 1");
                break;
            case 0xd2:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "rol";
                        break;
                    case 1:
                        s = "ror";
                        break;
                    case 2:
                        s = "rcl";
                        break;
                    case 3:
                        s = "rcr";
                        break;
                    case 4:
                        s = "shl";
                        break;
                    case 5:
                        s = "shr";
                        break;
                    case 6:
                        s = "shl";
                        break;
                    case 7:
                        s = "sar";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", cl");
                break;
            case 0xd3:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "rol";
                        break;
                    case 1:
                        s = "ror";
                        break;
                    case 2:
                        s = "rcl";
                        break;
                    case 3:
                        s = "rcr";
                        break;
                    case 4:
                        s = "shl";
                        break;
                    case 5:
                        s = "shr";
                        break;
                    case 6:
                        s = "shl";
                        break;
                    case 7:
                        s = "sar";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                len = strlen(op1);
                snprintf(op1+len, sizeof(op1)-len, ", cl");
                break;
           case 0xd4:
                s = "aam";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)*b);
                break;
            case 0xd5:
                s = "aad";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)*b);
                break;
            case 0xd6:
                s = "salc";
                break;
            case 0xd7:
                s = "xlat";
                break;
            case 0xd8:
                if(*++b == 0xd1){
                   s = "fcom    st(1)";
                } else if(*b == 0xd9){
                    s = "fcomp   st(1)";
                } else{
                    switch((*b&0x38)>>3){
                        case 0:
                            s = "fadd";
                            b += decodeModSM_float(b, op1, 1, 0, flip_addr_sz);
                            break;
                        case 1:
                            s = "fmul";
                            b += decodeModSM_float(b, op1, 1, 0, flip_addr_sz);
                            break;
                        case 2:
                            s = "fcom";
                            b += decodeModSM_float(b, op1, 1, 0, flip_addr_sz);
                            break;
                        case 3:
                            s = "fcomp";
                            b += decodeModSM_float(b, op1, 1, 0, flip_addr_sz);
                            break;
                        case 4:
                            s = "fsub";
                            b += decodeModSM_float(b, op1, 1, 0, flip_addr_sz);
                            break;
                        case 5:
                            s = "fsubr";
                            b += decodeModSM_float(b, op1, 1, 0, flip_addr_sz);
                            break;
                        case 6:
                            s = "fdiv";
                            b += decodeModSM_float(b, op1, 1, 0, flip_addr_sz);
                            break;
                        case 7:
                            s = "fdivr";
                            b += decodeModSM_float(b, op1, 1, 0, flip_addr_sz);
                            break;
                        default:
                            puts("Invalid Mod R/M byte.");
                            exit(-1);
                    }
                }
                break;
           case 0xe0:
                s = "loopnz";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0xe1:
                s = "loopz";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0xe2:
                s = "loop";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0xe3:
                s = "jcxz";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0xe4:
                s = "in";
                ++b;
                snprintf(op1, sizeof(op1), "al, %p", (void *)*b);
                break;
            case 0xe5:
                s = "in";
                ++b;
                snprintf(op1, sizeof(op1), flip_imm_sz ? "ax, %p": "eax, %p", (void *)*b);
                break;
            case 0xe6:
                s = "out";
                ++b;
                snprintf(op1, sizeof(op1), "%p, al", (void *)*b);
                break;
            case 0xe7:
                s = "in";
                ++b;
                snprintf(op1, sizeof(op1), flip_imm_sz ? "%p, ax": "%p, eax", (void *)*b);
                break;
            case 0xe8:
                s = "call";
                if(flip_imm_sz){
                snprintf(op1, sizeof(op1), "%p", entry+(int)b-(int)f_entry+*(short *)++b+3);
                    b += 2;
                } else{
                    snprintf(op1, sizeof(op1), "%p",(void *)entry+(int)b-(int)f_entry+*(int *)++b+4);
                    b += 3;
                }
                break;
            case 0xe9:
                s = "jmp";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "near ptr %p", entry+(int)b-(int)f_entry+*(short *)++b+3);
                    ++b;
                } else{
                    snprintf(op1, sizeof(op1), "near ptr %p", (void *)entry+(int)b-(int)f_entry+*(int *)++b+4);
                    b += 3;
                }
                break;
            case 0xea:
                s = "jmp";
                if(flip_imm_sz){
                    snprintf(op1, sizeof(op1), "%p:%p", *(short *)(b+2), *(short *)++b);
                    b += 3;
                } else{
                    snprintf(op1, sizeof(op1), "%p:%p", *(short *)(b+4), *(int *)++b);
                    b += 5;
                }
                break;
            case 0xeb:
                s = "jmp";
                ++b;
                snprintf(op1, sizeof(op1), "%p", (void *)entry+(int)b-(int)f_entry+*b+1);
                break;
            case 0xec:
                s = "in      al, dx";
                break;
            case 0xed:
                s = flip_imm_sz ? "in      ax, dx": "in      eax, dx";
                break;
            case 0xee:
                s= "out     dx, al";
                break;
            case 0xef:
                s = flip_imm_sz ? "out     dx, ax": "out     dx, eax";
                break;
            case 0xf1:
                s = "int     1";
                break;
            case 0xf4:
                s = "hlt";
                break;
            case 0xf5:
                s = "cmc";
                break;
            case 0xf6:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "test";
                        len = strlen(op1);
                        snprintf(op1+len, sizeof(op1)-len, "%p", *(char *)++b);
                        break;
                    case 1:
                        s = "test";
                        len = strlen(op1);
                        snprintf(op1+len, sizeof(op1)-len, "%p", *(char *)++b);
                        break;
                    case 2:
                        s = "not";
                        break;
                    case 3:
                        s = "neg";
                        break;
                    case 4:
                        s = "mul     ax, al, ";
                        break;
                    case 5:
                        s = "imul    ax, al, ";
                        break;
                    case 6:
                        s = "div     al, ah, ax, ";  //check format
                        break;
                    case 7:
                        s = "idiv    al, ah, ax, ";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                break;
            case 0xf7:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                switch((*b&0x38)/8){
                    case 0:
                        s = "test";
                        len = strlen(op1);
                        if(flip_imm_sz){
                            snprintf(op1+len, sizeof(op1)-len, "%p", *(short *)++b);
                            ++b;
                        } else{
                            snprintf(op1+len, sizeof(op1)-len, "%p", *(int *)++b);
                            b += 3;
                        }
                        break;
                    case 1:
                        s = "test";
                        len = strlen(op1);
                        if(flip_imm_sz){
                            snprintf(op1+len, sizeof(op1)-len, "%p", *(short *)++b);
                            ++b;
                        } else{
                            snprintf(op1+len, sizeof(op1)-len, "%p", *(int *)++b);
                            b += 3;
                        }
                        break;
                    case 2:
                        s = "not";
                        break;
                    case 3:
                        s = "neg";
                        break;
                    case 4:
                        s = "mul     rdx, rax, ";
                        break;
                    case 5:
                        s = "imul    rdx, rax, ";
                        break;
                    case 6:
                        s = "div     rdx, rax, ";
                        break;
                    case 7:
                        s = "idiv    rdx, rax, ";
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                break;
           case 0xf8:
                s = "clc";
                break;
            case 0xf9:
                s = "stc";
                break;
            case 0xfa:
                s = "cli";
                break;
            case 0xfb:
                s = "sti";
                break;
            case 0xfc:
                s = "cld";
                break;
            case 0xfd:
                s = "std";
                break;
            case 0xfe:
                b += decodeModSM(++b, op1, 1, 0, flip_addr_sz);
                if(!((*b&0x38)/8)){
                    s = "inc";
                } else if((*b&0x38)/8 == 1){
                    s = "dec";
                } else{
                    puts("Invalid Mod R/M byte.");
                    exit(-1);
                }
                break;
            case 0xff:
                switch((*++b&0x38)>>3){
                    case 0:
                        s = "inc";
                        b += decodeModSM(b, op1, 1, 0, flip_addr_sz);
                        break;
                    case 1:
                        s = "dec";
                        b += decodeModSM(b, op1, 1, 0, flip_addr_sz);
                        break;
                    case 2:
                        s = "call";
                        b += decodeModSM(b, op1, 1, 0, flip_addr_sz);
                        break;
                    case 3:  //add seg select
                        s = "callf";
                        b += decodeModSM_memonly(b, op1, 1, 0, flip_addr_sz);
                        break;
                    case 4:
                        s = "jmp";
                        b += decodeModSM(b, op1, 1, 0, flip_addr_sz);
                        break;
                    case 5:  //add seg select
                        s = "jmpf";
                        b += decodeModSM_memonly(b, op1, 1, 0, flip_addr_sz);
                        break;
                    case 6:
                        s = "push";
                        b += decodeModSM(b, op1, 1, 0, flip_addr_sz);
                        break;
                    default:
                        puts("Invalid Mod R/M byte.");
                        exit(-1);
                }
                break;
            default:
                puts("invalid opcode\n");
                exit(-1);
        }

        printf("%p:  %-7s %s\n", entry+(int)a-(int)f_entry, s, op1);
        ++b;

    }

    return b-a;
}

int main(int argc, char **argv){
    int elf;
    Elf32_Ehdr *elf_hdr;    
    Elf32_Phdr *p_hdr;
    int i, sz = 0;
    unsigned char *instruct = 0;
    struct stat st;

    if(argc != 2){
        printf("Usage: %s <ELF file>\n", argv[0]);
        exit(-1);
    }

    if( (elf = open(argv[1], O_RDONLY)) == -1){
        printf("Cannot open file \"%s\" for reading.\n", argv[1]);
        exit(-1);
    }

    //get size of file
    stat(argv[1], &st);
    sz = st.st_size;

    if(sz < sizeof(Elf32_Ehdr)+sizeof(Elf32_Phdr)){
        printf("\"%s\" has unexpected file size.\n", argv[1]);
        exit(-1);
    }

    //map file into memory
    elf_hdr = (Elf32_Ehdr *)mmap(0, sz, PROT_READ, MAP_PRIVATE, elf, 0);
    close(elf);        
    
    if(!memcmp(elf_hdr->e_ident, "\x7fELF\x01\x01", 6) || 
        elf_hdr->e_type != 2){
        printf("\"%s\" is not a valid 32-bit ELF executable.\n", argv[1]);
        exit(-1);
    }

    p_hdr = (Elf32_Phdr *)((int)elf_hdr + elf_hdr->e_phoff);

    //find file offset of entry point
    entry = elf_hdr->e_entry;
    for(i=0; i < elf_hdr->e_phnum; i++){
        if(elf_hdr->e_entry >= p_hdr->p_vaddr && 
          elf_hdr->e_entry < p_hdr->p_vaddr + p_hdr->p_filesz){

            f_entry = (unsigned char *)((int)p_hdr->p_offset + entry- p_hdr->p_vaddr);
            break;

        }
        p_hdr = (Elf32_Phdr *)((int)p_hdr + elf_hdr->e_phentsize);
    } 

    if(f_entry == 0             ||
       p_hdr->p_type != PT_LOAD ||
       p_hdr->p_flags != (PF_R | PF_X)){
        puts("Invalid entry point in ELF header.");    
        exit(-1);
    }   

    f_entry = (unsigned char *)((int)elf_hdr + (int)f_entry);
    sz = f_entry + p_hdr->p_filesz; //define stopping point for linear sweep
    instruct = f_entry;
   
    while(instruct < sz){
        instruct += decode(instruct);
    }

    return 0;
}
