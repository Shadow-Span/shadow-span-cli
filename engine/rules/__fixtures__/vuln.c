#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
void cmd(char *n){ system(n); }
void cmd2(char *c){ popen(c, "r"); }
void cp1(char *d, char *s){ strcpy(d, s); }
void cp2(char *d, char *s){ strcat(d, s); }
void sp(char *b, char *s){ sprintf(b, "%s", s); }
void g(char *b){ gets(b); }
void fmt(char *u){ printf(u); }
void slog(char *u){ syslog(3, u); }
void h1(void *c){ MD5_Init(c); }
void h2(void *c){ SHA1_Init(c); }
int rnd(void){ return rand(); }
void tls1(void *h){ curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0); }
void tls2(void *ctx){ SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0); }
