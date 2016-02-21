//------------------------------------------------------------------------------
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
//------------------------------------------------------------------------------
#include "sighand.h"
//------------------------------------------------------------------------------

#define SIGHAND_RAISE_SIGNALS

void dump_mem(unsigned char *ptr,int count)
{
 printf("Stack dump:");
 for (int i = -count; i < count; i++)
 {
  if ((i%0x10)==0) printf("\n%8x: ",(unsigned int)(ptr+i));
  printf("%2x ",*(unsigned char *)(ptr+i));
  if ((i-0xf)==0) printf (" <--");
 }
}

void handle_critical_signal(int signum)
{
 int _signum = signum;
 printf("\nSignal %i received.\n",signum);
 dump_mem((unsigned char *)&_signum,0x100);
 std::cout.flush();
 std::cerr.flush();
 signal(signum,SIG_IGN);
 raise(signum);
}

void handle_sigterm(int signum)
{
 printf("\nProgram terminated.\n");
 std::cout.flush();
 std::cerr.flush();
#ifdef SIGHAND_RAISE_SIGNALS
 signal(signum,SIG_DFL);
 raise(signum);
#endif
}

void handle_sigint(int signum)
{
 printf("\nProgram interrupted.\n");
 std::cout.flush();
 std::cerr.flush();
#ifdef SIGHAND_RAISE_SIGNALS
 signal(signum,SIG_DFL);
 raise(signum);
#endif
}

void handle_sigfpe(int signum)
{
 printf("\nFloating point error.\n");
 std::cout.flush();
 std::cerr.flush();
#ifdef SIGHAND_RAISE_SIGNALS
 signal(signum,SIG_DFL);
 raise(signum);
#endif
}

/*
void handle_sigfpe(int signum){}
void handle_sigsegv(int signum){}
void handle_sigbus(int signum){}
void handle_sigterm(int signum){}
void handle_sigint(int signum){}
void handle_sigquit(int signum){}
*/

void init_sighand(void)
{
 signal(SIGFPE,handle_sigfpe);
 signal(SIGSEGV,handle_critical_signal);
 signal(SIGTERM,handle_sigterm);
 signal(SIGINT,handle_sigint);
}

void done_sighand(void)
{
 signal(SIGFPE,SIG_DFL);
 signal(SIGSEGV,SIG_DFL);
 signal(SIGTERM,SIG_DFL);
 signal(SIGINT,SIG_DFL);
}

//------------------------------------------------------------------------------
