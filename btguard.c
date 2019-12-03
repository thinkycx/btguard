/*
 * Date: 20191114
 * Updated: 20191120
 * Author: thinkycx
 * Description:
        hook the target function and calculate the backtrace canary of it.
 * Usage:
        gcc -fPIC -shared -o btguard.so btguard.c -ldl

        DEBUG_BTCANARY=1 LD_PRELOAD=./btguard.so MODE=0 ./program 
        DEBUG_BTCANARY=0 LD_PRELOAD=./btguard.so MODE=1 ./program 
        
        |_ DEBUG_BTCANARY   show debug output in terminal
        |_ LD_PRELOAD       load the library
        |_ MODE             0 for COMPLAIN 1 for RESTRICT
 * Test:
 *      comment dlopen dlsym functions.. and 
        gcc btguard.c -o btguard -ldl
        MODE=0 ./btguard    // COMPLAIN mode, output: ./btguard-<func>-btcanary.txt
        MODE=1 ./btguard    // RESTRICT mode, use the ./btguard-<func>-btcanary.txt
 * Output:
        [COMPLAIN] TIME: 1573805426s 	 BackTrace: 0x400c4a 0x401120 0x7fe0a0287830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [+] NEW 0
        [COMPLAIN] TIME: 1573805442s 	 BackTrace: 0x400c4a 0x401120 0x7fec5531e830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [=] NUM 0
        [RESTRICT] TIME: 1573805461s 	 BackTrace: 0x400c4a 0x401120 0x7f69b8a94830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [=] NUM 0
        [RESTRICT] TIME: 1573805468s 	 BackTrace: 0x400c4a 0x401120 0x7fba5598f830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [=] NUM 0
        [COMPLAIN] TIME: 1573805473s 	 BackTrace: 0x400c4a 0x401120 0x7f49d1b00830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [=] NUM 0
 * Notice:
        1. use DEBUG_BTCANARY=0 for /bin/bash, as printf() may not suitable for it.
 * */
#define _GNU_SOURCE

#include <stdio.h>
#include <execinfo.h>   // backtrace()
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>   // get_file_size()
#include <string.h>
#include <unistd.h>     // open() read() write() execve()  
#include <dlfcn.h>      // dlopen() dlsym()
#include <sys/time.h>   // gettimeofday()
#include <errno.h>
#include <sys/mman.h>   // mmap

#define MAX_BT_DEPTH 1024
#define MAX_BT_UNIQUE_CANARY 8192
#define BT_CANARY_NAME "btcanary.txt"
#define LOG_NAME "btcanary.log"

#define LIBC_SO_6_RX_SIZE  0x1c0000         // for execve_patcher


extern char *program_invocation_short_name;
extern char *program_invocation_name;

static char *debug;
static int debug_mode=0;                    // not suitable for /bin/bash

void * get_pc () { return __builtin_return_address(0); }

unsigned long get_file_size(const char *path)
{
	unsigned long filesize = -1;                // not exists	
	struct stat statbuff;
	if(stat(path, &statbuff) < 0){
		return filesize;
	}else{
		filesize = statbuff.st_size;
	}
	return filesize;
}

/**
 * hook - get the backtrace and calculate the btcanary and check whether it is unique.
 * @original_func_name:   original func_name in glibc.so. e.g: "execve"
 *      [0] initial: btcanary_filepath & btcanary_filesize
 *      [1] get backtrace
 *      [2] bt_canary: sum each canary's last 3 bit
 *      [3] check whether bt_canary is unique?
 * Output:
 *      ./<program_name>-<func>-btcanary.txt, store each btcanary
 *      ./<program_name>-<func>-btcanary.log, store each log for the func_name in libc.so
 * 
*/
int hook(const char *original_func_name)
{

    int log_fd;                                                             // btcanary.log
    char log_info[500] = {0};                                               // buffer fo store the log before written
    char log_filepath[255];
    struct timeval log_timeval;

    unsigned long long backtrace_buffer[MAX_BT_DEPTH] = {0};                // should initial
    unsigned long long bt_canary_array[MAX_BT_UNIQUE_CANARY] = {0};
    unsigned long long bt_canary = 0;                                       // should initial

    char btcanary_filepath[255];
    signed int btcanary_filesize;           // -1 means not exists
    int result = 0;
    char *env = getenv("MODE");
    char *pwd = getenv("PWD");  
    int env_mode = 0;    

    // [0] initial: btcanary_filepath & btcanary_filesize 
    sprintf(btcanary_filepath, "%s/%s-%s-%s", pwd, program_invocation_short_name, original_func_name, BT_CANARY_NAME);
    btcanary_filesize = get_file_size(btcanary_filepath);                   // btcanary_filesize = -1 if file not exists...
    // [0] initial: env_mode
    if (env)
        env_mode = atoi(env);                                               //  complain 0 restrict 1

    // [1] get backtrace
    memset(backtrace_buffer, 0, MAX_BT_DEPTH*sizeof(void *));
    backtrace((void *)backtrace_buffer, MAX_BT_DEPTH); 
      
    // [log] write log
    sprintf(log_filepath, "%s/%s-%s-%s", pwd, program_invocation_short_name, original_func_name, LOG_NAME);
    log_fd = open(log_filepath, O_CREAT | O_RDWR | O_APPEND, S_IRWXU);      // open log_fd
    // [log] write log if btcanary_filesize it wrong
    // if (btcanary_filesize == -1) 
    //     sprintf(log_info,"[*] btcanary_filepath: %s not exists.\n", btcanary_filepath);
    //     write(log_fd, log_info, strlen(log_info));
    // if( btcanary_filesize > MAX_BT_UNIQUE_CANARY*sizeof(void *) ){
    //     sprintf(log_info,"[*] btcanary_filesize : %d is too large.\n", btcanary_filesize);
    //     write(log_fd, log_info, strlen(log_info));
    // }
    
    // [0] debug printf
    // The only printf for log_filepath, comment this when used for bash.
    if (debug_mode == 1)
    {
        printf("[*] [hook] pwd %s\n", pwd);
        printf("[*] [hook] log_filepath %s\n", log_filepath);                       
        printf("[*] [hook] btcanary_filepath %s \n", btcanary_filepath);           
    }

    // [log] write mode
    if (env_mode != 1)  
    {
        env_mode = 0;                                                       // default set to COMPLAIN 0
        write(log_fd, "[COMPLAIN] ", 11);
    }
    else if (env_mode == 1)
        write(log_fd, "[RESTRICT] ", 11);

    // [log] write time
    gettimeofday(&log_timeval,NULL);
    sprintf(log_info, "TIME: %lds \t BackTrace: ", log_timeval.tv_sec);
    write(log_fd, log_info, strlen(log_info));

    // [2] bt_canary: sum each canary's last 3 bit
    for(int i=0; i<MAX_BT_DEPTH; i++){                                      // get each addr in the backtrace
        sprintf(log_info, "%p ", (void *)backtrace_buffer[i]);       
        write(log_fd, log_info, strlen(log_info));                          // [log] write each backtrace pointer
        backtrace_buffer[i] = backtrace_buffer[i] & 0xfff;                  // get the last 3 bit
        bt_canary = bt_canary + backtrace_buffer[i];                        // original has bug here, cause of not initial to bt_canary.
        // printf("backtrace_buffer[%d] 0x%llx now bt_canary 0x%llx\n", i, backtrace_buffer[i], bt_canary);
        if (backtrace_buffer[i] == 0){
            break;
        }
    }
    sprintf(log_info, "\t BT_CANARY: 0x%llx ", bt_canary);  
    // [log] write bt_canary
    write(log_fd, log_info, strlen(log_info)); 

    // [3] check whether bt_canary is unique?
    // read bt_canary_array from btcanary.txt 
    int btcanary_fd = open(btcanary_filepath, O_CREAT | O_RDWR | O_APPEND, S_IRWXU);  // create if not exists, append, rwx  
    read(btcanary_fd, bt_canary_array, btcanary_filesize);
    int i=0; 
    for(;bt_canary_array[i] != 0; i++ ){
        // [N] not unique.
        if (bt_canary_array[i] == bt_canary){
                sprintf(log_info,"\t [=] NUM %d \n", i );                   // [log] write bt_canary                
                write(log_fd, log_info, strlen(log_info)); 
            goto END;
        }
    }
    // [Y] unique! NOT EQUALS! get new bt_canary!
    if (env_mode == 0){                                                     // COMPLAIN mode                          
        sprintf(log_info,"\t [+] NEW %d \n", i );
        write(log_fd, log_info, strlen(log_info)); 
        write(btcanary_fd, &bt_canary, 8);                                  // write new canary into btcanart.txt.   

    }else if(env_mode == 1){                                                // STRICT mode          
        sprintf(log_info,"\t [!] NEW \n");               
        sprintf(log_info,"[*] Attack Detected! Backtrace canary is not found!\n");
        // the only printf
        printf("[*] Attack Detected! Backtrace canary is not found!\n");
        write(log_fd, log_info, strlen(log_info)); 
        result = -1;                                                        // change result value when return
    }

END:
    close(btcanary_fd);
    close(log_fd);
    return result;
}


// start to hook functions
// typedef int(*EXECVE)(const char*filename, char *const argv[], char *const envp[]);
int (*original_execve)(const char*filename, char *const argv[], char *const envp[]);
int (*original_mprotect)(void *addr, size_t len, int prot);
void (*original_mmap)(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset);

/**
 * execve_patcher - patch original function in libc.so, max destroy assemble size is 8-12 byte.
 * @original_func_name:      original function name, such as "execve"
 * @proxy_func:             proxy function addr in btguard.so, such as execve() in btguard.so
 * 
 *                - [1] change permissions to rwxp
 *                - [2] patch original function in libc.so  & jmp to proxy_func
 *                          mov rax, addr; jmp rax; nop... ; now assume rax is useless.
 *                          Overwrite at least 8-12 bytes of original func in libc.so
 *                          Notice: jmp qword ptr [rip+offset];  is only 5 bytes. But not suitable for all cases;
 *                - [3] change permissions to r-xp
*/
void func_patcher(char *original_func_name, void *proxy_func)
{
    // static void *handle = NULL; 
    void *handle = NULL; 
    void *original_func;

    // [0] get base addr of libc.so.6
    if( !handle ){
        handle = dlopen("libc.so.6", RTLD_LAZY);                               // handle -> libc base addr
    }
    original_func = dlsym(handle, original_func_name);                     // libc.so.6 r-xp  0x1c0000
    if(debug_mode){
        printf("[*] [func_patcher] handle of libc.so.6 addr : 0x%llx\n", *(long long int *)handle);
        printf("[*] [func_patcher] func_patcher for %s @ %p -> %p\n", original_func_name, original_func, proxy_func);
    }


    // [1] change permission to 7 rwxp
    int result;
    result = original_mprotect((void *)*(long long int *)handle , LIBC_SO_6_RX_SIZE, PROT_READ|PROT_EXEC|PROT_WRITE);
    if (result != 0){
        perror("[*] [func_patcher] mprotect failed - rwx.");
    }
    
    // [2] patch original_function in libc.so
    char jmp_shellcode[20]={"\x90"};
    long long *addr = (long long *)proxy_func;
    
    if ((long long )addr < 0x100000000){                        // jmp from libc.so to .text 
        // mov rax,0x400000c; jmp rax; 
        // "\x48\xc7\xc0\x0c\x00\x00\x04\xff\xe0"
        memcpy(jmp_shellcode, "\x48\xc7\xc0", 3);       
        memcpy(jmp_shellcode+3, &addr, 4);
        memcpy(jmp_shellcode+7,  "\xff\xe0", 2);                // jmp rax
    }else{                                                      // jmp from libc.so to btguard.so 
        // mov rax,0x12345678aabbccdd; jmp rax;
        // "\x48\xb8\xdd\xcc\xbb\xaa\x78\x56\x34\x12\xff\xe0"
        memcpy(jmp_shellcode, "\x48\xb8", 2);  
        memcpy(jmp_shellcode+2, &addr, 8);
        memcpy(jmp_shellcode+10, "\xff\xe0", 2);                // jmp rax
    }

    // copy the max length to original func in libc.so
    memcpy((void *)original_func, jmp_shellcode, 12);        

    // [3] change permission to 5 r-xp
    result = original_mprotect((void *)*(long long int *)handle , LIBC_SO_6_RX_SIZE, PROT_READ|PROT_EXEC);
    if (result != 0){
        perror("[*] [func_patcher] mprotect failed.. - r-x");
    }

}

/**
 * addr_patcher - patch addr in libc.so.6
 * @addr: start addr
 * @shellcode: shellcode to be copies
 * @len: copy length
 * 
*/
void addr_patcher(void *addr, char* shellcode ,int len){

    void *handle = NULL; 

    if( !handle ){
        handle = dlopen("libc.so.6", RTLD_LAZY);                               // handle -> libc base addr
    }
    if( addr > handle){
        printf("[!] [addr_patcher] addr is not valid\n");
    }

    int result;
    result = original_mprotect((void *)*(long long int *)handle , LIBC_SO_6_RX_SIZE, PROT_READ|PROT_EXEC|PROT_WRITE);
    if (result != 0){
        perror("[*] [addr_patcher] mprotect failed - rwx.");
    }

    memcpy(addr, shellcode, len);

    result = original_mprotect((void *)*(long long int *)handle , LIBC_SO_6_RX_SIZE, PROT_READ|PROT_EXEC);
    if (result != 0){
        perror("[*] [addr_patcher] mprotect failed - r-x.");
    }

}
/**
 * execve - proxy of the execve() in libc.so, execve() in btguard.so.
 *        - [1] save registers needed for the original execve function: rdi rsi rdx
 *        - [2] anything before real execve() in libc.so
 *                  printf...
 *                  call hook() to check backtrace cananry
 *                  ...
 *        - [3] restore registers needed
 *        - [4] restore and call original first (N asm code), len(N asm code) >=12  // N=3 for execve
 *        - [5] jmp back to original execve()+ nbytes(= N asm code) in libc.so      // nbytes=13 for execve
 * RETURN VALUE
            On success, execve() does not return, on error -1 is returned, and errno is set appropriately.
 
    pwndbg> x/7i execve                                                    # execve in glibc
    0x7ffff7ad9770 <execve>:	mov    eax,0x3b
    0x7ffff7ad9775 <execve+5>:	syscall
    0x7ffff7ad9777 <execve+7>:	cmp    rax,0xfffffffffffff001
    0x7ffff7ad977d <execve+13>:	jae    0x7ffff7ad9780 <execve+16>
    0x7ffff7ad977f <execve+15>:	ret
    0x7ffff7ad9780 <execve+16>:	mov    rcx,QWORD PTR [rip+0x2f76f1]        # 0x7ffff7dd0e78

    pwndbg> x/16xb 0x7ffff7ad9770
    0x7ffff7ad9770 <execve>:	0xb8	0x3b	0x00	0x00	0x00	0x0f	0x05	0x48
    0x7ffff7ad9778 <execve+8>:	0x3d	0x01	0xf0	0xff	0xff	0x73	0x01	0xc3
*/         
int execve(const char* filename, char *const argv[], char *const envp[])
{   
    // [1] save the registers: rdi rsi rdx for execve() in libc.so
    __asm__ __volatile__ (
    //     "int $3"
    "  push %%rdi\n"
    "  push %%rsi\n"
    "  push %%rdx\n"
    :
    :
    :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
    );

    // [2] Do anything you want to do before execve() in libc.so
    //    ...
    // printf("*[%s proxy]: arg1=<%s>\n", __func__, filename);
    int result = 0;
    result = hook("execve");                                                // guard module

    if(result != -1){
        // if not patched just run the execve() in libc.so        
        // original_execve(filename, argv, envp);             

        __asm__ __volatile__ (
        // [3] restore the original registers for execve: rdx rsi rdi
        "  pop %%rdx\n"
        "  pop %%rsi\n"
        "  pop %%rdi\n"

        // [4] call original first N bytes
        "  mov      $0x3b, %%eax\n"                                         // original asm code you have written
        "  syscall\n"
        "  cmp      $0xfffffffffffff001, %%rax\n"
        :
        :
        :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
        );

        // [5] jmp back to original execve()+N in libc.so
        int (*ptr)(const char*, char *const*, char *const*);
        ptr = (void *)original_execve+13;
        (*ptr)(filename, argv, envp);

    }else{
        __asm__ __volatile__ (
        // restore the original registers for execve: rdx rsi rdi
        "  pop %%rdx\n"
        "  pop %%rsi\n"
        "  pop %%rdi\n"
        // Now, don't need to execute first N asm code in execve() libc.so.
        // "  mov      $0x3b, %%eax\n"
        // // "  syscall\n"
        // "  mov      $0xffffffffffffffff, %%rax\n"                           //return fail
        // "  cmp      $0xfffffffffffff001, %%rax\n"
        :
        :
        :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
        );

    }
    return result;
}

/** mprotect - proxy of the mprotect() in libc.so, mprotect() in btguard.so.
 *           - same as execve()
 *           - Notice: when mprotect() return value is not 0, perror() output maybe wrong. low priority.
 * 
 * RETURN VALUE
       On success, mprotect() returns zero.  On error, -1 is returned, and errno is set appropriately.

 pwndbg> x/10i mprotect
   0x7ffff790a770 <mprotect>:	mov    eax,0xa
   0x7ffff790a775 <mprotect+5>:	syscall
   0x7ffff790a777 <mprotect+7>:	cmp    rax,0xfffffffffffff001
   0x7ffff790a77d <mprotect+13>:	jae    0x7ffff790a780 <mprotect+16>
=> 0x7ffff790a77f <mprotect+15>:	ret
   0x7ffff790a780 <mprotect+16>:	mov    rcx,QWORD PTR [rip+0x2c26f1]        # 0x7ffff7bcce78
   0x7ffff790a787 <mprotect+23>:	neg    eax
   0x7ffff790a789 <mprotect+25>:	mov    DWORD PTR fs:[rcx],eax
   0x7ffff790a78c <mprotect+28>:	or     rax,0xffffffffffffffff
   0x7ffff790a790 <mprotect+32>:	ret
*/
int mprotect(void *addr, size_t len, int prot)
{
    __asm__ __volatile__ (
    "  push %%rdi\n"
    "  push %%rsi\n"
    "  push %%rdx\n"
    :
    :
    :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
    );
    int result = 0;
    result = hook("mprotect");
    if(result != -1){
        
        int (*ptr)(void *, size_t , int );
        ptr = (void *)original_mprotect+13;     

        __asm__ __volatile__ (
        // [3] restore the original registers for mprotect: rdx rsi rdi
        "  pop %%rdx\n"
        "  pop %%rsi\n"
        "  pop %%rdi\n"

        // [4] call original first N bytes
        "  mov      $0xa, %%eax\n"                                         // original asm code you have written
        "  syscall\n"
        "  cmp      $0xfffffffffffff001, %%rax\n"
        "  push %%rax\n"                                                   // save the return value
        :  
        :
        :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
        );

        // add asm code will change $eflags from 0x217 -> 0x206
        // change *ptr position

        // [5] jmp back to original mprotect()+N in libc.so
        (*ptr)(addr, len, prot);                                          // call rax; it will change rax register.

        __asm__ __volatile__ (
        "  pop %%rax\n"                                                   // restore the return value
                                                                          // bug: cannot restore the perror output
                                                                          // such as : invalid argument
        :  
        :
        :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
        );

        return;     // ignore the return value, has put into the %%rax;

    }else{                                                                // invalid call
        __asm__ __volatile__ (
            // [3] restore the original registers for mprotect: rdx rsi rdi
            "  pop %%rdx\n"
            "  pop %%rsi\n"
            "  pop %%rdi\n"
        :
        :
        :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
        );
        return -1;
    }
}

/**
 * mmap - proxy of the mmap() in libc.so, mmap() in btguard.so.
 *      - same as execve()
 *      - Notice: As first N asm code in mmap has "push", you should patch last "pop" asm code. 
 * RETURN VALUE
       On success, mmap() returns a pointer to the mapped area.  On error, the value MAP_FAILED (that is, (void *) -1) is returned,
       and errno is set to indicate the cause of the error.

       On success, munmap() returns 0.  On failure, it returns -1, and errno is set to indicate the cause of the error (probably to
       EINVAL).
       
pwndbg> x/10i 0x7ffff7706680
   0x7ffff7706680 <__mmap>:	test   rdi,rdi
   0x7ffff7706683 <__mmap+3>:	push   r15              // 1 push
   0x7ffff7706685 <__mmap+5>:	mov    r15,r9   
   0x7ffff7706688 <__mmap+8>:	push   r14              // 2 push
   0x7ffff770668a <__mmap+10>:	mov    r14d,ecx             
   0x7ffff770668d <__mmap+13>:	push   r13              // unchanged 
   0x7ffff770668f <__mmap+15>:	mov    r13,rsi
   0x7ffff7706692 <__mmap+18>:	push   r12
   ...
   0x7ffff7b0e6aa <__mmap+42>:	mov    rdx,rbx
   0x7ffff7b0e6ad <__mmap+45>:	mov    rsi,r13
   0x7ffff7b0e6b0 <__mmap+48>:	mov    rdi,r12
   0x7ffff7b0e6b3 <__mmap+51>:	mov    eax,0x9
   0x7ffff7b0e6b8 <__mmap+56>:	syscall
   0x7ffff7b0e6ba <__mmap+58>:	cmp    rax,0xfffffffffffff000
   0x7ffff7b0e6c0 <__mmap+64>:	ja     0x7ffff7b0e718 <__mmap+152>
   0x7ffff7b0e6c2 <__mmap+66>:	pop    rbx
   0x7ffff7b0e6c3 <__mmap+67>:	pop    rbp
   0x7ffff7b0e6c4 <__mmap+68>:	pop    r12
   0x7ffff7b0e6c6 <__mmap+70>:	pop    r13
   0x7ffff7b0e6c8 <__mmap+72>:	pop    r14             // patch it to nop
   0x7ffff7b0e6ca <__mmap+74>:	pop    r15             // patch it to nop
   0x7ffff7b0e6cc <__mmap+76>:	ret
*/
void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
    __asm__ __volatile__ (
    "  push %%rdi\n"
    "  push %%r15\n"
    "  push %%r9\n"
    "  push %%r14\n"
    "  push %%rcx\n"
    :
    :
    :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
    );
    int result = 0;
    result = hook("mmap");
    if(result != -1){
        // Important. different from execve() or mmap()
        // patch mmap last two pop asm code, as we have patched two push asm code in the beginning.
        void *mmap_end_addr = original_mmap + 72;
        char nop[8] = {"\x90\x90\x90\x90\x90\x90\x90\x90"};
        addr_patcher(mmap_end_addr, nop, 4);

        void * (*ptr)(void *, size_t , int, int, int, off_t);
        ptr = (void *)original_mmap+13; 

        __asm__ __volatile__ (
        "  pop %%rcx\n"
        "  pop %%r14\n"
        "  pop %%r9\n"
        "  pop %%r15\n"
        "  pop %%rdi\n"

        "  test %%rdi, %%rdi\n"                                         // original asm code in mmap() in libc.so
        "  push %%r15\n"
        "  mov  %%r9, %%r15\n"
        "  push %%r14\n"
        "  mov  %%rcx, %%r14\n"

        :
        :
        :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
        );
        void *mmap_result;
        mmap_result = (*ptr)(addr, length, prot, flags, fd, offset);    // notice the type
        
        __asm__ __volatile__ (
        "  pop %%r14\n"
        "  pop %%r15\n"
        :
        :
        :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
        );
        return mmap_result;

    }else{
        __asm__ __volatile__ (                                              // invalid mmap call
            "  pop %%rcx\n"
            "  pop %%r14\n"
            "  pop %%r9\n"
            "  pop %%r15\n"
            "  pop %%rdi\n"
            :
            :
            :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
        );
        return (void *)-1;
    }
}


/**
 * controller - rename the original function in libc.so for proxy function to call 
 *            - each program starts, this function will be called. e.g. 3 times, if exists system("whoami");
 *                                                                               program + /bin/dash + /usr/bin/whoami
 * 
 * 
*/
__attribute__((constructor)) void controller()
{
    debug = getenv("DEBUG_BTCANARY");
    if (debug)
        debug_mode = atoi(debug);                                           // debug 0 or 1
    if (debug_mode)
        printf("\n[*] [controller] controller() called: %s\n", program_invocation_name);

    original_execve = dlsym(RTLD_NEXT, "execve");
    original_mprotect = dlsym(RTLD_NEXT, "mprotect");
    original_mmap = dlsym(RTLD_NEXT, "mmap");

    // __asm__ __volatile__ (
    //     "int $3"
    // :
    // :
    // :"memory", "rsi", "rdi", "rax", "rbx", "rcx", "rdx"
    // );

    func_patcher("execve", execve);
    func_patcher("mprotect", mprotect);
    func_patcher("mmap", mmap);

     if (debug_mode){
            printf("[*] [controller] original_execve %p\n", original_execve);
            printf("[*] [controller] now execve %p\n", execve);

            printf("[*] [controller] original_mprotect %p\n", original_mprotect);
            printf("[*] [controller] now mprotect %p\n", mprotect);

            printf("[*] [controller] original_mmap %p\n", original_mmap);
            printf("[*] [controller] now mmap %p\n", mmap);
     }
    if (debug_mode)
        printf("\n[*] [controller] controller() quitted: %s\n", program_invocation_name);


}


void main()
{
    char *filename="/bin/sh";
    char **argv;
    char **env;
    argv = NULL;
    env = NULL;

    // test mmap
    size_t pagesize = getpagesize();
    printf("System page size: %zu bytes\n", pagesize);
    char * region = mmap(
        (void*) (pagesize * (1 << 20)),   // Map from the start of the 2^20th page
        pagesize,                         // for one page length
        PROT_READ|PROT_WRITE|PROT_EXEC,
        MAP_ANON|MAP_PRIVATE,            // to a private block of hardware memory
        0, 
        pagesize);

    // test execve
    execve(filename, argv, env);
}

