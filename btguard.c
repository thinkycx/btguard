/*
 * Date: 20191114
 * Author: thinkycx
 * Description:
        hook the target function and calculate the backtrace canary of it.
 * Usage:
        gcc -fPIC -shared -o btguard.so btguard.c -ldl
        LD_PRELOAD=./btguard.so ./program 
 * Test:
 *      comment dlopen dlsym functions.. and 
        gcc btguard.c -o btguard -ldl
        MODE=0 ./btguard    // COMPLAIN mode, output: ./btguard-btcanary.txt
        MODE=1 ./btguard    // RESTRICT mode, use the ./btguard-btcanary.txt
 * Output:
        [COMPLAIN] TIME: 1573805426s 	 BackTrace: 0x400c4a 0x401120 0x7fe0a0287830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [+] NEW 0
        [COMPLAIN] TIME: 1573805442s 	 BackTrace: 0x400c4a 0x401120 0x7fec5531e830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [=] NUM 0
        [RESTRICT] TIME: 1573805461s 	 BackTrace: 0x400c4a 0x401120 0x7f69b8a94830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [=] NUM 0
        [RESTRICT] TIME: 1573805468s 	 BackTrace: 0x400c4a 0x401120 0x7fba5598f830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [=] NUM 0
        [COMPLAIN] TIME: 1573805473s 	 BackTrace: 0x400c4a 0x401120 0x7f49d1b00830 0x400a29 (nil) 	 BT_CANARY: 0x1fc3 	 [=] NUM 0
 * Notice:
        1. comment printf() for /bin/bash, as it may output some errors.
 * */

#include <stdio.h>
#include <execinfo.h>   // backtrace()
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>   // get_file_size()
#include <string.h>
#include <unistd.h>     // open() read() write()   
#include <dlfcn.h>      // dlopen() dlsym()
#include <sys/time.h>   // gettimeofday()
#include <errno.h>

#define _GNU_SOURCE
#define MAX_BT_DEPTH 1024
#define MAX_BT_UNIQUE_CANARY 8192
#define BT_CANARY_NAME "btcanary.txt"
#define LOG_NAME "btcanary.log"

extern char *program_invocation_short_name;

typedef int(*EXECVE)(const char*filename, char *const argv[], char *const envp[]);

unsigned long get_file_size(const char *path)
{
	unsigned long filesize = -1;	
	struct stat statbuff;
	if(stat(path, &statbuff) < 0){
		return filesize;
	}else{
		filesize = statbuff.st_size;
	}
	return filesize;
}

int execve(const char* filename, char *const argv[], char *const envp[])
{
    static void *handle = NULL;                                         // hook execve function
    static EXECVE old_execve = NULL;
    if( !handle ){
        handle = dlopen("libc.so.6", RTLD_LAZY);
        old_execve = (EXECVE)dlsym(handle, "execve");
    }
    
    char *pwd;                                                          // caculate the bt cannary                         
    long long buffer[MAX_BT_DEPTH];
    long long bt_canary;
    char log_filename[255];
    int env_mode;
    char *env;
    env = getenv("MODE");
    if (env)
        env_mode = atoi(env);        //  complain 0 restrict 1
    pwd = getenv("PWD"); //getenv("PWD");
    // printf("pwd %s\n", getenv("PWD"));
    memset(buffer, 0, MAX_BT_DEPTH*sizeof(void *));
    backtrace((void *)buffer, MAX_BT_DEPTH);                              // backtrace
    sprintf(log_filename, "%s/%s-%s", pwd, program_invocation_short_name, BT_CANARY_NAME);
    // printf("log_filename %s\n", log_filename);                      // comment this when used for bash
    

    //get bt canary                                                    // create if not exists
    int fd = open(log_filename, O_CREAT | O_RDWR | O_APPEND, S_IRWXU); // mode = 00700 ; user (file owner) has read, write, and execute permissions
    long long bt_canary_array[MAX_BT_UNIQUE_CANARY] = {0};
    int filesize;
    filesize = get_file_size(log_filename);
    if( filesize > MAX_BT_UNIQUE_CANARY*sizeof(void *) ){
        printf("filesize is too long...\n");
        return -1;
    }
    read(fd, bt_canary_array, filesize);                        // read the content from the file
    
    char log[500];                                              //record time and backtrace into the log_file
    char log_name[255];
    struct timeval tv;
    int log_fd;

    sprintf(log_name, "%s/%s-%s", pwd, program_invocation_short_name, LOG_NAME);
    // printf("log_name %s\n", log_name);                                           // comment this when used for bash..
    log_fd = open(log_name, O_CREAT | O_RDWR | O_APPEND, S_IRWXU);  // open log_fd


    if (env_mode != 0 && env_mode != 1)                          //default set to COMPLAIN 0
        env_mode = 0;
    
    if (env_mode == 0)
        write(log_fd, "[COMPLAIN] ", 11);
    else if (env_mode ==1)
        write(log_fd, "[RESTRICT] ", 11);

    gettimeofday(&tv,NULL);
    sprintf(log, "TIME: %lds \t BackTrace: ", tv.tv_sec);

    write(log_fd, log, strlen(log));

    // sum backtrace
    for(int i=0; i<MAX_BT_DEPTH; i++){                           // get each addr in the backtrace
        // printf("%p\n", (void *)buffer[i]);      
        sprintf(log, "%p ", (void *)buffer[i]);       
        write(log_fd, log, strlen(log)); 

        buffer[i] = buffer[i] & 0xfff;                          // get the last 3 bit
        // write(fd, &buffer[i], 8);
        bt_canary += buffer[i]; 
        if (buffer[i] == 0){
            // write(fd, &buffer[i], 8);
            break;
        }
    }
    sprintf(log, "\t BT_CANARY: 0x%llx ", bt_canary);       
    write(log_fd, log, strlen(log)); 

    // check whether the bt_canary is unique?
    int i=0; 
    for(;bt_canary_array[i] != 0; i++ ){
        if (bt_canary_array[i] == bt_canary){
                sprintf(log,"\t [=] NUM %d \n", i );    
                write(log_fd, log, strlen(log)); 
            goto END;
        }
    }
    // NOT EQUALS! get new bt_canary!
    if (env_mode == 0){
        sprintf(log,"\t [+] NEW %d \n", i );
        write(log_fd, log, strlen(log)); 

        write(fd, &bt_canary, 8);                   // write new canary into the file.
    }else if(env_mode == 1){
        sprintf(log,"\t [!] NEW \n");
        write(log_fd, log, strlen(log)); 
        return -1;
    }

END:
    // record args if needed...
    // sprintf(log,"EXECVE function invoked. filename: s1=<%s> \n", filename);
    // write(log_fd, log, strlen(log)); 
    // printf("s1=<%s>\n", filename);

    old_execve(filename, argv, envp);

    close(fd);
    close(log_fd);

    return 0;
}

void main()
{
    char *filename="/bin/sh";
    char **argv;
    char **env;
    argv = NULL;
    env = NULL;
    execve(filename, argv, env);
}

