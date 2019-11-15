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
 *      gcc btguard.c -o btguard -ldl
        MODE=0 ./btguard    // COMPLAIN mode, output: ./bt-canary.txt
        MODE=1 ./btguard    // RESTRICT mode, use the ./bt-canary.txt
 
 * */

#include <stdio.h>
#include <execinfo.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h> // get file size
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>


#define BT_BUF_SIZE 20
#define MAX_BT_CANARY_NUM 8192

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
    static void *handle = NULL;
    static EXECVE old_execve = NULL;
    if( !handle ){
        handle = dlopen("libc.so.6", RTLD_LAZY);
        old_execve = (EXECVE)dlsym(handle, "execve");
    }
    printf("hack function invoked. s1=<%s> \n", filename);
    
    char *pwd; 
    long long buffer[BT_BUF_SIZE];
    long long bt_canary;
    char log_filename[255];
    int env_mode;
    char *env;
    env = getenv("MODE");
    if (env)
        env_mode = atoi(env);        //  complain 0 restrict 1
    pwd = getenv("PWD");
    // printf("pwd %s\n", getenv("PWD"));
    memset(buffer, 0, BT_BUF_SIZE*sizeof(void *));
    backtrace((void *)buffer, BT_BUF_SIZE);
    sprintf(log_filename, "%s/%s", pwd, "bt-canary.txt");
    printf("filename %s\n", log_filename);
    

    //get bt canary
    int fd = open(log_filename, O_CREAT | O_RDWR | O_APPEND, S_IRWXU); // 00700 user (file owner) has read, write, and execute permissions
    long long bt_canary_array[MAX_BT_CANARY_NUM] = {0};
    int filesize;
    filesize = get_file_size(log_filename);
    if( filesize > MAX_BT_CANARY_NUM*sizeof(void *) ){
        printf("filesize is too long...\n");
        return -1;
    }
    read(fd, bt_canary_array, filesize);
    
    // sum backtrace
    for(int i=0; i<BT_BUF_SIZE; i++){
        printf("%p\n", (void *)buffer[i]);
        buffer[i] = buffer[i] & 0xfff;
        // write(fd, &buffer[i], 8);
        bt_canary += buffer[i]; 
        if (buffer[i] == 0){
            // write(fd, &buffer[i], 8);
            break;
        }
    }

    if (env_mode != 0 && env_mode != 1) //default set to COMPLAIN 0
        env_mode = 0;

    // make sure: 
    //          write into the file if the bt_canary is unique
    for(int i=0; bt_canary_array[i] != 0; i++ ){
        if (bt_canary_array[i] == bt_canary){
            if( env_mode == 0 )
                printf("Equals to the num: %d , value: 0x%x \n", i, (int )bt_canary);
            goto END;
        }
    }
    // NOT EQUALS
    if (env_mode == 0){
        printf("New canary! write into the file...\n");
        write(fd, &bt_canary, 8);
    }else if(env_mode == 1){
        printf("New canary in restrict mode!\n");
        return -1;
    }

END:
    close(fd);
    old_execve(filename, argv, envp);

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

