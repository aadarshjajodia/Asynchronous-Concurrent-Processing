#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "work_item.h"

#define ENCRYPTDECRYPT_FLAG_NOT_PRESENT 2

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

extern int create_socket();
extern void send_message_to_kernel(char* message);
extern void* kernel_callback_function();

extern int waitflag;

void display_usage()
{
    printf("Name:xcipher\n");
    printf("Usage:\n");
    printf("Mandatory args:\n");
    printf("-p ARG,\t\tto provide the encryption/decryption key, (ARG) is the key\n");
    printf("-e/-d, \t\tto encrpyt/decrypt\n");
    printf("infile, \tthe name of an input file to encrypt or decrypt\n");
    printf("outfile, \tthe output file\n");
	printf("-j ARG, \t\tThe job types:\n \
		   1: XCRYPT,\n \
		   2: COMPRESSION,\n \
		   3: CONCATENATE_FILES,\n \
		   4: LIST_QUEUED_JOBS,\n \
		   5: CHANGE_JOB_PRIORITY,\n \
		   6: REMOVE_JOB\n");
	printf("-k ARG,	\t\tThe priority of the job: Possible Values:\n \
		   1: HIGH,\n \
		   2: MEDIUM,\n \
		   3: LOW,\n \
		   In case user wants to change job priority,\n \
		   this should hold the new job priority\n");
	printf("-c ARG, \t\tThe cipher name to be used\n");
	printf("-z ARG, \t\tThe job id to delete when job type is\n \
		   REMOVE_JOB and job priority to change to\n \
		   when job type is CHANGE_JOB_PRIORITY\n");
    printf("Optional args:\n");
    printf("-h, \t\tto display this help message\n");
}

unsigned int get_job_id()
{
	static int count = 1;
	return (getpid() + count++);
}

int main(int argc, char **argv)
{
	waitflag = 0;

	char c;
	int job_id_flag = 0;
	char *cipher_key = NULL;
	enum job_type jobType;
	enum job_priority jobPriority = MEDIUM; // Assigning a default priority MEDIUM
	char *cipher_name = NULL;
	char *inFile, *outFile;
	int index, count = 0, rc, job_id;
	unsigned int flags = ENCRYPTDECRYPT_FLAG_NOT_PRESENT;
	pthread_t threads;
	while ((c = getopt (argc, argv, "edhc:p:j:k:z:")) != -1)
	{
		switch(c) {
			case 'j':
				if(strcmp(optarg, "1") == 0)
					jobType = XCRYPT;
				else if(strcmp(optarg, "2") == 0)
					jobType = COMPRESSION;
				else if(strcmp(optarg, "3") == 0)
					jobType = CONCATENATE_FILES;
				else if(strcmp(optarg, "4") == 0)
					jobType = LIST_QUEUED_JOBS;
				else if(strcmp(optarg, "5") == 0)
					jobType = CHANGE_JOB_PRIORITY;
				else if(strcmp(optarg, "6") == 0)
					jobType = REMOVE_JOB;
				else {
					errno = -EINVAL;
					perror("Invalid Job Type");
				}
				break;
			case 'k':
                if(strcmp(optarg, "1") == 0)
                    jobPriority = HIGH;
                else if(strcmp(optarg, "2") == 0)
                    jobPriority = MEDIUM;
                else if(strcmp(optarg, "3") == 0)
                    jobPriority = LOW;
                else {
                    errno = -EINVAL;
                    perror("Invalid Job Priority");
                }
				break;
            case 'e':
                count++;
                flags = 0;
                flags = flags | 1;
                break;
            case 'd':
                count++;
                flags = 0;
                break;
			case 'c':
				cipher_name = optarg;
				break;
            case 'h':
                display_usage();
                break;
            case 'p':
                if(strlen(optarg) < 6) {
                    errno = EINVAL;
                    perror("Error: Password is too short,\n \
						   please enter a password of minimum length 6");
                    return -1;
                }
                else
					cipher_key = optarg;
                break;
			case 'z':
				job_id_flag = 1;
				sscanf(optarg, "%d", &job_id);
				break;
            case '?':
                errno = EINVAL;
                if (optopt == 'c')
                    perror("Option -c requires an argument");
                else if(optopt == 'p')
                    perror("Option -p requires an argument");
                else if(optopt == 'u')
                    perror("Option -u requires an argument");
                else if(optopt == 'l')
                    perror("Option -l requires an argument");
                else
                    perror("Unknown option character");
                return -1;
            default:
                abort();
        }
    }

	index = optind;
    inFile = argv[index];
    index++;
    outFile = argv[index];

	struct work_item_node new_work_item;
	new_work_item.wi_id = get_job_id();
	new_work_item.wi_priority = jobPriority;
	new_work_item.wi_opt = jobType;
	new_work_item.flags = 0;
	new_work_item.key = NULL;
	new_work_item.infile = NULL;
	new_work_item.outfile = NULL;
	new_work_item.args = NULL;
	switch(jobType) {
		case XCRYPT:
			if(count == 2) {
				errno = -EINVAL;
				perror("Both encrypt and decrypt flags are present,\n \
					   only of the flags should be passed");
				display_usage();
				return -1;
			}
			if(flags == ENCRYPTDECRYPT_FLAG_NOT_PRESENT) {
				errno = EINVAL;
				perror("Error: Encrypt/Decrypt Flag is not present,\n \
					   please look at mandatory arguments in the help menu below");
				display_usage();
				return -1;
			}
			if(!cipher_key) {
				errno = EINVAL;
				perror("Password flag not passed");
				display_usage();
				return -1;
			}
            char inFile_absolute_path[PATH_MAX + 1];
            char outFile_absolute_path[PATH_MAX + 1];
            realpath(inFile, inFile_absolute_path);
            realpath(outFile, outFile_absolute_path);

            unsigned char hash[SHA_DIGEST_LENGTH]; // == 20
			SHA1((unsigned char*)cipher_key, strlen(cipher_key), hash);
			hash[16] = 0;
			new_work_item.flags = flags;
			new_work_item.keyLength = SHA_DIGEST_LENGTH - 4;
			new_work_item.key = hash;
			new_work_item.infile = inFile_absolute_path;
			new_work_item.outfile = outFile_absolute_path;

			create_socket(new_work_item.wi_id);

			/*  Creating a thread to allow program to wait for
				kernel callback function in a separate thread
			*/
			rc = pthread_create(&threads, NULL, &kernel_callback_function,
														(void *)NULL);
			break;
		case REMOVE_JOB:
			if(job_id_flag == 0) {
				errno = EINVAL;
				perror("Please enter the job id to delete");
				display_usage();
				break;
			}
			new_work_item.args = (int*)malloc(sizeof(int));
			*(int*)(new_work_item.args) = job_id;
			printf("Removing Job: [%d]\n", *(int*)(new_work_item.args));
			break;
		case LIST_QUEUED_JOBS:
			new_work_item.args = malloc(sizeof(int)*WIQUEUESIZE);
			memset(new_work_item.args, 0, sizeof(int)*WIQUEUESIZE);
			break;
		case CHANGE_JOB_PRIORITY:
            if(job_id_flag == 0) {
                errno = EINVAL;
                perror("Please enter the job id to delete");
                display_usage();
                break;
            }
			new_work_item.args = (int*)malloc(sizeof(int));
            *(int*)(new_work_item.args) = job_id;
			printf("Changing Priority of Job [%d] to [%d]\n",
						*(int*)(new_work_item.args), new_work_item.wi_priority);
			break;
		default:
			break;
	}

	rc = syscall(__NR_submitjob, &new_work_item);

	if (rc == 0) {
		
		if (jobType == LIST_QUEUED_JOBS) {

			int *hold = new_work_item.args;

			int *listed_id = NULL;
			int count = 1;

			listed_id = (int *)(new_work_item.args);
			
			do {

				int id = *listed_id;
				if (0 != id)
					printf("%d\n", id);

				new_work_item.args = new_work_item.args + sizeof(int);
				listed_id = (int *)new_work_item.args;
				count++;

			}while(listed_id != NULL && count <= WIQUEUESIZE);

			free(hold);
		} 
	}
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	if(jobType == XCRYPT) {
		printf("TID = %ld -", syscall(SYS_gettid));
		printf(" System call exited.");
		printf(" Now waiting for");
		printf(" user callback to get data.\n");
	
		while(waitflag != 1) {
			printf("TID = %ld -", syscall(SYS_gettid));
			printf(" Waiting for callback to come\n");
			sleep(1);
		}
		pthread_join(threads, NULL);
	}	
	
	exit(rc);
}
