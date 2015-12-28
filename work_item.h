#ifndef _WORK_ITEM_H
#define _WORK_ITEM_H

/* Encryption Specific Headers */
#define EKEYMISMATCH 240

#define WIQUEUESIZE 4

struct xrypt_args
{
    int flags;
    unsigned int encryptionUnitSize;
    unsigned int keyLength;
    unsigned char *key;
    char* infile;
    char* outfile;
    char* cipherName;
};

int xcrypt(void *arg);

/* Compression Specific Headers */
struct compress_args
{
	char *compress_algo;
    int flags;
};

/* Checksum Specific Headers */

struct checksum_args
{
	char *checksum_algorithm;
	int flags;
};

typedef enum job_priority {
	HIGH,
	MEDIUM,
	LOW
} job_priority;

typedef enum job_type {
	XCRYPT,
	COMPRESSION,
	CONCATENATE_FILES,
	LIST_QUEUED_JOBS,
	CHANGE_JOB_PRIORITY,
	REMOVE_JOB
}job_type;

struct work_item_node{
	int			 wi_id;
	job_type	 wi_opt;
	job_priority wi_priority;
	int flags;
    unsigned int keyLength;
    char* infile;
    char* outfile;
	char *cipherName;
    unsigned char *key;
	void *args;
};

#endif
