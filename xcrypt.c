#include <linux/linkage.h>
#include <asm/page.h>
#include <linux/slab.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>
#include <crypto/sha.h>
#include <linux/delay.h>
#include "work_item.h"

#define READ_BUFFER_SIZE PAGE_SIZE
#define REHASH_KEY_LENGTH 20
#define TEMP_FILE_EXTENSION ".swp"

/*	Computing the hash of the key received from the user which will
	be stored in the preamble of the output file.Do note this is different
	from the key that would be used to encrypt/decrypt the text.
	@buf - input parameter, the key passed from userland to encrypt the data
	@rehash - output parameter, the resulting hash of the key.
	return 0 on success, < 0 on failure
*/
int compute_hash_of_cipher_key(unsigned char *buf, char *rehash)
{
	struct scatterlist sg;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	int error = 0;
	size_t len = strlen(buf);

	sg_init_one(&sg, buf, len);
	tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc.tfm = tfm;
	desc.flags = 0;
	error = crypto_hash_init(&desc);
	if (error < 0)
		goto crypto_hash_init_failed;
	error = crypto_hash_update(&desc, &sg, len);
	if (error < 0)
		goto crypto_hash_update_failed;
	error = crypto_hash_final(&desc, rehash);
	if (error < 0)
		goto crypto_hash_final_failed;
	crypto_free_hash(desc.tfm);

crypto_hash_init_failed:
crypto_hash_update_failed:
crypto_hash_final_failed:
	return error;
}

/*	Function to initialize the cipher. We allocate the cipher
	and then set the key provided by the user for encrypting/decrypting
	and a constant iv for the cipher.

	@key - input paramater, key to be used for encryptiny/decrypting
	@cipherName - input parameter, the name of the cipher to be used
	returns the blkcipher pointer
*/
struct crypto_blkcipher *initialize_cipher(char *key)
{
	struct crypto_blkcipher *blkcipher = NULL;
	int err;
	char iv[] = "abcdefghijklmnop";
	char *cipher = "ctr(aes)";
	unsigned int ivsize = 0;

	blkcipher = crypto_alloc_blkcipher(cipher, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(blkcipher)) {
		err = -EINVAL;
		printk("could not allocate blkcipher handle for %s\n", cipher);
		return ERR_PTR(err);
	}

	if (crypto_blkcipher_setkey(blkcipher, key, strlen(key))) {
		err = -EINVAL;
		printk("key could not be set\n");
		return ERR_PTR(err);
	}
	ivsize = crypto_blkcipher_ivsize(blkcipher);
	if (ivsize) {
		if (ivsize != strlen(iv))
			printk("IV length differs from expected length\n");
		crypto_blkcipher_set_iv(blkcipher, iv, ivsize);
	}

	return blkcipher;
}

/*	Function which encrypts/decrypts(based on a flag), the input text
	provided by the user.
	@blkcipher			-	input parameter, pointer to crypto_blkcipher,
							which will be used to encrypt/decrypt.
	@inBuffer			-	input parameter, the text to be
							encrypted/decrypted.
	@numberOfBytesRead	-	input parameter, the number of bytes of
							data read and hence to be encrypted.
	@flags				-	input paramater, flag to decide whether
							we want to encrypt/decrypt.
	@outBuffer			-	output parameter, the encrypted/decrypted text.
	returns 0 on success, and < 0 on failure
*/
int encryptDecrypt(struct crypto_blkcipher *blkcipher, char *inBuffer,
					char *outBuffer, int numberOfBytesRead, int flags)
{
	struct scatterlist inputScatterList[1], outputScatterList[1];
	struct blkcipher_desc desc;
	int err;

	desc.flags = 0;
	desc.tfm = blkcipher;

	sg_init_one(inputScatterList, inBuffer, numberOfBytesRead);
	sg_init_one(outputScatterList, outBuffer, numberOfBytesRead);

	if (flags == 1)
		err = crypto_blkcipher_encrypt(&desc, outputScatterList,
										inputScatterList, numberOfBytesRead);
	else
		err = crypto_blkcipher_decrypt(&desc, outputScatterList,
										inputScatterList, numberOfBytesRead);
	return err;
}

/*	Function to check whether two files are same or not.
	vfs_stat is used to check for same files. By comparing inode number of
	the file we can check whether two files are same or not.
	Function also performs regular check for files.
	The input and output file if present should be regular files.
	@inFile		-	input paramater, input file name.
	@outFile	-	input parameter, output file name.
*/
int handlingSameFiles(const char *inFile, const char *outFile)
{
	int error, rc;
	struct kstat insb, outsb;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	error = vfs_stat(inFile, &insb);
	if (error == 0) {
		/* Check if input file is regular or not */
		if (S_ISREG(insb.mode) == 0) {
			printk("Input File is not a regular file\n");
			error = -EBADF;
			goto not_a_regular_file;
		}
		rc = vfs_stat(outFile, &outsb);
		if (rc == 0) {
			if (S_ISREG(outsb.mode) == 0) {
				printk("Output File is not a regular file\n");
				error = -EBADF;
				goto not_a_regular_file;
			}

			if (insb.ino == outsb.ino) {
				printk("Both input and output files are the same\n");
				error = -EINVAL;
			}
		} else if (rc == -ENOENT)
			;
		else
			error = rc;
	}

not_a_regular_file:
	set_fs(oldfs);
	return error;
}

/*	Function to validate given files exists or not and if we have proper
	read permissions to open the file.
	@fileName - input parameter, the file to be validated.
	returns the file pointer of the file
*/
struct file *validateInputFile(const char *fileName)
{
	int err;
	struct file *filp;

	filp = filp_open(fileName, O_RDONLY, 0);
	if (!filp || IS_ERR(filp)) {
		printk("file_validations err: Unable to access file %s %d\n",
				fileName, (int) PTR_ERR(filp));
		err = -ENOENT;
		return ERR_PTR(err);
	}

	if (!filp->f_op || !filp->f_op->read) {
		printk("No read permissions or file does not exist\n");
		err = -EACCES;
		return ERR_PTR(err);
	}
	return filp;
}

/*  Function to validate given files exists or not and if we have proper
    write permissions to open the file. If file does not exist we create
	the file with the permissions same as that of the running process.
    @fileName - input parameter, the file to be validated.
    returns the file pointer of the file
*/
struct file *validateOutputFile(const char *fileName)
{
	int err;
	struct file *filp;

	/*	Creating the output file with the same permissions as that
		of the running process*/

	filp = filp_open(fileName, O_WRONLY | O_CREAT | O_TRUNC,
									0777 & ~current_umask());

	if (!filp || IS_ERR(filp)) {
		printk("file_validations err: Unable to access file %s %d\n",
			fileName, (int) PTR_ERR(filp));
		err = -ENOENT;
	return ERR_PTR(err);
	}

	if (!filp->f_op || !filp->f_op->write) {
		printk("No write permissions or file does not exist\n");
		err = -EACCES;
		return ERR_PTR(err);
	}
	return filp;
}

/*	This function is used to create a temporay filw where we would initially
	write the ecrypted/decrypted text. Please note this file would be deleted
	and renamed with the output file on successful encryption/decryption.

	@outFileName	- 	input paramater, the output file name.
	@tempFileName	-	output parameter, the temporary file that is to be
						created where encrypted/decrypted text would be
						written temporarily
*/
void create_temp_file(const char *outFileName, char *tempFileName)
{
	strcpy(tempFileName, outFileName);
	strcat(tempFileName, TEMP_FILE_EXTENSION);
}

/*	Function to check whether two files are same or not, considering
	we have the file pointers. We check for the file pointer's inode.
	If they are same we check whether the files are in different file
	systems by checking for their superblock name entries.
	@f1		- input paramater, first file pointer
	@f2		- input paramater, second file pointer
	returs 0 if files are different and -1 if files are same
*/
int checkForSameFiles(struct file *f1, struct file *f2)
{
	/*	Files maybe same since inode number is same. Check for filesystem
		values for superblock */

	if (f1->f_inode->i_ino == f2->f_inode->i_ino) {
		if (strcmp(f1->f_inode->i_sb->s_type->name,
			f2->f_inode->i_sb->s_type->name) == 0) {
			printk("Input and output files are the same\n");
			return -1;
		}
	}
	return 0;
}

/*	Function to read a fixed number of bytes(specified as an argumennt)
	into a buffer provided by the user

	@filp	-	input parameter, input file pointer which will be
				used to read the file.
	@buf	-	input paramater, the buffer where the read contents
				would be stored.
	@len	-	the number of bytes to read from the file.
	returns > 0(as the number of bytes that have been read),
	< 0 if an error occured.
*/
int wrapfs_read_file(struct file *filp, char *buf, int len)
{
	int err, bytesRead;
	mm_segment_t oldfs;

	if (!filp || IS_ERR(filp)) {
		printk("file_validations err: Unable to access file %d\n",
				(int) PTR_ERR(filp));
		err = -ENOENT;
		return err;
	}
	if (!filp->f_op || !filp->f_op->read) {
		printk("No read permissions or file does not exist\n");
		err = -EACCES;
		return err;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytesRead = vfs_read(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);
	return bytesRead;
}

/*  Function to write a fixed number of bytes(specified as an argumennt)
	into a buffer provided by the user
	@filp	-	input parameter, output file pointer which will be
				used to write to the file.
	@buf	-	input paramater, the buffer which has the contents
				to be written.
	@len	- 	the number of bytes to write to the file.
	returns > 0(as the number of bytes that have been written),
				< 0 if an error occured.
*/
int wrapfs_write_file(struct file *filp, char *buf, int len)
{
	int bytesWritten, err;
	mm_segment_t oldfs;

	if (!filp || IS_ERR(filp)) {
		printk("file_validations err: Unable to access output file %d\n",
				(int) PTR_ERR(filp));
		err = -ENOENT;
		return err;
	}

	if (!filp->f_op || !filp->f_op->write) {
		printk("No write permissions or file does not exist\n");
		err = -EACCES;
		return err;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytesWritten = vfs_write(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);
	return bytesWritten;
}

/* Read Encrypt Write Loop*/
int read_xcrypt_write_loop(struct crypto_blkcipher *cipher,
						   struct file *inFile, struct file *outFile,
						   int encryptDecryptFlag, char *readbuffer)
{
	char *outBuffer;
	int rc, err = 0;

	rc = wrapfs_read_file(inFile, readbuffer, READ_BUFFER_SIZE);
	if (rc < 0) {
		err = rc;
		goto return_err;
	}
	outBuffer = kmalloc(rc, GFP_KERNEL);
	err = encryptDecrypt(cipher, readbuffer, outBuffer, rc, encryptDecryptFlag);
	if (err < 0)
		goto deallocate_output_buffer;
	rc = wrapfs_write_file(outFile, outBuffer, rc);
	if (rc < 0) {
		err = rc;
		goto deallocate_output_buffer;
	}

deallocate_output_buffer:
	kfree(outBuffer);
return_err:
	return err;
}

int readWriteFilePreamble(struct file *f1, struct file *f2,
							char *rehash, char *buf, int encryptDecryptFlag)
{
	int rc;

	if (encryptDecryptFlag == 1)
		rc = wrapfs_write_file(f2, rehash, REHASH_KEY_LENGTH);
	else {
		rc = wrapfs_read_file(f1, buf, REHASH_KEY_LENGTH);
		if (strncmp(buf, rehash, REHASH_KEY_LENGTH) != 0) {
			printk("Keys are not the same\n");
			rc = -EKEYMISMATCH;
		} else
			printk("Keys are same\n");
	}
	return rc;
}

int xcrypt(void *arg)
{
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	struct file *inputFilePtr, *outputFilePtr;
	long long numberOfWholePages, partiallyFilledPage;
	int rc, err = 0, encryptDecryptFlag;
	char *buf = NULL, *rehash = NULL;

	inputFilePtr = outputFilePtr = NULL;

	if (arg == NULL)
		return -EINVAL;
	else {
		struct xrypt_args *cmdLineArgs = arg;
		struct crypto_blkcipher *cipher;

		/* Verify userland args */
		if (!cmdLineArgs->key) {
			printk("cmdline args key failed\n");

			err = -EINVAL;
			goto return_err;
		}
		if (!cmdLineArgs->infile) {
			err = -EINVAL;
			goto return_err;
		}
		if (!cmdLineArgs->outfile) {
			err = -EINVAL;
			goto return_err;
		}
		encryptDecryptFlag = cmdLineArgs->flags & 1;
		/*	Allocating memory for read buffer. This is the buffer
			that will be used to read data from the input file in
			chunks of PAGE_SIZE
		*/
		buf = kmalloc(READ_BUFFER_SIZE, GFP_KERNEL);
		if (!buf) {
			err = -ENOMEM;
			goto deallocate_ciphername;
		}
		err = handlingSameFiles(cmdLineArgs->infile, cmdLineArgs->outfile);
		if (err < 0)
			goto deallocate_ciphername;

		/* Create temp file */
		inputFilePtr = validateInputFile(cmdLineArgs->infile);
		if (IS_ERR(inputFilePtr)) {
			err = PTR_ERR(inputFilePtr);
			goto deallocate_read_buffer;
		}

		/* Check for 0 length files */
		if (inputFilePtr->f_inode->i_size == 0) {
			printk("Zero length files are not allowed\n");
			err = -EINVAL;
			goto deallocate_read_buffer;
		}

		outputFilePtr = validateOutputFile(cmdLineArgs->outfile);
		if (IS_ERR(outputFilePtr)) {
			err = PTR_ERR(outputFilePtr);
			goto deallocate_read_buffer;
		}

		/*	If the output exists the permissions of the temporary is made
			same as the already existing output file
		*/

		numberOfWholePages = (inputFilePtr->f_inode->i_size) / READ_BUFFER_SIZE;
		partiallyFilledPage = (inputFilePtr->f_inode->i_size) % READ_BUFFER_SIZE;

		/*	Initializing the cipher here which will be
			used to encrypt/decrypt.
		*/

		cipher = initialize_cipher(cmdLineArgs->key);
		if (IS_ERR(cipher)) {
			err = PTR_ERR(cipher);
			goto deallocate_rehash_buffer;
		}
		rehash = kmalloc(REHASH_KEY_LENGTH, GFP_KERNEL);
		err = compute_hash_of_cipher_key(cmdLineArgs->key, rehash);
		if (err < 0)
			goto deallocate_rehash_buffer;

		rc = readWriteFilePreamble(inputFilePtr, outputFilePtr,
									rehash, buf, encryptDecryptFlag);
		if (rc < 0) {
			err = rc;
			goto deallocate_rehash_buffer;
		}

		/*	Read Xcrypt Write Loop for Completely Filled Buffer */
		while (numberOfWholePages--) {
			err = read_xcrypt_write_loop(cipher, inputFilePtr,
											outputFilePtr,
											encryptDecryptFlag,
											buf);
			if (err < 0)
				goto deallocate_rehash_buffer;
		}
		/*	Read Encrypt Write Loop for Remaining file,
		 *	not a multiple of PAGE_SIZE
		 */
		if (partiallyFilledPage > 0) {
			err = read_xcrypt_write_loop(cipher, inputFilePtr, outputFilePtr,
											encryptDecryptFlag, buf);
			if (err < 0)
				goto deallocate_rehash_buffer;
		}
deallocate_rehash_buffer:
	kfree(rehash);
	if (outputFilePtr)
		filp_close(outputFilePtr, NULL);

	if (inputFilePtr)
		filp_close(inputFilePtr, NULL);

deallocate_read_buffer:
	kfree(buf);
deallocate_ciphername:
return_err:
		return err;
	}
}
