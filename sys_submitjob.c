#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/buffer_head.h>
#include <linux/sched.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "sys_submitjob.h"

struct sock *nl_sk = NULL;

asmlinkage extern long (*sysptr)(void *arg);

/*	Function which sends a message to the user space informing
	user about the success or failure of his requested work_item.
	@pid - unique id dentoting the user process.
	@err_number - the error which occured while processing the job
				- 0 For Success
				- <0 Failure
*/
static void send_message_to_userspace(int pid, int err_number)
{
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int res;

	skb_out = nlmsg_new(sizeof(int), 0);
	if (!skb_out) {
		printk(KERN_ERR "Failed to allocate new skb\n");
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(int), 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	memcpy(nlmsg_data(nlh), &err_number, sizeof(int));

	res = nlmsg_unicast(nl_sk, skb_out, pid);
	
	if (res < 0)
		printk(KERN_INFO "Error while sending bak to user\n");
}

/*  Iterate over the queue and find the job with job_id.
 *  delete it from the list and return it.
 *  @ job_id - job id to be deleted
 */
struct work_queue_node * delete_job(int job_id)
{
    struct work_queue_node  *temp;
	struct list_head *q1, *pos1;
	struct list_head *q2, *pos2;
	struct list_head *q3, *pos3;

	list_for_each_safe(pos1, q1, &((*wi_queue->wi_high_head).list)) {
        temp = list_entry(pos1, struct work_queue_node, list);
        if (temp && job_id == temp->wi->wi_id) {
            list_del(pos1);
            return temp;
        }
	}

	list_for_each_safe(pos2, q2, &((*wi_queue->wi_medium_head).list)) {
        temp = list_entry(pos2, struct work_queue_node, list);
        if (temp && job_id == temp->wi->wi_id) {
            list_del(pos2);
            return temp;
        }
	}

	list_for_each_safe(pos3, q3, &((*wi_queue->wi_low_head).list)) {
        temp = list_entry(pos3, struct work_queue_node, list);
        if (temp && job_id == temp->wi->wi_id) {
            list_del(pos3);
            return temp;
        }
	}

	printk(KERN_ALERT "could not find the node with id %d\n", job_id);

    return ERR_PTR(-EINVAL);
}

/* Remove a job from the list and return it */

struct work_queue_node * deque_job(void)
{
    struct work_queue_node  *temp;
	struct list_head *q1, *pos1;
	struct list_head *q2, *pos2;
	struct list_head *q3, *pos3;

	list_for_each_safe(pos1, q1, &((*wi_queue->wi_high_head).list)) {
        temp = list_entry(pos1, struct work_queue_node, list);
        if (temp) {
            list_del(pos1);
            return temp;
        }
	}

	list_for_each_safe(pos2, q2, &((*wi_queue->wi_medium_head).list)) {
        temp = list_entry(pos2, struct work_queue_node, list);
        if (temp) {
            list_del(pos2);
            return temp;
        }
	}

	list_for_each_safe(pos3, q3, &((*wi_queue->wi_low_head).list)) {
        temp = list_entry(pos3, struct work_queue_node, list);
        if (temp) {
            list_del(pos3);
            return temp;
        }
	}

    return NULL;
}

/* Enqueue the job into work item queue
 * wi is the work item of the job that is to be enqueued */
int enqueue_job(struct work_item_node *wi)
{
	int err = 0;

	struct work_queue_node	 *tmp;

/* Before enqueuing the jobs, check the size of queue. If it is full
 * then throttle the producers.
 */
threadlooper:
	mutex_lock(&wi_queue->mutex_queue);

	if (atomic_read(&(wi_queue->queue_size)) >= WIQUEUESIZE) {

		mutex_unlock(&wi_queue->mutex_queue);
		if (atomic_read(&(throttled_producers)) <= MAXPRODUCERS) {
			
			atomic_inc(&(throttled_producers));
			printk(KERN_ALERT "Throttling the producer with id %d\n", wi->wi_id);
			wait_event_interruptible(producer_wait_queue,
						 atomic_read(&(wi_queue->queue_size)) < WIQUEUESIZE);

			printk(KERN_ALERT "Releasing the producer with id %d\n", wi->wi_id);
			atomic_dec(&(throttled_producers));

			goto threadlooper;
		}
		else {
			printk(KERN_ALERT "Cannot throttle more producers\n");
			return -ENOSPC;
		}
	}

	/* Else enqueue the job based on the priority into appropriate head */

	tmp = (struct work_queue_node *)kmalloc(sizeof(struct work_queue_node),
											GFP_KERNEL);

	if (NULL == tmp) {
		err = -ENOMEM;
		goto exit;
	}

	tmp->wi = wi;

	switch (tmp->wi->wi_priority) {
	case HIGH:
		list_add_tail(&(tmp->list), &(wi_queue->wi_high_head->list));
		break;
	case MEDIUM:
		list_add_tail(&(tmp->list), &(wi_queue->wi_medium_head->list));
		break;
	case LOW:
		list_add_tail(&(tmp->list), &(wi_queue->wi_low_head->list));
		break;
	default:
		printk(KERN_ALERT "Invaid priority\n");
		err = -EINVAL;
		kfree(tmp);
		goto exit;
	}

	atomic_inc(&(wi_queue->queue_size));

exit:
	mutex_unlock(&wi_queue->mutex_queue);

	return err;
}

/* remove a job from the queue
 * @ job_id the id of job which is supposed to be deleted */
int remove_job(int job_id)
{
	struct work_queue_node  *temp = NULL;

	LOG_TRACE;

	mutex_lock(&wi_queue->mutex_queue);

	temp = delete_job(job_id);

	if (IS_ERR(temp)) {
		mutex_unlock(&wi_queue->mutex_queue);
		return PTR_ERR(temp);
	}

	atomic_dec(&(wi_queue->queue_size));

	mutex_unlock(&wi_queue->mutex_queue);

	printk(KERN_DEFAULT "deleting job with id %d\n", job_id);

	kfree(temp);

	return 0;
}

/* worker function that the worker thread uses to work on work item */

int work_on_consumer(void *data)
{
	struct work_queue_node  *temp = NULL;
	int err = 0;

	struct xrypt_args xcryptargs;

/* label where the thread returns to start working on the job */
threadlooper:
	LOG_TRACE;

	mutex_lock(&wi_queue->mutex_queue);

	/* if the queue is empty , then wait till its not empty */
	if (atomic_read(&(wi_queue->queue_size)) == 0) {

		mutex_unlock(&wi_queue->mutex_queue);
		wait_event_interruptible(consumer_wait_queue,
							 atomic_read(&(wi_queue->queue_size)) > 0);
	}

	/* Flag for gracefull exit */ 
	if (is_exit == 1) {
		printk ("kernel thread gracefull exit\n");
		goto exit;
	}

	/* remove first element from the queue. Queue implementation already handles 
	 * the priority of the job */

	LOG_TRACE;

	temp = deque_job();

	atomic_dec(&(wi_queue->queue_size));

	if (atomic_read(&(wi_queue->queue_size)) < WIQUEUESIZE)
		wake_up_all(&producer_wait_queue);

	mutex_unlock(&wi_queue->mutex_queue);

	/* Find out which job it is and call appropriate function */

	switch (temp->wi->wi_opt) {
		case XCRYPT:
			xcryptargs.flags = temp->wi->flags;
			xcryptargs.keyLength = temp->wi->keyLength;
			xcryptargs.key = temp->wi->key;
			xcryptargs.infile = temp->wi->infile;
			xcryptargs.outfile = temp->wi->outfile;
			err = xcrypt(&xcryptargs);
			send_message_to_userspace(temp->wi->wi_id, err);
			break;
		case COMPRESSION:
			//printk("COMPRESSION\n");
			//call compressor
			send_message_to_userspace(temp->wi->wi_id, err);
			break;
		default:
			printk(KERN_ALERT "invalid option\n");
			err = -EINVAL;
			break;
	}

	/* Work is completed now (successfully or unsuccessfully
	 * so free the work item
	 */

	kfree(temp->wi);
	kfree(temp);

	schedule();
	goto threadlooper;

exit:
	return 0;
}

/* Change priority of an enqueued job.
 * @job_id - id of the job whose priority to be changed
 * @ newpriorrity - new priority to be assigned
 */

int change_priority(int job_id, job_priority newpriority)
{
	int err = 0;

	struct work_queue_node  *temp = NULL;

	LOG_TRACE;

	mutex_lock(&wi_queue->mutex_queue);

	
	temp = delete_job(job_id);

	if (IS_ERR(temp)) {
		mutex_unlock(&wi_queue->mutex_queue);
		printk(KERN_ALERT "job not found\n");
		return PTR_ERR(temp);
	}

	atomic_dec(&(wi_queue->queue_size));
	
	mutex_unlock(&wi_queue->mutex_queue);

	(temp->wi->wi_priority) = newpriority;

	err = enqueue_job(temp->wi);

	if (0 != err) {
		printk("Could not enqueue job\n");
		goto exit;
	}

exit:
	return err;
}

/* fill the ids of enqueued jobs to a user space address */

int list_jobs(void *destination)
{
    struct work_queue_node  *temp;

    struct list_head *q1, *pos1;
    struct list_head *q2, *pos2;
    struct list_head *q3, *pos3;

	int retval = 0;

	int idlist[WIQUEUESIZE];

	int count = 0;
    mutex_lock(&wi_queue->mutex_queue);

    list_for_each_safe(pos1, q1, &((*wi_queue->wi_high_head).list)) {
        temp = list_entry(pos1, struct work_queue_node, list);
        if (temp) {
			idlist[count] = temp->wi->wi_id;
			count++;
        }
    }

    list_for_each_safe(pos2, q2, &((*wi_queue->wi_medium_head).list)) {
        temp = list_entry(pos2, struct work_queue_node, list);
        if (temp) {
			idlist[count] = temp->wi->wi_id;
			count++;
        }
    }

    list_for_each_safe(pos3, q3, &((*wi_queue->wi_low_head).list)) {
        temp = list_entry(pos3, struct work_queue_node, list);
        if (temp) {
			idlist[count] = temp->wi->wi_id;
			count++;
        }
    }
	
	retval = copy_to_user(destination, (void *)idlist, sizeof(int) * count);

	if (0 != retval) {
		printk("could not copy to user space %d\n", retval);
		return -ENOMEM;
	}
   
    mutex_unlock(&wi_queue->mutex_queue);

    return 0;
}


int validate(void *arg)
{
	if (NULL == arg) {
		printk(KERN_ALERT "arguement received is null\n");
		return -EINVAL;
	}


	return 0;
}

/* System call that will enqueue the job into work item queue */

asmlinkage long submitjob(void *arg)
{
	int err = 0, job_id;
	struct work_item_node *wi = NULL;
    int bytesNotCopied;
    struct work_item_node* source = arg;
    struct work_item_node *temp = NULL;

	LOG_TRACE;

	if (arg == NULL) {
		printk("arguement received is null\n");
		err = -EINVAL;
		goto exit;
	}

	err = validate(arg);

	if (0 != err) {
		printk(KERN_ALERT "args for system call are wrong\n");
		goto exit;
	}

	wi = kmalloc(sizeof(struct work_item_node), GFP_KERNEL);
    if (NULL == wi) {
        err = -ENOMEM;
        printk(KERN_ALERT "Could not allocate memory for arg \n");
        goto exit;
    }

	bytesNotCopied = copy_from_user(wi, arg, sizeof(struct work_item_node));
	if(bytesNotCopied != 0)
		printk("Failed to copy user args\n");

	switch(source->wi_opt) {
		/* If it is an encryption job, enqueue it into work item queue */
		case XCRYPT:
			wi->infile = kmalloc(strlen_user(source->infile), GFP_KERNEL);
			if (!wi->infile) {
				err = -ENOMEM;
				goto clean_wi;
			}

			bytesNotCopied = copy_from_user(wi->infile, source->infile,
											strlen_user(source->infile));

			if (bytesNotCopied != 0)
				printk("Failed to copy infile name from the user memory\n");

			wi->outfile = kmalloc(strlen_user(source->outfile),
													GFP_KERNEL);
			if (!wi->outfile) {
				err = -ENOMEM;
				goto clean_wi;
			}

			bytesNotCopied = copy_from_user(wi->outfile,
											source->outfile,
											strlen_user(source->outfile));
			if (bytesNotCopied != 0)
				printk("Failed to copy outfile name from the user memory\n");

			wi->key = kmalloc(strlen_user(source->key), GFP_KERNEL);
			if (!wi->key) {
				err = -ENOMEM;
				goto clean_wi;
			}

			bytesNotCopied = copy_from_user(wi->key, source->key,
											strlen_user(source->key));

			if (bytesNotCopied != 0)
				printk("Failed to copy key from the user memory\n");
			break;

		/* Remove, list, and change priorrity jobs are treated syncronously.
		 * It will acquire lock on the work item queue at that very moment
		 * and perform the operation */
        case REMOVE_JOB:
			wi->args = (int*)kmalloc(sizeof(int), GFP_KERNEL);
            bytesNotCopied = copy_from_user(wi->args,
										source->args, sizeof(int));
			job_id = *(int*)(wi->args);
			printk("Removing Job ID: %d\n", job_id);
            err = remove_job(job_id);
			goto clean_wi;

        case LIST_QUEUED_JOBS:
            temp = (struct work_item_node *)arg;
            err = list_jobs(temp->args);
			goto clean_wi;

		case CHANGE_JOB_PRIORITY:
			wi->args = (int*)kmalloc(sizeof(int), GFP_KERNEL);
            bytesNotCopied = copy_from_user(wi->args,
									source->args, sizeof(int));
            job_id = *(int*)(wi->args);
            printk("Changing Priority of Job ID: %d to %d\n",
				   job_id, wi->wi_priority);
            err = change_priority(job_id, wi->wi_priority);
            goto clean_wi;

		case CONCATENATE_FILES:
            goto clean_wi;

		case COMPRESSION:
            goto clean_wi;
		default:
			printk(KERN_ALERT "Wrong operation\n");
			goto exit;
    }

	/* Enqueue the job in work item queue */
	err = enqueue_job(wi);

	if (0 != err) {
		printk("Could not enqueue job\n");
		goto clean_wi;
	}

	/* Wake up consumers as now we have data in work item queue */

	wake_up_all(&consumer_wait_queue);

	return err;

clean_wi:
	kfree(wi);
exit:
	return err;
}

/* Setup the list heads for queues associated with difference priorities
 * Initialize the size and locks for the queue data structure */

int setup_wi_queue(void)
{
	int err = 0;
	int i = 0;

	wi_queue	= kzalloc(sizeof(struct work_queue), GFP_KERNEL);

	if (NULL == wi_queue) {
		err = -ENOMEM;
		goto exit;
	}

	wi_queue->wi_high_head	= kzalloc(sizeof(struct work_queue_node),
									  GFP_KERNEL);

	if (NULL == wi_queue->wi_high_head) {
		err = -ENOMEM;
		goto exit;
	}

	wi_queue->wi_medium_head	= kzalloc(sizeof(struct work_queue_node),
										  GFP_KERNEL);

	if (NULL == wi_queue->wi_medium_head) {
		err = -ENOMEM;
		goto exit;
	}

	wi_queue->wi_low_head	= kzalloc(sizeof(struct work_queue_node),
									  GFP_KERNEL);

	if (NULL == wi_queue->wi_low_head) {
		err = -ENOMEM;
		goto exit;
	}

	INIT_LIST_HEAD(&(wi_queue->wi_high_head->list));
	INIT_LIST_HEAD(&(wi_queue->wi_medium_head->list));
	INIT_LIST_HEAD(&(wi_queue->wi_low_head->list));

	mutex_init(&wi_queue->mutex_queue);
	atomic_set(&(wi_queue->queue_size), 0);;

	for (i = 0; i < MAXCONSUMERS; ++i)
		consumers[i] = kthread_create(work_on_consumer, NULL, "consumer");

	for (i = 0; i < MAXCONSUMERS; ++i)
		wake_up_process(consumers[i]);

exit:
	return err;
}

static int __init init_sys_submitjob(void)
{
	int err = 0;

	struct netlink_kernel_cfg cfg = {
        .flags  = NL_CFG_F_NONROOT_RECV,
    };

	/* Setup work item queue */
	err = setup_wi_queue();

	/* Setup netlink for callback */
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

	is_exit = 0;

	if (0 != err) {
		printk("Could not setup wi queue\n");
		goto exit;
	}

	/* Initialize waitqueue for consumer and producer threads */

	init_waitqueue_head(&consumer_wait_queue);
	init_waitqueue_head(&producer_wait_queue);

	atomic_set(&(throttled_producers), 0);

	if (sysptr == NULL)
		sysptr = submitjob;

exit:
	return err;
}

static void  __exit exit_sys_submitjob(void)
{
	struct list_head    *pos1 = NULL, *q1 = NULL;
	struct list_head    *pos2 = NULL, *q2 = NULL;
	struct list_head    *pos3 = NULL, *q3 = NULL;

	/* Cleanup the work item queue while unloading syscall */

	list_for_each_safe(pos1, q1, &((*wi_queue->wi_high_head).list)) {
		struct work_queue_node *tmp1;
		tmp1 = list_entry(pos1, struct work_queue_node, list);
		list_del_init(pos1);
		kfree(tmp1);
    }

	list_for_each_safe(pos2, q2, &((*wi_queue->wi_medium_head).list)) {
		struct work_queue_node *tmp1;
		tmp1 = list_entry(pos2, struct work_queue_node, list);
		list_del_init(pos2);
		kfree(tmp1);
    }

	list_for_each_safe(pos3, q3, &((*wi_queue->wi_low_head).list)) {
		struct work_queue_node *tmp1;
		tmp1 = list_entry(pos3, struct work_queue_node, list);
		list_del_init(pos3);
		kfree(tmp1);
    }

	/* Enabling the exit flag and waking up sleeping worker threads
	 * for gracefull exit */

	is_exit = 1;
	atomic_inc(&(wi_queue->queue_size));

	wake_up_all(&consumer_wait_queue);

	if (sysptr != NULL)
		sysptr = NULL;

	/* Cleaning up netlink stuff */

	netlink_kernel_release(nl_sk);
	printk("removed sys_submitjob module\n");
}

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
