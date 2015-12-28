#define MAXCONSUMERS 2
#define MAXPRODUCERS 5

#include "work_item.h"

#define LOG_TRACE //printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#define NETLINK_USER 31
#define TESTING 0

extern int calculate_distance(int a, int b);
extern int xcrypt(void *arg);

struct task_struct * consumers[MAXCONSUMERS];

int is_exit;

struct work_queue_node {
	struct work_item_node *wi;
	struct list_head	list;
};

struct work_queue {
	struct work_queue_node *wi_high_head;
	struct work_queue_node *wi_medium_head;
	struct work_queue_node *wi_low_head;
	struct mutex	mutex_queue;
	atomic_t queue_size;
};

atomic_t throttled_producers;

static wait_queue_head_t consumer_wait_queue;
struct work_queue *wi_queue;
static wait_queue_head_t producer_wait_queue;
