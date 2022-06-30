#if !defined(__x86_64__)
#error "This program only works for x86_64"
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include "include/http_parser.h"

/* HTTP responses*/
#define RESPONSE_METHOD_NOT_ALLOWED "HTTP/1.1 405 Method Not Allowed\r\n"

// To avoid file io, only return a simple HelloWorld!
#define RESPONSE_OK "HTTP/1.1 200 OK\r\n" \
                    "Content-Length: 21\r\n" \
                    "Content-Type: text/html\r\n" \
                    "Connection: keep-alive\r\n" \
                    "Server: uThreads-http\r\n" \
                    "\r\n" \
                    "<p>Hello World!</p>\n"
#define	HTTP_REQUEST_HEADER_END	"\n\r\n\r"

#define MAXIMUM_THREADS_PER_CLUSTER 8
#define INPUT_BUFFER_LENGTH         1024 //4 KB
#define PORT_NO                     8888
#define ERROR(msg) perror(msg);

http_parser_settings settings;

/**
 * @brief Spin Lock object
 */
typedef struct {
    volatile int lock;
    unsigned int locker;
} spin_t;

/**
 * @brief Mutex object
 */
typedef struct {
    volatile int lock;
    unsigned int locker;
} mutex_t;

#define gettid() syscall(SYS_gettid)

/**
 * @brief Initialize the spinlock object
 * @param lock Spinlock object
 */
static inline int spin_init(spin_t *l)
{
    volatile int out;
    volatile int *lck = &(l->lock);
    asm("movl $0x0,(%1);" : "=r"(out) : "r"(lck));
    l->locker = 0;
    return 0;
}

/**
 * @brief Acquire a lock and wait atomically for the lock object
 * @param lock Spinlock object
 */
static inline int spin_acquire(spin_t *l)
{
    int out;
    volatile int *lck = &(l->lock);
    asm("whileloop:"
        "xchg %%al, (%1);"
        "test %%al,%%al;"
        "jne whileloop;"
        : "=r"(out)
        : "r"(lck));
    return 0;
}

/**
 * @brief Release lock atomically
 * @param lock Spinlock object
 */
static inline int spin_release(spin_t *l)
{
    int out;
    volatile int *lck = &(l->lock);
    asm("movl $0x0,(%1);" : "=r"(out) : "r"(lck));
    l->locker = 0;
    return 0;
}

/**
 * @brief Initialize the mutex lock object
 * @param lock Mutex Lock object
 */
static inline int mutex_init(mutex_t *m)
{
    volatile int *lck = &(m->lock);
    int out;
    asm("movl $0x0,(%1);" : "=r"(out) : "r"(lck));
    m->locker = 0;
    return 0;
}

/**
 * @brief Atomically acquire the lock and wait by sleeping if not available
 * @param lock Mutex Lock object
 */
static __attribute__((noinline)) int mutex_acquire(mutex_t *m)
{
    volatile int out;
    volatile int *lck = &(m->lock);
    asm("mutexloop:"
        "mov $1, %%eax;"
        "xchg %%al, (%%rdi);"
        "test %%al,%%al;"
        "je end"
        : "=r"(out)
        : "r"(lck));
    syscall(SYS_futex, m, FUTEX_WAIT, 1, NULL, NULL, 0);
    asm("jmp mutexloop");
    asm("end:");
    return 0;
}

/**
 * @brief Release the lock object atomically and wake up waiting threads
 * @param lock Mutex Lock object
 */
static inline int mutex_release(mutex_t *m)
{
    volatile int out;
    volatile int *lck = &(m->lock);
    asm("movl $0x0,(%1);" : "=r"(out) : "r"(lck));
    m->locker = 0;
    syscall(SYS_futex, m, FUTEX_WAKE, 1, NULL, NULL, 0);
    return 0;
}

/**
 * @brief Default stack size for a thread
 */
#define STACK_SZ 65536

/**
 * @brief Default guard page size for a thread
 */
#define GUARD_SZ getpagesize()

/**
 * @brief Flags passed to clone system call in one-one implementation
 */
#define CLONE_FLAGS                                                     \
    (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | \
     CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID)
#define TGKILL 234

/**
 * @brief Thread Object
 */
typedef unsigned long thread_t;

/**
 * @brief Arguments passed to the wrapper function
 */
typedef struct {
    void (*f)(void *);
    void *arg;
    void *stack;
} funcargs_t;

/**
 * @brief Node in the TCB of the thread
 */
typedef struct __node {
    unsigned long int tid, tid_copy;
    void *ret_val;
    struct __node *next;
    funcargs_t *fa;
} node_t;

/**
 * @brief Singly-linked list of thread control blocks (TCB)
 */
typedef struct {
    node_t *head, *tail;
} list_t;

#define INIT_SIGNALS()                              \
    do {                                            \
        sigset_t signal_mask;                       \
        sigfillset(&signal_mask);                   \
        sigdelset(&signal_mask, SIGINT);            \
        sigdelset(&signal_mask, SIGSTOP);           \
        sigdelset(&signal_mask, SIGCONT);           \
        sigprocmask(SIG_BLOCK, &signal_mask, NULL); \
    } while (0)

/**
 * @brief Initialize the singly-linked list
 * @param ll Pointer to a linked list object
 * @return 0 on sucess, -1 on failure -1
 */
int list_init(list_t *ll)
{
    if (!ll)
        return -1;
    ll->head = ll->tail = NULL;
    return 0;
}

/**
 * @brief Insert a node into the linked list
 * @param ll Pointer to the linked list
 * @param tid Thread ID of the new node
 * @return Pointer to new node on success, NULL on failure
 */
node_t *list_insert(list_t *ll, unsigned long int tid)
{
    node_t *tmp;
    if (posix_memalign((void **) &tmp, 8, sizeof(node_t))) {
        perror("ll alloc");
        return NULL;
    }
    tmp->tid = tid;
    tmp->next = NULL;
    tmp->ret_val = NULL;
    if (!ll->head) {
        ll->head = ll->tail = tmp;
    } else {
        ll->tail->next = tmp;
        ll->tail = tmp;
    }
    return tmp;
}

/**
 * @brief Delete a node from the linked list
 * @param ll Pointer to the linked list
 * @param tid Thread ID of the node
 * @return 0 on deletion, -1 on not found
 */
int list_delete(list_t *ll, unsigned long int tid)
{
    node_t *tmp = ll->head;
    if (!tmp)
        return -1;

    if (tmp->tid_copy == tid) {
        ll->head = ll->head->next;
        if (tmp->fa && munmap(tmp->fa->stack, STACK_SZ + getpagesize()))
            return errno;
        free(tmp->fa);
        free(tmp);
        if (!ll->head)
            ll->tail = NULL;
        return 0;
    }

    for (; tmp->next; tmp = tmp->next) {
        if (tmp->next->tid_copy == tid) {
            node_t *tmpNext = tmp->next->next;
            if (tmp->next == ll->tail)
                ll->tail = tmp;
            if (tmp->next->fa &&
                munmap(tmp->next->fa->stack, STACK_SZ + getpagesize()))
                return errno;
            free(tmp->next->fa);
            free(tmp->next);
            tmp->next = tmpNext;
            break;
        }
    }
    return 0;
}

/**
 * @brief Get the address of the node with a given tid
 * @param ll Pointer to linked list
 * @param tid Thread ID of the node
 * @return address of tail on success, NULL on failure
 */
static unsigned long int *get_tid_addr(list_t *ll, unsigned long int tid)
{
    for (node_t *tmp = ll->head; tmp; tmp = tmp->next) {
        if (tmp->tid_copy == tid)
            return &(tmp->tid);
    }
    return NULL;
}

static inline node_t *get_node_from_tid(list_t *ll, unsigned long int tid)
{
    for (node_t *tmp = ll->head; tmp; tmp = tmp->next) {
        if (tmp->tid_copy == tid)
            return tmp;
    }
    return NULL;
}

/**
 * @brief Send process wide signal dispositions to all active threads
 * @param ll Pointer to linked list
 * @param signum Signal number
 * @return 0 on success, errno on failure
 */
static int kill_all_threads(list_t *ll, int signum)
{
    pid_t pid = getpid(), delpid[100];
    int counter = 0;
    for (node_t *tmp = ll->head; tmp; tmp = tmp->next) {
        if (tmp->tid == gettid()) {
            tmp = tmp->next;
            continue;
        }

        printf("Killed thread %lu\n", tmp->tid);
        int ret = syscall(TGKILL, pid, tmp->tid, signum);
        if (ret == -1) {
            perror("tgkill");
            return errno;
        }
        if (signum == SIGINT || signum == SIGKILL)
            delpid[counter++] = tmp->tid;
    }
    if (signum == SIGINT || signum == SIGKILL) {
        for (int i = 0; i < counter; i++)
            list_delete(ll, delpid[i]);
    }
    return 0;
}

/**
 * @brief Umbrella function to free resources used by threads
 * @param l Pointer to list_t list
 */
static void delete_all_threads(list_t *l)
{
    int *deleted = NULL;
    int n_deleted = 0;
    for (node_t *tmp = l->head; tmp; tmp = tmp->next) {
        if (tmp->tid == 0) {
            deleted = realloc(deleted, (++n_deleted) * sizeof(int));
            deleted[n_deleted - 1] = tmp->tid_copy;
        }
    }

    for (int i = 0; i < n_deleted; i++)
        list_delete(l, deleted[i]);
    free(deleted);
}

/**
 * @brief Thread object
 */
typedef unsigned long int thread_t;

/**
 * @brief Macro for installing custom signal handlers for threads
 */
#define WRAP_SIGNALS(signum)                        \
    do {                                            \
        signal(signum, sig_handler);                \
        sigemptyset(&base_mask);                    \
        sigaddset(&base_mask, signum);              \
        sigprocmask(SIG_UNBLOCK, &base_mask, NULL); \
    } while (0)

#define RED "\033[1;31m"
#define RESET "\033[0m"

/**
 * @brief Custom signal handler function
 * @param signum Signal Number
 */
static void sig_handler(int signum)
{
    printf(RED "Signal Dispatched\n" RESET);
    printf("Thread tid %ld handled signal\n", (long) gettid());
    fflush(stdout);
}

static spin_t global_lock;
static list_t tid_list;

/**
 * @brief Cleanup handler for freeing resources of all threads at exit
 */
static void cleanup()
{
    delete_all_threads(&tid_list);
    free(tid_list.head);
}

/**
 * @brief Library initialzer for setting up data structures and handlers
 */
static void init()
{
    spin_init(&global_lock);
    INIT_SIGNALS();
    list_init(&tid_list);
    node_t *node = list_insert(&tid_list, getpid());
    node->tid_copy = node->tid;
    node->fa = NULL;
    atexit(cleanup);
}

/**
 * @brief Function to allocate a stack to One One threads
 * @param size Size of stack excluding the guard size
 * @param guard Size of guard page
 */
static void *alloc_stack(size_t size, size_t guard)
{
    /* Align the memory to a 64 bit compatible page size and associate a guard
     * area for the stack.
     */
    void *stack = mmap(NULL, size + guard, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) {
        perror("Stack Allocation");
        return NULL;
    }

    if (mprotect(stack, guard, PROT_NONE)) {
        munmap(stack, size + guard);
        perror("Stack Allocation");
        return NULL;
    }
    return stack;
}

void thread_exit(void *ret);

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/**
 * @brief Wrapper for the routine passed to the thread
 * @param fa Function pointer of the routine passed to the thread
 */
static int wrap(void *fa)
{
    funcargs_t *tmp = (funcargs_t *) fa;
    sigset_t base_mask;
    int sig_arr[] = {SIGTERM, SIGFPE, SIGSYS, SIGABRT, SIGPIPE};
    sigset_t mask_arr[ARRAY_SIZE(sig_arr)];
    for (int i = 0; i < ARRAY_SIZE(sig_arr); i++) {
        base_mask = mask_arr[i];
        WRAP_SIGNALS(sig_arr[i]);
    }
    (tmp->f)(tmp->arg);
    thread_exit(NULL);
    return 0;
}

/**
 * @brief Function to send signals to a specific thread
 * @param tid TID of the thread to which the signal has to be sent
 * @param signum Signal number of the signal to be sent to the thread
 */
int thread_kill(pid_t tid, int signum)
{
    if (signum == 0)
        return -1;

    int ret;
    node_t *node = get_node_from_tid(&tid_list, tid);
    if (signum == SIGINT || signum == SIGCONT || signum == SIGSTOP) {
        kill_all_threads(&tid_list, signum);
        pid_t pid = getpid();
        ret = syscall(TGKILL, pid, gettid(), signum);
        if (ret == -1) {
            perror("tgkill");
            return ret;
        }
        return ret;
    }
    if (node->tid == 0)
        return -1;

    ret = syscall(TGKILL, getpid(), tid, signum);
    if (ret == -1) {
        perror("tgkill");
        return ret;
    }
    return ret;
}

/**
 * @brief Function to wait for a specific thread to terminate
 * @param t TID of the thread to wait for
 * @param guard Size of guard pag
 */
int thread_join(thread_t t, void **retval)
{
    spin_acquire(&global_lock);
    void *addr = get_tid_addr(&tid_list, t);
    if (!addr) {
        spin_release(&global_lock);
        return ESRCH;
    }
    if (*((pid_t *) addr) == 0) {
        spin_release(&global_lock);
        return EINVAL;
    }

    int ret = 0;
    while (*((pid_t *) addr) == t) {
        spin_release(&global_lock);
        ret = syscall(SYS_futex, addr, FUTEX_WAIT, t, NULL, NULL, 0);
        spin_acquire(&global_lock);
    }
    syscall(SYS_futex, addr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    if (retval)
        *retval = get_node_from_tid(&tid_list, t)->ret_val;

    spin_release(&global_lock);
    return ret;
}

/**
 * @brief Function to make a thread terminate itself
 * @param ret return value of the thread to be available to thread_join()
 * @note Implicit call to thread_exit is made by each thread after completing
 * the execution of routine
 */
void thread_exit(void *ret)
{
    spin_acquire(&global_lock);
    void *addr = get_tid_addr(&tid_list, gettid());
    if (!addr) {
        spin_release(&global_lock);
        return;
    }

    if (ret) {
        node_t *node = get_node_from_tid(&tid_list, gettid());
        node->ret_val = ret;
    }
    syscall(SYS_futex, addr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    spin_release(&global_lock);
    kill(SIGINT, gettid());
}

#define safe_printf(print_lock, f_, ...) \
    do {                                 \
        spin_acquire(print_lock);        \
        printf((f_), ##__VA_ARGS__);     \
        spin_release(print_lock);        \
    } while (0)

static mutex_t lock, rwlock;
static spin_t print_lock;

typedef struct Connection{
    /* used with polling */
    //PollData* pd;
    //related file descriptor
    int fd;
}Connection;
Connection* sconn; //Server socket

typedef struct {
    Connection* conn;
    bool keep_alive;
    char* url;
    int url_length;
} custom_data_t;

Connection* accept_conn(Connection *conn){
    //assert(conn->fd != -1);
    //check connection queue for waiting connections
    //Set the fd as nonblocking
    int sockfd = accept4(conn->fd, NULL, NULL, SOCK_NONBLOCK );
    while( (sockfd == -1) && (errno == EAGAIN || errno == EWOULDBLOCK)){
        //User level blocking using nonblocking io
        //IOHandler::iohandler.wait(*pd, IOHandler::Flag::UT_IOREAD);
        sockfd = accept4(conn->fd, NULL, NULL, SOCK_NONBLOCK );
    }
    //otherwise return the result
    if(sockfd > 0){
        Connection *new_conn = (Connection *)malloc(sizeof(Connection));
        new_conn->fd = sockfd;
        return new_conn;
    }else{
        //printf("sfd:%d, fd: %d, errno: %d\n", conn->fd, sockfd, errno);
        ERROR("Error on accpet");
        return NULL;
    }

}

void init_conn(Connection *conn){
    conn->fd = -1;
    //conn->pd = NULL;
}

void close_conn(Connection *conn){
    // IOHandler::iohandler.close(*pd)
    close(conn->fd);
}

ssize_t recv_conn(int fd, void *buf, size_t len, int flags){
    //assert(buf != NULL);
    //assert(fd != -1);

    ssize_t res = recv(fd, (void*)buf, len, flags);
    while( (res == -1) && (errno == EAGAIN || errno == EWOULDBLOCK)){
           //User level blocking using nonblocking io
           //IOHandler::iohandler.wait(*pd, IOHandler::Flag::UT_IOREAD);
           res = recv(fd, buf, len, flags);
    }
    return res;
}

ssize_t send_conn(int fd, const void *buf, size_t len, int flags){
    //assert(buf != NULL);
    //assert(fd != -1);

    ssize_t res = send(fd, buf, len, flags);
    while( (res == -1) && (errno == EAGAIN || errno == EWOULDBLOCK)){
        //IOHandler::iohandler.wait(*pd, IOHandler::Flag::UT_IOWRITE);
        res = send(fd, buf, len, flags);
    }
    return res;
}

ssize_t read_http_request(Connection *cconn, void *vptr, size_t n){

	size_t nleft;
	ssize_t nread;
	char * ptr;

	ptr = (char *)vptr;
	nleft = n;

	//uThread::yield(); //yield before read
    while(nleft >0){
    	if( (nread = recv_conn(cconn->fd, ptr, INPUT_BUFFER_LENGTH - 1, 0)) <0){
    		if (errno == EINTR)
    			nread =0;
    		else
    			return (-1);
    	}else if(nread ==0)
    		break;

    	nleft -= nread;

    	//Check whether we are at the end of the http_request
    	if(memcmp((const void*)&ptr[nread-4], HTTP_REQUEST_HEADER_END, 4))
    		break;

    	ptr += nread;

    }

    return (n-nleft);
}

ssize_t writen(Connection *cconn, const void *vptr, size_t n){

	size_t nleft;
	ssize_t nwritten;
	const char *ptr;

	ptr = (char*)vptr;
	nleft = n;

	while(nleft > 0){
		if( (nwritten = send_conn(cconn->fd, ptr, nleft, 0)) <= 0){
			if(errno == EINTR)
				nwritten = 0; /* If interrupted system call => call the write again */
			else
				return (-1);
		}
		nleft -= nwritten;
		ptr += nwritten;

	}

	return (n);
}

int on_headers_complete(http_parser* parser){

    //Check whether we should keep-alive or close
    custom_data_t *my_data = (custom_data_t*)parser->data;
    my_data->keep_alive = http_should_keep_alive(parser);

    return 0;
}

int on_header_field(http_parser* parser, const char* header, long unsigned int size){
    printf("%s\n", header);
    return 0;
}

/* handle connection after accept */
void *handle_connection(void *arg){
	Connection* cconn = (Connection*) arg;

	custom_data_t *my_data = (custom_data_t*)malloc(sizeof(custom_data_t));
	my_data->conn = cconn;
	my_data->keep_alive = 0;
	my_data->url = NULL;

    http_parser *parser = (http_parser *) malloc(sizeof(http_parser));
    if(parser == NULL)
        exit(1);
    http_parser_init(parser, HTTP_REQUEST);
	//pass connection and custom data to the parser
    parser->data = (void *) my_data;



    char buffer[INPUT_BUFFER_LENGTH]; //read buffer from the socket
    bzero(buffer, INPUT_BUFFER_LENGTH);

    size_t nparsed;
    ssize_t nrecvd; //return value for for the read() and write() calls.

    do{
        //Since we only accept GET, just try to read INPUT_BUFFER_LENGTH
        nrecvd = read_http_request(cconn, buffer, INPUT_BUFFER_LENGTH -1);
        if(nrecvd<0){
            //if RST packet by browser, just close the connection
            //no need to show an error.
            if(errno != ECONNRESET){
                ERROR("Error reading from socket");
                printf("fd %d\n", cconn->fd);
            }
            break;
        }

        nparsed = http_parser_execute(parser, &settings, buffer, nrecvd);
        if(nrecvd == 0) break;
        if(nparsed != nrecvd){
            ERROR("Error in Parsing the request!");
        }else{
            //We only handle GET Requests
            if(parser->method == 1)
            {
                //Write the response
                writen(cconn, RESPONSE_OK, sizeof(RESPONSE_OK));
            }else{
                //Method is not allowed
                writen(cconn, RESPONSE_METHOD_NOT_ALLOWED, sizeof(RESPONSE_METHOD_NOT_ALLOWED));
            }
        }
        //reset data
        my_data->url_length = 0;
    }while(my_data->keep_alive);
    close_conn(cconn);
    free(my_data);
    free(cconn);
    free(parser);
}
/**
 * @brief Create a One One mapped thread
 * @param t Reference to the thread
 * @param routine Function associated with the thread
 * @param arg Arguments to the routine
 */
int thread_create(thread_t *t, void *routine, void *arg)
{
    spin_acquire(&global_lock);
    static bool init_state = false;
    if (!t || !routine) {
        spin_release(&global_lock);
        return EINVAL;
    }
    if (!init_state) {
        init_state = true;
        init();
    }

    node_t *node = list_insert(&tid_list, 0);
    if (!node) {
        printf("Thread address not found\n");
        spin_release(&global_lock);
        return -1;
    }

    funcargs_t *fa = malloc(sizeof(funcargs_t));
    if (!fa) {
        printf("Malloc failed\n");
        spin_release(&global_lock);
        return -1;
    }

    fa->f = routine;
    fa->arg = arg;
    void *thread_stack = alloc_stack(STACK_SZ, GUARD_SZ);
    if (!thread_stack) {
        perror("thread create");
        spin_release(&global_lock);
        free(fa);
        return errno;
    }
    fa->stack = thread_stack;
    thread_t tid = clone(wrap, (char *) thread_stack + STACK_SZ + GUARD_SZ,
                         CLONE_FLAGS, fa, &(node->tid), NULL, &(node->tid)); //EXP1 = EXP2 = node->tid
    node->tid_copy = tid;
    node->fa = fa;

    if (tid == -1) {
        perror("thread create");
        free(thread_stack);
        spin_release(&global_lock);
        return errno;
    }
    *t = tid;
    spin_release(&global_lock);
    return 0;
}

int main(int argc, char *argv[]){
    mutex_init(&lock);
    mutex_init(&rwlock);
    spin_init(&print_lock);

    /**
     * Server socked
     */
    struct sockaddr_in serv_addr;
    sconn = (Connection *)malloc(sizeof(Connection));
    sconn->fd = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);    //opening a socket for the tcp server
    if (sconn->fd < 0){
       ERROR("Error opening socket");
       exit(1);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));  //Init server_addr
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT_NO);

    if (bind(sconn->fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){  //bind socket 於本機所有IP(INADDR_ANY)和指定port
        ERROR("Error on binding");
        exit(1);
    }
    thread_t t;
    //listen for client, max queue length
    listen(sconn->fd, 65535);
    while(1){
        Connection *cconn = accept_conn(sconn);
        // uthreads -> handle connection
        if (!cconn)
            continue;
        thread_create(&t, handle_connection, (void *)cconn);
    }
    close(sconn->fd);
    return 0;
}