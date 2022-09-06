// rename some redis type
typedef unsigned long long ruint64_t;
typedef unsigned long long rsize_t;
typedef long long rtime_t;
typedef long roff_t;

// https://github.com/redis/redis/blob/6.2.1/src/sds.h#L43
typedef char *sds;
// https://github.com/redis/redis/blob/6.2.1/src/connection.h#L37
typedef struct connection connection;
// https://github.com/redis/redis/blob/6.2.1/src/connection.h#L39
typedef enum {
    CONN_STATE_NONE = 0,
    CONN_STATE_CONNECTING,
    CONN_STATE_ACCEPTING,
    CONN_STATE_CONNECTED,
    CONN_STATE_CLOSED,
    CONN_STATE_ERROR
} ConnectionState;
// https://github.com/redis/redis/blob/6.2.1/src/connection.h#L73
struct connection {
    void *type;
    ConnectionState state;
    short int flags;
    short int refs;
    int last_errno;
    void *private_data;
    void *conn_handler;
    void *write_handler;
    void *read_handler;
    int fd;
};
// https://github.com/redis/redis/blob/6.2.1/src/server.h#L58
typedef long long mstime_t; /* millisecond time type. */
// https://github.com/redis/redis/blob/6.2.1/src/server.h#L106
#define CONFIG_RUN_ID_SIZE 40
// https://github.com/redis/redis/blob/6.2.1/src/server.h#L142
#define PROTO_REPLY_CHUNK_BYTES (16*1024) /* 16k output buffer */
// https://github.com/redis/redis/blob/6.2.1/src/server.h#L660
#define LRU_BITS 24
// https://github.com/redis/redis/blob/6.2.1/src/server.h#L667
typedef struct redisObject {
    unsigned type:4;
    unsigned encoding:4;
    unsigned lru:LRU_BITS; /* LRU time (relative to global lru_clock) or
                            * LFU data (least significant 8 bits frequency
                            * and most significant 16 bits access time). */
    int refcount;
    void *ptr;
} robj;
// https://github.com/redis/redis/blob/6.2.1/src/server.h#L729
typedef struct multiState {
    void *commands;     /* Array of MULTI commands */
    int count;              /* Total number of MULTI commands */
    int cmd_flags;          /* The accumulated command flags OR-ed together.
                               So if at least a command has a given flag, it
                               will be set in this field. */
    int cmd_inv_flags;      /* Same as cmd_flags, OR-ing the ~flags. so that it
                               is possible to know if all the commands have a
                               certain flag. */
    int minreplicas;        /* MINREPLICAS for synchronous replication */
    rtime_t minreplicas_timeout; /* MINREPLICAS timeout as unixtime. */
} multiState;
// https://github.com/redis/redis/blob/6.2.1/src/server.h#L744
typedef struct blockingState {
    /* Generic fields. */
    mstime_t timeout;       /* Blocking operation timeout. If UNIX current time
                             * is > timeout then the operation timed out. */

    /* BLOCKED_LIST, BLOCKED_ZSET and BLOCKED_STREAM */
    void *keys;             /* The keys we are waiting to terminate a blocking
                             * operation such as BLPOP or XREAD. Or NULL. */
    void *target;           /* The key that should receive the element,
                             * for BLMOVE. */
    struct listPos {
        int wherefrom;      /* Where to pop from */
        int whereto;        /* Where to push to */
    } listpos;              /* The positions in the src/dst lists
                             * where we want to pop/push an element
                             * for BLPOP, BRPOP and BLMOVE. */

    /* BLOCK_STREAM */
    rsize_t xread_count;     /* XREAD COUNT option. */
    void *xread_group;      /* XREADGROUP group name. */
    void *xread_consumer;   /* XREADGROUP consumer name. */
    mstime_t xread_retry_time, xread_retry_ttl;
    int xread_group_noack;

    /* BLOCKED_WAIT */
    int numreplicas;        /* Number of replicas we are waiting for ACK. */
    long long reploffset;   /* Replication offset to reach. */

    /* BLOCKED_MODULE */
    void *module_blocked_handle; /* RedisModuleBlockedClient structure.
                                    which is opaque for the Redis core, only
                                    handled in module.c. */
} blockingState;
// https://github.com/redis/redis/blob/6.2.1/src/server.h#L855
typedef struct client {
    ruint64_t id;            /* Client incremental unique ID. */
    connection *conn;
    int resp;               /* RESP protocol version. Can be 2 or 3. */
    void *db;            /* Pointer to currently SELECTed DB. */
    robj *name;             /* As set by CLIENT SETNAME. */
    sds querybuf;           /* Buffer we use to accumulate client queries. */
    rsize_t qb_pos;          /* The position we have read in querybuf. */
    sds pending_querybuf;   /* If this client is flagged as master, this buffer
                               represents the yet not applied portion of the
                               replication stream that we are receiving from
                               the master. */
    rsize_t querybuf_peak;   /* Recent (100ms or more) peak of querybuf size. */
    int argc;               /* Num of arguments of current command. */
    robj **argv;            /* Arguments of current command. */
    int original_argc;      /* Num of arguments of original command if arguments were rewritten. */
    robj **original_argv;   /* Arguments of original command if arguments were rewritten. */
    rsize_t argv_len_sum;    /* Sum of lengths of objects in argv list. */
    void *cmd, *lastcmd;  /* Last command executed. */
    void *user;             /* User associated with this connection. If the
                               user is set to NULL the connection can do
                               anything (admin). */
    int reqtype;            /* Request protocol type: PROTO_REQ_* */
    int multibulklen;       /* Number of multi bulk arguments left to read. */
    long bulklen;           /* Length of bulk argument in multi bulk request. */
    void *reply;            /* List of reply objects to send to the client. */
    unsigned long long reply_bytes; /* Tot bytes of objects in reply list. */
    rsize_t sentlen;         /* Amount of bytes already sent in the current
                               buffer or object being sent. */
    rtime_t ctime;           /* Client creation time. */
    long duration;          /* Current command duration. Used for measuring latency of blocking/non-blocking cmds */
    rtime_t lastinteraction; /* Time of the last interaction, used for timeout */
    rtime_t obuf_soft_limit_reached_time;
    ruint64_t flags;         /* Client flags: CLIENT_* macros. */
    int authenticated;      /* Needed when the default user requires auth. */
    int replstate;          /* Replication state if this is a slave. */
    int repl_put_online_on_ack; /* Install slave write handler on first ACK. */
    int repldbfd;           /* Replication DB file descriptor. */
    roff_t repldboff;        /* Replication DB file offset. */
    roff_t repldbsize;       /* Replication DB file size. */
    sds replpreamble;       /* Replication DB preamble. */
    long long read_reploff; /* Read replication offset if this is a master. */
    long long reploff;      /* Applied replication offset if this is a master. */
    long long repl_ack_off; /* Replication ack offset, if this is a slave. */
    long long repl_ack_time;/* Replication ack time, if this is a slave. */
    long long psync_initial_offset; /* FULLRESYNC reply offset other slaves
                                       copying this slave output buffer
                                       should use. */
    char replid[CONFIG_RUN_ID_SIZE+1]; /* Master replication ID (if master). */
    int slave_listening_port; /* As configured with: REPLCONF listening-port */
    char *slave_addr;       /* Optionally given by REPLCONF ip-address */
    int slave_capa;         /* Slave capabilities: SLAVE_CAPA_* bitwise OR. */
    multiState mstate;      /* MULTI/EXEC state */
    int btype;              /* Type of blocking op if CLIENT_BLOCKED. */
    blockingState bpop;     /* blocking state */
    long long woff;         /* Last write global replication offset. */
    void *watched_keys;     /* Keys WATCHED for MULTI/EXEC CAS */
    void *pubsub_channels;  /* channels a client is interested in (SUBSCRIBE) */
    void *pubsub_patterns;  /* patterns a client is interested in (SUBSCRIBE) */
    sds peerid;             /* Cached peer ID. */
    sds sockname;           /* Cached connection target address. */
    void *client_list_node; /* list node in client list */
    void *paused_list_node; /* list node within the pause list */
    void *auth_callback; /* Module callback to execute
                                               * when the authenticated user
                                               * changes. */
    void *auth_callback_privdata; /* Private data that is passed when the auth
                                   * changed callback is executed. Opaque for
                                   * Redis Core. */
    void *auth_module;      /* The module that owns the callback, which is used
                             * to disconnect the client if the module is
                             * unloaded for cleanup. Opaque for Redis Core.*/

    /* If this client is in tracking mode and this field is non zero,
     * invalidation messages for keys fetched by this client will be send to
     * the specified client ID. */
    ruint64_t client_tracking_redirection;
    void *client_tracking_prefixes; /* A dictionary of prefixes we are already
                                      subscribed to in BCAST mode, in the
                                      context of client side caching. */
    /* In clientsCronTrackClientsMemUsage() we track the memory usage of
     * each client and add it to the sum of all the clients of a given type,
     * however we need to remember what was the old contribution of each
     * client, and in which categoty the client was, in order to remove it
     * before adding it the new value. */
    ruint64_t client_cron_last_memory_usage;
    int      client_cron_last_memory_type;
    /* Response buffer */
    int bufpos;
    char buf[PROTO_REPLY_CHUNK_BYTES];
} client;