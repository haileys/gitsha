#include <ruby.h>
#include <signal.h>
#include <pthread.h>
#include <openssl/sha.h>

static const char*
hex_lut = "0123456789abcdef";

static size_t
header_len(size_t data_len)
{
    char buff[64];
    sprintf(buff, "commit %zu", data_len);
    return strlen(buff) + 1;
}

static void
write_counter_hex(char* buff, uint64_t counter)
{
    int i;
    for(i = 0; i < 16; i++) {
        buff[i] = hex_lut[(counter >> (i * 4)) & 0xf];
    }
}

typedef struct {
    pthread_t thread;
    pthread_mutex_t* finished_mutex;
    pthread_cond_t* finished_cond_var;
    /* worker args: */
    char* scratch_buff;
    size_t scratch_len;
    size_t counter_offset;
    char* prefix;
    size_t prefix_len;
    unsigned char prefix_half_dig;
    char prefix_has_half_dig;
    size_t counter;
    int stride;
    /* worker output: */
    int complete;
    unsigned char sha[20];
}
worker_t;

static void
bruteforce_loop(char* output_sha, char* scratch_buff, size_t scratch_len, size_t counter_offset, char* prefix, size_t prefix_len, size_t counter, int stride)
{
    unsigned char sha[20];

    while(1) {
        write_counter_hex(scratch_buff + counter_offset, counter);
        SHA1((unsigned char*)scratch_buff, scratch_len, sha);
        if(memcmp(sha, prefix, prefix_len) == 0) {
            memcpy(output_sha, sha, 20);
            return;
        }
        counter += stride;
    }
}

static void
bruteforce_loop_with_half_dig(char* output_sha, char* scratch_buff, size_t scratch_len, size_t counter_offset, char* prefix, size_t prefix_len, size_t counter, int stride, unsigned char half_dig)
{
    unsigned char sha[20];

    while(1) {
        write_counter_hex(scratch_buff + counter_offset, counter);
        SHA1((unsigned char*)scratch_buff, scratch_len, sha);
        if((prefix_len == 0 || memcmp(sha, prefix, prefix_len) == 0) && (sha[prefix_len] >> 4) == half_dig) {
            memcpy(output_sha, sha, 20);
            return;
        }
        counter += stride;
    }
}

static void
thread_term()
{
    pthread_exit(NULL);
}

static void*
worker_thread_main(void* arg)
{
    worker_t* w = arg;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    signal(SIGTERM, thread_term);
    if(w->prefix_has_half_dig) {
        bruteforce_loop_with_half_dig(
            (char*)w->sha,
            w->scratch_buff,
            w->scratch_len,
            w->counter_offset,
            w->prefix,
            w->prefix_len,
            w->counter,
            w->stride,
            w->prefix_half_dig);
    } else {
        bruteforce_loop(
            (char*)w->sha,
            w->scratch_buff,
            w->scratch_len,
            w->counter_offset,
            w->prefix,
            w->prefix_len,
            w->counter,
            w->stride);
    }
    w->complete = 1;
    pthread_mutex_lock(w->finished_mutex);
    pthread_cond_signal(w->finished_cond_var);
    pthread_mutex_unlock(w->finished_mutex);
    return NULL;
}

static void
setup_worker(worker_t* w, char* commit_data, size_t commit_data_len, char* prefix, size_t prefix_len, char prefix_has_half_dig, int i, int ncpus)
{
    size_t data_length = commit_data_len + 2 + 16;
    size_t header_length = header_len(data_length);
    size_t total_length = header_length + data_length;

    char* prefix_copy = malloc(prefix_len);
    char* scratch_buff = malloc(total_length + 1);

    memcpy(prefix_copy, prefix, prefix_len);
    sprintf(scratch_buff, "commit %zu", data_length);

    memcpy(scratch_buff + header_length, commit_data, commit_data_len);
    scratch_buff[header_length + commit_data_len] = '\n';
    scratch_buff[header_length + commit_data_len + 1] = '\n';

    w->scratch_buff = scratch_buff;
    w->scratch_len = total_length;
    w->counter_offset = header_length + commit_data_len + 2;
    w->prefix = prefix_copy;
    if(prefix_has_half_dig) {
        w->prefix_len = prefix_len - 1;
        w->prefix_half_dig = (unsigned char)prefix[prefix_len - 1] >> 4;
        w->prefix_has_half_dig = 1;
    } else {
        w->prefix_len = prefix_len;
        w->prefix_has_half_dig = 0;
    }
    w->counter = i;
    w->stride = ncpus;
}

static void
destroy_worker(worker_t* w)
{
    pthread_kill(w->thread, SIGTERM);
    pthread_join(w->thread, NULL);
    free(w->scratch_buff);
    free(w->prefix);
}

static VALUE
start_bruteforce(char* commit_data, size_t commit_data_len, char* prefix, size_t prefix_len, int has_half_dig, int ncpus)
{
    worker_t* workers = malloc(sizeof(worker_t) * ncpus);
    int i;
    VALUE ret = Qnil;

    pthread_mutex_t finished_mutex;
    pthread_cond_t finished_cond_var;

    pthread_mutex_init(&finished_mutex, NULL);
    pthread_cond_init(&finished_cond_var, NULL);

    for(i = 0; i < ncpus; i++) {
        setup_worker(&workers[i], commit_data, commit_data_len, prefix, prefix_len, has_half_dig, i, ncpus);
        workers[i].complete = 0;
        workers[i].finished_mutex = &finished_mutex;
        workers[i].finished_cond_var = &finished_cond_var;
    }

    for(i = 0; i < ncpus; i++) {
        pthread_create(&workers[i].thread, NULL, worker_thread_main, &workers[i]);
    }

    pthread_cond_wait(&finished_cond_var, &finished_mutex);

    for(i = 0; i < ncpus; i++) {
        if(workers[i].complete) {
            ret = rb_ary_new3(2,
                rb_str_new(workers[i].scratch_buff, workers[i].scratch_len),
                rb_str_new((char*)workers[i].sha, 20));
            break;
        }
    }

    for(i = 0; i < ncpus; i++) {
        destroy_worker(&workers[i]);
    }

    pthread_mutex_unlock(&finished_mutex);
    pthread_cond_destroy(&finished_cond_var);
    pthread_mutex_destroy(&finished_mutex);

    free(workers);

    return ret;
}

static VALUE
bruteforce(VALUE _, VALUE commit_data, VALUE sha_prefix, VALUE sha_prefix_half_hex_dig, VALUE ncpus)
{
    if(TYPE(commit_data) != T_STRING || TYPE(sha_prefix) != T_STRING) {
        rb_raise(rb_eTypeError, "expected commit_data, sha_prefix to be strings");
    }

    if(TYPE(ncpus) != T_FIXNUM) {
        rb_raise(rb_eTypeError, "expected ncpus to be a fixnum");
    }

    if(FIX2INT(ncpus) <= 0) {
        rb_raise(rb_eTypeError, "expected ncpus to be > 0");
    }

    if(RSTRING_LEN(sha_prefix) > 20) {
        rb_raise(rb_eArgError, "expected sha_prefix to be at most 20 bytes long");
    }

    return start_bruteforce(
        RSTRING_PTR(commit_data),
        RSTRING_LEN(commit_data),
        RSTRING_PTR(sha_prefix),
        RSTRING_LEN(sha_prefix),
        RTEST(sha_prefix_half_hex_dig),
        FIX2INT(ncpus));
}

void
Init_gitsha()
{
    VALUE GitSha;

    GitSha = rb_define_module("GitSha");
    rb_define_singleton_method(GitSha, "bruteforce!", bruteforce, 4);
}
