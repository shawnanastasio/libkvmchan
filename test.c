#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/eventfd.h>

#include <check.h>

#include "libkvmchan.h"
#include "ringbuf.h"

// Support older versions of check
#ifndef ck_assert_ptr_nonnull
#define ck_assert_ptr_nonnull(x) ck_assert((x) != NULL)
#endif

// If we're using GCC/Clang, we can take advantage of the cleanup attribute
// to automatically free memory used during tests.
#ifdef __GNUC__
void cleanup_free(void *val_) {
    void **val = (void **)val_;
    free(*val);
}

void cleanup_close(void *val) {
    close(*(int *)val);
}
#define __auto_free __attribute__((__cleanup__(cleanup_free)))
#define __auto_close __attribute__((__cleanup__(cleanup_close)))
#else
// Just leak... This is fine for a short-lived test program such as this.
#define __auto_free
#define __auto_close
#endif

uint8_t *get_random_bytes(size_t num) {
    uint8_t *buf = malloc(num);
    static int fd = -1;
    if (fd < 0) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            free(buf);
            return NULL;
        }
    }

    return read(fd, buf, num) > 0 ? buf : NULL;
}


// Test patterns
static const uint8_t test_pattern_10[10] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBA, 0xF0, 0x0F};

/// ringbuf:io tests

// Make sure the ring buffer denies writes that are too big
START_TEST(ringbuf_overflow_test) {
    ringbuf_t rb;
    __auto_free uint8_t *rb_buf = malloc(1000 + 1);
    ck_assert_ptr_nonnull(rb_buf);
    ck_assert(ringbuf_init(&rb, rb_buf, 1000 + 1, 0, RINGBUF_DIRECTION_LOCAL, -1, -1) == RB_SUCCESS);

    // Get 1001 random bytes and try to write to the buffer
    __auto_free uint8_t *rand_buf = get_random_bytes(1001);
    ck_assert_ptr_nonnull(rand_buf);
    ck_assert(ringbuf_write(&rb, rand_buf, 1001) == RB_NOSPACE);
}
END_TEST

// Make sure the ring buffer denies writes once it's full
START_TEST(ringbuf_nospace_test) {
    ringbuf_t rb;
    __auto_free uint8_t *rb_buf = malloc(1000 + 1);
    ck_assert_ptr_nonnull(rb_buf);
    ck_assert(ringbuf_init(&rb, rb_buf, 1000 + 1, 0, RINGBUF_DIRECTION_LOCAL, -1, -1) == RB_SUCCESS);

    // Get 1000 random bytes and write to the buffer
    __auto_free uint8_t *rand_buf = get_random_bytes(1000 + 1 /* 1 is used later */);
    ck_assert_ptr_nonnull(rand_buf);
    ck_assert(ringbuf_write(&rb, rand_buf, 1000) == RB_SUCCESS);

    // Now that the buffer is full, assert that we can't write to it
    ck_assert(ringbuf_write(&rb, rand_buf, 1) == RB_NOSPACE);

    // Read the bytes back and ensure that nothing got corrupted
    __auto_free uint8_t *tmp_buf = malloc(1000);
    ck_assert_ptr_nonnull(tmp_buf);
    ck_assert(ringbuf_read(&rb, tmp_buf, 1000) == RB_SUCCESS);
    ck_assert(memcmp(tmp_buf, rand_buf, 1000) == 0);

    // Make sure a write for 1001 bytes will fail
    ck_assert(ringbuf_write(&rb, rand_buf, 1001) == RB_NOSPACE);

    // Make sure a write for 1000 bytes will still succeed
    ck_assert(ringbuf_write(&rb, rand_buf, 1000) == RB_SUCCESS);
}
END_TEST

// Test writes that wrap from the end to the front of the buf
START_TEST(ringbuf_write_wrap_test) {
    ringbuf_t rb;
    __auto_free uint8_t *rb_buf = malloc(1000 + 1 + 1 /* test byte to check for overflow */);
    ck_assert_ptr_nonnull(rb_buf);
    rb_buf[1001] = 0x55; // Magic byte that will be compared at end
    ck_assert(ringbuf_init(&rb, rb_buf, 1000 + 1, 0, RINGBUF_DIRECTION_LOCAL, -1, -1) == RB_SUCCESS);

    // Write and read to offset the start pointer by 2
    const uint8_t test_bytes[2] = {0xAB, 0xCD};
    uint8_t tmp[2];
    ck_assert(ringbuf_write(&rb, test_bytes, 2) == RB_SUCCESS);
    ck_assert(ringbuf_read(&rb, tmp, 2) == RB_SUCCESS);
    ck_assert(test_bytes[0] == tmp[0]);

    // Write 998 bytes leaving two spaces left, the last of which will wrap
    __auto_free uint8_t *rand = get_random_bytes(998);
    ck_assert_ptr_nonnull(rand);
    ck_assert(ringbuf_write(&rb, rand, 998) == RB_SUCCESS);

    // Write the two bytes and confirm that overflow occurred
    ck_assert(ringbuf_write(&rb, test_bytes, 2) == RB_SUCCESS);
    ck_assert_msg(rb_buf[1] == test_bytes[1], "Last byte didn't wrap around as expected!");
    ck_assert_msg(rb_buf[1000] == test_bytes[0], "First byte didn't end up at end of buffer!");

    // Confirm that further writes fail
    ck_assert(ringbuf_write(&rb, rand, 1) != RB_SUCCESS);

    // Read everything back and confirm no corruption
    __auto_free uint8_t *rand_tmp = malloc(998);
    ck_assert_ptr_nonnull(rand_tmp);
    ck_assert(ringbuf_read(&rb, rand_tmp, 998) == RB_SUCCESS);
    ck_assert(memcmp(rand, rand_tmp, 998) == 0);

    ck_assert(ringbuf_read(&rb, tmp, 2) == RB_SUCCESS);
    ck_assert_msg(test_bytes[0] == tmp[0] && test_bytes[1] == tmp[1],
                  "FAILED: {0x%x, 0x%x}", tmp[0], tmp[1]);

    // Check magic byte
    ck_assert(rb_buf[1001] = 0x55);

}
END_TEST

// Test writes that occur after a wrap
START_TEST(ringbuf_write_after_wrap_test) {
    ringbuf_t rb;
    __auto_free uint8_t *rb_buf = malloc(1000 + 1);
    ck_assert_ptr_nonnull(rb_buf);
    ck_assert(ringbuf_init(&rb, rb_buf, 1000 + 1, 0, RINGBUF_DIRECTION_LOCAL, -1, -1) == RB_SUCCESS);

    // Write a byte and read it back to offset the start pointer by 2
    const uint8_t test_bytes[2] = {0xAB, 0xCD};
    uint8_t tmp[2];
    ck_assert(ringbuf_write(&rb, test_bytes, 1) == RB_SUCCESS);
    ck_assert(ringbuf_read(&rb, tmp, 1) == RB_SUCCESS);
    ck_assert(test_bytes[0] == tmp[0]);

    // Write 1000 bytes, the last two bytes of which will wrap
    __auto_free uint8_t *rand = get_random_bytes(1000 + 1 /* 1 used later */);
    ck_assert_ptr_nonnull(rand);
    ck_assert(ringbuf_write(&rb, rand, 1000) == RB_SUCCESS);

    // Read 500 bytes and write 500 new bytes back
    __auto_free uint8_t *rand2 = get_random_bytes(500);
    ck_assert_ptr_nonnull(rand2);
    __auto_free uint8_t *rand_tmp = malloc(1000);
    ck_assert_ptr_nonnull(rand_tmp);
    ck_assert(ringbuf_read(&rb, rand_tmp, 500) == RB_SUCCESS);
    ck_assert(memcmp(rand_tmp, rand, 500) == 0);
    ck_assert(ringbuf_write(&rb, rand2, 500) == RB_SUCCESS);

    // Flush the whole buffer and confirm no corruption occurred
    ck_assert(ringbuf_read(&rb, rand_tmp, 500) == RB_SUCCESS);
    ck_assert(memcmp(rand_tmp, rand + 500, 500) == 0);
    ck_assert(ringbuf_read(&rb, rand_tmp, 500) == RB_SUCCESS);
    ck_assert(memcmp(rand_tmp, rand2, 500) == 0);

    // Now the ring buffer should be empty.
    // Confirm that writes for 1001 bytes fail and 1000 succeed
    ck_assert(ringbuf_write(&rb, rand, 1001) == RB_NOSPACE);
    ck_assert(ringbuf_write(&rb, rand, 1000) == RB_SUCCESS);

}
END_TEST


/// ringbuf:feature tests

void *ringbuf_blocking_write_test_host_thread(void *rb_) {
    ringbuf_t *rb = rb_;

    // Sleep 0.2s and flush the buffer
    usleep(200 * 1000);
    uint8_t tmp[10];
    if (ringbuf_read(rb, tmp, 10) != RB_SUCCESS)
        return "Failed to flush ringbuf!";

    return NULL;
}

void *ringbuf_blocking_write_test_client_thread(void *rb) {
    // Perform a blocking write on the ringbuf
    uint8_t *write_buf = get_random_bytes(10);
    if (!write_buf)
        return "Failed to get 10 random bytes!";

    if (ringbuf_write(rb, write_buf, 10) != RB_SUCCESS)
        return "Failed to write to buffer!";

    return NULL;
}

// Make sure blocking writes work as expected
START_TEST(ringbuf_blocking_write_test) {
    ringbuf_t rb;
    uint8_t rb_buf[10 + 1];
    ck_assert(ringbuf_init(&rb, rb_buf, 10 + 1, RINGBUF_FLAG_BLOCKING,
                           RINGBUF_DIRECTION_LOCAL, eventfd(0, 0), -1) == RB_SUCCESS);

    // Fill the ring buffer up to prevent instant writes
    ck_assert(ringbuf_write(&rb, test_pattern_10, 10) == RB_SUCCESS);

    // Spawn two threads
    // - The client thread will perform a blocking write operation
    // - The host thread will wait and read 10 bytes, freeing the client thread to write

    pthread_t host, client;
    void *host_ret, *client_ret;
    ck_assert(!pthread_create(&host, NULL, ringbuf_blocking_write_test_host_thread, &rb));
    ck_assert(!pthread_create(&client, NULL, ringbuf_blocking_write_test_client_thread, &rb));
    pthread_join(host, &host_ret);
    pthread_join(client, &client_ret);

    // The threads will return NULL on success or a string error message on fail.
    ck_assert_msg(!host_ret, "Host thread failed: %s", (const char *)host_ret);
    ck_assert_msg(!client_ret, "Client thread failed: %s", (const char *)client_ret);
}
END_TEST

void *ringbuf_blocking_read_test_host_thread(void *rb_) {
    ringbuf_t *rb = rb_;

    // Sleep 0.2s and write 10 bytes
    usleep(200 * 1000);
    if (ringbuf_write(rb, test_pattern_10, 10) != RB_SUCCESS)
        return "Failed to write to buffer!";

    return NULL;
}

void *ringbuf_blocking_read_test_client_thread(void *rb) {
    uint8_t tmp[10];
    if (ringbuf_read(rb, tmp, 10) != RB_SUCCESS)
        return "Failed to read from buffer!";

    if (memcmp(tmp, test_pattern_10, 10) != 0)
        return "Read returned bad data!";

    return NULL;
}

// Make sure blocking reads work as expected
START_TEST(ringbuf_blocking_read_test) {
    ringbuf_t rb;
    uint8_t rb_buf[10 + 1];
    ck_assert(ringbuf_init(&rb, rb_buf, 10 + 1, RINGBUF_FLAG_BLOCKING,
                           RINGBUF_DIRECTION_LOCAL, eventfd(0, 0), -1) == RB_SUCCESS);

    // Spawn two threads
    // - The client thread will perform a blocking read operation
    // - The host will wait and write 10 bytes, freeing the client to read
    pthread_t host, client;
    void *host_ret, *client_ret;
    ck_assert(!pthread_create(&host, NULL, ringbuf_blocking_read_test_host_thread, &rb));
    ck_assert(!pthread_create(&client, NULL, ringbuf_blocking_read_test_client_thread, &rb));
    pthread_join(host, &host_ret);
    pthread_join(client, &client_ret);

    // The threads will return NULL on success or a string error message on fail.
    ck_assert_msg(!host_ret, "Host thread failed: %s", (const char *)host_ret);
    ck_assert_msg(!client_ret, "Client thread failed: %s", (const char *)client_ret);
}
END_TEST

// Make sure relative buffer mode works
START_TEST(ringbuf_relative_test) {
    __auto_free uint8_t *rb_buf = malloc(100 + 1);
    ck_assert_ptr_nonnull(rb_buf);

    ringbuf_t rb;
    ck_assert(ringbuf_init(&rb, rb_buf, 100 + 1, RINGBUF_FLAG_RELATIVE, RINGBUF_DIRECTION_LOCAL, -1, -1) == RB_SUCCESS);

    // Write 100 random bytes and ensure that they're in the correct position
    __auto_free uint8_t *rand = get_random_bytes(100);
    ck_assert_ptr_nonnull(rand);

    ck_assert(ringbuf_write(&rb, rand, 100) == RB_SUCCESS);
    ck_assert(rb_buf[0] == rand[0]);
    ck_assert(rb_buf[99] == rand[99]);

    // Read the data back and ensure nothing went wrong
    __auto_free uint8_t *tmp = malloc(100);
    ck_assert_ptr_nonnull(tmp);
    ck_assert(ringbuf_read(&rb, tmp, 100) == RB_SUCCESS);
    ck_assert(memcmp(tmp, rand, 100) == 0);
}
END_TEST

void *ringbuf_eventfd_test_host_thread(void *rb) {
    // Sleep 0.2s and write a byte to the rb
    usleep(200 * 1000);
    uint8_t buf[1] = {0xAA};

    if (ringbuf_write(rb, buf, 1) != RB_SUCCESS)
        return "Failed to write to ringbuffer!";

    return NULL;
}

void *ringbuf_eventfd_test_client_thread(void *rb) {
    // Wait for the eventfd to signal available bytes
    int fd = ringbuf_get_eventfd(rb);
    if (fd < 0)
        return "Failed to obtain eventfd!";

    // Block on it until data is ready
    uint8_t buf[8];
    if (read(fd, buf, 8) < 0)
        return "Read failed!";

    ringbuf_clear_eventfd(rb);

    // Read from ringbuf
    if (ringbuf_read(rb, buf, 1) != RB_SUCCESS)
        return "Failed to read from ringbuf!";

    if (buf[0] != 0xAA)
        return "Invalid value read from ringbuf!";

    return NULL;
}

// Make sure eventfd notifications work
START_TEST(ringbuf_eventfd_test) {
    ringbuf_t rb;
    uint8_t rb_buf[10 + 1];
    ck_assert(ringbuf_init(&rb, rb_buf, 10 + 1, RINGBUF_FLAG_BLOCKING,
                           RINGBUF_DIRECTION_LOCAL, eventfd(0, 0), -1) == RB_SUCCESS);

    pthread_t host_thread, client_thread;
    void *host_ret, *client_ret;
    ck_assert(!pthread_create(&host_thread, NULL, ringbuf_eventfd_test_host_thread, &rb));
    ck_assert(!pthread_create(&client_thread, NULL, ringbuf_eventfd_test_client_thread, &rb));
    pthread_join(host_thread, &host_ret);
    pthread_join(client_thread, &client_ret);

    // The threads will return NULL on success or a string error message on fail.
    ck_assert_msg(!host_ret, "Host thread failed: %s", (const char *)host_ret);
    ck_assert_msg(!client_ret, "Client thread failed: %s", (const char *)client_ret);
}
END_TEST

// Make sure we can init and infer sec ring buffers
START_TEST(ringbuf_sec_init_infer_test) {
    ringbuf_t rb;
    ringbuf_pub_t pub;
    uint8_t rb_buf[10 + 1];
    ck_assert(ringbuf_sec_init(&rb, &pub, rb_buf, 10 + 1, 0, RINGBUF_DIRECTION_LOCAL, -1, -1) == RB_SUCCESS);

    ringbuf_t rb_i;
    ck_assert(ringbuf_sec_infer_priv(&rb_i, &pub, rb_buf, 10 + 1, 0, RINGBUF_DIRECTION_LOCAL, -1, -1) == RB_SUCCESS);

    ck_assert_msg(rb.flags == rb_i.flags, "rb.flags: 0x%x, rb_i.flags: 0x%x", rb.flags, rb_i.flags);
    ck_assert_msg(rb.size == rb_i.size, "rb.size: 0x%x, rb_i.size: 0x%x", rb.size, rb_i.size);
    ck_assert_msg(rb.start == rb_i.start, "rb.start: 0x%x, rb_i.start: 0x%x", rb.start, rb_i.start);
    ck_assert_msg(rb.pos_start == rb_i.pos_start, "rb.pos_start: 0x%x, rb_i.pos_start: 0x%x", rb.pos_start, rb_i.pos_start);
    ck_assert_msg(rb.pos_end == rb_i.pos_end, "rb.pos_end: 0x%x, rb_i.pos_end: 0x%x", rb.pos_end, rb_i.pos_end);
}
END_TEST

// Make sure we can read/write from sec ring buffers
START_TEST(ringbuf_sec_read_write_test) {
    ringbuf_t rb;
    ringbuf_pub_t pub;
    uint8_t rb_buf[10 + 1];
    ck_assert(ringbuf_sec_init(&rb, &pub, rb_buf, 10 + 1, 0, RINGBUF_DIRECTION_WRITE, -1, -1) == RB_SUCCESS);

    ringbuf_t rb_i;
    ck_assert(ringbuf_sec_infer_priv(&rb_i, &pub, rb_buf, 10 + 1, 0, RINGBUF_DIRECTION_READ, -1, -1) == RB_SUCCESS);

    // Write from rb, read from rb_i
    uint8_t buf[10] = "HI__WORLD";
    ck_assert(ringbuf_sec_write(&rb, &pub, buf, 10) == RB_SUCCESS);

    uint8_t buf2[10];
    ringbuf_ret_t ret = ringbuf_sec_read(&rb_i, &pub, buf2, 10);
    ck_assert_msg(ret == RB_SUCCESS, "couldn't read, res: %d", ret);
    ck_assert_msg(memcmp(buf, buf2, 10) == 0, "buf2 fail. Contents: %s", buf2);

    // Do it again
    strcpy((char *)buf, "ASDF_ABCD");
    ck_assert(ringbuf_sec_write(&rb, &pub, buf, 10) == RB_SUCCESS);

    ck_assert_msg((ret = ringbuf_sec_read(&rb_i, &pub, buf2, 10)) == RB_SUCCESS,
                  "return code: %d", ret);
    ck_assert(memcmp(buf, buf2, 10) == 0);
}
END_TEST

struct rb_sec_pair {
    ringbuf_t *rb;
    ringbuf_pub_t *pub;
};

void *ringbuf_sec_blocking_read_test_thread(void *rb) {
    struct rb_sec_pair *sp = rb;
    // Sleep for 0.2 seconds and write data to unblock
    usleep(200 * 1000);

    if (ringbuf_sec_write(sp->rb, sp->pub, test_pattern_10, 10) != RB_SUCCESS)
        return "Unable to write to ringbuf!";

    return NULL;
}

// Make sure blocking reads on a sec buffer works
START_TEST(ringbuf_sec_blocking_read_test) {
    ringbuf_t rb;
    ringbuf_pub_t pub;
    __auto_close int ev1 = eventfd(0, 0);
    __auto_close int ev2 = eventfd(0, 0);
    ck_assert(ev1 > 0); ck_assert(ev2 > 0);

    uint8_t rb_buf[10 + 1];
    ck_assert(ringbuf_sec_init(&rb, &pub, rb_buf, 10 + 1, RINGBUF_FLAG_BLOCKING,
              RINGBUF_DIRECTION_WRITE, ev1, ev2) == RB_SUCCESS);

    ringbuf_t rb_i;
    ck_assert(ringbuf_sec_infer_priv(&rb_i, &pub, rb_buf, 10 + 1, RINGBUF_FLAG_BLOCKING,
              RINGBUF_DIRECTION_READ, ev2, ev1) == RB_SUCCESS);

    // Spawn a thread to write to the ringbuf and unblock it
    pthread_t thread;
    void *ret;
    struct rb_sec_pair sp = { &rb, &pub };
    ck_assert(!pthread_create(&thread, NULL, ringbuf_sec_blocking_read_test_thread, &sp));

    // Start a blocking read
    uint8_t tmp[10];
    ck_assert_uint_eq(ringbuf_sec_read(&rb_i, &pub, tmp, 10), RB_SUCCESS);

    // Join the thread
    pthread_join(thread, &ret);
    ck_assert_msg(!ret, "Thread failed: %s", ret);

    ck_assert(memcmp(test_pattern_10, tmp, 10) == 0);
}
END_TEST

#if 0
void *ringbuf_sec_blocking_write_test_thread(void *rb) {
    struct rb_sec_pair *sp = rb;
    // Sleep for 0.2 seconds and read data to unblock
    usleep(200 * 1000);

    uint8_t buf[10];
    if (ringbuf_sec_read(sp->rb, sp->pub, buf, 10) != RB_SUCCESS)
        return "Unable to read from ringbuf!";

    return NULL;
}

// Make sure blocking reads on a sec buffer works
START_TEST(ringbuf_sec_blocking_write_test) {
    ringbuf_t rb;
    ringbuf_pub_t pub;

    uint8_t rb_buf[10 + 1];
    ck_assert(ringbuf_sec_init(&rb, &pub, rb_buf, 10 + 1, RINGBUF_FLAG_BLOCKING) == RB_SUCCESS);

    ringbuf_t rb_i;
    ck_assert(ringbuf_sec_infer_priv(&rb_i, &pub, rb_buf, 10 + 1, RINGBUF_FLAG_BLOCKING) == RB_SUCCESS);

    // Fill the buffer up initially
    ck_assert(ringbuf_sec_write(&rb_i, &pub, test_pattern_10, 10) == RB_SUCCESS);

    // Spawn a thread to read from the ringbuf and unblock it
    pthread_t thread;
    void *ret;
    struct rb_sec_pair sp = { &rb, &pub };
    ck_assert(!pthread_create(&thread, NULL, ringbuf_sec_blocking_write_test_thread, &sp));

    // Start a blocking write
    uint8_t tmp[10];
    ck_assert(ringbuf_sec_write(&rb_i, &pub, tmp, 10) == RB_SUCCESS);

    // Join the thread
    pthread_join(thread, &ret);
    ck_assert_msg(!ret, "Thread failed: %s", ret);
}
END_TEST
#endif

Suite *ringbuf_test_suite(void) {
    Suite *s = suite_create("ringbuf");

    TCase *tc_io = tcase_create("io");
    tcase_add_test(tc_io, ringbuf_overflow_test);
    tcase_add_test(tc_io, ringbuf_nospace_test);
    tcase_add_test(tc_io, ringbuf_write_wrap_test);
    tcase_add_test(tc_io, ringbuf_write_after_wrap_test);
    suite_add_tcase(s, tc_io);

    TCase *tc_feature = tcase_create("feature");
    tcase_add_test(tc_feature, ringbuf_blocking_write_test);
    tcase_add_test(tc_feature, ringbuf_blocking_read_test);
    tcase_add_test(tc_feature, ringbuf_relative_test);
    tcase_add_test(tc_feature, ringbuf_eventfd_test);
    suite_add_tcase(s, tc_feature);

    TCase *tc_sec = tcase_create("sec");
    tcase_add_test(tc_sec, ringbuf_sec_init_infer_test);
    tcase_add_test(tc_sec, ringbuf_sec_read_write_test);
    tcase_add_test(tc_sec, ringbuf_sec_blocking_read_test);
    //tcase_add_test(tc_sec, ringbuf_sec_blocking_write_test);
    suite_add_tcase(s, tc_sec);

    return s;
}

int main() {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = ringbuf_test_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
