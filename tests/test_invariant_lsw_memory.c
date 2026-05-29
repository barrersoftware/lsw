#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

/* Simulated kernel memory region structure */
#define REGION_SIZE 256

typedef struct {
    void *kernel_addr;
    size_t size;
} kernel_region_t;

/* Safe read function that enforces boundary checks */
static int safe_kernel_read(kernel_region_t *region, size_t offset, size_t bytes_to_read, void *buffer, size_t buffer_size) {
    /* Security invariant: offset and size must be within allocated region */
    if (region == NULL || region->kernel_addr == NULL) {
        return -1;
    }
    if (bytes_to_read == 0) {
        return 0;
    }
    /* Check offset is within region */
    if (offset >= region->size) {
        return -1;
    }
    /* Check offset + bytes_to_read does not overflow or exceed region */
    if (bytes_to_read > region->size - offset) {
        return -1;
    }
    /* Check bytes_to_read fits in output buffer */
    if (bytes_to_read > buffer_size) {
        return -1;
    }
    /* Safe to copy */
    memcpy(buffer, (char *)region->kernel_addr + offset, bytes_to_read);
    return (int)bytes_to_read;
}

START_TEST(test_kernel_read_boundary_invariant)
{
    /* Invariant: kernel memory reads must never access memory outside the allocated region,
       regardless of user-supplied offset and size parameters */

    /* Setup a simulated kernel region */
    unsigned char kernel_mem[REGION_SIZE];
    memset(kernel_mem, 0xAB, REGION_SIZE);

    kernel_region_t region;
    region.kernel_addr = kernel_mem;
    region.size = REGION_SIZE;

    unsigned char output_buffer[REGION_SIZE * 2];
    memset(output_buffer, 0, sizeof(output_buffer));

    typedef struct {
        size_t offset;
        size_t bytes_to_read;
        int should_succeed;
        const char *description;
    } test_case_t;

    test_case_t cases[] = {
        /* Valid cases */
        { 0,              1,              1, "read 1 byte at offset 0" },
        { 0,              REGION_SIZE,    1, "read entire region" },
        { REGION_SIZE-1,  1,              1, "read last byte" },
        { 10,             50,             1, "read middle of region" },

        /* Boundary violation: offset beyond region */
        { REGION_SIZE,    1,              0, "offset == region size" },
        { REGION_SIZE+1,  1,              0, "offset just beyond region" },
        { REGION_SIZE*2,  1,              0, "offset 2x region size" },
        { SIZE_MAX,       1,              0, "offset SIZE_MAX" },
        { SIZE_MAX-1,     1,              0, "offset SIZE_MAX-1" },

        /* Boundary violation: offset + size overflows or exceeds region */
        { 0,              REGION_SIZE+1,  0, "size exceeds region" },
        { 1,              REGION_SIZE,    0, "offset+size exceeds region by 1" },
        { REGION_SIZE/2,  REGION_SIZE,    0, "offset+size exceeds region" },
        { 1,              SIZE_MAX,       0, "size SIZE_MAX" },
        { SIZE_MAX/2,     SIZE_MAX/2+2,   0, "offset+size integer overflow" },
        { SIZE_MAX-1,     SIZE_MAX-1,     0, "large offset + large size overflow" },
        { 0,              SIZE_MAX,       0, "zero offset, SIZE_MAX size" },
        { REGION_SIZE-1,  2,              0, "last byte offset, size 2" },
        { REGION_SIZE-1,  SIZE_MAX,       0, "last byte offset, SIZE_MAX size" },

        /* Zero size edge cases */
        { 0,              0,              1, "zero bytes to read at offset 0" },
        { REGION_SIZE,    0,              1, "zero bytes to read at boundary offset" },

        /* Attack: try to read before region (wrap-around) */
        { SIZE_MAX - 10,  20,             0, "wrap-around read attempt" },
        { SIZE_MAX,       SIZE_MAX,       0, "both SIZE_MAX" },
    };

    int num_cases = (int)(sizeof(cases) / sizeof(cases[0]));

    for (int i = 0; i < num_cases; i++) {
        memset(output_buffer, 0, sizeof(output_buffer));

        int result = safe_kernel_read(&region,
                                      cases[i].offset,
                                      cases[i].bytes_to_read,
                                      output_buffer,
                                      sizeof(output_buffer));

        if (cases[i].should_succeed) {
            if (cases[i].bytes_to_read == 0) {
                ck_assert_msg(result == 0,
                    "Case %d (%s): expected 0 for zero-size read, got %d",
                    i, cases[i].description, result);
            } else {
                ck_assert_msg(result == (int)cases[i].bytes_to_read,
                    "Case %d (%s): expected %zu bytes read, got %d",
                    i, cases[i].description, cases[i].bytes_to_read, result);
                ck_assert_msg(memcmp(output_buffer,
                                     (char *)kernel_mem + cases[i].offset,
                                     cases[i].bytes_to_read) == 0,
                    "Case %d (%s): data mismatch after valid read",
                    i, cases[i].description);
            }
        } else {
            ck_assert_msg(result < 0,
                "SECURITY VIOLATION in case %d (%s): "
                "out-of-bounds read with offset=%zu size=%zu was not rejected (result=%d)",
                i, cases[i].description,
                cases[i].offset, cases[i].bytes_to_read, result);
        }
    }
}
END_TEST

START_TEST(test_null_region_rejected)
{
    /* Invariant: null region pointer must always be rejected */
    unsigned char buf[64];
    int result = safe_kernel_read(NULL, 0, 10, buf, sizeof(buf));
    ck_assert_msg(result < 0, "SECURITY VIOLATION: null region was not rejected");
}
END_TEST

START_TEST(test_output_buffer_overflow_prevented)
{
    /* Invariant: read size must not exceed output buffer capacity */
    unsigned char kernel_mem[REGION_SIZE];
    memset(kernel_mem, 0xCD, REGION_SIZE);

    kernel_region_t region;
    region.kernel_addr = kernel_mem;
    region.size = REGION_SIZE;

    unsigned char small_buf[16];
    memset(small_buf, 0, sizeof(small_buf));

    /* Request more bytes than the output buffer can hold */
    int result = safe_kernel_read(&region, 0, REGION_SIZE, small_buf, sizeof(small_buf));
    ck_assert_msg(result < 0,
        "SECURITY VIOLATION: read size exceeding output buffer was not rejected");
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_kernel_read_boundary_invariant);
    tcase_add_test(tc_core, test_null_region_rejected);
    tcase_add_test(tc_core, test_output_buffer_overflow_prevented);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
