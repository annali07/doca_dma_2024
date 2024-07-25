/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <pthread.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_mmap.h>

#include <samples/common.h>

#include "pack.h"
#include "utils.h"

#include "dma_common.h"
#include "latency_helpers.h"

#define BILLION  1000000000L
#define CC_MAX_QUEUE_SIZE 10	   /* Max number of messages on Comm Channel queue */
#define SLEEP_IN_NANOS (10 * 1000) /* Sample the job every 10 microseconds  */
#define STATUS_SUCCESS true	   /* Successful status */
#define STATUS_FAILURE false	   /* Unsuccessful status */

DOCA_LOG_REGISTER(DMA_COPY_SAMPLE);

/*
 * Send status message
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @status [in]: Status to send
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
send_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr, bool status)
{
	struct cc_msg_dma_status status_msg;
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	status_msg.is_success = status;

	while ((result = doca_comm_channel_ep_sendto(ep, &status_msg, sizeof(struct cc_msg_dma_status),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send status message: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Allocate memory and populate it into the memory map
 *
 * @core_state [in]: DOCA core structure
 * @buffer_len [in]: Allocated buffer length
 * @access_flags [in]: The access permissions of the mmap
 * @buffer [out]: Allocated buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
memory_alloc_and_populate(struct core_state *core_state, size_t buffer_len, uint32_t access_flags, char **buffer)
{
	doca_error_t result;

	result = doca_mmap_set_permissions(core_state->mmap, access_flags);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set access permissions of memory map: %s", doca_get_error_string(result));
		return result;
	}

	*buffer = (char *)malloc(buffer_len);
	if (*buffer == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for source buffer");
		return DOCA_ERROR_NO_MEMORY;
	}

	result = doca_mmap_set_memrange(core_state->mmap, *buffer, buffer_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memrange of memory map: %s", doca_get_error_string(result));
		free(*buffer);
		return result;
	}

	/* Populate local buffer into memory map to allow access from DPU side after exporting */
	result = doca_mmap_start(core_state->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to populate memory map: %s", doca_get_error_string(result));
		free(*buffer);
	}

	return result;
}

/*
 * DPU side function for file size and location negotiation
 *
 * @cfg [in]: Application configuration
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_negotiate_dma_direction_and_size(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t *ep,
				     struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_direction host_dma_direction = {0};
	struct cc_msg_dma_direction dpu_dma_direction = {0};
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;
	size_t msg_len;

	if (cfg->is_file_found_locally) {
		DOCA_LOG_INFO("File was found locally, it will be DMA copied to the Host");
		dpu_dma_direction.file_in_host = false;
		dpu_dma_direction.file_size = htonl(cfg->file_size);
	} else {
		DOCA_LOG_INFO("File was not found locally, it will be DMA copied from the Host");
		dpu_dma_direction.file_in_host = true;
	}

	result = doca_comm_channel_ep_listen(ep, SERVER_NAME);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Comm Channel endpoint couldn't start listening: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("Waiting for Host to send negotiation message");

	/* Wait until Host negotiation message will arrive */
	msg_len = sizeof(struct cc_msg_dma_direction);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&host_dma_direction, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(struct cc_msg_dma_direction);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Response message was not received: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	if (msg_len != sizeof(struct cc_msg_dma_direction)) {
		DOCA_LOG_ERR("Response negotiation message was not received correctly");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* Make sure file is located only on one side */
	if (cfg->is_file_found_locally && host_dma_direction.file_in_host == true) {
		DOCA_LOG_ERR("Error - File was found on both Host and DPU");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;

	} else if (!cfg->is_file_found_locally) {
		if (!host_dma_direction.file_in_host) {
			DOCA_LOG_ERR("Error - File was not found on both Host and DPU");
			send_status_msg(ep, peer_addr, STATUS_FAILURE);
			return DOCA_ERROR_INVALID_VALUE;
		}
		cfg->file_size = ntohl(host_dma_direction.file_size);
	}

	/* Send direction message to Host */
	while ((result = doca_comm_channel_ep_sendto(ep, &dpu_dma_direction, sizeof(struct cc_msg_dma_direction),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send negotiation buffer to DPU: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * DPU side function for clean DOCA core objects
 *
 * @state [in]: DOCA core structure
 */
static void
dpu_cleanup_core_objs(struct core_state *state)
{
	doca_error_t result;

	// Remove all WorkQ from one ctx
	for (int i = 0; i < MAX_WORKQ_NUM; ++i) {
        if (state->workq_array[i] != NULL) {
            result = doca_ctx_workq_rm(state->ctx, state->workq_array[i]);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to remove work queue %d from ctx: %s", i, doca_get_error_string(result));
            }
        }
    }
	
	result = doca_ctx_stop(state->ctx);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Unable to stop DMA context: %s", doca_get_error_string(result));

	result = doca_ctx_dev_rm(state->ctx, state->dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to remove device from DMA ctx: %s", doca_get_error_string(result));
}

/*
 * DPU side function for receiving export descriptor on Comm Channel
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @export_desc_buffer [out]: Buffer to save the export descriptor
 * @export_desc_len [out]: Export descriptor length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_receive_export_desc(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr,
			char *export_desc_buffer, size_t *export_desc_len)
{
	size_t msg_len;
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	DOCA_LOG_INFO("Waiting for Host to send export descriptor");

	/* Receive exported descriptor from Host */
	msg_len = CC_MAX_MSG_SIZE;
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)export_desc_buffer, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = CC_MAX_MSG_SIZE;
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to receive export descriptor from Host: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	*export_desc_len = msg_len;
	DOCA_DLOG_INFO("Export descriptor received successfully from Host");

	result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	if (result != DOCA_SUCCESS)
		return result;

	return result;
}

/*
 * DPU side function for receiving remote buffer address and offset on Comm Channel
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @host_addr [out]: Remote buffer address
 * @host_offset [out]: Remote buffer offset
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_receive_addr_and_offset(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr,
			    char **host_addr, size_t *host_offset)
{
	doca_error_t result;
	uint64_t received_addr, received_addr_len;
	size_t msg_len;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	DOCA_LOG_INFO("Waiting for Host to send address and offset");

	/* Receive remote source buffer address */
	msg_len = sizeof(received_addr);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&received_addr, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(received_addr);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to receive remote address from Host: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	received_addr = ntohq(received_addr);
	if (received_addr > SIZE_MAX) {
		DOCA_LOG_ERR("Address size exceeds pointer size in this device");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;
	}
	*host_addr = (char *)received_addr;

	DOCA_DLOG_INFO("Remote address received successfully from Host: %" PRIu64 "", received_addr);

	result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	if (result != DOCA_SUCCESS)
		return result;

	/* Receive remote source buffer length */
	msg_len = sizeof(received_addr_len);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&received_addr_len, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(received_addr_len);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to receive remote address offset from Host: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	received_addr_len = ntohq(received_addr_len);
	if (received_addr_len > SIZE_MAX) {
		DOCA_LOG_ERR("Offset exceeds SIZE_MAX in this device");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;
	}
	*host_offset = (size_t)received_addr_len;

	DOCA_DLOG_INFO("Address offset received successfully from Host: %" PRIu64 "", received_addr_len);

	result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	if (result != DOCA_SUCCESS)
		return result;

	return result;
}

/*
 * DPU side function for submitting DMA job into the work queue and save into a file if needed
 *
 * @cfg [in]: Application configuration
 * @core_state [in]: DOCA core structure
 * @bytes_to_copy [in]: Number of bytes to DMA copy
 * @buffer [in]: local DMA buffer
 * @local_doca_buf [in]: local DOCA buffer
 * @remote_doca_buf [in]: remote DOCA buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_submit_dma_job(struct dma_copy_cfg *cfg, struct core_state *core_state, char *buffer,
			struct doca_dma_job_memcpy dma_job, int workq_index)
{	
	struct doca_event event = {0};
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;

	/* Enqueue DMA job */
	result = doca_workq_submit(core_state->workq_array[workq_index], &dma_job.base);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(result));
		return result;
	}

	/* Wait for job completion */
	while ((result = doca_workq_progress_retrieve(core_state->workq_array[workq_index], &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
	       DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
	}

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to retrieve DMA job: %s", doca_get_error_string(result));
		return result;
	}

	/* event result is valid */
	result = (doca_error_t)event.result.u64;
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s", doca_get_error_string(result));
		return result;
	}

	// DOCA_LOG_INFO("DMA copy was done Successfully");

	return result;
}

struct thread_args {
    struct dma_copy_cfg *cfg;
    struct core_state *core_state;
	struct doca_mmap *remote_mmap;
    char *buffer;
	char *host_dma_addr;
	size_t host_dma_offset;
    int workq_index;
	int requests;
	double *latencies;
	struct doca_comm_channel_ep_t *ep;
	struct doca_comm_channel_addr_t **peer_addr;
	struct doca_buf_inventory *buf_inv;	
};

void *handle_dpu_submit_job(void *arg)
{	
	doca_error_t result;
	int counter = 0;
	struct timespec start, stop;
    double latency;
    struct thread_args *targs = (struct thread_args *)arg;
	
	for (int i = 0; i < targs->requests; i++){
		// Reinitialize buffer
		struct doca_buf *remote_doca_buf;
		struct doca_buf *local_doca_buf;

		// Construct DOCA buffer for remote (Host) address range
		result = doca_buf_inventory_buf_by_addr(targs->buf_inv, targs->remote_mmap, targs->host_dma_addr, targs->host_dma_offset,
						&remote_doca_buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA remote buffer: %s", doca_get_error_string(result));
			send_status_msg(targs->ep, targs->peer_addr, STATUS_FAILURE);
			doca_mmap_destroy(targs->remote_mmap);
			dpu_cleanup_core_objs(targs->core_state);
			free(targs->buffer);
			return NULL;

		}

		// Construct DOCA buffer for local (DPU) address range
		result = doca_buf_inventory_buf_by_addr(targs->buf_inv, targs->core_state->mmap, targs->buffer, targs->host_dma_offset,
							&local_doca_buf);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA local buffer: %s", doca_get_error_string(result));
			send_status_msg(targs->ep, targs->peer_addr, STATUS_FAILURE);
			doca_buf_refcount_rm(remote_doca_buf, NULL);
			doca_mmap_destroy(targs->remote_mmap);
			dpu_cleanup_core_objs(targs->core_state);
			free(targs->buffer);
			return NULL;

		}

		/* Set src and dst buffers */
		void *data;
		struct doca_buf *src_buf;
		struct doca_buf *dst_buf;

		/* Determine DMA copy direction */
		if (targs->cfg->is_file_found_locally) {
			src_buf = local_doca_buf;
			dst_buf = remote_doca_buf;
		} else {
			src_buf = remote_doca_buf;
			dst_buf = local_doca_buf;
		}

		/* Set data position in src_buf */
		result = doca_buf_get_data(src_buf, &data);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to get data address from DOCA buffer: %s", doca_get_error_string(result));
			return NULL;
		}

		result = doca_buf_set_data(src_buf, data, targs->host_dma_offset);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
			return NULL;
		}

		/* Construct DMA job */
		struct doca_dma_job_memcpy dma_job = {0};
		dma_job.base.type = DOCA_DMA_JOB_MEMCPY;
		dma_job.base.flags = DOCA_JOB_FLAGS_NONE;
		dma_job.base.ctx = targs->core_state->ctx;
		dma_job.src_buff = src_buf;
		dma_job.dst_buff = dst_buf;

		if(clock_gettime(CLOCK_REALTIME, &start) == -1) {
			perror("clock gettime");
			return NULL;
		}

		// Submit DMA job into the queue and wait until job completion
		result = dpu_submit_dma_job(targs->cfg, targs->core_state, targs->buffer, dma_job, targs->workq_index);
		if (result != DOCA_SUCCESS) {
			send_status_msg(targs->ep, targs->peer_addr, STATUS_FAILURE);
			doca_buf_refcount_rm(local_doca_buf, NULL);
			doca_buf_refcount_rm(remote_doca_buf, NULL);
			doca_mmap_destroy(targs->remote_mmap);
			dpu_cleanup_core_objs(targs->core_state);
			free(targs->buffer);
			return NULL;
		}

		if(clock_gettime(CLOCK_REALTIME, &stop) == -1) {
			perror("clock gettime");
			return NULL;
		}

		latency = (stop.tv_sec - start.tv_sec) * (double)BILLION
			     + (double)(stop.tv_nsec - start.tv_nsec);
		latency = latency / 1000.0;

		int start_index = targs->workq_index * targs->requests;
		targs->latencies[start_index + i] = latency;

		doca_buf_refcount_rm(local_doca_buf, NULL);
		doca_buf_refcount_rm(remote_doca_buf, NULL);

		if(i % 1000 == 0){
			counter++;
			DOCA_LOG_INFO("%d / 1000 finished", counter);
			
		}
	}

    return NULL;
}

doca_error_t
dpu_start_dma_copy(struct dma_copy_cfg *dma_cfg, struct core_state *core_state, struct doca_comm_channel_ep_t *ep,
		   struct doca_comm_channel_addr_t **peer_addr)
{
	char *buffer;
	char *host_dma_addr = NULL;
	char export_desc_buf[CC_MAX_MSG_SIZE];
	struct doca_mmap *remote_mmap;
	size_t host_dma_offset, export_desc_len;
	doca_error_t result;

	int test_rounds = atoi(dma_cfg->total_loop);
	DOCA_LOG_INFO("Total Trials is %d", test_rounds);
	int num_threads = atoi(dma_cfg->number_of_workq);
	DOCA_LOG_INFO("Number of WorkQ is %d", num_threads);
	
    double total_latency;
    double *latencies;

	if (test_rounds == 0){
		test_rounds = DEFAULT_LOOP_SIZE;
	}
	if (num_threads == 0){
		num_threads = 1;
	}

	/* Negotiate DMA copy direction with Host */
	result = dpu_negotiate_dma_direction_and_size(dma_cfg, ep, peer_addr);
	if (result != DOCA_SUCCESS) {
		dpu_cleanup_core_objs(core_state);
		return result;
	}

	/* Allocate memory to be used for read operation in case file is found locally, otherwise grant write access */
	uint32_t access = dma_cfg->is_file_found_locally ? DOCA_ACCESS_LOCAL_READ_ONLY : DOCA_ACCESS_LOCAL_READ_WRITE;

	result = memory_alloc_and_populate(core_state, dma_cfg->file_size, access, &buffer);
	DOCA_LOG_INFO("Success");
	if (result != DOCA_SUCCESS) {
		dpu_cleanup_core_objs(core_state);
		return result;
	}

	/* Receive export descriptor from Host */
	result = dpu_receive_export_desc(ep, peer_addr, export_desc_buf, &export_desc_len);
	if (result != DOCA_SUCCESS) {
		dpu_cleanup_core_objs(core_state);
		free(buffer);
		return result;
	}

	/* Create a local DOCA mmap from export descriptor */
	result = doca_mmap_create_from_export(NULL, (const void *)export_desc_buf, export_desc_len,
						core_state->dev, &remote_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create memory map from export descriptor");
		dpu_cleanup_core_objs(core_state);
		free(buffer);
		return result;
	}

	/* Receive remote address and offset from Host */
	result = dpu_receive_addr_and_offset(ep, peer_addr, &host_dma_addr, &host_dma_offset);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create memory map from export");
		doca_mmap_destroy(remote_mmap);
		dpu_cleanup_core_objs(core_state);
		free(buffer);
		return result;
	}
 
    total_latency = 0;
    latencies = malloc(sizeof(double) * test_rounds);
	for (size_t i = 0; i != test_rounds; i++) {
	     latencies[i] = 0;
	}

	int requests_per_thread = test_rounds / num_threads;
	pthread_t threads[num_threads];
    struct thread_args targs[num_threads];

	for (int j = 0; j < num_threads; j++) {
            targs[j].cfg = dma_cfg;
            targs[j].core_state = core_state;
			targs[j].remote_mmap = remote_mmap;
            targs[j].buffer = buffer;
			targs[j].host_dma_addr = host_dma_addr;
			targs[j].host_dma_offset = host_dma_offset;
            targs[j].workq_index = j;
			targs[j].requests = requests_per_thread;
			targs[j].latencies = latencies;
			targs[j].ep = ep;
        	targs[j].peer_addr = peer_addr;
			targs[j].buf_inv = core_state->buf_inv_array[j];
            pthread_create(&threads[j], NULL, handle_dpu_submit_job, (void *)&targs[j]);
    }

	for (int j = 0; j < num_threads; j++) {
		pthread_join(threads[j], NULL);
	}

	for (int i = 0; i < test_rounds; i++){
		total_latency += latencies[i];
	}
	
	int target_metric_value = atoi(dma_cfg->target_metric);
	DOCA_LOG_INFO("Target Metric is %d", target_metric_value);
	
    int target_metric;
	if (target_metric_value == 0){
		target_metric = DEFAULT_TARGET_METRIC;
	}
	else {
		target_metric = target_metric_value;
	}

	Statistics LatencyStats;
	Percentiles PercentileStats;
	GetStatistics(latencies, (size_t)test_rounds, &LatencyStats, &PercentileStats);
	printf(
		"Result for %d requests of %ld bytes (%.2lf seconds):\nRPS: %.2lf RPS\nStdErr: %.2lf\n", 
		test_rounds,
		(long) host_dma_offset,
		(total_latency / 1000000),
		(test_rounds / total_latency * 1000000),
		LatencyStats.StandardError
	);
	switch (target_metric) {
        case 1:
            printf("Min: %.2lf, Max: %.2lf, 50th: %.2lf, 90th: %.2lf, 99th: %.2lf, 99.9th: %.2lf, 99.99th: %.2lf\n",
                   LatencyStats.Min,
                   LatencyStats.Max,
                   PercentileStats.P50,
                   PercentileStats.P90,
                   PercentileStats.P99,
                   PercentileStats.P99p9,
                   PercentileStats.P99p99);
            break;
        case 2:
            printf("Min: %.2lf\n", LatencyStats.Min);
            break;
        case 3:
            printf("Max: %.2lf\n", LatencyStats.Max);
            break;
        case 4:
            printf("50th: %.2lf\n", PercentileStats.P50);
            break;
        case 5:
            printf("90th: %.2lf\n", PercentileStats.P90);
            break;
        case 6:
            printf("99th: %.2lf\n", PercentileStats.P99);
            break;
        case 7:
            printf("99.9th: %.2lf\n", PercentileStats.P99p9);
            break;
        case 8:
            printf("99.99th: %.2lf\n", PercentileStats.P99p99);
            break;
        default:
            printf("Invalid target metric.\n");
            break;
    }
	
	free(latencies);
	send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	doca_mmap_destroy(remote_mmap);
	dpu_cleanup_core_objs(core_state);
	free(buffer);
	return result;
}
