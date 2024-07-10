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

#define CC_MAX_QUEUE_SIZE 10	   /* Max number of messages on Comm Channel queue */
#define WORKQ_DEPTH 32		   /* Work queue depth */
#define SLEEP_IN_NANOS (10 * 1000) /* Sample the job every 10 microseconds  */
#define STATUS_SUCCESS true	   /* Successful status */
#define STATUS_FAILURE false	   /* Unsuccessful status */

DOCA_LOG_REGISTER(DMA_COPY_HOST);

/*
 * Wait for status message
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
wait_for_successful_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_status msg_status;
	doca_error_t result;
	size_t msg_len, status_msg_len = sizeof(struct cc_msg_dma_status);
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	msg_len = status_msg_len;
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&msg_status, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = status_msg_len;
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Status message was not received: %s", doca_get_error_string(result));
		return result;
	}

	if (!msg_status.is_success) {
		DOCA_LOG_ERR("Failure status received");
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

/*
 * Fill local buffer with file content
 *
 * @cfg [in]: Application configuration
 * @buffer [out]: Buffer to save information into
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
fill_buffer_with_file_content(struct dma_copy_cfg *cfg, char *buffer)
{
	FILE *fp;

	fp = fopen(cfg->file_path, "r");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to open %s", cfg->file_path);
		return DOCA_ERROR_IO_FAILED;
	}

	/* Read file content and store it in the local buffer which will be exported */
	if (fread(buffer, 1, cfg->file_size, fp) != cfg->file_size) {
		DOCA_LOG_ERR("Failed to read content from file: %s", cfg->file_path);
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}
	fclose(fp);

	return DOCA_SUCCESS;
}

/*
 * Host side function for file size and location negotiation
 *
 * @cfg [in]: Application configuration
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
host_negotiate_dma_direction_and_size(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t *ep,
				      struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_direction host_dma_direction = {0};
	struct cc_msg_dma_direction dpu_dma_direction = {0};
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;
	size_t msg_len;

	result = doca_comm_channel_ep_connect(ep, SERVER_NAME, peer_addr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to establish a connection with the DPU: %s", doca_get_error_string(result));
		return result;
	}

	while ((result = doca_comm_channel_peer_addr_update_info(*peer_addr)) == DOCA_ERROR_CONNECTION_INPROGRESS)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to validate the connection with the DPU: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("Connection to DPU was established successfully");

	/* First byte indicates if file is located on Host, other 4 bytes determine file size */
	if (cfg->is_file_found_locally) {
		DOCA_LOG_INFO("File was found locally, it will be DMA copied to the DPU");
		host_dma_direction.file_size = htonl(cfg->file_size);
		host_dma_direction.file_in_host = true;
	} else {
		DOCA_LOG_INFO("File was not found locally, it will be DMA copied from the DPU");
		host_dma_direction.file_in_host = false;
	}

	while ((result = doca_comm_channel_ep_sendto(ep, &host_dma_direction, sizeof(host_dma_direction),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send negotiation buffer to DPU: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("Waiting for DPU to send negotiation message");

	msg_len = sizeof(struct cc_msg_dma_direction);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&dpu_dma_direction, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(struct cc_msg_dma_direction);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Negotiation message was not received: %s", doca_get_error_string(result));
		return result;
	}

	if (msg_len != sizeof(struct cc_msg_dma_direction)) {
		DOCA_LOG_ERR("Negotiation with DPU on file location and size failed");
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (!cfg->is_file_found_locally)
		cfg->file_size = ntohl(dpu_dma_direction.file_size);

	DOCA_LOG_INFO("Negotiation with DPU on file location and size ended successfully");
	return DOCA_SUCCESS;
}

/*
 * Host side function for exporting memory map to DPU side with Comm Channel
 *
 * @core_state [in]: DOCA core structure
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @export_desc [out]: Export descriptor to send
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
host_export_memory_map_to_dpu(struct core_state *core_state, struct doca_comm_channel_ep_t *ep,
			      struct doca_comm_channel_addr_t **peer_addr, const void **export_desc)
{
	doca_error_t result;
	size_t export_desc_len;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Export memory map to allow access to this memory region from DPU */
	result = doca_mmap_export_dpu(core_state->mmap, core_state->dev, export_desc, &export_desc_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to export DOCA mmap: %s", doca_get_error_string(result));
		return result;
	}

	/* Send the memory map export descriptor to DPU */
	while ((result = doca_comm_channel_ep_sendto(ep, *export_desc, export_desc_len, DOCA_CC_MSG_FLAG_NONE,
						     *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send config files to DPU: %s", doca_get_error_string(result));
		return result;
	}

	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS)
		return result;

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
 * Host side function to send buffer address and offset
 *
 * @src_buffer [in]: Buffer to send info on
 * @src_buffer_size [in]: Buffer size
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
host_send_addr_and_offset(const char *src_buffer, size_t src_buffer_size, struct doca_comm_channel_ep_t *ep,
			  struct doca_comm_channel_addr_t **peer_addr)
{
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Send the full buffer address and length */
	uint64_t addr_to_send = htonq((uintptr_t)src_buffer);
	uint64_t length_to_send = htonq((uint64_t)src_buffer_size);

	while ((result = doca_comm_channel_ep_sendto(ep, &addr_to_send, sizeof(addr_to_send),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send address to start DMA from: %s", doca_get_error_string(result));
		return result;
	}

	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS)
		return result;

	while ((result = doca_comm_channel_ep_sendto(ep, &length_to_send, sizeof(length_to_send),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send config files to DPU: %s", doca_get_error_string(result));
		return result;
	}

	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS)
		return result;

	DOCA_LOG_INFO(
		"Address and offset to start DMA from sent successfully, waiting for DPU to Ack that DMA finished");

	return result;
}

doca_error_t
host_start_dma_copy(struct dma_copy_cfg *dma_cfg, struct core_state *core_state, struct doca_comm_channel_ep_t *ep,
		    struct doca_comm_channel_addr_t **peer_addr)
{

	doca_error_t result;
	char *buffer = NULL;
	const void *export_desc = NULL;

	/* Negotiate DMA copy direction with DPU */
	result = host_negotiate_dma_direction_and_size(dma_cfg, ep, peer_addr);
	if (result != DOCA_SUCCESS)
		return result;	

	/* Allocate memory to be used for read operation in case file is found locally, otherwise grant write access */
	uint32_t dpu_access = dma_cfg->is_file_found_locally ? DOCA_ACCESS_DPU_READ_ONLY : DOCA_ACCESS_DPU_READ_WRITE;

	result = memory_alloc_and_populate(core_state, dma_cfg->file_size, dpu_access, &buffer);
	if (result != DOCA_SUCCESS)
		return result;

	/* Export memory map and send it to DPU */
	result = host_export_memory_map_to_dpu(core_state, ep, peer_addr, &export_desc);
	if (result != DOCA_SUCCESS) {
		free(buffer);
		return result;
	}

	/* Fill the buffer before DPU starts DMA operation */
	if (dma_cfg->is_file_found_locally) {
		result = fill_buffer_with_file_content(dma_cfg, buffer);
		if (result != DOCA_SUCCESS) {
			free(buffer);
			return result;
		}
	}

	/* Send source buffer address and offset (entire buffer) to enable DMA and wait until DPU is done */
	result = host_send_addr_and_offset(buffer, dma_cfg->file_size, ep, peer_addr);
	if (result != DOCA_SUCCESS) {
		free(buffer);
		return result;
	}

	/* Wait to DPU status message to indicate DMA was ended */
	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS) {
		free(buffer);
		return result;
	}

	DOCA_LOG_INFO("Final status message was successfully received");

	free(buffer);

	return DOCA_SUCCESS;
}