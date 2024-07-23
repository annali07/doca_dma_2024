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
#include <stdio.h>
#include <ctype.h>

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
#define SLEEP_IN_NANOS (10 * 1000) /* Sample the job every 10 microseconds  */
#define STATUS_SUCCESS true	   /* Successful status */
#define STATUS_FAILURE false	   /* Unsuccessful status */

DOCA_LOG_REGISTER(DMA_COPY_CORE);

/*
 * ARGP validation Callback - check if input file exists
 *
 * @config [in]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
args_validation_callback(void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;

	if (cfg->file_size) {
		cfg->is_file_found_locally = true;
	}

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dev_pci_addr_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	const char *dev_pci_addr = (char *)param;

	if (strnlen(dev_pci_addr, DOCA_DEVINFO_PCI_ADDR_SIZE) == DOCA_DEVINFO_PCI_ADDR_SIZE) {
		DOCA_LOG_ERR("Entered device PCI address exceeding the maximum size of %d", DOCA_DEVINFO_PCI_ADDR_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}

	strlcpy(cfg->cc_dev_pci_addr, dev_pci_addr, DOCA_DEVINFO_PCI_ADDR_SIZE);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle file parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
file_size_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	char *file_size = (char *)param;

	if (isdigit(*file_size)) {
		int file_size_value = *file_size - '0';
		if (file_size_value > MAX_FILE_SIZE || file_size_value < 1) {
			DOCA_LOG_INFO("Entered file size number is not within the range of 1 to %d", MAX_FILE_SIZE);
			return DOCA_ERROR_INVALID_VALUE;
		}
	}
	else{
		DOCA_LOG_INFO("Entered file size is not a numerical value.");
		return DOCA_ERROR_INVALID_VALUE;
	}

	strlcpy(cfg->file_path, file_size, MAX_FILE_SIZE);
	cfg->file_size = (uint32_t)strtoul(cfg->file_path, NULL, 10);

	DOCA_LOG_INFO("File size: %u\n", cfg->file_size);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device representor PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
rep_pci_addr_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	const char *rep_pci_addr = (char *)param;

	if (cfg->mode == DMA_COPY_MODE_DPU) {
		if (strnlen(rep_pci_addr, DOCA_DEVINFO_REP_PCI_ADDR_SIZE) == DOCA_DEVINFO_REP_PCI_ADDR_SIZE) {
			DOCA_LOG_ERR("Entered device representor PCI address exceeding the maximum size of %d",
				     DOCA_DEVINFO_REP_PCI_ADDR_SIZE - 1);
			return DOCA_ERROR_INVALID_VALUE;
		}

		strlcpy(cfg->cc_dev_rep_pci_addr, rep_pci_addr, DOCA_DEVINFO_REP_PCI_ADDR_SIZE);
	}

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle Total Loop
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
total_trials_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	const char *total_loop = (char *)param;

	if (isdigit(*total_loop)) {
		int total_loop_value = *total_loop - '0';
		if (total_loop_value > MAX_LOOP_SIZE || total_loop_value < 1) {
			DOCA_LOG_INFO("Entered number of trials to be run exceeding the maximum size of %d or is non-positive", MAX_LOOP_SIZE);
			return DOCA_ERROR_INVALID_VALUE;
		}
	}
	else{
		DOCA_LOG_INFO("Entered number of trials is not a numerical value.");
		return DOCA_ERROR_INVALID_VALUE;
	}
	strlcpy(cfg->total_loop, total_loop, MAX_LOOP_SIZE);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - WorkQ Depth
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
workq_depth_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	const char *workq_depth = (char *)param;

	if (isdigit(*workq_depth)) {
		int workq_depth_value = *workq_depth - '0';
		if (workq_depth_value > MAX_WORKQ_DEPTH || workq_depth_value < 1) {
			DOCA_LOG_INFO("Entered number of trials to be run exceeding the maximum size of %d or is non-positive", MAX_WORKQ_DEPTH);
			return DOCA_ERROR_INVALID_VALUE;
		}
	}
	else{
		DOCA_LOG_INFO("Entered number of trials is not a numerical value.");
		return DOCA_ERROR_INVALID_VALUE;
	}
	strlcpy(cfg->workq_depth, workq_depth, MAX_WORKQ_DEPTH);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Target Metric
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
target_metric_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	const char *target_metric = (char *)param;

	if (isdigit(*target_metric)) {
		int target_metric_value = *target_metric - '0';
		if (target_metric_value > MAX_TARGET_METRIC || target_metric_value < 1) {
			DOCA_LOG_INFO("Entered target metric number is not within the range of 1 to %d", MAX_TARGET_METRIC);
			return DOCA_ERROR_INVALID_VALUE;
		}
	}
	else{
		DOCA_LOG_INFO("Entered target metric is not a numerical value.");
		return DOCA_ERROR_INVALID_VALUE;
	}
	strlcpy(cfg->target_metric, target_metric, MAX_TARGET_METRIC);

	return DOCA_SUCCESS;
}

/*
 * Check if DOCA device is DMA capable
 *
 * @devinfo [in]: Device to check
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t check_dev_dma_capable(struct doca_devinfo *devinfo)
{
	return doca_dma_job_get_supported(devinfo, DOCA_DMA_JOB_MEMCPY);
}

/*
 * Set Comm Channel properties
 *
 * @mode [in]: Running mode
 * @ep [in]: DOCA comm_channel endpoint
 * @dev [in]: DOCA device object to use
 * @dev_rep [in]: DOCA device representor object to use
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
set_cc_properties(enum dma_copy_mode mode, struct doca_comm_channel_ep_t *ep, struct doca_dev *dev, struct doca_dev_rep *dev_rep)
{
	doca_error_t result;

	result = doca_comm_channel_ep_set_device(ep, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DOCA device property");
		return result;
	}

	result = doca_comm_channel_ep_set_max_msg_size(ep, CC_MAX_MSG_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set max_msg_size property");
		return result;
	}

	result = doca_comm_channel_ep_set_send_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set snd_queue_size property");
		return result;
	}

	result = doca_comm_channel_ep_set_recv_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set rcv_queue_size property");
		return result;
	}

	if (mode == DMA_COPY_MODE_DPU) {
		result = doca_comm_channel_ep_set_device_rep(ep, dev_rep);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to set DOCA device representor property");
	}

	return result;
}

void
destroy_cc(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t *peer,
	   struct doca_dev *dev, struct doca_dev_rep *dev_rep)
{
	doca_error_t result;

	if (peer != NULL) {
		result = doca_comm_channel_ep_disconnect(ep, peer);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to disconnect from Comm Channel peer address: %s",
				     doca_get_error_string(result));
	}

	result = doca_comm_channel_ep_destroy(ep);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy Comm Channel endpoint: %s", doca_get_error_string(result));

	if (dev_rep != NULL) {
		result = doca_dev_rep_close(dev_rep);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to close Comm Channel DOCA device representor: %s",
				     doca_get_error_string(result));
	}

	result = doca_dev_close(dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to close Comm Channel DOCA device: %s", doca_get_error_string(result));
}

doca_error_t
init_cc(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t **ep, struct doca_dev **dev,
	struct doca_dev_rep **dev_rep)
{
	doca_error_t result;

	result = doca_comm_channel_ep_create(ep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Comm Channel endpoint: %s", doca_get_error_string(result));
		return result;
	}

	result = open_doca_device_with_pci(cfg->cc_dev_pci_addr, NULL, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
		doca_comm_channel_ep_destroy(*ep);
		return result;
	}

	/* Open DOCA device representor on DPU side */
	if (cfg->mode == DMA_COPY_MODE_DPU) {
		result = open_doca_device_rep_with_pci(*dev, DOCA_DEV_REP_FILTER_NET, cfg->cc_dev_rep_pci_addr, dev_rep);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to open Comm Channel DOCA device representor based on PCI address");
			doca_comm_channel_ep_destroy(*ep);
			doca_dev_close(*dev);
			return result;
		}
	}

	result = set_cc_properties(cfg->mode, *ep, *dev, *dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set Comm Channel properties");
		doca_comm_channel_ep_destroy(*ep);
		if (cfg->mode == DMA_COPY_MODE_DPU)
			doca_dev_rep_close(*dev_rep);
		doca_dev_close(*dev);
	}

	return result;
}

doca_error_t
register_dma_copy_params(void)
{
	doca_error_t result;
	struct doca_argp_param *file_size_param, *dev_pci_addr_param, *rep_pci_addr_param, *total_loop_param, *workq_depth_param, *target_metric_param;

	/* Create and register string to dma copy param */
	result = doca_argp_param_create(&file_size_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(file_size_param, "f");
	doca_argp_param_set_long_name(file_size_param, "file size");
	doca_argp_param_set_description(file_size_param,
					"Size of the file to be transferred after a successful DMA copy");
	doca_argp_param_set_callback(file_size_param, file_size_callback);
	doca_argp_param_set_type(file_size_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(file_size_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register Comm Channel DOCA device PCI address */
	result = doca_argp_param_create(&dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(dev_pci_addr_param, "p");
	doca_argp_param_set_long_name(dev_pci_addr_param, "pci-addr");
	doca_argp_param_set_description(dev_pci_addr_param,
					"DOCA Comm Channel device PCI address");
	doca_argp_param_set_callback(dev_pci_addr_param, dev_pci_addr_callback);
	doca_argp_param_set_type(dev_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(dev_pci_addr_param);
	result = doca_argp_register_param(dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register Comm Channel DOCA device representor PCI address */
	result = doca_argp_param_create(&rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rep_pci_addr_param, "r");
	doca_argp_param_set_long_name(rep_pci_addr_param, "rep-pci");
	doca_argp_param_set_description(rep_pci_addr_param,
					"DOCA Comm Channel device representor PCI address (needed only on DPU)");
	doca_argp_param_set_callback(rep_pci_addr_param, rep_pci_addr_callback);
	doca_argp_param_set_type(rep_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register Total Numer of Loops to be run */
	result = doca_argp_param_create(&total_loop_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(total_loop_param, "l");
	doca_argp_param_set_long_name(total_loop_param, "loops_num");
	doca_argp_param_set_description(total_loop_param,
					"Total Trials to be run (needed only on DPU)");
	doca_argp_param_set_callback(total_loop_param, total_trials_callback);
	doca_argp_param_set_type(total_loop_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(total_loop_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register Workq depth */
	result = doca_argp_param_create(&workq_depth_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(workq_depth_param, "q");
	doca_argp_param_set_long_name(workq_depth_param, "workq_depth");
	doca_argp_param_set_description(workq_depth_param,
					"The WorkQ depth of the operation");
	doca_argp_param_set_callback(workq_depth_param, workq_depth_callback);
	doca_argp_param_set_type(workq_depth_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(workq_depth_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register target metric */
	result = doca_argp_param_create(&target_metric_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(target_metric_param, "t");
	doca_argp_param_set_long_name(target_metric_param, "target_metric");
	doca_argp_param_set_description(target_metric_param,
					"Target metric of the DMA operation (needed only on dpu).\n\t\t\t\t\t\t1 All\n\t\t\t\t\t\t2 Min\n\t\t\t\t\t\t3 Max\n\t\t\t\t\t\t4 50th\n\t\t\t\t\t\t5 90th\n\t\t\t\t\t\t6 99th\n\t\t\t\t\t\t7 99.9th\n\t\t\t\t\t\t8 99.99th");
	doca_argp_param_set_callback(target_metric_param, target_metric_callback);
	doca_argp_param_set_type(target_metric_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(target_metric_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Register validation callback */
	result = doca_argp_register_validation_callback(args_validation_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program validation callback: %s", doca_get_error_string(result));
		return result;
	}

	/* Register version callback for DOCA SDK & RUNTIME */
	result = doca_argp_register_version_callback(sdk_version_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register version callback: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t
open_dma_device(struct doca_dev **dev)
{
	doca_error_t result;

	result = open_doca_device_with_capabilities(check_dev_dma_capable, dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to open DOCA DMA capable device");

	return result;
}

doca_error_t
create_core_objs(struct core_state *state, enum dma_copy_mode mode, struct dma_copy_cfg *dma_cfg)
{
	doca_error_t result;
	size_t num_elements = 2;

	result = doca_mmap_create(NULL, &state->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create mmap: %s", doca_get_error_string(result));
		return result;
	}

	if (mode == DMA_COPY_MODE_HOST)
		return DOCA_SUCCESS;

	result = doca_buf_inventory_create(NULL, num_elements, DOCA_BUF_EXTENSION_NONE, &state->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_dma_create(&(state->dma_ctx));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create DMA engine: %s", doca_get_error_string(result));
		return result;
	}

	state->ctx = doca_dma_as_ctx(state->dma_ctx);

	int workq_depth;
	int workq_depth_val = atoi(dma_cfg->workq_depth);
	DOCA_LOG_INFO("WorkQ depth is %d", workq_depth_val);
	
	if (workq_depth_val == 0){
		workq_depth = DEFAULT_WORKQ_DEPTH;
	}
	else {
		workq_depth = workq_depth_val;
	}

	result = doca_workq_create((uint32_t) workq_depth, &(state->workq));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

doca_error_t
init_core_objs(struct core_state *state, struct dma_copy_cfg *cfg)
{
	doca_error_t result;

	result = doca_mmap_dev_add(state->mmap, state->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to mmap: %s", doca_get_error_string(result));
		return result;
	}

	if (cfg->mode == DMA_COPY_MODE_HOST)
		return DOCA_SUCCESS;

	result = doca_buf_inventory_start(state->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_dev_add(state->ctx, state->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register device with DMA context: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_start(state->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DMA context: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_workq_add(state->ctx, state->workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register work queue with context: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

void
destroy_core_objs(struct core_state *state, struct dma_copy_cfg *cfg)
{
	doca_error_t result;

	if (cfg->mode == DMA_COPY_MODE_DPU) {
		result = doca_workq_destroy(state->workq);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy work queue: %s", doca_get_error_string(result));
		state->workq = NULL;

		result = doca_dma_destroy(state->dma_ctx);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy dma: %s", doca_get_error_string(result));
		state->dma_ctx = NULL;
		state->ctx = NULL;

		result = doca_buf_inventory_destroy(state->buf_inv);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy buf inventory: %s", doca_get_error_string(result));
		state->buf_inv = NULL;
	}

	result = doca_mmap_destroy(state->mmap);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy mmap: %s", doca_get_error_string(result));
	state->mmap = NULL;

	result = doca_dev_close(state->dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to close device: %s", doca_get_error_string(result));
	state->dev = NULL;
}