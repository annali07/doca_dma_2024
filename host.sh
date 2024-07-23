#!/bin/bash

# Step 1: Run meson build
meson build

# Step 2: Change directory to build
cd build

# Step 3: Run ninja to build the project
ninja

# Step 4: Change directory to dma_copy_host_benchmark
cd dma_copy_host_benchmark

# Step 5: Execute the built executable with the specified arguments
./doca_dma_copy_host_benchmark -p e1:00.1 -q 50
