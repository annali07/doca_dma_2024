#!/bin/bash


ssh_into_host() {
    echo "Starting SSH into farnet1..."
    ssh $FARNET1_USER@$FARNET1_IP "bash -s" << 'EOF' &
    echo "Connected to farnet1..."
    cd transfer/doca_dma_2024
    echo $FARNET1_SCRIPT
    pwd
    echo "Running host.sh..."
    ./host.sh
    exit
EOF
    echo "SSH session to farnet1 initiated."
}

# Run SSH into farnet1 in the background
ssh_into_host

# Give the server some time to start
sleep 20

# Step 1: Run meson build
meson build

# Step 2: Change directory to build
cd build

# Step 3: Run ninja to build the project
ninja

# Step 4: Change directory to dma_copy_host_benchmark
cd dma_copy_dpu_benchmark

# Step 5: Execute the built executable with the specified arguments

./doca_dma_copy_dpu_benchmark -p 03:00.1 -r e1:00.1 -l 10000 -d 1 -t 1 -f 8 -q 10
