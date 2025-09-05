#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <PID>"
    exit 1
fi

PID=$1

# 检查进程是否存在
if [ ! -d "/proc/$PID" ]; then
    echo "Process $PID does not exist"
    exit 1
fi

# 检测 cgroup 版本
if [ -d "/sys/fs/cgroup/cpu" ] && [ -d "/sys/fs/cgroup/memory" ]; then
    # cgroup v1
    echo "Using cgroup v1"
    
    # 获取 cgroup 路径
    CPU_PATH=$(grep -E "^[0-9]+:cpu[,:]" /proc/$PID/cgroup | cut -d: -f3)
    MEM_PATH=$(grep -E "^[0-9]+:memory[,:]" /proc/$PID/cgroup | cut -d: -f3)
    
    # 读取 CPU 使用量
    echo "CPU Usage:"
    echo "  Total CPU time: $(cat /sys/fs/cgroup/cpu$CPU_PATH/cpuacct.usage) ns"
    echo "  CPU stats:"
    cat /sys/fs/cgroup/cpu$CPU_PATH/cpuacct.stat
    
    # 读取内存使用量
    echo "Memory Usage:"
    echo "  Current: $(cat /sys/fs/cgroup/memory$MEM_PATH/memory.usage_in_bytes) bytes"
    echo "  Maximum: $(cat /sys/fs/cgroup/memory$MEM_PATH/memory.max_usage_in_bytes) bytes"
    echo "  Memory stats (partial):"
    grep -E "^(rss|cache|swap)" /sys/fs/cgroup/memory$MEM_PATH/memory.stat
    
else
    # cgroup v2
    echo "Using cgroup v2"
    
    # 获取 cgroup 路径
    CGROUP_PATH=$(grep -E "^0::" /proc/$PID/cgroup | cut -d: -f3)
    
    # 读取 CPU 使用量
    echo "CPU Usage:"
    cat /sys/fs/cgroup$CGROUP_PATH/cpu.stat
    
    # 读取内存使用量
    echo "Memory Usage:"
    echo "  Current: $(cat /sys/fs/cgroup$CGROUP_PATH/memory.current) bytes"
    if [ -f "/sys/fs/cgroup$CGROUP_PATH/memory.peak" ]; then
        echo "  Peak: $(cat /sys/fs/cgroup$CGROUP_PATH/memory.peak) bytes"
    fi
    echo "  Memory stats (partial):"
    grep -E "^(anon|file|shmem)" /sys/fs/cgroup$CGROUP_PATH/memory.stat
fi

