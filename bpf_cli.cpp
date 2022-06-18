#include <android-base/macros.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <bpf/BpfMap.h>
#include <bpf/BpfUtils.h>
#include <libbpf_android.h>

int main()
{
    constexpr const char tp_prog_path[] = "/sys/fs/bpf/prog_bpf_sys_tracepoint_raw_syscalls_sys_enter";
    constexpr const char tp_map_path[] = "/sys/fs/bpf/map_bpf_sys_sys_enter_map";
    // Attach tracepoint and wait for 4 seconds
    int mProgFd = bpf_obj_get(tp_prog_path);
    // int mMapFd = bpf_obj_get(tp_map_path);
    bpf_attach_tracepoint(mProgFd, "raw_syscalls", "sys_enter");
    sleep(1);
    android::bpf::BpfMap<int, int> myMap(tp_map_path);

    const auto iterFunc = [&](const uint32_t &key, const uint32_t &val, android::bpf::BpfMap<int, int> &) {
        printf("pid is:%d,syscall_id:%d\n", key, val);
        return android::base::Result<void>();
    };

    while (1)
    {
        usleep(40000);
        myMap.iterateWithValue(iterFunc);
    }

    exit(0);
}