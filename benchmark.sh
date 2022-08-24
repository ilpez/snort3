kernels=(\
    384 \
    768 \
    1536 \
    3072 \
    6144 \
    )
chars=(\
    500000 \
    1000000 \
    1500000 \
    2000000 \
    )

test_time=$(date +%Y%m%d_%H%M)
root_dir="/home/ilpez/snort3"
src_dir="src/search_engines"
make_dir="build"
exec_dir="../snort-builds"

log_dir="../snort-logs"
log_name="kecepatan."$test_time".csv"
config="etc/snort/snort.lua"

echo $log_dir"/"$log_name
echo "engine,kernel,char,rule,data,result" >> $log_dir"/"$log_name


rules=(~/rules/snort3-community.rules)
datasets=(  ~/nfs/pcap/bigFlows \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-1-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-17-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-21-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-20-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-3-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-33-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-34-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-35-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-36-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-39-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-42-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-43-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-44-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-48-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-49-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-52-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-60-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-7-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-8-1 \
            # ~/nfs/pcap/IoT-23-Malware/CTU-IoT-Malware-Capture-9-1 \
            )
engines=('ac_full')
mkdir -v ~/nfs/pcap/results/$test_time
for kernel in "${kernels[@]}"
do
    cd $root_dir
    cd $src_dir
    sed -i -e "s/KERNEL_SIZE [0-9]\+/KERNEL_SIZE $kernel/g" acsmx2.h
    for char in "${chars[@]}"
    do
        cd $root_dir
        cd $src_dir
        sed -i -e "s/BUFFER_SIZE [0-9]\{2,\}/BUFFER_SIZE $char/g" acsmx2.h
        cd $root_dir
        ./build.sh
        cd $exec_dir
        for data in "${datasets[@]}"
        do
            for rule in "${rules[@]}"
            do
                for engine in "${engines[@]}"
                do
                        sudo sync
                        sudo killall snort
			echo 3 | sudo tee /proc/sys/vm/drop_caches
                        echo $engine $kernel $char $rule $data
                        sleep 5
                        res="$(bin/snort -c $config -R $rule --pcap-dir $data --lua "search_engine = {search_method = '$engine'}" | grep "seconds:" | sed "s/^.*: //")"
                        echo "engines: "$engine "kernel: "$kernel "char: "$char "rules: "$rule "dataset: "$data "result: "$res
                        echo $engine","$kernel","$char","$rule","$data","$res >> ~/nfs/pcap/results/$test_time"/"$log_name
                        cp ~/nfs/pcap/results.json ~/nfs/pcap/results/$test_time/$kernel"_"$char"_results.json"
                done
            done
        done
    done
done
