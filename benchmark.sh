kernels=(384 768 1536 3072 6144)
chars=(500000 1000000 1500000 2000000)

root_dir="/home/ilpez/snort3"
src_dir="src/search_engines"
make_dir="build"
exec_dir="../snort-builds"

log_dir="../snort-logs"
log_name="kecepatan."$(date +%Y-%m-%d_%H:%M)".csv"
config="etc/snort/snort.lua"

echo $log_dir"/"$log_name
echo "engine,kernel,char,rule,data,result" >> $log_dir"/"$log_name

rules=(~/rules/snort3-community.rules)
datasets=(~/pcap/bigFlows.pcap)
engines=('ac_full' 'ac_gpu')

for kernel in "${kernels[@]}" 
do
    cd $root_dir
    cd $src_dir
    sed -i -e "s/KERNEL_SIZE [0-9]\+/KERNEL_SIZE $kernel/g" acsmx3.h
    for char in "${chars[@]}"
    do
        cd $root_dir
        cd $src_dir
        sed -i -e "s/acsm->buffer_size = [0-9]\{2,\}/acsm->buffer_size = $char/g" acsmx3.cc
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
                    echo $engine $kernel $char $rule $data
                    res="$(bin/snort -c $config -R $rule -r $data --lua "search_engine = {search_method = '$engine'}" | grep "seconds:" | sed "s/^.*: //")"
                    echo "engines: "$engine "kernel: "$kernel "char: "$char "rules: "$rule "dataset: "$data "result: "$res
                    echo $engine","$kernel","$char","$rule","$data","$res >> $log_dir"/"$log_name
                done
            done
        done
    done
done