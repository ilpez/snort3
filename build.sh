./configure_cmake.sh --prefix=$HOME/snort-builds --build-type=Release
cd build
make -j 5 install

ln -sf $HOME/snort3/ac_gpu.cl $HOME/snort-builds/ac_gpu.cl