## IB-CH-KEF方案实现（基于 PBC Library）
### 测试环境：Ubuntu 20.04 及以上
### Install PBC Library
```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar zxvf pbc-0.5.14.tar.gz
cd pbc
./configure
make
sudo make install
sudo ldconfig
```

### Build
```bash
mkdir build && cd build
cmake ..
make
```

### Run
```bash
./IB_CH_Our_test {type} {turns} {function} {swapG1G2} KEF
```

params meaning:

    type: 
        the curve type in PBC default; 
        choose from [a|e|i|f|d224];

    turns: 
        controll running function how many times; 
        must be positive integer;

    function: 
        choose which function to run {turns} times; 
        choose from [setup|hash|keygen|collision|all]; 
        if choose all means run setup, hash, keygen, collision {turns} times;
    
    swapG1G2:
        controll swap G1 and G2 group in nonsymmetric pairing groups;
        choose from [0|1];
