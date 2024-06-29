## IB-CH-KEF Schemes Implementation（on PBC Library）

### Develop environment：Ubuntu 20.04 and above

### Introduce to folder

We save all header file in folder `include`, and their cpp file in folder `src`. We implement unit test and save the cpp file in folder `unit_test`.

For folder `include`, in folder `base` we write `ElementList.h` to define a curve element list class. In folder `curve` we write `params.h` to save initial parameter used in PBC Library. In folder `scheme` we implement six schemes in four papers. Then we save their implementation in the same relative path in folder `src`.

### Introduce to paper

`IB_CH_Zhang` reference to ID-based chameleon hashes from bilinear pairings, IACR Cryptol. ePrint Arch. 2003/208. In this file we make three class `IB_CH`, `IB_CH_S1` and `IB_CH_S2`. The `IB_CH` is just for easy to write code, and `IB_CH_S1` is used to implement scheme `Scheme 1` in the paper, and so on to `IB_CH_S2`.

`IB_CH_KEF` reference to Identity-based chameleon hash scheme without key exposure, ACISP 2010

`IB_CH_nonRO` reference to Identity-based chameleon hash without random oracles and application in the mobile internet, ICC 2021

`IB_CH_Our` reference to Identity-Based Chameleon Hashes in the Standard Model for Mobile Devices. In this file we make two class `Our_IB_CH` and `Our_IB_CH_KEF`. The `Our_IB_CH` is used to implement scheme `Our-1` in the paper, and the `Our_IB_CH` is used to implement scheme `Our-2`.

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

explain the parameters:

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
