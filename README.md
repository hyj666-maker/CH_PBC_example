## IB-CH-KEF Schemes Implementation（on PBC Library）

These are implementations of our proposed identity-based chameleon hash (IB-CH) schemes and previous IB-CH ones for comparison.

### Code structure

The `include` directory houses all header files, mirrored by the `src` directory which contains their respective source (cpp) implementations.

Within `include/base`, the `ElementList.h` file defines a class for managing curve element lists. The `curve` subfolder contains `params.h`, where initial parameters vital to the PBC Library are defined.

In the `scheme` directory, we implement 4 distinct schemes: `IB_CH_KEF`, `IB_CH_Our`, `IB_CH_Zhang`, and `IB_CH_nonRO`.

The `unit_test` folder contains standalone test cases, each named according to the scheme it validates, e.g., `IB_CH_KEF_test.cpp`.

```bash
IB_CH/
├── include/
│   ├── base/
│   │   └── ElementList.h
│   ├── curve/
│   │   └── params.h
│   ├── scheme/
│   │   ├── IB_CH_KEF.h
│   │   ├── IB_CH_Our.h
│   │   ├── IB_CH_Zhang.h
│   │   └── IB_CH_nonRO.h
│   └── utils/
│       └── func.h
├── src/
│   ├── base/
│   │   └── ElementList.cpp
│   ├── curve/
│   │   └── params.cpp
│   ├── scheme/
│   │   ├── IB_CH_KEF.cpp
│   │   ├── IB_CH_Our.cpp
│   │   ├── IB_CH_Zhang.cpp
│   │   └── IB_CH_nonRO.cpp
│   └── utils/
│       └── func.cpp
├── unit_test/
│   ├── IB_CH_KEF_test.cpp
│   ├── IB_CH_Our_test.cpp
│   ├── IB_CH_Zhang_test.cpp
│   └── IB_CH_nonRO_test.cpp
├── CMakeLists.txt
└── README.md
```

### Introduction to IB-CH schemes

- `IB_CH_Zhang` references to ID-based chameleon hashes from bilinear pairings, IACR Cryptol. ePrint Arch. 2003/208. In this file we make three classes `IB_CH`, `IB_CH_S1` and `IB_CH_S2`. The `IB_CH` is just for easy to write code, and `IB_CH_S1` is used to implement scheme `Scheme 1` in the paper, and so on to `IB_CH_S2`.

- `IB_CH_KEF` references to Identity-based chameleon hash scheme without key exposure, ACISP 2010

- `IB_CH_nonRO` references to Identity-based chameleon hash without random oracles and application in the mobile internet, ICC 2021

- `IB_CH_Our` references to Identity-Based Chameleon Hashes in the Standard Model for Mobile Devices. In this file we make two classes `Our_IB_CH` and `Our_IB_CH_KEF`. The `Our_IB_CH` is used to implement the `Our-1` scheme in our paper, and the `Our_IB_CH_KEF` is used to implement the `Our-2` scheme.

## Quick start

- Develop environment：Ubuntu 20.04 and above

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

### Usage

```
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
```
