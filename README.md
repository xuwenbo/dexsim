# dexsim

A python3 version for [dex-oracle](https://github.com/CalebFenton/dex-oracle).
You can read more details on [dex-oracle](https://github.com/CalebFenton/dex-oracle).

### Install

1. smali
2. adb
3. pip install -r requirements.txt

Note: Please make sure your cmd can run baksmali/smali, adb, java.

### Usage

1. Conect to a Device or Emulator
2. `dexsim.bat smali_dir/dex/apk`

### Support

- [x] Ljava/lang/String;->\<init>([B)V
- [x] func(Ljava/lang/String;)Ljava/lang/String;
- [x] func(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
- [x] func(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
- [x] func(I)Ljava/lang/String;
- [x] func(II)Ljava/lang/String;
- [x] func(III)Ljava/lang/String;
- [x] func([B)Ljava/lang/String;
- [x] func([I)Ljava/lang/String;
- [x] Replace Variable : I
- [x] Replace Variable : Ljava/lang/String;
- [ ] Replace Variable : [B
- [ ] fun(Ljava/lang/String;)[B
