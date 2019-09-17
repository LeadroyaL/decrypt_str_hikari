# 使用 unicorn 去除 hikari 的字符串加密

- prepare-hikari.py IDAPython，确定大致BasicBlock 范围，写入 result.json
- decrypt-hikari.py python3脚本，读取 result.json 的内容， 模拟执行，Patch 程序
- native-lib.cpp libnative-lib.so libnative.patch.so 相关的cpp源码和native文件
