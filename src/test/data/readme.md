# 测试用数据库

这个数据库在解密后，无法访问表TransTable，报数据损坏。

```bash
cargo run -- -k 30ef78833ada4b4fa339209da7eeaefde7a0f64fc06148b08e205acdd499c37d -f ./src/test/data --vv 3 -o ./src/test/data/dump
```