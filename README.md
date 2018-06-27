# Strawberry:掌控数据包传送的细节
![](https://github.com/mm530/strawberry/raw/master/logo.jpg)

Strawberry，监控传输层的数据包，解决调试网络方面的困扰。

这个库包含的功能:
* 监控ICMP, TCP, UDP数据包
* 可以只监控指定协议，源地址，目的地址， 源端口，目的端口的通信信息
* 保存数据包

## 教程 & 使用
捕获ICMP，TCP，UDP数据包，并打印：
```python
from strawberry import core

snf = core.Sniffer()
snf.run()
```

## 安装
```bash
$ pip3 install git+https://github.com/mm530/strawberry
```

## 待开发功能
- [ ] TCP数据包的解析
- [ ] UDP数据包的解析
- [ ] HTTP数据包解析
- [ ] 可配置选项，只显示用户想显示的信息
- [ ] 保存数据包

## 鸣谢
* Python
* Linux
* Pycharm
* Justin Seitz

## 声明
本项目仅供学习交流，任何由此产生的法律纠纷均与本人无关。