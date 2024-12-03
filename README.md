由shadowsocks-libev魔改而来

- 仅支持xor加密，用于简单地转发tunnel过墙
- 移除了libcork/libbloom/libsodium/mbedtls等库的依赖，方便部署在路由器上
- 需要配合[修改版的ss-server](https://github.com/lixingcong/shadowsocks-libev-patches)使用
