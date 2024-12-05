由shadowsocks-libev魔改而来，属于删减版

- 仅支持rc4-md5加密，用于简单地转发tunnel过墙
- 移除了libcork/libbloom/libsodium/mbedtls等库的依赖，方便部署在路由器上

除了ss-libev以外，还用到的第三方库

- [md5-c](https://github.com/Zunawe/md5-c)
- [rc4](https://github.com/ogay/rc4)
