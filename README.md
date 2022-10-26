This is the source code for the device authentication server, including an admin panel. Documentation is available [here](https://github.com/kinnay/nintendoclients/wiki/DAuth-Server).

Before building the service, you must place `prod.keys` and `dev.keys` into `dauth/resources` (create this folder if it does not exist). These can be dumped with [Lockpick_RCM](https://github.com/shchmue/Lockpick_RCM).

Example configuration for localhost:
```
COMPOSE_PROJECT_NAME: 
DAUTH_ISS: dauth-localhost
DAUTH_JKU: http://localhost:10001/keys
DAUTH_PORT: 10000
DCERT_PORT: 10001
DADMIN_PORT: 10002
DADMIN_USERNAME: test
DADMIN_PASSWORD: test
DEVICE_TYPE: NX Prod 1
```

The playground server assumes that device certificates are verified by a reverse proxy. It expects that the reverse proxy provides the device certificate in PEM format in the `X-Device-Certificate` header. For local testing, where no reverse proxy is used, the `X-Device-Certificate` header can be used directly.

The playground server is not compatible with device certificates that are dumped from real consoles. Instead, device certificates can be generated on the admin panel. The reason is that the device certificate contains encrypted data in the subject alternative name, which is probably where the serial number and device id are stored. Because I have no idea what format and encryption algorithm are used by Nintendo, the playground server uses a custom encoding here.
