# godaddy-ddns

Another version of [godaddy-ddns](https://github.com/CarlEdman/godaddy-ddns) supports wildcard DNS records and a list of URLs to get the public IP address.

You can get the GoDaddy API key from [https://developer.godaddy.com/keys/](https://developer.godaddy.com/keys/).

```bash
# Python 3 only!!!
python godaddy-ddns.py --domain *.example.com --ip-resolvers https://checkip.amazonaws.com/ --api-key KEY:SECRET

python godaddy-ddns.py --domain *.example.com --ip 123.123.123.123 --api-key KEY:SECRET
```
