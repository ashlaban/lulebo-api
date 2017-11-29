LuleboApi
=========

Catch phrase.

Summary
-------

To be defined.

Basic browser usage
-------------------

To be defined.

Basic terminal usage
--------------------

Sign up by
```
to come
```

Login by
```
wget -qO- http://localhost:8081/login               \
--save-cookies c.txt                                \
--post-data '{"username":"kim", "password":"pass"}' \
--header="Content-Type: application/json"           \
--keep-session-cookie
```
or
```
wget -S -qO- http://kim:pass@localhost:8081/login \
--save-cookies c.txt                              \
--keep-session-cookie
```
Test this resource with
```
wget -qO- --load-cookies c.txt http://localhost:8081/u
```
or
```
wget -S -qO- http://kim:pass@localhost:8081/login \
http://localhost:8081/u
```

Testing with curl
```
curl -c '' '{kim:pass@localhost:8081/login,localhost:8081/u}'
```