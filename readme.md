# Final project of linux2022q1
modify from quiz6's user-level thread

## compile
first `cd` into one of three version that you wanna compile.
then:
```shell
gcc -O3 -g -o server `$SERVER`.c include/http_parser.c
```
where `$SERVER` is one of [m2n_server one2one_server webserver]