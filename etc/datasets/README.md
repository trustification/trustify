# Datasets

## DS1

The original.

Create it:

```shell
rm ds1.zip
pushd ds1
zip -r ../ds1.zip .
popd
```

## DS2

An OSV based example for generating dumps. Used in combination with `cargo xtask generate-dump`

## DS3

A variant of DS1, including the corresponding CVE files.

```shell
rm ds3.zip
pushd ds3
zip -r ../ds3.zip .
popd
```
