# Dockerfile for building usdex binaries.

Now, you can build your own usdex files on all systems with docker and do it easy without installing depends on your system.

## How:

### Build docker image

```
sudo docker build .
```

### Run docker container

Builder will return HASH of image
Example:
Successfully built 9bbff825d50f

```
sudo docker run -it -v ~/path/to/usdex/folder:/usdex 9bbff825d50f
```

If your system uses SELINUX you may use --privileged=true key

```
sudo docker run --privileged=true -it -v ~/development/usdex:/usdex 9bbff825d50f
```

See usdex-qt file in used usdex folder and usdexd file in src subfolder.