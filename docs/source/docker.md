# Docker install


- Clone the repository
- Install docker image 

<!-- With the user UID, `wpwatcher` will then run as this user. The following will use the current logged user UID. Won't work if you build the image as root.
```bash
docker image build \
    --build-arg USER_ID=$(id -u ${USER}) \
    -t wpwatcher .
```
- Create and map a WPWatcher folder containing your `wpwatcher.conf` file to the docker runner.
`wpwatcher` command would look like :  
```bash
docker run -it -v '/path/to/wpwatcher.conf/folder/:/wpwatcher/.wpwatcher/' wpwatcher [...]
``` -->

```bash
docker image build -t wpwatcher .
```

- `wpwatcher` command would look like :  
```
docker run -it -v 'wpwatcher_data:/wpwatcher/.wpwatcher/' wpwatcher
```

It will use [docker volumes](https://stackoverflow.com/questions/18496940/how-to-deal-with-persistent-storage-e-g-databases-in-docker?answertab=votes#tab-top) in order to write files and save reports

- Create config file: As root, check `docker volume inspect wpwatcher_data` to see Mountpoint, then create the config file
```bash
docker run -it wpwatcher --template_conf > /var/lib/docker/volumes/wpwatcher_data/_data/wpwatcher.conf
vim /var/lib/docker/volumes/wpwatcher_data/_data/wpwatcher.conf
```

- Create an alias and your good to go
```
alias wpwatcher="docker run -it -v 'wpwatcher_data:/wpwatcher/.wpwatcher/' wpwatcher"
```
