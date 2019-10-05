# curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
# add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
# apt-get update
# apt-get install -y docker-ce

#docker build --no-cache -t electrum-xrc-appimage-builder-img contrib/build-linux/appimage
docker run -it \
    --name electrum-xrc-appimage-builder-cont \
    -v $PWD:/opt/electrum-xrc \
    --rm \
    --workdir /opt/electrum-xrc/contrib/build-linux/appimage \
    electrum-xrc-appimage-builder-img \
    ./build.sh
