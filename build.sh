container=$(buildah from golang:latest)

buildah config --workingdir /usr/src/app $container
buildah copy $container go.mod go.sum ./
buildah run $container -- go mod download
buildah copy $container . .
buildah run $container -- go build -v -o /usr/local/bin/starlink-exporter ./...

buildah config --entrypoint "/usr/local/bin/starlink-exporter" $container
buildah config --author "Nathan Benner nathan.benner2@nutrien.com" --label name=starlink-exporter $container

buildah commit $container starlink-exporter