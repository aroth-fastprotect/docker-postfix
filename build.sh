#!/bin/bash -x
script_file=`readlink -f "$0"`
script_dir=`dirname "$script_file"`
script_docker_image_name=`basename "$script_dir"`
tag='latest'
docker_user='rothan'
got_tag=0
build_ldap=0

function usage() {
    set +x
	echo "Usage: $script_file [OPTIONS] [TAG]"
	echo "OPTIONS:"
	echo "    -h, --help            shows this help"
	echo "    -v, --verbose         enable verbose output"
	echo ""
	echo "  TAG        name of the docker image tag (default $tag)"
	echo ""
	echo "Builds the docker image: $script_docker_image_name, tag $tag"
	exit 0
}

# parse command line arguments
while [ $# -ne 0 ]; do
	case "$1" in
	'-?'|'-h'|'--help') usage;;
	'-v'|'--verbose') verbose=1; ;;
	-*)
		echo "Unrecognized option $1" >&2
		exit 1
		;;
	*)
        if [ $got_tag -eq 0 ]; then
            tag="$1"
            got_tag=1
        else
			echo "Docker image tag $tag already specified." >&2
			exit 1
		fi
		;;
	esac
	shift
done

echo "Builds the docker image: $script_docker_image_name, tag $tag"

full_image_name="${script_docker_image_name}:${tag}"
docker build --tag "$full_image_name" -f "$script_dir/Dockerfile" "$script_dir"

docker tag "$full_image_name" "$docker_user/$full_image_name"
docker push "$docker_user/$full_image_name"
