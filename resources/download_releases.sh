#!/bin/bash

# For release 4 to 84
for release in {4..84}
do
	echo "Downloading release ${release}"
	if [ $release -lt 41 ]
	then
		# Download the source code
		wget "https://ftp.mozilla.org/pub/firefox/releases/${release}.0/source/firefox-${release}.0.source.tar.bz2"
		# Extract the files
		mkdir datasets/release_${release}/
		tar -xvjf firefox-${release}.0.source.tar.bz2 -C datasets/release_${release}/
		# Cleanup
		rm firefox-${release}.0.source.tar.bz2
		mv datasets/release_${release}/*/* datasets/release_${release}/
	else
		# Download the source code
		wget "https://ftp.mozilla.org/pub/firefox/releases/${release}.0/source/firefox-${release}.0.source.tar.xz"
		# Extract the files
		mkdir datasets/release_${release}/
		tar -xvzf firefox-${release}.0.source.tar.xz -C datasets/release_${release}/
		# Cleanup
		rm firefox-${release}.0.source.tar.xz
		mv datasets/release_${release}/*/* datasets/release_${release}/
	fi

	# Remove all non-C/C++ files
	find datasets/release_${release}/ -type f ! -name "*.c" ! -name "*.cpp" -exec rm {} \;
done
