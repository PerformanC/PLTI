#!/system/bin/sh
# count.sh <runs> [unlink] [unhook] -- runs target that many times and prints "<survivors>/<runs> survived"
n=$1
shift
s=0
i=0
unlink=0
mkdir -p unlink
if [ "$1" = unlink ]; then
  unlink=1
  shift
fi
while [ "$i" -lt "$n" ]; do
  # Every run needs its own copy of the library, as the run deletes it.
  if [ "$unlink" = 1 ]; then
    cp libvictim.so unlink/libvictim.so
    VICTIM="$PWD/unlink/libvictim.so" PLTI_GOT_RACE_UNLINK=1 ./target "$@" > /dev/null 2>&1 && s=$((s + 1))
  else
    ./target "$@" > /dev/null 2>&1 && s=$((s + 1))
  fi
  i=$((i + 1))
done
echo "$s/$n survived"
