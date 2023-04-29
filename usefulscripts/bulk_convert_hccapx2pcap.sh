#!/bin/bash
# Useful for transient from m16800 to m22000

# Verify that argument 1 and 2 are passed
if [ $# -lt 2 ]; then
  echo "Error: Please provide two arguments: source folder with hccapx files and destination folder for pcap files."
  exit 1
fi

# Verify that argument 1 and 2 are existing folders
if [ ! -d "$1" ]; then
  echo "Error: $1 is not an existing folder."
  exit 1
fi

if [ ! -d "$2" ]; then
  echo "Error: $2 is not an existing folder."
  exit 1
fi

# Verify that the second folder is writable
if [ ! -w "$2" ]; then
  echo "Error: $2 is not writable."
  exit 1
fi

# Iterate over the files with extension .hccapx in folder 1
for file in `ls "$1"/*.hccapx`;do
  echo "Processing file: $file"
  new_filename="$(basename "$file" .hccapx).cap"
  hcxhash2cap --hccapx="$file" -c "$2/$new_filename"
done

