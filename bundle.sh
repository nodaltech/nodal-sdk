#!/bin/bash

if [ -e ./nsdk.py ];
then
    rm nsdk.py
fi

touch nsdk.py

for i in `ls nodal_sdk | grep "\.py"`;
do
    echo >> nsdk.py
    echo >> nsdk.py
    echo "# FROM nodal_sdk/$i:" >> nsdk.py
    cat nodal_sdk/$i >> nsdk.py
done

echo "Bundle finished!"