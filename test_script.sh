echo " "

rm temp*
rm output*

echo "Functionality demo"

echo "Encrypting file"
./xhw3 -j 1 -k 1 -e -p "Thisismypassphrase" input.txt temp1 > output1 2>&1
echo "Deccrypting the file"
./xhw3 -j 1 -k 1 -d -p "Thisismypassphrase" temp1 plain > output1 2>&1

echo "Calculating diff"
diff input.txt plain

sleep 4 

echo "Consumer Threads - 2 and Queue Size 4"
echo "Enqueuing 8 jobs. Each job takes approximately 8 seconds to complete"
echo "Last two producers will be throttled"
echo " "

echo "Running job 1"
./xhw3 -j 1 -k 1 -e -p "Thisismypassphrase" input.txt temp1 > output1 2>&1 &
sleep 1
echo "listing enqued jobs"
./xhw3 -j 4
echo " "
echo " "
echo "Running job 2"
./xhw3 -j 1 -k 1 -e -p "Thisismypassphrase" input.txt temp2 > output2 2>&1 &
sleep 1
echo "listing enqued jobs"
./xhw3 -j 4
echo " "
echo " "

echo "Running job 3"
./xhw3 -j 1 -k 1 -e -p "Thisismypassphrase" input.txt temp3 > output3 2>&1 &
sleep 1
echo "listing enqued jobs"
./xhw3 -j 4
echo " "
echo " "

echo "Running job 4"
./xhw3 -j 1 -k 1 -e -p "Thisismypassphrase" input.txt temp4 > output4 2>&1 &
sleep 1
echo "listing enqued jobs"
./xhw3 -j 4
echo " "
echo " "

echo "Running job 5"
./xhw3 -j 1 -k 1 -e -p "Thisismypassphrase" input.txt temp5 > output5 2>&1 &
sleep 1
echo "listing enqued jobs"
./xhw3 -j 4
echo " "
echo " "

echo "Running job 6"
./xhw3 -j 1 -k 1 -e -p "Thisismypassphrase" input.txt temp6 > output6 2>&1 &
sleep 1
echo "listing enqued jobs"
./xhw3 -j 4
echo " "
echo " "

echo "Running job 7"
./xhw3 -j 1 -k 1 -e -p "Thisismypassphrase" input.txt temp7 > output7 2>&1 &
sleep 1
echo "listing enqued jobs"
./xhw3 -j 4
echo " "
echo " "

echo "Running job 8"
./xhw3 -j 1 -k 1 -e -p "Thisismypassphrase" input.txt temp8 > output8 2>&1 &
sleep 1
echo "listing enqued jobs"
./xhw3 -j 4
echo " "
echo " "

sleep 2
