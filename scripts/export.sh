# WINDOWS SCRIPT change VBoxManage.exe for vboxmanage in Linux

# comment this is VManage.exe is in the path 
cd 'C:\Program Files\Oracle\VirtualBox\'

VBoxManage.exe list vms | tac
echo "-"

for vm in `VBoxManage.exe list vms | tac`;
do
    for i in $(echo $vm | tr " " "\n")
    do
        if [[ $i == *"host"* || $i == *"firewall"* || $i == *"client"* || $i == *"admin"* ]]; then
            echo $i
            #printf "Halting $vm\n"
            #VBoxManage.exe controlvm "$i" acpipowerbutton 2> /dev/null

            #printf "Exporting $vm\n"
            #VBoxManage.exe export "$i" -o "./build/$i.ova"
        fi
        
    done
	
done

$SHELL