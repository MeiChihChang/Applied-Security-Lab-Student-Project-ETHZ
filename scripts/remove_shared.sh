# WINDOWS SCRIPT change VBoxManage.exe for vboxmanage in Linux

# comment this is VManage.exe is in the path 
cd 'C:\Program Files\Oracle\VirtualBox\'

VBoxManage.exe list vms | tac

for vm in `VBoxManage.exe list vms | tac`;
do
    for i in $(echo $vm | tr " " "\n")
    do
        if [[ $i == *"host"* || $i == *"firewall"* || $i == *"client"* || $i == *"admin"* ]]; then
            printf "Halting $vm\n"
            VBoxManage.exe controlvm "$i" acpipowerbutton 2> /dev/null

            printf "Removing vagrant $vm\n"
            VBoxManage.exe sharedfolder remove "$i" --name vagrant 2> /dev/null
        fi
        
    done
	
done

$SHELL