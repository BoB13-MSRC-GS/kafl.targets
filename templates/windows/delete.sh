sudo virsh snapshot-delete --domain windows_x86_64_vagrant-kafl-windows extra
sudo virsh snapshot-delete --domain windows_x86_64_vagrant-kafl-windows ready_provision
sudo virsh destroy windows_x86_64_vagrant-kafl-windows
sudo virsh undefine windows_x86_64_vagrant-kafl-windows

cd ~/kAFL/kafl/examples/windows_x86_64
sudo vagrant destroy

cd ../templates/windows/
sudo make import

cd ~