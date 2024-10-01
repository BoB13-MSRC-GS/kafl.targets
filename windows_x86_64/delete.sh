sudo virsh snapshot-delete --domain kafl_windows extra
sudo virsh snapshot-delete --domain kafl_windows ready_provision
sudo virsh destroy kafl_windows
sudo virsh undefine kafl_windows

cd ~/kAFL/kafl/examples/windows_x86_64
sudo vagrant destroy

cd ../templates/windows/
sudo make import

cd ~
