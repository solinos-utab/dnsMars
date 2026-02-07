ping 8.8.8.8
ip a
systemctl status ssh
sudo ufw status
sudo ufw allow ssh
sudo ufw reload
sudo ufw status
sudo ufw allow 22/tcp
ip a
ls /etc/netplan/
sudo nano /etc/netplan/00-installer-config.yaml
sudo netplan apply
sudo reboot
