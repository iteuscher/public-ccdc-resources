## sudo bash install_unsecure_lamp.sh
#!/bin/bash

echo "Starting UNSECURE LAMP installation..."
sleep 2

# Update system
echo "[*] Updating system..."
sudo apt update && sudo apt upgrade -y

# Install Apache (no firewall, no security modules)
echo "[*] Installing Apache..."
sudo apt install apache2 -y
sudo systemctl enable --now apache2

# Install MySQL (No password for root)
echo "[*] Installing MySQL..."
sudo apt install mysql-server -y
sudo systemctl enable --now mysql

echo "[*] Creating unsecure MySQL user with full privileges..."
sudo mysql -e "CREATE USER 'hacker'@'%' IDENTIFIED BY 'password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%' WITH GRANT OPTION;"
sudo mysql -e "FLUSH PRIVILEGES;"

# Install PHP (No security settings)
echo "[*] Installing PHP..."
sudo apt install php libapache2-mod-php php-mysql -y

# Set Apache to execute PHP before HTML (default, no hardening)
echo "[*] Configuring Apache for PHP..."
sudo sed -i 's/index.html/index.php index.html/g' /etc/apache2/mods-enabled/dir.conf
sudo systemctl restart apache2

# Download an example website (Unsecured)
echo "[*] Downloading example website..."
sudo apt install wget unzip -y
cd /var/www/html
sudo wget -O website.zip "https://www.tooplate.com/zip-templates/2127_barista.zip"
sudo unzip website.zip
sudo mv 2127_barista/* .
sudo rm -r 2127_barista website.zip

# Set 777 permissions (No security!)
echo "[*] Setting 777 permissions on web root..."
sudo chmod -R 777 /var/www/html
sudo chown -R www-data:www-data /var/www/html

# Disable Apache security mods (if any)
echo "[*] Disabling Apache security settings..."
sudo a2dismod security2 headers

# Restart services
echo "[*] Restarting Apache & MySQL..."
sudo systemctl restart apache2
sudo systemctl restart mysql

echo "🚨 LAMP Stack Installed UNSECURELY! 🚨"
echo "❌ No root password for MySQL"
echo "❌ MySQL user 'hacker' has full privileges"
echo "❌ Apache has open permissions"
echo "❌ No firewall rules"
echo "✔ Now, practice hardening it!"
