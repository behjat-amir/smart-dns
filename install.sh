#!/bin/bash

#colors
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
rest='\033[0m'
myip=$(hostname -I | awk '{print $1}')

# Function to detect Linux distribution
detect_distribution() {
    local supported_distributions=("ubuntu" "debian" "centos" "fedora")
    
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        if [[ "${ID}" = "ubuntu" || "${ID}" = "debian" || "${ID}" = "centos" || "${ID}" = "fedora" ]]; then
            pm="apt"
            [ "${ID}" = "centos" ] && pm="yum"
            [ "${ID}" = "fedora" ] && pm="dnf"
        else
            echo "Unsupported distribution!"
            exit 1
        fi
    else
        echo "Unsupported distribution!"
        exit 1
    fi
}

# Open required ports for smartSNI (53 DNS, 80 HTTP, 443 SNI, 853 DoT, 8443 DoH/nginx)
open_firewall_ports() {
    echo -e "${yellow}Checking firewall...${rest}"
    # UFW (Ubuntu/Debian)
    if command -v ufw &> /dev/null; then
        if ufw status 2>/dev/null | grep -q "active"; then
            echo -e "${yellow}UFW is active. Opening smartSNI ports (53, 80, 443, 853, 8443).${rest}"
            ufw allow 53/udp 2>/dev/null
            ufw allow 53/tcp 2>/dev/null
            ufw allow 80/tcp 2>/dev/null
            ufw allow 443/tcp 2>/dev/null
            ufw allow 853/tcp 2>/dev/null
            ufw allow 8443/tcp 2>/dev/null
            ufw reload 2>/dev/null
            echo -e "${green}Ports opened in UFW.${rest}"
        else
            echo -e "${green}UFW is not active.${rest}"
        fi
        return
    fi
    # firewalld (CentOS/Fedora/RHEL)
    if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        echo -e "${yellow}firewalld is active. Opening smartSNI ports (53, 80, 443, 853, 8443).${rest}"
        firewall-cmd --permanent --add-port=53/udp 2>/dev/null
        firewall-cmd --permanent --add-port=53/tcp 2>/dev/null
        firewall-cmd --permanent --add-port=80/tcp 2>/dev/null
        firewall-cmd --permanent --add-port=443/tcp 2>/dev/null
        firewall-cmd --permanent --add-port=853/tcp 2>/dev/null
        firewall-cmd --permanent --add-port=8443/tcp 2>/dev/null
        firewall-cmd --reload 2>/dev/null
        echo -e "${green}Ports opened in firewalld.${rest}"
        return
    fi
    # iptables: add rules if iptables is in use (no -F, just append)
    if command -v iptables &> /dev/null; then
        echo -e "${yellow}Adding iptables rules for smartSNI ports.${rest}"
        for port in 53 80 443 853 8443; do
            iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
            [ "$port" = "53" ] && ( iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null )
        done
        echo -e "${green}iptables rules added (53/udp, 53/tcp, 80, 443, 853, 8443).${rest}"
        return
    fi
    echo -e "${green}No firewall (ufw/firewalld/iptables) detected.${rest}"
}

# Free port 53 if systemd-resolved (or similar) is using it
ensure_port_53_available() {
    if ! ss -ulnp 2>/dev/null | grep -q ':53 ' && ! ss -tlnp 2>/dev/null | grep -q ':53 '; then
        return 0
    fi
    echo -e "${yellow}Port 53 is in use. Checking systemd-resolved...${rest}"
    if [ ! -f /etc/systemd/resolved.conf ]; then
        echo -e "${yellow}Port 53 in use but no /etc/systemd/resolved.conf. Stop the process using port 53 manually.${rest}"
        return 0
    fi
    if grep -q '^DNSStubListener=no' /etc/systemd/resolved.conf 2>/dev/null; then
        echo -e "${green}DNSStubListener already disabled.${rest}"
        return 0
    fi
    echo -e "${yellow}Disabling DNS stub listener so smartSNI can use port 53.${rest}"
    sed -i 's/^#*DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
    if ! grep -q '^DNSStubListener=' /etc/systemd/resolved.conf; then
        echo 'DNSStubListener=no' >> /etc/systemd/resolved.conf
    fi
    systemctl restart systemd-resolved 2>/dev/null || true
    sleep 1
    echo -e "${green}Port 53 should now be free.${rest}"
}

# Install necessary packages
install_dependencies() {
    detect_distribution
    $pm update -y
    local packages=("nginx" "git" "jq" "certbot" "python3-certbot-nginx" "wget" "tar")
    
    for package in "${packages[@]}"; do
        if ! dpkg -s "$package" &> /dev/null; then
            echo -e "${yellow}$package is not installed. Installing...${rest}"
            $pm install -y "$package"
        else
            echo -e "${green}$package is already installed.${rest}"
        fi
    done
    
    if ! command -v go &> /dev/null; then
        install_go
    else
        echo -e "${green}go is already installed.${rest}"
    fi
    setup_go_env
}

# Install Go
install_go() {
    echo -e "${yellow}go is not installed. Installing...${rest}"
    
    ARCH=$(dpkg --print-architecture)
    
    if [[ $ARCH == "amd64" || $ARCH == "arm64" ]]; then
        wget https://go.dev/dl/go1.21.1.linux-"$ARCH".tar.gz
        rm -rf /usr/local/go && rm -f /usr/local/bin/go && tar -C /usr/local -xzf go1.21.1.linux-"$ARCH".tar.gz
        export GOROOT=/usr/local/go
        export PATH=$GOROOT/bin:$PATH
        ln -sf /usr/local/go/bin/go /usr/local/bin/go 2>/dev/null || true
        
        rm -f go1.21.1.linux-"$ARCH".tar.gz
        rm -rf /root/go
        echo -e "${cyan}Go has been installed.${rest}"
    else
        echo -e "${red}Unsupported architecture: $ARCH${rest}"
        exit 1
    fi
}

# Ensure Go env is set (GOROOT/PATH) so "go" works even if only binary was copied
setup_go_env() {
    if [ -d /usr/local/go ]; then
        export GOROOT=/usr/local/go
        export PATH=$GOROOT/bin:$PATH
    fi
    if ! command -v go &> /dev/null; then
        echo -e "${red}Go not found. Install Go first.${rest}"
        exit 1
    fi
}

# install SNI service
install() {
    if systemctl is-active --quiet sni.service; then
        echo -e "${yellow}********************${rest}"
        echo -e "${green}Service is already installed and active.${rest}"
        echo -e "${yellow}********************${rest}"
    else
        install_dependencies
        open_firewall_ports
        git clone https://github.com/behjat-amir/smart-dns.git /root/smartSNI
         
        sleep 1
        setup_go_env
        cd /root/smartSNI || exit 1
        echo -e "${yellow}Downloading Go modules and building...${rest}"
        go mod download && go mod tidy && go build -o smartSNI .
        if [ $? -ne 0 ]; then
            echo -e "${red}Build failed. Check errors above.${rest}"
            exit 1
        fi
        echo -e "${green}Build successful.${rest}"
        cd - > /dev/null || true

        sleep 1
        clear
        echo -e "${yellow}********************${rest}"
        read -p "Enter your domain: " domain
        echo -e "${yellow}********************${rest}"
        read -p "Enter Website names (separated by commas)[example: intel.com,youtube]: " site_list
        echo -e "${yellow}********************${rest}"
        # Split the input into an array
        IFS=',' read -ra sites <<< "$site_list"
        
        # Prepare a string with the new domains
        new_domains="{"
        for ((i = 0; i < ${#sites[@]}; i++)); do
            new_domains+="\"${sites[i]}\": \"$myip\""
            if [ $i -lt $((${#sites[@]}-1)) ]; then
                new_domains+=", "
            fi
        done
        new_domains+="}"
        
        # Create a JSON Object with host and domains
        json_content="{ \"host\": \"$domain\", \"domains\": $new_domains }"
        
        # Save JSON to config.json file
        echo "$json_content" | jq '.' > /root/smartSNI/config.json

        nginx_conf="/etc/nginx/sites-enabled/default"
        sed -i "s/server_name _;/server_name $domain;/g" "$nginx_conf"
        sed -i "s/<YOUR_HOST>/$domain/g" /root/smartSNI/nginx.conf

        # Obtain SSL certificates
        certbot --nginx -d $domain --register-unsafely-without-email --non-interactive --agree-tos --redirect

        sudo cp /root/smartSNI/nginx.conf "$nginx_conf"
        systemctl stop nginx
        systemctl restart nginx

        config_file="/root/smartSNI/config.json"

        sed -i "s/<YOUR_HOST>/$domain/g" "$config_file"
        sed -i "s/<YOUR_IP>/$myip/g" "$config_file"
        
        # Create systemd service file (runs compiled binary, no Go needed at runtime)
        cat > /etc/systemd/system/sni.service <<EOL
[Unit]
Description=Smart SNI Service

[Service]
User=root
WorkingDirectory=/root/smartSNI
ExecStart=/root/smartSNI/smartSNI
Restart=always

[Install]
WantedBy=default.target
EOL

        # Free port 53 if systemd-resolved (or similar) is using it
        ensure_port_53_available

        # Reload systemd, enable and start the service
        systemctl daemon-reload
        systemctl enable sni.service
        systemctl start sni.service

        # Check if the service is active
        if systemctl is-active --quiet sni.service; then
            echo -e "${yellow}_______________________________________${rest}"
            echo -e "${green}Service Installed Successfully and activated.${rest}"
            echo -e "${yellow}_______________________________________${rest}"
            echo ""
            echo -e "${cyan}DOH --> https://$domain/dns-query${rest}"
            echo -e "${yellow}_______________________________________${rest}"
        else
            echo -e "${yellow}____________________________${rest}"
            echo -e "${red}Service is not active.${rest}"
            echo -e "${yellow}____________________________${rest}"
        fi
    fi
}

# Uninstall function
uninstall() {
    if [ ! -f "/etc/systemd/system/sni.service" ]; then
        echo -e "${yellow}____________________________${rest}"
        echo -e "${red}The service is not installed.${rest}"
        echo -e "${yellow}____________________________${rest}"
        return
    fi
    # Stop and disable the service
    sudo systemctl stop sni.service
    sudo systemctl disable sni.service 2>/dev/null

    # Remove service file
    sudo rm /etc/systemd/system/sni.service
    rm -rf /root/smartSNI
    rm -rf /root/go
    echo -e "${yellow}____________________________________${rest}"
    echo -e "${green}Uninstallation completed successfully.${rest}"
    echo -e "${yellow}____________________________________${rest}"
}

# Show Websites
display_sites() {
    config_file="/root/smartSNI/config.json"

    if [ -d "/root/smartSNI" ]; then
        echo -e "${yellow}****${cyan} [Websites] ${yellow}****${rest}"
        # Initialize a counter
        counter=1
        # Loop through the domains and display with numbering
        jq -r '.domains | keys_unsorted | .[]' "$config_file" | while read -r domain; do
            echo "$counter) $domain"
            ((counter++))
        done
        echo ""
        echo -e "${yellow}********************${rest}"
    else
        echo -e "${yellow}********************${rest}"
        echo -e "${red}Not installed. Please Install first.${rest}"
    fi
}

# Check service
check() {
    if systemctl is-active --quiet sni.service; then
        echo -e "${cyan}[Service Actived]${rest}"
    else
        echo -e "${yellow}[Service Not Active]${rest}"
    fi
}

# Fix port 53 in use (e.g. systemd-resolved) and restart sni
fix_port_53_and_restart() {
    if [ ! -f "/etc/systemd/system/sni.service" ]; then
        echo -e "${red}smartSNI is not installed. Install first.${rest}"
        return
    fi
    echo -e "${yellow}Freeing port 53 and restarting sni.service...${rest}"
    ensure_port_53_available
    systemctl restart sni.service
    sleep 1
    if systemctl is-active --quiet sni.service; then
        echo -e "${green}sni.service is now running.${rest}"
    else
        echo -e "${red}sni.service still not active. Check: journalctl -u sni.service -n 30${rest}"
    fi
}

# Add sites
add_sites() {
    config_file="/root/smartSNI/config.json"

    if [ -d "/root/smartSNI" ]; then
        echo -e "${yellow}********************${rest}"
        read -p "Enter additional Websites (separated by commas):" additional_sites
        IFS=',' read -ra new_sites <<< "$additional_sites"

        current_domains=$(jq -r '.domains | keys_unsorted | .[]' "$config_file")
        for site in "${new_sites[@]}"; do
            if [[ ! " ${current_domains[@]} " =~ " $site " ]]; then
                jq ".domains += {\"$site\": \"$myip\"}" "$config_file" > temp_config.json
                mv temp_config.json "$config_file"
                echo -e "${yellow}********************${rest}"
                echo -e "${green}Domain ${cyan}'$site'${green} added successfully.${rest}"
            else
                echo -e "${yellow}Domain ${cyan}'$site' already exists.${rest}"
            fi
        done

        # Restart the service
        systemctl restart sni.service
    else
        echo -e "${yellow}********************${rest}"
        echo -e "${red}Not installed. Please Install first.${rest}"
    fi
}

# Remove sites
remove_sites() {
    config_file="/root/smartSNI/config.json"

    if [ -d "/root/smartSNI" ]; then
        # Display available sites
        display_sites
        
        read -p "Enter Websites names to remove (separated by commas): " domains_to_remove
        IFS=',' read -ra selected_domains <<< "$domains_to_remove"

        # Remove selected domains from JSON
        for selected_domain in "${selected_domains[@]}"; do
            if jq -e --arg selected_domain "$selected_domain" '.domains | has($selected_domain)' "$config_file" > /dev/null; then
                jq "del(.domains[\"$selected_domain\"])" "$config_file" > temp_config.json
                mv temp_config.json "$config_file"
                echo -e "${yellow}********************${rest}"
                echo -e "${green}Domain ${cyan}'$selected_domain'${green} removed successfully.${rest}"
            else
                echo -e "${yellow}********************${rest}"
                echo -e "${yellow}Domain ${cyan}'$selected_domain'${yellow} not found.${rest}"
            fi
        done

        # Restart the service
        systemctl restart sni.service
    else
        echo -e "${yellow}********************${rest}"
        echo -e "${red}Not installed. Please Install first.${rest}"
    fi
}

clear
echo -e "${cyan}By --> Peyman * Github.com/amir * ${rest}"
echo ""
check
echo -e "${purple}*******************${rest}"
echo -e "${purple}* ${green}SMART SNI PROXY${purple} *${rest}"
echo -e "${purple}*******************${rest}"
echo -e "${yellow}1] ${green}Install${rest}        ${purple}*"
echo -e "${purple}                  * "
echo -e "${yellow}2] ${green}Uninstall${rest}      ${purple}*"
echo -e "${purple}                  * "
echo -e "${yellow}3] ${green}Show Websites ${rest} ${purple}*"
echo -e "${purple}                  * "
echo -e "${yellow}4] ${green}Add Sites${rest}      ${purple}*"
echo -e "${purple}                  * "
echo -e "${yellow}5] ${green}Remove Sites${rest}   ${purple}*"
echo -e "${purple}                  * "
echo -e "${yellow}6] ${green}Fix port 53 & restart${rest} ${purple}*"
echo -e "${purple}                  * "
echo -e "${red}0${yellow}] ${purple}Exit${rest}${purple}           *"
echo -e "${purple}*******************${rest}"
read -p "Enter your choice: " choice
case "$choice" in
    1)
        install
        ;;
    2)
        uninstall
        ;;
    3) 
        display_sites
        ;;
    4) 
        add_sites
        ;;
    5)
        remove_sites
        ;;
    6)
        fix_port_53_and_restart
        ;;
    0)
        echo -e "${cyan}By 🖐${rest}"
        exit
        ;;
    *)
        echo -e "${yellow}********************${rest}"
        echo "Invalid choice. Please select a valid option."
        ;;
esac
