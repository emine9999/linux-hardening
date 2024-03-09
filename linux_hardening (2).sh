#!/bin/bash
#https://www.linkedin.com/in/amine-elhasbi-a8273b226/
# Linux Hardening Script
 
figlet "LinuxHard"
echo "By Amine Elhasbi ©ENSA marrakech GCDSTE"


# Ensure script is executed as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root please try again. Exiting..."
    exit 1
fi
# Update system and install necessary packages
apt-get update
apt-get upgrade -y

# Backup sysctl.conf
cp /etc/sysctl.conf /etc/sysctl.conf.backup


echo "Let's apply configuration changes to improve system security."
echo "1) kernel Recommended configuration"
changes=(
    "kernel.dmesg_restrict=1  # Restrict access to the dmesg buffer (equivalent to CONFIG_SECURITY_DMESG_RESTRICT=y)"
    "kernel.kptr_restrict=2  # Hide kernel addresses in /proc and various other interfaces, including from privileged users"
    "kernel.pid_max=65536  # Explicitly specify the process id space supported by the kernel, 65536 being an example value"
    "kernel.perf_cpu_time_max_percent=1  # Restrict the use of the perf subsystem"
    "kernel.perf_event_max_sample_rate=1  # Prohibit unprivileged access to the perf_event_open() system call. With a value greater than 2, we impose the possession of CAP_SYS_ADMIN, in order to collect the perf events."
    "kernel.randomize_va_space=2  # Activate Address Space Layout Randomization (ASLR)"
    "kernel.sysrq=0  # Disable Magic System Request Key combinations"
    "kernel.unprivileged_bpf_disabled=1  # Restrict kernel BPF usage to privileged users"
    "kernel.panic_on_oops=1  # Completely shut down the system if the Linux kernel behaves unexpectedly"
    "sysctl kernel.modules_disabled=1 # Prevent dynamic loading of modules by any process "
    "sysctl kernel.randomize_va_space=2  # Prevent processes from making their heap executable "
)

for change in "${changes[@]}"; do
    explanation=$(echo "$change" | cut -d '#' -f2)
    echo -e "Change to apply:\n$explanation"
    echo "Do you want to apply this change? (yes/no)"
    read response

    case "$response" in
        "yes")
            parameter=$(echo "$change" | awk '{print $1}')
            echo "$parameter" >> /etc/sysctl.conf
            echo "Change applied successfully."
            ;;
        "no")
            echo "Change skipped."
            ;;
        *)
            echo "Invalid response. Change skipped."
            ;;
    esac
done
echo "Kernel configuration changes  completed."

echo "2) network Recommended configuration."
changes=(
    "net.ipv4.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0  # Disable source routing to prevent malicious route redirection."
    "net.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0  # Ignore ICMP redirects to prevent potential route manipulation attacks."
    "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1  # Recommended for better security. Disable IPv6 if not needed."
    "net.ipv4.icmp_echo_ignore_broadcasts = 1  # Ignore ICMP echo broadcasts for enhanced security."
    "net.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1  # Enable reverse path filtering to protect against IP spoofing."
    "net.ipv4.tcp_syncookies = 1  # Recommended for protection against SYN flood attacks. Enable TCP SYN cookies."
    "net.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0  # Disable sending ICMP redirects for security reasons."
    "net.ipv4.icmp_ignore_bogus_error_responses = 1  # Enable protection against sending responses to bad ICMP error messages."
    "net.ipv4.conf.all.log_martians = 1  # Log 'martian' packets, which are packets with impossible addresses."
    "net.ipv4.icmp_ignore_bogus_error_responses = 1  # Disable logging of bogus ICMP errors for a cleaner log."
    "kernel.sysrq = 0  # Disable the 'magic-sysrq' key combinations for improved security."
)

for change in "${changes[@]}"; do
    explanation=$(echo "$change" | cut -d '#' -f2)
    echo -e "\nChange to apply:\n$explanation"
    
    parameter=$(echo "$change" | awk '{print $1}' | awk -F'#' '{print $1}')
    
    recommended=$(echo "$explanation" | grep -i "Recommended")

    if [ -n "$recommended" ]; then
        echo -e "\nThis change is recommended for better security."
    fi

    echo "Do you want to apply this change? (yes/no)"
    read response

    case "$response" in
        "yes")
            echo "$parameter" >> /etc/sysctl.conf
            echo "Change applied successfully."
            ;;
        "no")
            echo "Change skipped."
            ;;
        *)
            echo "Invalid response. Change skipped."
            ;;
    esac
done

echo "Network configuration changes  completed."


echo "3) hardlink and symlinks  Recommended  configuration."

changes=(
    "fs.protected_hardlinks = 1  # Set a secure value for /proc/sys/fs/protected_hardlinks"
    "fs.protected_symlinks = 1  # Set a secure value for /proc/sys/fs/protected_symlinks"
    "fs.protected_fifos=2   # opening FIFOs and regular files that are not owned by the user in sticky folders for everyone to write" 
    "fs.protected_regular=2 #"
)

echo -e "You are about to configure the following system settings:\n"
for change in "${changes[@]}"; do
    explanation=$(echo "$change" | cut -d '#' -f2)
    echo -e "$explanation\n"
done

echo "Do you want to apply these changes? (yes/no)"
read response

case "$response" in
    "yes")
        # Apply changes
        cat <<EOL >> /etc/sysctl.conf
$change
EOL
        sysctl -p
        echo -e "\nChanges applied successfully."
        ;;
    "no")
        echo "Changes skipped."
        ;;
    *)
        echo "Invalid response. Changes skipped."
        ;;
esac

echo -e "\nAdditional file system hardening configurations will be applied:\n"

file_system_hardening=(
    "sudo chmod 440 /etc/sudoers  # Restrict access to the sudoers file (/etc/sudoers)"
    "sudo chmod 644 /etc/passwd  # Restrict access to the passwd file (/etc/passwd)"
    "sudo chmod 400 /etc/shadow  # Restrict access to the shadow file (/etc/shadow)"
    "sudo chown root:root /etc/sudoers /etc/passwd /etc/shadow  # Adjust ownership of sensitive files to root"
    "echo 'umask 0077' >> /etc/profile  # Set a new files' permissions to be unreadable by anyone other than the owner"
)

for hardening_change in "${file_system_hardening[@]}"; do
    explanation=$(echo "$hardening_change" | cut -d '#' -f2)
    echo -e "$explanation\n"
done

echo "Do you want to apply these additional changes? (yes/no)"
read response_hardening

case "$response_hardening" in
    "yes")
        # Apply additional changes
        for hardening_change in "${file_system_hardening[@]}"; do
            eval $hardening_change
        done
        echo -e "\nAdditional changes applied successfully."
        ;;
    "no")
        echo "Additional changes skipped."
        ;;
    *)
        echo "Invalid response. Additional changes skipped."
        ;;
esac

# PAM modules configurations
echo -e "4) \nPAM module configurations will be applied:\n"

pam_modules_changes=(
    "cp /etc/pam.d/common-password /etc/pam.d/common-password.bak  # Backup PAM configuration files"
    "cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak"
    "cp /etc/pam.d/common-account /etc/pam.d/common-account.bak"
    "cp /etc/pam.d/common-session /etc/pam.d/common-session.bak"
    "echo 'password required pam_pwquality.so retry=2 minlen=16 difok=6 dcredit=-3 ucredit=-2 lcredit=-2 ocredit=-3 enforce_for_root' >> /etc/pam.d/common-password  # Set strong password policies"
    "echo 'password required pam_unix.so use_authtok sha512 shadow' >> /etc/pam.d/common-password"
    "echo 'auth optional pam_faildelay.so delay=4000000' >> /etc/pam.d/common-auth  # Enforce delay after failed login attempt"
    "chage -m 5 -M 90 -w 3 <username>  # Set a user's password to expire in 90 days"
    "echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su  # Restricting su"
)

for pam_change in "${pam_modules_changes[@]}"; do
    explanation=$(echo "$pam_change" | cut -d '#' -f2)
    echo -e "$explanation\n"
done

echo "Do you want to apply these PAM module configurations? (yes/no)"
read response_pam

case "$response_pam" in
    "yes")
        # Apply PAM module configurations
        for pam_change in "${pam_modules_changes[@]}"; do
            eval $pam_change
        done
        echo -e "\nPAM module configurations applied successfully."
        ;;
    "no")
        echo "PAM module configurations skipped."
        ;;
    *)
        echo "Invalid response. PAM module configurations skipped."
        ;;
esac

echo "5) Configure GRUB for added security."

echo "Do you want to set a password for GRUB? (yes/no)"
read response_set_password

case "$response_set_password" in
    "yes")
        echo "Enter the GRUB password:"
        read -s grub_password

        # Generate the password hash using grub-mkpasswd-pbkdf2
        password_hash=$(grub-mkpasswd-pbkdf2 <<< "$grub_password")
        echo "Password hash generated."

        # Set the superuser and password in the GRUB configuration
        echo -e "set superusers=\"root\"\npassword_pbkdf2 root $password_hash" | sudo tee -a /etc/grub.d/40_custom > /dev/null
        echo "GRUB configuration updated."

        # Regenerate the GRUB configuration file
        sudo grub-mkconfig -o /boot/grub/grub.cfg
        echo "GRUB configuration regenerated."

        echo "GRUB is now password-protected. The password is set for the user 'root'."
        ;;
    "no")
        echo "GRUB password not set. Skipping GRUB configuration changes."
        ;;
    *)
        echo "Invalid response. Skipping GRUB configuration changes."
        ;;
esac

echo "6) This script will guide you through the process of enabling OTP-based authentication."

if ! command -v google-authenticator &> /dev/null; then
    echo "Installing libpam-google-authenticator..."
    sudo apt-get install -y libpam-google-authenticator
fi

echo "Do you want to enable OTP-based authentication for your user? (yes/no)"
read response_enable_otp

case "$response_enable_otp" in
    "yes")
        echo "Configuring PAM for OTP..."
        echo "auth required pam_google_authenticator.so" | sudo tee -a /etc/pam.d/common-auth > /dev/null

        # Guide the user through OTP setup
        echo "Follow these steps to set up OTP:"
        echo "1. Run the command 'google-authenticator' in your terminal."
        echo "2. Answer 'y' to the prompts asking whether to update your 'google_authenticator' file, disallow multiple uses of the same authentication"
        echo "   token, and increase the time skew allowed for token use."
        echo "3. Answer 'n' to the prompt asking whether to do rate-limiting of the login attempts."
        echo "4. Scan the QR code with your authenticator app or manually enter the secret key."
        echo "5. Generate backup codes when prompted and keep them in a safe place."
        echo "6. Make sure to remember these backup codes in case you lose access to your authenticator app."
        echo "7. Save the emergency scratch codes provided as well."
        echo "8. Press 'Enter' to continue once you have completed the above steps."
        
        read -p ""

        echo "OTP-based authentication has been enabled for your user."
        ;;
    "no")
        echo "OTP-based authentication not enabled. Exiting."
        ;;
    *)
        echo "Invalid response. Exiting."
        ;;
esac

echo "7) Let's find and secure files with no associated user or group."

echo "Finding files with no associated user or group..."
files_without_user_group=$(find / -type f \( -nouser -o -nogroup \) -print 2>/dev/null)

if [ -z "$files_without_user_group" ]; then
    echo "No files found with no associated user or group."
else
    echo -e "Files with no associated user or group:\n$files_without_user_group"
    echo -n "Do you want to secure these files? (yes/no): "
    read response_secure_files

    if [ "$response_secure_files" == "yes" ]; then
        echo -n "Enter the username to assign: "
        read username

        echo -n "Enter the group name to assign: "
        read groupname

        echo "Securing files..."
        find / -type f \( -nouser -o -nogroup \) -exec chown "$username:$groupname" {} +

        echo "Files secured successfully."
    else
        echo "Files were not secured."
    fi
fi


echo "8) Setting the appropriate permissions for sensitive files."

sensitive_files=(
    "/etc/gshadow"
    "/etc/shadow"
    "/etc/passwd"
    "/etc/group"
    "/etc/ssh/sshd_config"
    "/etc/sudoers"
    "/root/.ssh/id_rsa"
    "/root/.bash_history"
    "/var/log/auth.log"
    "/var/log/secure"
    "/var/log/wtmp"
)

for file in "${sensitive_files[@]}"; do
    if [ -e "$file" ]; then
        file_owner=$(stat -c %U "$file")

        if [ "$file_owner" == "root" ]; then
            chmod 400 "$file"
            echo "Set permissions for $file: $file_owner read-only (root)."
        else
            chmod 400 "$file"
            echo "Set permissions for $file: $file_owner read-only (owner)."
        fi
    else
        echo "File not found: $file. Skipped."
    fi
done

echo "Securing sensitive files done."

echo "9) security measures to secure processes using Yama LSM."

security_policies=(
    "Restrict process tracing using ptrace  # sysctl kernel.yama.ptrace_scope=1"
    "Prevent non-root users from sniffing the credentials of processes they don't own  # sysctl kernel.yama.ptrace_scope=2"
    "Restrict interprocess signal handling to improve security  # sysctl kernel.yama.ptrace_scope=3"
)

for policy in "${security_policies[@]}"; do
    explanation=$(echo "$policy" | cut -d '#' -f1)
    echo -e "Security Policy:\n$explanation"
    echo "Do you want to apply this security policy? (yes/no)"
    read response

    case "$response" in
        "yes")
            
            command=$(echo "$policy" | cut -d '#' -f2)
            echo "Applying: $command"
   
            sysctl $command
            ;;
        "no")
            echo "Security policy skipped."
            ;;
        *)
            echo "Invalid response. Security policy skipped."
            ;;
    esac
done

echo "10) This will Apply security measures for setuid, setgid, and sticky bits on common files."
common_files=(
    "/bin/ls"
    "/bin/cat"
    "/bin/mkdir"
    "/bin/rm"
    "/bin/cp"
    "/bin/mv"
    "/usr/bin/passwd"
    "/usr/bin/chsh"
    "/usr/bin/sudo"
    "/usr/bin/gpasswd"
    "/sbin/ifconfig"
    "/sbin/reboot"
    "/sbin/shutdown"
    "/etc/passwd"
    "/etc/group"
    "/etc/hostname"
)

for file in "${common_files[@]}"; do
    explanation="Secure setuid, setgid, and sticky bits on $file"
    echo -e "Security Policy:\n$explanation"
    echo "Do you want to apply this security policy? (yes/no)"
    read response
    case "$response" in
        "yes")
            
            echo "Applying: chmod u-s,g-s,+t $file"
            chmod u-s,g-s,+t "$file"
            ;;
        "no")
            echo "Security policy skipped for $file."
            ;;
        *)
            echo "Invalid response. Security policy skipped for $file."
            ;;
    esac
done


echo "11) let's disable non-necessary services on a Linux system."

common_services=(
    "dhcpd"
    "zeroconf"
    "portmap"
    "rpc.statd"
    "rpcbind"
    "cups"  
    "avahi-daemon"  
    "nfs"  
    "nfs-common"  
    "rpcbind"  
    "bluetooth"  
    "ModemManager"  
)

for service in "${common_services[@]}"; do
    echo "Service to consider: $service"
    echo "Do you want to disable this service? (yes/no)"
    read response

    case "$response" in
        "yes")
            echo "Disabling service: systemctl disable $service"
            systemctl disable "$service"
            ;;
        "no")
            echo "Service skipped."
            ;;
        *)
            echo "Invalid response. Service skipped."
            ;;
    esac
done


echo "12) blacklisting of Bluetooth modules and blocking uncommon network protocols and filesystems ."

security_policies=(
    "Blacklist Bluetooth module  # echo 'install btusb /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Blacklist Bluetooth service  # echo 'install bluetooth /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Blacklist Uncommon Network Protocols  # echo 'install dccp /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Blacklist SCTP  # echo 'install sctp /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Blacklist RDS  # echo 'install rds /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Blacklist TIPC  # echo 'install tipc /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Blacklist N-HDLC  # echo 'install n_hdlc /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Blacklist AX.25  # echo 'install ax25 /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Blacklist NET/ROM  # echo 'install netrom /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Block uncommon filesystems  # echo 'install cramfs /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Block FreeVxFS  # echo 'install freevxfs /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Block JFFS2  # echo 'install jffs2 /bin/true' >> /etc/modprobe.d/blacklist.conf"
    "Block HFS  # echo 'install hfs /bin/true' >> /etc/modprobe.d/blacklist.conf"
)

for policy in "${security_policies[@]}"; do
    explanation=$(echo "$policy" | cut -d '#' -f1)
    echo -e "Security Policy:\n$explanation"
    echo "Do you want to apply this security policy? (yes/no)"
    read response

    case "$response" in
        "yes")
            echo "Applying: $explanation"
            eval "$(echo "$policy" | cut -d '#' -f2)"
            ;;
        "no")
            echo "Security policy skipped."
            ;;
        *)
            echo "Invalid response. Security policy skipped."
            ;;
    esac
done

echo "Linux hardening completed."
