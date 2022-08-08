
############################################################################################################################

##Category 5.3 Access, Authentication and Authorization - Configure PAM
echo
echo -e "${BLUE}5.3 Access, Authentication and Authorization - Configure PAM${NC}"

#Ensure password creation requirements are configured
echo
echo -e "${RED}5.3.1${NC} Ensure password creation requirements are configured"
egrep -q "^\s*password\s+requisite\s+pam_pwquality.so\s+" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+requisite\s+pam_pwquality.so\s+/ { /^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*(\s+try_first_pass)(\s+.*)?$/! s/^(\s*password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1try_first_pass \2/ }' /etc/pam.d/password-auth && sed -ri '/^\s*password\s+requisite\s+pam_pwquality.so\s+/ { /^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*(\s+retry=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1retry=3 \2/ }' /etc/pam.d/password-auth && sed -ri 's/(^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*\s+)retry=[0-9]+(\s+.*)?$/\1retry=3\3/' /etc/pam.d/password-auth || echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/password-auth
egrep -q "^\s*password\s+requisite\s+pam_pwquality.so\s+" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+requisite\s+pam_pwquality.so\s+/ { /^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*(\s+try_first_pass)(\s+.*)?$/! s/^(\s*password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1try_first_pass \2/ }' /etc/pam.d/system-auth && sed -ri '/^\s*password\s+requisite\s+pam_pwquality.so\s+/ { /^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*(\s+retry=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+requisite\s+pam_pwquality.so\s+)(.*)$/\1retry=3 \2/ }' /etc/pam.d/system-auth && sed -ri 's/(^\s*password\s+requisite\s+pam_pwquality.so(\s+\S+)*\s+)retry=[0-9]+(\s+.*)?$/\1retry=3\3/' /etc/pam.d/system-auth || echo "password requisite pam_pwquality.so try_first_pass retry=3" >> /etc/pam.d/system-auth
egrep -q "^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$/\minlen=14\2/" /etc/security/pwquality.conf || echo "minlen=14" >> /etc/security/pwquality.conf
egrep -q "^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$/\dcredit=-1\2/" /etc/security/pwquality.conf || echo "dcredit=-1" >> /etc/security/pwquality.conf
egrep -q "^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$/\ucredit=-1\2/" /etc/security/pwquality.conf || echo "ucredit=-1" >> /etc/security/pwquality.conf
egrep -q "^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$/\ocredit=-1\2/" /etc/security/pwquality.conf || echo "ocredit=-1" >> /etc/security/pwquality.conf
egrep -q "^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$" /etc/security/pwquality.conf && sed -ri "s/^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$/\lcredit=-1\2/" /etc/security/pwquality.conf || echo "lcredit=-1" >> /etc/security/pwquality.conf
echo -e "${GREEN}Remediated:${NC} Ensure password creation requirements are configured"
success=$((success + 1))

#Ensure password reuse is limited
echo
echo -e "${RED}5.3.3${NC} Ensure password reuse is limited"
egrep -q "^\s*password\s+sufficient\s+pam_unix.so(\s+.*)$" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+remember=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1remember=5 \2/ }' /etc/pam.d/password-auth && sed -ri 's/(^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*\s+)remember=[0-9]+(\s+.*)?$/\1remember=5\3/' /etc/pam.d/password-auth || echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/password-auth
egrep -q "^\s*password\s+sufficient\s+pam_unix.so(\s+.*)$" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+remember=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1remember=5 \2/ }' /etc/pam.d/system-auth && sed -ri 's/(^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*\s+)remember=[0-9]+(\s+.*)?$/\1remember=5\3/' /etc/pam.d/system-auth || echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/system-auth
echo -e "${GREEN}Remediated:${NC} Ensure password reuse is limited"
success=$((success + 1))

#Ensure password hashing algorithm is SHA-512
echo
echo -e "${RED}5.3.4${NC} Ensure password hashing algorithm is SHA-512"
egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/password-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/password-auth || echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/password-auth
egrep -q "^\s*password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/system-auth && sed -ri '/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }' /etc/pam.d/system-auth || echo "password sufficient pam_unix.so sha512" >> /etc/pam.d/system-auth
echo -e "${GREEN}Remediated:${NC} Ensure password hashing algorithm is SHA-512"
success=$((success + 1))

############################################################################################################################

##Category 5.4 Access, Authentication and Authorization - User Accounts and Environment
echo
echo -e "${BLUE}5.4 Access, Authentication and Authorization - User Accounts and Environment${NC}"

#Ensure password expiration is 365 days or less
echo
echo -e "${RED}5.4.1.1${NC} Ensure password expiration is 365 days or less"
egrep -q "^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MAX_DAYS 90\2/" /etc/login.defs || echo "PASS_MAX_DAYS 90" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --maxdays 90
echo -e "${GREEN}Remediated:${NC} Ensure password expiration is 365 days or less"
success=$((success + 1))

#Ensure minimum days between password changes is 7 or more
echo
echo -e "${RED}5.4.1.2${NC} Ensure minimum days between password changes is 7 or more"
egrep -q "^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 7\2/" /etc/login.defs || echo "PASS_MIN_DAYS 7" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --mindays 7
echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is 7 or more"
success=$((success + 1))

#Ensure password expiration warning days is 7 or more
echo
echo -e "${RED}5.4.1.3${NC} Ensure password expiration warning days is 7 or more"
egrep -q "^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S+(\s*#.*)?\s*$/\PASS_WARN_AGE 7\2/" /etc/login.defs || echo "PASS_WARN_AGE 7" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --warndays 7
echo -e "${GREEN}Remediated:${NC} Ensure password expiration warning days is 7 or more"
success=$((success + 1))

#Ensure inactive password lock is 30 days or less
echo
echo -e "${RED}5.4.1.4${NC} Ensure inactive password lock is 30 days or less"
useradd -D -f 30 && getent passwd | cut -f1 -d ":" | xargs -n1 chage --inactive 30
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure inactive password lock is 30 days or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure inactive password lock is 30 days or less"
  fail=$((fail + 1))
fi

#Ensure system accounts are non-login
echo
echo -e "${RED}5.4.2${NC} Ensure system accounts are non-login"
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]; then
    /usr/sbin/usermod -L $user
    if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
      /usr/sbin/usermod -s /sbin/nologin $user
    fi
  fi
done
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure system accounts are non-login"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure system accounts are non-login"
  fail=$((fail + 1))
fi

#Ensure default group for the root account is GID 0
echo
echo -e "${RED}5.4.3${NC} Ensure default group for the root account is GID 0"
usermod -g 0 root
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure default group for the root account is GID 0"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure default group for the root account is GID 0"
  fail=$((fail + 1))
fi

#Ensure default user umask is 027 or more restrictive
echo
echo -e "${RED}5.4.4${NC} Ensure default user umask is 027 or more restrictive"
egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/bashrc && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/bashrc || echo "umask 077" >> /etc/bashrc
egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/profile || echo "umask 077" >> /etc/profile
egrep -q "^(\s*)umask\s+\S+(\s*#.*)?\s*$" /etc/profile.d/*.sh && sed -ri "s/^(\s*)umask\s+\S+(\s*#.*)?\s*$/\1umask 077\2/" /etc/profile.d/*.sh || echo "umask 077" >> /etc/profile.d/*.sh
echo -e "${GREEN}Remediated:${NC} Ensure default user umask is 027 or more restrictive"

#Ensure default user shell timeout is 900 seconds or less
echo
echo -e "${RED}5.4.5${NC} Ensure default user shell timeout is 900 seconds or less"
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/bashrc && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/bashrc || echo "TMOUT=600" >> /etc/bashrc
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile || echo "TMOUT=600" >> /etc/profile
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile.d/*.sh && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile.d/*.sh || echo "TMOUT=600" >> /etc/profile.d/*.sh
echo -e "${GREEN}Remediated:${NC} Ensure default user shell timeout is 900 seconds or less"

#Ensure access to the su command is restricted
echo
echo -e "${RED}5.6${NC} Ensure access to the su command is restricted"
egrep -q "^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$" /etc/pam.d/su && sed -ri '/^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$/ { /^\s*auth\s+required\s+pam_wheel.so(\s+\S+)*(\s+use_uid)(\s+.*)?$/! s/^(\s*auth\s+required\s+pam_wheel.so)(\s+.*)?$/\1 use_uid\2/ }' /etc/pam.d/su || echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure access to the su command is restricted"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure access to the su command is restricted"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 6.1 System Maintenance - System File Permissions
echo
echo -e "${BLUE}6.1 System Maintenance - System File Permissions${NC}"
 
#Ensure permissions on /etc/passwd are configured
echo
echo -e "${RED}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
chown root:root /etc/passwd && chmod 644 /etc/passwd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/shadow are configured
echo
echo -e "${RED}6.1.3${NC} Ensure permissions on /etc/shadow are configured"
chown root:root /etc/shadow && chmod 000 /etc/shadow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow are configured"
  fail=$((fail + 1))
fi
 
#Ensure permissions on /etc/group are configured
echo
echo -e "${RED}6.1.4${NC} Ensure permissions on /etc/group are configured"
chown root:root /etc/group && chmod 644 /etc/group
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/gshadow are configured
echo
echo -e "${RED}6.1.5${NC} Ensure permissions on /etc/gshadow are configured"
chown root:root /etc/gshadow && chmod 000 /etc/gshadow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/passwd- are configured
echo
echo -e "${RED}6.1.6${NC} Ensure permissions on /etc/passwd- are configured"
chown root:root /etc/passwd- && chmod u-x,go-wx /etc/passwd-
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd- are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/shadow- are configured
echo
echo -e "${RED}6.1.7${NC} Ensure permissions on /etc/shadow- are configured"
chown root:root /etc/shadow- && chmod 000 /etc/shadow-
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow- are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/group- are configured
echo
echo -e "${RED}6.1.8${NC} Ensure permissions on /etc/group- are configured"
chown root:root /etc/group- && chmod u-x,go-wx /etc/group-
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group- are configured"
  fail=$((fail + 1))
fi

#Ensure permissions on /etc/gshadow- are configured
echo
echo -e "${RED}6.1.9${NC} Ensure permissions on /etc/gshadow- are configured"
chown root:root /etc/gshadow- && chmod 000 /etc/gshadow-
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow- are configured"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow- are configured"
  fail=$((fail + 1))
fi

############################################################################################################################

##Category 6.2 System Maintenance - User and Group Settings
echo
echo -e "${BLUE}6.2 System Maintenance - User and Group Settings${NC}"

#Ensure no legacy '+' entries exist in /etc/passwd
echo
echo -e "${RED}6.2.2${NC} Ensure no legacy '+' entries exist in /etc/passwd"
sed -ri '/^\+:.*$/ d' /etc/passwd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy '+' entries exist in /etc/passwd"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy '+' entries exist in /etc/passwd"
  fail=$((fail + 1))
fi

#Ensure no legacy '+' entries exist in /etc/shadow
echo
echo -e "${RED}6.2.3${NC} Ensure no legacy '+' entries exist in /etc/shadow"
sed -ri '/^\+:.*$/ d' /etc/shadow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy '+' entries exist in /etc/shadow"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy '+' entries exist in /etc/shadow"
  fail=$((fail + 1))
fi

#Ensure no legacy '+' entries exist in /etc/group
echo
echo -e "${RED}6.2.4${NC} Ensure no legacy '+' entries exist in /etc/group"
sed -ri '/^\+:.*$/ d' /etc/group
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure no legacy '+' entries exist in /etc/group"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure no legacy '+' entries exist in /etc/group"
  fail=$((fail + 1))
fi

############################################################################################################################

echo
echo -e "${GREEN}Remediation script for CentOS Linux 7 executed successfully!!${NC}"
echo
echo -e "${YELLOW}Summary:${NC}"
echo -e "${YELLOW}Remediation Passed:${NC} $success" 
echo -e "${YELLOW}Remediation Failed:${NC} $fail"

###########################################################################################################################