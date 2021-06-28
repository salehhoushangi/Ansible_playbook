#!/bin/bash
clear
CIS_LEVEL=2
WIDTH=95
if [ $CIS_LEVEL -gt 1 ];then
  RESULT_FIELD=10
else
  RESULT_FIELD=6
fi
MSG_FIELD=$(($WIDTH - $RESULT_FIELD))
BOLD=$(tput bold)
RED=$BOLD$(tput setaf 1)
GREEN=$BOLD$(tput setaf 2)
YELLOW=$BOLD$(tput setaf 3)
CYAN=$BOLD$(tput setaf 6)
NC=$(tput sgr0)
PASSED_CHECKS=0
FAILED_CHECKS=0
OUTPUT_PASSED_CHECKS=0
OUTPUT_FAILED_CHECKS=0
OUTPUT_PRESET_CHECKS=0
OUTPUT_SETMANUALLY_CHECKS=0
BBLUE=$(tput setb 4)
OUTPUT_RESULT_FIELD=$((RESULT_FIELD-17))
OUTPUT_MSG_FIELD=$(($WIDTH - $OUTPUT_RESULT_FIELD))
OUTPUTRESULT="0"


echo -e "\e[104m"
cat <<EOF 
$YELLOW$BOLD
                                                                                                     
     ____        _   _         ____                       _ _           _____                        
    |  _ \  ___ | |_(_)_ __   / ___|  ___  ___ _   _ _ __(_) |_ _   _  |_   _|__  __ _ _ __ ___      
    | | | |/ _ \| __| | '_ \  \___ \ / _ \/ __| | | | '__| | __| | | |   | |/ _ \/ _  | '_  _  \     
    | |_| | (_) | |_| | | | |  ___) |  __/ (__| |_| | |  | | |_| |_| |   | |  __/ (_| | | | | | |    
    |____/ \___/ \__|_|_| |_| |____/ \___|\___|\__,_|_|  |_|\__|\__, |   |_|\___|\__,_|_| |_| |_|    
                                                                |___/                                
                                                                                                     
                                  ## ScriptName: RHEL7-8_Hardening_Script                            
                                  ## Version   : 1.0                                                 
                                  ## Date&Time : $(date +"%d-%m-%y %H:%M")                                      
                                                                                                     $NC    
EOF
echo -e "\e[49m"

function header() {
    local HEADING=$1
    local TEXT=$((${#HEADING}+2))
    local LBAR=5
    local RBAR=$(($WIDTH - $TEXT - $LBAR))
    for (( x=0; x < $LBAR; x++));do
        printf %s '#' >> RHEL7-8_Auditing_Report.txt
    done
    echo -n " $YELLOW$HEADING$NC " >> RHEL7-8_Auditing_Report.txt 
    for (( x=0; x < $RBAR; x++));do
        printf %s '#' >> RHEL7-8_Auditing_Report.txt
    done
    echo "" >> RHEL7-8_Auditing_Report.txt
}

function msg() {
  printf "%-${MSG_FIELD}s" " - ${1}" >> RHEL7-8_Auditing_Report.txt
}

function success_result() {
    PASSED_CHECKS=$((PASSED_CHECKS+1))
    local RESULT="$GREEN${1:-[PASSED]}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT >> RHEL7-8_Auditing_Report.txt
}

function failed_result() {
    FAILED_CHECKS=$((FAILED_CHECKS+1))
    local RESULT="$RED${1:-[FAILED]}$NC" 
    printf "%-${RESULT_FIELD}s\n" $RESULT >> RHEL7-8_Auditing_Report.txt
}

function OUTPUT_success_result() {
    OUTPUT_PASSED_CHECKS=$((OUTPUT_PASSED_CHECKS+1))
    local RESULT="$GREEN${1:-[PASSED]}$NC"
    printf "%-${OUTPUT_RESULT_FIELD}s\n" $RESULT
}

function OUTPUT_failed_result() {
    OUTPUT_FAILED_CHECKS=$((OUTPUT_FAILED_CHECKS+1))
    local RESULT="$RED${1:-[FAILED]}$NC"
    printf "%-${OUTPUT_RESULT_FIELD}s\n" $RESULT
}

function OUTPUT_preset_result() {
    OUTPUT_PRESET_CHECKS=$((OUTPUT_PRESET_CHECKS+1))
    local RESULT="$CYAN${1:-[PRESET]}$NC"
    printf "%-${OUTPUT_RESULT_FIELD}s\n" $RESULT
}

function OUTPUT_setmanually_result() {
    OUTPUT_SETMANUALLY_CHECKS=$((OUTPUT_SETMANUALLY_CHECKS+1))
    local RESULT="$YELLOW${1:-[SETMANUALLY]}$NC"
    printf "%-${OUTPUT_RESULT_FIELD}s\n" $RESULT
}

function check_retval_eq_0() {
  RETVAL=$1
  if [ $RETVAL -eq 0 ]; then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
    failed_result
  fi
}

function check_retval_ne_0() {
  RETVAL=$1
  if [ $RETVAL -ne 0 ]; then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
    failed_result
  fi
}

function OUTPUT_MSG() {
printf "%-${OUTPUT_MSG_FIELD}s" " $YELLOW${1}$NC"
}

function OUTPUT_SUCCESS_CHECK () {
 SUCCESS_VALUE=$1
 if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_success_result
 else
   OUTPUT_failed_result
 fi
 OUTPUTRESULT="0"
}

function audit_response_check () {
if [ $1 -eq 0 ];then
  audit_response=$((audit_response+1))
else
  audit_response=$audit_response
fi
}
####################################################################
echo "" > RHEL7-8_Auditing_Report.txt
echo "RHEL7-8_Auditing_Report                                                          $(date +"%d-%m-%y %H:%M")" >> RHEL7-8_Auditing_Report.txt
for (( x=0; x < $(($WIDTH+6)); x++));do
    printf %s '=' | tee -a RHEL7-8_Auditing_Report.txt
done
printf "\n" | tee -a RHEL7-8_Auditing_Report.txt

####################
# 1.1.6 /var setup #
####################
if [ $CIS_LEVEL -gt 1 ];then
header "01-Ensure separate partition exists for /var"
msg "mount | grep -E '\s/var\s'"
OUTPUT_MSG "01-Ensure separate partition exists for /var"
mount | grep -E '\s/var\s' &> /dev/null
check_retval_eq_0 $?
fi
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
 else
   OUTPUT_setmanually_result
 fi
 OUTPUTRESULT="0"

########################################################
# 1.1.11 Ensure separate partition exists for /var/log #
########################################################
if [ $CIS_LEVEL -gt 1 ];then
  header "02-Ensure separate partition exists for /var/log"
  msg " mount | grep /var/log"
  OUTPUT_MSG "02-Ensure separate partition exists for /var/log"
  mount | grep /var/log &> /dev/null
  check_retval_eq_0 $?
fi
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
 else
   OUTPUT_setmanually_result
 fi
 OUTPUTRESULT="0"

########################
# 1.1.7 /var/tmp setup #
########################
if [ $CIS_LEVEL -gt 1 ];then
  FURTHER_VAR_TMP_CHECKS=1
  header "03-Ensure separate partition exists for /var/tmp"
  OUTPUT_MSG "03-Ensure separate partition exists for /var/tmp"
  msg " mount | grep /var/tmp"
  mount | grep /var/tmp &> /dev/null
  if [ $? -eq 0 ];then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
#    FURTHER_VAR_TMP_CHECKS=0
    failed_result
  fi

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
   OUTPUT_setmanually_result
fi
OUTPUTRESULT="0"

   if [ 2 -gt 1 ];then
#  if [ $FURTHER_VAR_TMP_CHECKS -gt 0 ];then
    let tmp=03
    for option in nodev nosuid noexec;do
      OUTPUTRESULT="0"
      tmp=$((tmp+1))
      header "0$tmp-Ensure $option option set on /var/tmp"
      OUTPUT_MSG "0$tmp-Ensure $option option set on /var/tmp"
      msg " mount | grep -E '\s/var/tmp\s' | grep $option"
      mount | grep -E '\s/var/tmp\s' | grep $option &> /dev/null
      check_retval_eq_0 $?
	  SUCCESS_VALUE=1
	  if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
		  OUTPUT_preset_result
	  else
	     OUTPUT_setmanually_result
	  fi
      OUTPUTRESULT="0"
    done
  fi
fi

###############################
# 1.1.12 /var/log/audit setup #
###############################
if [ $CIS_LEVEL -gt 1 ];then
  header "07-Ensure separate partition exists for /var/log/audit"
  OUTPUT_MSG "07-Ensure separate partition exists for /var/log/audit"
  msg " mount | grep /var/log/audit"
  mount | grep /var/log/audit &> /dev/null
  check_retval_eq_0 $?
  SUCCESS_VALUE=1
  if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
	 OUTPUT_preset_result
  else
	 OUTPUT_setmanually_result
  fi
  OUTPUTRESULT="0"
fi

#####################################################
# 1.1.13 Ensure separate partition exists for /home #
#####################################################
if [ $CIS_LEVEL -gt 1 ];then
  header "08-Ensure separate partition exists for /home"
  OUTPUT_MSG "08-Ensure separate partition exists for /home"
  msg " mount | grep /home"
  mount | grep /home &> /dev/null
  check_retval_eq_0 $?
  SUCCESS_VALUE=1
  if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
	 OUTPUT_preset_result
  else
	 OUTPUT_setmanually_result
  fi
  OUTPUTRESULT="0"
fi

####################################################
# 1.1.14 Ensure nodev option set on /home partition#
####################################################
if [ $CIS_LEVEL -gt 1 ];then
  header "09-Ensure nodev option set on /home partition"
  OUTPUT_MSG "09-Ensure nodev option set on /home partition"
  msg " mount | grep /home | grep nodev"
  mount | grep /home | grep nodev &> /dev/null
  check_retval_eq_0 $?
  SUCCESS_VALUE=1
  if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
	 OUTPUT_preset_result
  else
	 OUTPUT_setmanually_result
  fi
  OUTPUTRESULT="0"
fi

############################
# 1.1.2 - 1.1.5 /tmp setup #
############################
if [ $CIS_LEVEL -gt 1 ];then
  FURTHER_TMP_CHECKS=1
  header "10-Ensure /tmp is configured"
  OUTPUT_MSG "10-Ensure /tmp is configured"
  msg " mount | grep -E '\s/tmp\s'"
  mount | grep -E '\s/tmp\s' &> /dev/null
  check_retval_eq_0 $? 
  
  msg " systemctl is-enabled tmp.mount "
  systemctl is-enabled tmp.mount &> /dev/null
  check_retval_eq_0 $?
  SUCCESS_VALUE=2
  if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
	 OUTPUT_preset_result
  else
	 OUTPUT_setmanually_result
  fi
  OUTPUTRESULT="0"

  if [ $FURTHER_TMP_CHECKS -gt 0 ];then
    let tmp=10
    for option in nodev nosuid noexec;do
      OUTPUTRESULT=0
      tmp=$((tmp+1))
      header "$tmp-Ensure $option mount option set on /tmp"
      OUTPUT_MSG "$tmp-Ensure $option mount option set on /tmp"     
      msg " mount | grep -E '\s/tmp\s' | grep $option"
      mount | grep -E '\s/tmp\s' | grep $option &> /dev/null
      check_retval_eq_0 $?
      SUCCESS_VALUE=1
      if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
	     OUTPUT_preset_result
      else
	     OUTPUT_setmanually_result
      fi
      OUTPUTRESULT="0"
    done
  fi
fi

#####################################################################
# 1.1.21 Ensure sticky bit is set on all world-writable directories #
#####################################################################
header "14-Ensure sticky bit is set on all world-writable directories"
OUTPUT_MSG "14-Ensure sticky bit is set on all world-writable directories"
msg "Verifying..."
sticky_check="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) | wc -l)"
check_retval_eq_0 $sticky_check
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
 else
   df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}' &> /dev/null
   if [ $? -eq 0 ];then
      OUTPUT_success_result
   else
      OUTPUT_failed_result
   fi
 fi
OUTPUTRESULT="0"

##########################################
# 1.5.1 Ensure core dumps are restricted #
##########################################
header "15-Ensure core dumps are restricted"
OUTPUT_MSG "15-Ensure core dumps are restricted"
msg 'grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*'
check_output=0
grep -E "\*\shard\score\s0" /etc/security/limits.conf &> /dev/null
check_output=$?
if [ $check_output -eq 0 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  grep -E "\*\shard\score\s0" /etc/security/limits.d/* &> /dev/null
  check_retval_eq_0 $?
fi

msg 'sysctl fs.suid_dumpable'
if [[ "$(sysctl fs.suid_dumpable)" == "fs.suid_dumpable = 0" ]];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg 'grep -E "fs\.suid_dumpable\s=\s0" /etc/sysctl.conf /etc/sysctl.d/*'
check_output=0*
grep -E "fs\.suid_dumpable\s=\s0" /etc/sysctl.conf &> /dev/null
check_output=$?
if [ $check_output -eq 0 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  grep -E "fs\.suid_dumpable\s=\s0" /etc/sysctl.d/* &> /dev/null
  check_retval_eq_0 $?
fi

#hardening
# for f in myFiles/*; do
  # sed -i 'd/pattern that matches line that you want to delete/' $f
# done
SUCCESS_VALUE=3
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/security/limits.conf
    if [ -f "$FILE" ]; then
	    sed -i '/\*\shard\score/d' /etc/security/limits.conf 2> /dev/null
	    HARD_OUTPUT1=$?
	    echo "* hard core 0" >> /etc/security/limits.conf 
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	# level 2
	FILE=/etc/sysctl.conf
	if [ -f "$FILE" ]; then
		sed -i '/fs\.suid_dumpable/d' /etc/sysctl.conf 2> /dev/null
	    HARD_OUTPUT3=$?
	    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf 
	    HARD_OUTPUT4=$?
    else
		HARD_OUTPUT3=1
		HARD_OUTPUT4=1
	fi
	# level 3
	sysctl -w fs.suid_dumpable=0 &> /dev/null
	HARD_OUTPUT5=$?
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ] && [ $HARD_OUTPUT5 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#####################################################################
# 1.5.3 Ensure address space layout randomization (ASLR) is enabled #
#####################################################################
header "16-Ensure ASLR is enabled"
OUTPUT_MSG "16-Ensure ASLR is enabled"
msg 'sysctl kernel.randomize_va_space'
if [[ "$(sysctl kernel.randomize_va_space)" == "kernel.randomize_va_space = 2" ]];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg 'grep -E "kernel\.randomize\sva\sspace\s=\s2" /etc/sysctl.conf /etc/sysctl.d/*'
check_output=0*
grep -E "kernel\.randomize_va_space\s=\s2" /etc/sysctl.conf &> /dev/null
check_output=$?
if [ $check_output -eq 0 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  grep -E "kernel\.randomize_va_space\s=\s2" /etc/sysctl.d/* &> /dev/null
  check_retval_eq_0 $?
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/sysctl.conf
    if [ -f "$FILE" ]; then
	    sed -i '/kernel\.randomize_va_space/d' /etc/sysctl.conf 2> /dev/null
	    HARD_OUTPUT1=$?
	    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	# level 2
	sysctl -w kernel.randomize_va_space=2 &> /dev/null
	HARD_OUTPUT3=$?
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

###########################################
# 2.2.10 Ensure FTP Server is not enabled #
###########################################
header "17-Ensure FTP Server is not enabled"
OUTPUT_MSG "17-Ensure FTP Server is not enabled"
msg 'systemctl is-enabled vsftpd'
check_output="$(systemctl is-enabled vsftpd 2>&1)"
if [ "$check_output" == "disabled" -o "$check_output" == "indirect" ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  if [[ $check_output =~ Failed.*to.*get.*unit.*file.*state.*for.* ]];then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
    failed_result
  fi
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    systemctl --now disable vsftpd &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

########################################
# 2.1.1 Ensure xinetd is not installed #  
########################################
header "18-Ensure xinetd is not installed "
OUTPUT_MSG "18-Ensure xinetd is not installed"
msg 'rpm -q xinetd'
rpm -q xinetd &> /dev/null
check_retval_ne_0 $?

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    yum remove xinetd &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

###########################################
# 2.2.11 Ensure DNS Server is not enabled #   
###########################################
header "19-Ensure DNS Server is not enabled"
OUTPUT_MSG "19-Ensure DNS Server is not enabled"
msg 'systemctl is-enabled named'
check_output="$(systemctl is-enabled named 2>&1)"
if [ "$check_output" == "disabled" -o "$check_output" == "indirect" ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  if [[ $check_output =~ Failed.*to.*get.*unit.*file.*state.*for.* ]];then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
    failed_result
  fi
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    systemctl --now disable named &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

############################################
# 2.2.14 Ensure LDAP server is not enabled #   
############################################
header "20-Ensure LDAP server is not enabled"
OUTPUT_MSG "20-Ensure LDAP server is not enabled"
msg 'systemctl is-enabled slapd'
check_output="$(systemctl is-enabled slapd 2>&1)"
if [ "$check_output" == "disabled" -o "$check_output" == "indirect" ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  if [[ $check_output =~ Failed.*to.*get.*unit.*file.*state.*for.* ]];then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
    failed_result
  fi
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    systemctl --now disable slapd &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#####################################
# 2.2.7 Ensure Samba is not enabled #
#####################################
header "21-Ensure Samba is not enabled"
OUTPUT_MSG "21-Ensure Samba is not enabled"
msg 'systemctl is-enabled smb'
check_output="$(systemctl is-enabled smb 2>&1)"
if [ "$check_output" == "disabled" -o "$check_output" == "indirect" ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  if [[ $check_output =~ Failed.*to.*get.*unit.*file.*state.*for.* ]];then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
    failed_result
  fi
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    systemctl --now disable smb &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

############################################
# 2.2.15 Ensure DHCP Server is not enabled #      
############################################
header "22-Ensure DHCP Server is not enabled"
OUTPUT_MSG "22-Ensure DHCP Server is not enabled"
msg 'systemctl is-enabled dhcpd'
check_output="$(systemctl is-enabled dhcpd 2>&1)"
if [ "$check_output" == "disabled" -o "$check_output" == "indirect" ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  if [[ $check_output =~ Failed.*to.*get.*unit.*file.*state.*for.* ]];then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
    failed_result
  fi
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    systemctl --now disable dhcpd &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

####################################
# 2.2.12 Ensure NFS is not enabled #
####################################
header "23-Ensure NFS is not enabled"
OUTPUT_MSG "23-Ensure NFS is not enabled"
msg 'systemctl is-enabled nfs'
check_output="$(systemctl is-enabled nfs 2>&1)"
if [ "$check_output" == "disabled" -o "$check_output" == "indirect" ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  if [[ $check_output =~ Failed.*to.*get.*unit.*file.*state.*for.* ]];then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
    failed_result
  fi
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    systemctl --now disable nfs &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

###########################################
# 2.2.5 Ensure SNMP Server is not enabled #      
###########################################
header "24-Ensure SNMP Server is not enabled"
OUTPUT_MSG "24-Ensure SNMP Server is not enabled"
msg 'systemctl is-enabled snmpd'
check_output="$(systemctl is-enabled snmpd 2>&1)"
if [ "$check_output" == "disabled" -o "$check_output" == "indirect" ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  if [[ $check_output =~ Failed.*to.*get.*unit.*file.*state.*for.* ]];then
    success_result
    OUTPUTRESULT=$((OUTPUTRESULT+1))
  else
    failed_result
  fi
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    systemctl --now disable snmpd &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#######################################
# 2.2.1.2 Ensure chrony is configured #
#######################################
header "25-Ensure chrony is configured"
OUTPUT_MSG "25-Ensure chrony is configured"
msg 'grep -E "^(server|pool)" /etc/chrony.conf'
grep -E "^(server|pool)" /etc/chrony.conf &> /dev/null
check_retval_eq_0 $?
msg 'ps -ef | grep -v grep | grep chronyd'
ps -ef | grep -v grep | grep chronyd &> /dev/null
check_retval_eq_0 $?

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
   OUTPUT_setmanually_result
fi
 OUTPUTRESULT="0"

##################################################
# 6.2.20 Ensure all users' home directories exist#
##################################################
header "26-Ensure all users' home directories exist"
OUTPUT_MSG "26-Ensure all users' home directories exist"
msg "Checking Script... "
check_output="$(cat /etc/passwd | awk -F: '$3 >= 1000 {print $1, $6 }' |
while read -r user directory; do
    if [ ! -d "$directory" ]; then
        echo "$user"
    fi
done
)"
if [ -z "$check_output" ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
   OUTPUT_setmanually_result
fi
OUTPUTRESULT="0"

#############################################################
# 5.4.1 Ensure password creation requirements are configured#
#############################################################
header "27-Ensure password creation requirements are configured"
OUTPUT_MSG "27-Ensure password creation requirements are configured"
msg 'grep pam_pwquality.so /etc/pam.d/password-auth  retry=3'
grep pam_pwquality.so /etc/pam.d/password-auth | grep -E "try_first_pass.*retry=3" &> /dev/null
check_retval_eq_0 $?
msg 'grep pam_pwquality.so /etc/pam.d/system-auth    retry=3'
grep pam_pwquality.so /etc/pam.d/system-auth | grep -E "try_first_pass.*retry=3" &> /dev/null
check_retval_eq_0 $?
msg "grep ^minlen /etc/security/pwquality.conf      minlen=12"
grep -E ^minlen /etc/security/pwquality.conf | grep -E "minlen\s?=\s?12" &> /dev/null
check_retval_eq_0 $?
msg 'grep ^minclass /etc/security/pwquality.conf    minclass=4'
grep ^minclass /etc/security/pwquality.conf | grep -E "minclass\s?=\s?4" &> /dev/null
check_retval_eq_0 $?

#hardening
# for f in myFiles/*; do
  # sed -i 'd/pattern that matches line that you want to delete/' $f
# done
SUCCESS_VALUE=4
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/security/pwquality.conf 
    if [ -f "$FILE" ]; then
	    sed -i '/minlen/d' /etc/security/pwquality.conf 2> /dev/null
	    HARD_OUTPUT1=$?
	    echo "minlen = 12" >> /etc/security/pwquality.conf
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	# level 2
	FILE=/etc/security/pwquality.conf
	if [ -f "$FILE" ]; then
		sed -i '/minclass/d' /etc/security/pwquality.conf 2> /dev/null
	    HARD_OUTPUT3=$?
	    echo "minclass = 4" >> /etc/security/pwquality.conf 
	    HARD_OUTPUT4=$?
    else
		HARD_OUTPUT3=1
		HARD_OUTPUT4=1
	fi
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ] ;then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

##################################
# 1.3.1 Ensure sudo is installed #
##################################
header "28-Ensure sudo is installed"
OUTPUT_MSG "28-Ensure sudo is installed"
msg 'rpm -q sudo'
rpm -q sudo  &> /dev/null
check_retval_eq_0 $?

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    yum install sudo -y &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#####################################
# 1.3.3 Ensure sudo log file exists #                                 
#####################################
header "29-Ensure sudo log file exists"
OUTPUT_MSG "29-Ensure sudo log file exists"
msg 'grep -Ei "^\s*Defaults\s+([^#]+,\s*)?logfile=" /etc/sudoers /etc/sudoers.d/*'
check_output=0
grep -Ei '^\s*Defaults\s+([^#]+,\s*)?logfile=' /etc/sudoers -s &> /dev/null
check_output=$?
if [ $check_output -eq 0 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  grep -Ei -s '^\s*Defaults\s+([^#]+,\s*)?logfile=' /etc/sudoers.d/* &> /dev/null
  check_retval_eq_0 $?
fi

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/sudoers 
    if [ -f "$FILE" ]; then
	    sed -i '/logfile/d' /etc/sudoers 2> /dev/null
	    HARD_OUTPUT1=$?
	    echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#########################################
# 3.1.1 Ensure IP forwarding is disabled#
#########################################
header "30-Ensure IP forwarding is disabled"
OUTPUT_MSG "30-Ensure IP forwarding is disabled"
msg 'sysctl net.ipv4.ip_forward'
if [[ "$(sysctl net.ipv4.ip_forward)" == "net.ipv4.ip_forward = 0" ]];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg 'grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf'
grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf &> /dev/null
check_retval_ne_0 $?
msg 'grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.d/*.conf'
grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.d/*.conf &> /dev/null
check_retval_ne_0 $?
msg 'grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /usr/lib/sysctl.d/*.conf'
grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /usr/lib/sysctl.d/*.conf &> /dev/null
check_retval_ne_0 $?
msg 'grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /run/sysctl.d/*.conf'
grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /run/sysctl.d/*.conf &> /dev/null
check_retval_ne_0 $?

SUCCESS_VALUE=5
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    grep -Els "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | \
	while read filename; do sed -ri "s/^\s*(net\.ipv4\.ip_forward\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; \
	sysctl -w net.ipv4.ip_forward=0 &> /dev/null; sysctl -w net.ipv4.route.flush=1 &> /dev/null
	HARD_OUTPUT1=$?
	if [ $HARD_OUTPUT1 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

###################################################
# 3.1.2 Ensure packet redirect sending is disabled#
###################################################
header "31-Ensure packet redirect sending is disabled"
OUTPUT_MSG "31-Ensure packet redirect sending is disabled"
msg "sysctl net.ipv4.conf.all.send_redirects"
if [[ "$(sysctl net.ipv4.conf.all.send_redirects)" == "net.ipv4.conf.all.send_redirects = 0" ]];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg "sysctl net.ipv4.conf.default.send_redirects"
sysctl net.ipv4.conf.default.send_redirects &> /dev/null
if [[ "$(sysctl net.ipv4.conf.default.send_redirects)" == "net.ipv4.conf.default.send_redirects = 0" ]];then
 success_result
 OUTPUTRESULT=$((OUTPUTRESULT+1))
else
 failed_result
fi
msg 'grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*'
check_output=0
grep -Ei "net\.ipv4\.conf\.all\.send_redirects\s?=\s?0" /etc/sysctl.conf -s &> /dev/null
check_output=$?
if [ $check_output -eq 0 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  grep -Ei -s "net\.ipv4\.conf\.all\.send_redirects\s?=\s?0" /etc/sysctl.d/* &> /dev/null
  check_retval_eq_0 $?
fi
msg 'grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*'
check_output=0
grep -Ei "net\.ipv4\.conf\.default\.send_redirects\s?=\s?0" /etc/sysctl.conf -s &> /dev/null
check_output=$?
if [ $check_output -eq 0 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  grep -Ei -s "net\.ipv4\.conf\.default\.send_redirects\s?=\s?0" /etc/sysctl.d/* &> /dev/null
  check_retval_eq_0 $?
fi

#hardening
# for f in myFiles/*; do
  # sed -i 'd/pattern that matches line that you want to delete/' $f
# done
SUCCESS_VALUE=4
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/sysctl.conf
    if [ -f "$FILE" ]; then
	    sed -i '/net\.ipv4\.conf\.all\.send_redirects/d' /etc/sysctl.conf 2> /dev/null
		echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf
	    HARD_OUTPUT1=$?
	    sed -i '/net\.ipv4\.conf\.default\.send_redirects/d' /etc/sysctl.conf 2> /dev/null
		echo 'net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.conf
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	# level 2
	find /etc/sysctl.d/ -name "*" -type f | xargs sed -i -e '/net\.ipv4\.conf\.all\.send_redirects/d' &> /dev/null
	HARD_OUTPUT3=$?
	find /etc/sysctl.d/ -name "*" -type f | xargs sed -i -e '/net\.ipv4\.conf\.default\.send_redirects/d' &> /dev/null
	HARD_OUTPUT4=$?
	# level 3
	sysctl -w net.ipv4.conf.all.send_redirects=0 &> /dev/null
	HARD_OUTPUT5=$?
	sysctl -w net.ipv4.conf.default.send_redirects=0 &> /dev/null
	HARD_OUTPUT6=$?
	sysctl -w net.ipv4.route.flush=1 &> /dev/null
	HARD_OUTPUT7=$?
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT5 -eq 0 ] && [ $HARD_OUTPUT6 -eq 0 ] && [ $HARD_OUTPUT7 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#######################################################
# 3.2.1 Ensure source routed packets are not accepted #
#######################################################
header "32-Ensure source routed packets aren not accepted"
OUTPUT_MSG "32-Ensure source routed packets aren not accepted"
msg "sysctl net.ipv4.conf.all.accept_source_route"
if [[ "$(sysctl net.ipv4.conf.all.accept_source_route)" == "net.ipv4.conf.all.accept_source_route = 0" ]];then
 success_result
 OUTPUTRESULT=$((OUTPUTRESULT+1))
else
 failed_result
fi

msg "sysctl net.ipv4.conf.default.accept_source_route"
if [[ "$(sysctl net.ipv4.conf.default.accept_source_route)" == "net.ipv4.conf.default.accept_source_route = 0" ]];then
 success_result
 OUTPUTRESULT=$((OUTPUTRESULT+1))
else
 failed_result
fi

#hardening
# for f in myFiles/*; do
  # sed -i 'd/pattern that matches line that you want to delete/' $f
# done
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/sysctl.conf
    if [ -f "$FILE" ]; then
	    sed -i '/net\.ipv4\.conf\.all\.accept_source_route/d' /etc/sysctl.conf 2> /dev/null
		echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.conf
	    HARD_OUTPUT1=$?
	    sed -i '/net\.ipv4\.conf\.default\.accept_source_route/d' /etc/sysctl.conf 2> /dev/null
		echo 'net.ipv4.conf.default.accept_source_route = 0' >> /etc/sysctl.conf
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	# level 2
	find /etc/sysctl.d/ -name "*" -type f | xargs sed -i -e '/net\.ipv4\.conf\.all\.accept_source_route/d' &> /dev/null
	HARD_OUTPUT3=$?
	find /etc/sysctl.d/ -name "*" -type f | xargs sed -i -e '/net\.ipv4\.conf\.default\.accept_source_route/d' &> /dev/null
	HARD_OUTPUT4=$?
	# level 3
	sysctl -w net.ipv4.conf.all.accept_source_route=0 &> /dev/null
	HARD_OUTPUT5=$?
	sysctl -w net.ipv4.conf.default.accept_source_route=0 &> /dev/null
	HARD_OUTPUT6=$?
	sysctl -w net.ipv4.route.flush=1 &> /dev/null
	HARD_OUTPUT7=$?
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] &&  [ $HARD_OUTPUT5 -eq 0 ] && [ $HARD_OUTPUT6 -eq 0 ] && [ $HARD_OUTPUT7 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

################################################
# 3.2.2 Ensure ICMP redirects are not accepted #
################################################
OUTPUTRESULT="0"
header "33-Ensure ICMP redirects are not accepted"
OUTPUT_MSG "33-Ensure ICMP redirects are not accepted"
msg "sysctl net.ipv4.conf.all.accept_redirects"
if [[ "$(sysctl net.ipv4.conf.all.accept_redirects)" == "net.ipv4.conf.all.accept_redirects = 0" ]];then
 success_result
 OUTPUTRESULT=$((OUTPUTRESULT+1))
else
 failed_result
fi

msg "sysctl net.ipv4.conf.default.accept_redirects"
if [[ "$(sysctl net.ipv4.conf.default.accept_redirects)" == "net.ipv4.conf.default.accept_redirects = 0" ]];then
 success_result
 OUTPUTRESULT=$((OUTPUTRESULT+1))
else
 failed_result
fi

#hardening
# for f in myFiles/*; do
  # sed -i 'd/pattern that matches line that you want to delete/' $f
# done
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/sysctl.conf
    if [ -f "$FILE" ]; then
	    sed -i '/net\.ipv4\.conf\.all\.accept_redirects/d' /etc/sysctl.conf 2> /dev/null
		echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf
	    HARD_OUTPUT1=$?
	    sed -i '/net\.ipv4\.conf\.default\.accept_redirects/d' /etc/sysctl.conf 2> /dev/null
		echo 'net.ipv4.conf.default.accept_redirects = 0' >> /etc/sysctl.conf
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	# level 2
	find /etc/sysctl.d/ -name "*" -type f | xargs sed -i -e '/net\.ipv4\.conf\.all\.accept_redirects/d' &> /dev/null
	HARD_OUTPUT3=$?
	find /etc/sysctl.d/ -name "*" -type f | xargs sed -i -e '/net\.ipv4\.conf\.default\.accept_redirects/d' &> /dev/null
	HARD_OUTPUT4=$?
	# level 3
	sysctl -w net.ipv4.conf.all.accept_redirects=0 &> /dev/null
	HARD_OUTPUT5=$?
	sysctl -w net.ipv4.conf.default.accept_redirects=0 &> /dev/null
	HARD_OUTPUT6=$?
	sysctl -w net.ipv4.route.flush=1 &> /dev/null
	HARD_OUTPUT7=$?
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT5 -eq 0 ] && [ $HARD_OUTPUT6 -eq 0 ] && [ $HARD_OUTPUT7 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

####################################################
# 3.2.5 Ensure broadcast ICMP requests are ignored #
####################################################
OUTPUTRESULT="0"
header "34-Ensure broadcast ICMP requests are ignored"
OUTPUT_MSG "34-Ensure broadcast ICMP requests are ignored"
msg "sysctl net.ipv4.icmp_echo_ignore_broadcasts"
if [[ "$(sysctl net.ipv4.icmp_echo_ignore_broadcasts)" == "net.ipv4.icmp_echo_ignore_broadcasts = 1" ]];then
 success_result
 OUTPUTRESULT=$((OUTPUTRESULT+1))
else
 failed_result
fi

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    grep -Els "^\s*net\.ipv4\.icmp_echo_ignore_broadcasts\s*=\s*0" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | \
    while read filename; do sed -ri "s/^\s*(net\.ipv4\.icmp_echo_ignore_broadcasts\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; \
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 &> /dev/null; sysctl -w net.ipv4.route.flush=1 &> /dev/null
	HARD_OUTPUT1=$?
	if [ $HARD_OUTPUT1 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#################################################
# 3.2.6 Ensure bogus ICMP responses are ignored #
#################################################
header "35-Ensure bogus ICMP responses are ignored"
OUTPUT_MSG "35-Ensure bogus ICMP responses are ignored"
msg "sysctl net.ipv4.icmp_ignore_bogus_error_responses"
if [[ "$(sysctl net.ipv4.icmp_ignore_bogus_error_responses)" == "net.ipv4.icmp_ignore_bogus_error_responses = 1" ]];then
 success_result
 OUTPUTRESULT=$((OUTPUTRESULT+1))
else
 failed_result
fi

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    grep -Els "^\s*net\.ipv4\.icmp_ignore_bogus_error_responses\s*=\s*0" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | \
    while read filename; do sed -ri "s/^\s*(net\.ipv4\.icmp_ignore_bogus_error_responses\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; \
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 &> /dev/null; sysctl -w net.ipv4.route.flush=1 &> /dev/null
	HARD_OUTPUT1=$?
	if [ $HARD_OUTPUT1 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

###########################################
# 3.2.8 Ensure TCP SYN Cookies is enabled #
###########################################
header "36-Ensure TCP SYN Cookies is enabled"
OUTPUT_MSG "36-Ensure TCP SYN Cookies is enabled"
msg "sysctl net.ipv4.tcp_syncookies"
if [[ "$(sysctl net.ipv4.tcp_syncookies)" == "net.ipv4.tcp_syncookies = 1" ]];then
 success_result
 OUTPUTRESULT=$((OUTPUTRESULT+1))
else
 failed_result
fi

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    grep -Els "^\s*net\.ipv4\.tcp_syncookies\s*=\s*[02]*" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | \
	while read filename; do sed -ri "s/^\s*(net\.ipv4\.tcp_syncookies\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; \
	sysctl -w net.ipv4.tcp_syncookies=1 &> /dev/null; sysctl -w net.ipv4.route.flush=1 &> /dev/null
	HARD_OUTPUT1=$?
	if [ $HARD_OUTPUT1 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

############################################
# 5.2.5 Ensure SSH LogLevel is appropriate #
############################################
header "37-Ensure SSH LogLevel is appropriate"
OUTPUT_MSG "37-Ensure SSH LogLevel is appropriate"
msg 'sshd -T | grep -Ei "loglevel" | grep -Ei "info|verbose"'
sshd -T | grep loglevel | grep -Ei "info|verbose" &> /dev/null 
check_retval_eq_0 $?

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/ssh/sshd_config 
    if [ -f "$FILE" ]; then
	    sed -i '/loglevel/Id' /etc/ssh/sshd_config  2> /dev/null
	    HARD_OUTPUT1=$?
	    echo 'LogLevel INFO' >> /etc/ssh/sshd_config 
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

############################################
# 5.2.10 Ensure SSH root login is disabled #
############################################
header "38-Ensure SSH root login is disabled"
OUTPUT_MSG "38-Ensure SSH root login is disabled"
msg 'sshd -T | grep -Ei "permitrootlogin" | grep -i no'
sshd -T | grep -Ei "permitrootlogin" | grep -i no &> /dev/null
check_retval_eq_0 $?

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/ssh/sshd_config 
    if [ -f "$FILE" ]; then
	    sed -i '/PermitRootLogin/Id' /etc/ssh/sshd_config  2> /dev/null
	    HARD_OUTPUT1=$?
	    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config 
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#####################################################
# 5.2.11 Ensure SSH PermitEmptyPasswords is disabled#
#####################################################
header "39-Ensure SSH PermitEmptyPasswords is disabled"
OUTPUT_MSG "39-Ensure SSH PermitEmptyPasswords is disabled"
msg 'sshd -T | grep -Ei "permitemptypasswords" | grep -i no'
sshd -T | grep permitemptypasswords | grep -i no &> /dev/null
check_retval_eq_0 $?

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/ssh/sshd_config 
    if [ -f "$FILE" ]; then
	    sed -i '/PermitEmptyPasswords/Id' /etc/ssh/sshd_config  2> /dev/null
	    HARD_OUTPUT1=$?
	    echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config 
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

######################################
# 5.2.2 Ensure SSH access is limited #
######################################
header "40-Ensure SSH access is limited"
OUTPUT_MSG "40-Ensure SSH access is limited"
msg 'sshd -T | grep -Ei "^\s*(allow|deny)(users|groups)\s+\S+"'
sshd -T | grep -Ei "^\s*(allow|deny)(users|groups)\s+\S+" &> /dev/null
check_retval_eq_0 $?

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
	OUTPUT_preset_result
else
	OUTPUT_setmanually_result
fi
OUTPUTRESULT="0"


#########################################################
# 5.2.13 Ensure SSH Idle Timeout Interval is configured #
#########################################################
header "41-Ensure SSH Idle Timeout Interval is configured"
OUTPUT_MSG "41-Ensure SSH Idle Timeout Interval is configured"
msg 'sshd -T | grep -Ei "clientaliveinterval\s14400"'
sshd -T | grep -Ei "clientaliveinterval\s14400" &> /dev/null
check_retval_eq_0 $?
msg 'sshd -T | grep -Ei "clientalivecountmax\s0"'
sshd -T | grep -Ei "clientalivecountmax\s0" &> /dev/null
check_retval_eq_0 $?

SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/ssh/sshd_config 
    if [ -f "$FILE" ]; then
	    sed -i '/ClientAliveInterval/Id' /etc/ssh/sshd_config  2> /dev/null
	    HARD_OUTPUT1=$?
	    echo 'ClientAliveInterval 14400' >> /etc/ssh/sshd_config 
	    HARD_OUTPUT2=$?
		sed -i '/ClientAliveCountMax/Id' /etc/ssh/sshd_config  2> /dev/null
	    HARD_OUTPUT3=$?
	    echo 'ClientAliveCountMax 0' >> /etc/ssh/sshd_config 
	    HARD_OUTPUT4=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
		HARD_OUTPUT3=1
		HARD_OUTPUT4=1
	fi
	#level 2
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"
systemctl restart sshd &> /dev/null

#####################################
# 4.1.1.1 Ensure auditd is installed#
#####################################
header "42-Ensure auditd is installed"
OUTPUT_MSG "42-Ensure auditd is installed"
msg 'rpm -q audit audit-libs'
rpm -q audit audit-libs &> /dev/null
check_retval_eq_0 $?

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    yum install audit audit-libs -y &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

###########################################
# 4.1.1.2 Ensure auditd service is enabled#
###########################################
header "43-Ensure auditd service is enabled"
OUTPUT_MSG "43-Ensure auditd service is enabled"
msg 'systemctl is-enabled auditd'
if [[ "$(systemctl is-enabled auditd)" == "enabled" ]];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    systemctl --now enable auditd &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

##########################################################################
# 4.1.2.2 Ensure max_log_file_action and num_logs options are configured #
##########################################################################
header "44-Ensure max_log_file_action and num_logs options are configured"
OUTPUT_MSG "44-Ensure max_log_file_action and num_logs options are configured"
msg 'grep max_log_file_action /etc/audit/auditd.conf       rotate'
grep -Ei "max_log_file_action\s?=\s?rotate"  /etc/audit/auditd.conf &> /dev/null
check_retval_eq_0 $?
msg 'grep -Ei "num_logs\s?=\s?5" /etc/audit/auditd.conf     5'
grep -Ei "num_logs\s?=\s?5" /etc/audit/auditd.conf &> /dev/null
check_retval_eq_0 $?

SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/audit/auditd.conf
    if [ -f "$FILE" ]; then
	    sed -i '/max_log_file_action/Id' /etc/audit/auditd.conf  2> /dev/null
	    HARD_OUTPUT1=$?
	    echo 'max_log_file_action = ROTATE' >> /etc/audit/auditd.conf 
	    HARD_OUTPUT2=$?
		sed -i '/num_logs/Id' /etc/audit/auditd.conf  2> /dev/null
	    HARD_OUTPUT3=$?
	    echo 'num_logs = 5' >> /etc/audit/auditd.conf
	    HARD_OUTPUT4=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
		HARD_OUTPUT3=1
		HARD_OUTPUT4=1
	fi
	#level 2
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

##############################################################################
# 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled#
##############################################################################
header "45-Ensure auditing for processes that start prior to auditd is enabled"
OUTPUT_MSG "45-Ensure auditing for processes that start prior to auditd is enabled"
msg 'grep "audit=1" /proc/cmdline'
check_output=0
grep "audit=1" /proc/cmdline &> /dev/null
check_output=$?
if [ $check_output -eq 0 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  grep "^\s*kernel" /boot/grub/grub.conf | grep "audit=1"
  check_retval_eq_0 $?
fi

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
	OUTPUT_preset_result
else
	OUTPUT_setmanually_result
fi
OUTPUTRESULT="0"

####################################################
# 4.1.1.4 Ensure audit_backlog_limit is sufficient #
####################################################
header "46-Ensure audit_backlog_limit is sufficient"
OUTPUT_MSG "46-Ensure audit_backlog_limit is sufficient"
msg 'grep "audit_backlog_limit=8192" /proc/cmdline'
grep "audit_backlog_limit=8192" /proc/cmdline &> /dev/null
check_retval_eq_0 $?

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
	OUTPUT_preset_result
else
	OUTPUT_setmanually_result
fi
OUTPUTRESULT="0"

#######################################################
# 4.1.2.1 Ensure audit log storage size is configured #
#######################################################
header "47-Ensure audit log storage size is configured"
OUTPUT_MSG "47-Ensure audit log storage size is configured"
msg 'grep -E "max_log_file = 500" /etc/audit/auditd.conf     500'
grep -E "max_log_file = 500" /etc/audit/auditd.conf &> /dev/null
check_retval_eq_0 $?

SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/audit/auditd.conf 
    if [ -f "$FILE" ]; then
	    sed -i -E '/max_log_file\s?=/Id' /etc/audit/auditd.conf  2> /dev/null
	    HARD_OUTPUT1=$?
	    echo 'max_log_file = 500' >> /etc/audit/auditd.conf 
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	#level 2
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

##########################################################################
# 4.1.6 Ensure events that modify date and time information are collected#
##########################################################################
header "48-Ensure events that modify date and time information are collected"
OUTPUT_MSG "48-Ensure events that modify date and time information are collected"
msg 'grep time-change /etc/audit/rules.d/*.rules'
audit_response=0
grep -s "time-change" /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" &> /dev/null
audit_response_check $?
grep -s "time-change" /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" &> /dev/null
audit_response_check $?
grep -s "time-change" /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S clock_settime -k time-change" &> /dev/null
audit_response_check $?
grep -s "time-change" /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S clock_settime -k time-change" &> /dev/null
audit_response_check $?
grep -s "time-change" /etc/audit/rules.d/*.rules | grep -e "-w /etc/localtime -p wa -k time-change" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 5 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg 'auditctl -l | grep time-change'
audit_response=$(auditctl -l | grep time-change | wc -l 2>&1) 
if [ $audit_response -ge 5 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" > /etc/audit/rules.d/time-change.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/time-change.rules 2> /dev/null
	HARD_OUTPUT2=$?
	echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/time-change.rules 2> /dev/null
	HARD_OUTPUT3=$?
	echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/time-change.rules 2> /dev/null
	HARD_OUTPUT4=$?
	echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/time-change.rules 2> /dev/null
	HARD_OUTPUT5=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT6=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ] && [ $HARD_OUTPUT5 -eq 0 ] && [ $HARD_OUTPUT6 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

########################################################################
# 4.1.11 Ensure events that modify user/group information are collected#
########################################################################
header '49-Ensure events that modify user/group information are collected'
OUTPUT_MSG "49-Ensure events that modify user/group information are collected"
msg 'grep identity /etc/audit/rules.d/*.rules'

audit_response=0
grep -s identity /etc/audit/rules.d/*.rules | grep -e "-w /etc/group -p wa -k identity"  &> /dev/null
audit_response_check $?
grep -s identity /etc/audit/rules.d/*.rules | grep -e "-w /etc/passwd -p wa -k identity" &> /dev/null
audit_response_check $?
grep -s identity /etc/audit/rules.d/*.rules | grep -e "-w /etc/gshadow -p wa -k identity" &> /dev/null
audit_response_check $?
grep -s identity /etc/audit/rules.d/*.rules | grep -e "-w /etc/shadow -p wa -k identity" &> /dev/null
audit_response_check $?
grep -s identity /etc/audit/rules.d/*.rules | grep -e "-w /etc/security/opasswd -p wa -k identity" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 5 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg 'auditctl -l | grep identity'
audit_response=$(auditctl -l | grep identity | wc -l 2>&1)
if [ $audit_response -ge 5 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-w /etc/group -p wa -k identity" > /etc/audit/rules.d/identity.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/identity.rules 2> /dev/null
	HARD_OUTPUT2=$?
	echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/identity.rules 2> /dev/null
	HARD_OUTPUT3=$?
	echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/identity.rules 2> /dev/null
	HARD_OUTPUT4=$?
	echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/identity.rules 2> /dev/null
	HARD_OUTPUT5=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT6=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ] && [ $HARD_OUTPUT5 -eq 0 ] && [ $HARD_OUTPUT6 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

###########################################################################
# Ensure events that modify the system's network environment are collected# 
###########################################################################
header "50-Ensure events that modify the system's network environment are collected"
OUTPUT_MSG "50-Ensure events that modify the system's network environment are collected"
msg 'grep system-locale /etc/audit/rules.d/*.rules'
audit_response=0
grep -s system-locale /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" &> /dev/null
audit_response_check $?
grep -s system-locale /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" &> /dev/null
audit_response_check $?
grep -s system-locale /etc/audit/rules.d/*.rules | grep -e "-w /etc/issue -p wa -k system-locale" &> /dev/null
audit_response_check $?
grep -s system-locale /etc/audit/rules.d/*.rules | grep -e "-w /etc/issue.net -p wa -k system-locale" &> /dev/null
audit_response_check $?
grep -s system-locale /etc/audit/rules.d/*.rules | grep -e "-w /etc/hosts -p wa -k system-locale" &> /dev/null
audit_response_check $?
grep -s system-locale /etc/audit/rules.d/*.rules | grep -e "-w /etc/sysconfig/network -p wa -k system-locale" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 6 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg 'auditctl -l | grep system-locale'
audit_response=$(auditctl -l | grep "system-locale" | wc -l 2>&1)
if [ $audit_response -ge 6 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" > /etc/audit/rules.d/system-locale.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules 2> /dev/null
	HARD_OUTPUT2=$?
	echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules 2> /dev/null
	HARD_OUTPUT3=$?
	echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules 2> /dev/null
	HARD_OUTPUT4=$?
	echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules 2> /dev/null
	HARD_OUTPUT5=$?
	echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules 2> /dev/null
	HARD_OUTPUT6=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT7=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ] && [ $HARD_OUTPUT5 -eq 0 ] && [ $HARD_OUTPUT6 -eq 0 ] && [ $HARD_OUTPUT7 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#######################################################################################
# 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected#
#######################################################################################
header "51-Ensure events that modify the system's Mandatory Access Controls are collected"
OUTPUT_MSG "51-Ensure events that modify the system's Mandatory Access Controls are collected"
msg 'grep MAC-policy /etc/audit/rules.d/*.rules'
audit_response=0
grep -s MAC-policy /etc/audit/rules.d/*.rules | grep -e "-w /etc/selinux/ -p wa -k MAC-policy" &> /dev/null
audit_response_check $?
grep -s MAC-policy /etc/audit/rules.d/*.rules | grep -e "-w /usr/share/selinux/ -p wa -k MAC-policy" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg 'auditctl -l | grep MAC-policy'
audit_response=$(auditctl -l | grep "MAC-policy" | wc -l 2>&1)
if [ $audit_response -ge 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-w /etc/selinux/ -p wa -k MAC-policy" > /etc/audit/rules.d/MAC-policy.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-w /usr/share/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/MAC-policy.rules 2> /dev/null
	HARD_OUTPUT2=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT3=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

######################################################
# 4.1.4 Ensure login and logout events are collected #
######################################################
header "52-Ensure login and logout events are collected"
OUTPUT_MSG "52-Ensure login and logout events are collected"
msg 'grep logins /etc/audit/rules.d/*.rules'
audit_response=0
grep -s logins /etc/audit/rules.d/*.rules | grep -e "-w /var/log/faillog -p wa -k logins" &> /dev/null
audit_response_check $?
grep -s logins /etc/audit/rules.d/*.rules | grep -e "-w /var/log/lastlog -p wa -k logins" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg 'auditctl -l | grep logins' 
audit_response=$(auditctl -l | grep "logins" | wc -l 2>&1)
if [ $audit_response -ge 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-w /var/log/faillog -p wa -k logins" > /etc/audit/rules.d/audit.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules 2> /dev/null
	HARD_OUTPUT2=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT3=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

###########################################################
# 4.1.5 Ensure session initiation information is collected#
###########################################################
header '53-Ensure session initiation information is collected'
OUTPUT_MSG "53-Ensure session initiation information is collected"
msg "grep -E '(session|logins)' /etc/audit/rules.d/*.rules"
audit_response=0
grep -s -E '(session|logins)' /etc/audit/rules.d/*.rules | grep -e "-w /var/run/utmp -p wa -k session" &> /dev/null
audit_response_check $?
grep -s -E '(session|logins)' /etc/audit/rules.d/*.rules | grep -e "-w /var/log/wtmp -p wa -k logins" &> /dev/null
audit_response_check $?
grep -s -E '(session|logins)' /etc/audit/rules.d/*.rules | grep -e "-w /var/log/btmp -p wa -k logins" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 3 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg "auditctl -l | grep -E '(session|logins)'"
audit_response=$(auditctl -l | grep -E '(session|logins)' | wc -l 2>&1)
if [ $audit_response -ge 3 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-w /var/run/utmp -p wa -k session" > /etc/audit/rules.d/logins.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/logins.rules 2> /dev/null
	HARD_OUTPUT2=$?
	echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/logins.rules 2> /dev/null
	HARD_OUTPUT3=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT4=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#########################################################################################
# 4.1.9 Ensure discretionary access control permission modification events are collected# 
#########################################################################################
header "54-Ensure discretionary access control permission modification events are collected "
OUTPUT_MSG "54-Ensure discretionary access control permission modification events are collected"
msg "grep perm_mod /etc/audit/rules.d/*.rules"
audit_response=0
grep -s perm_mod /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" &> /dev/null
audit_response_check $?
grep -s perm_mod /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" &> /dev/null
audit_response_check $?
grep -s perm_mod /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" &> /dev/null
audit_response_check $?
grep -s perm_mod /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" &> /dev/null
audit_response_check $?
grep -s perm_mod /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" &> /dev/null
audit_response_check $?
grep -s perm_mod /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 6 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg "auditctl -l | grep perm_mod"
audit_response=$(auditctl -l | grep "perm_mod" | wc -l 2>&1)
if [ $audit_response -ge 6 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" > /etc/audit/rules.d/perm_mod.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules 2> /dev/null
	HARD_OUTPUT2=$?
	echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules 2> /dev/null
	HARD_OUTPUT3=$?
	echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules 2> /dev/null
	HARD_OUTPUT4=$?
	echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules 2> /dev/null
	HARD_OUTPUT5=$?
	echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/perm_mod.rules 2> /dev/null
	HARD_OUTPUT6=$?
	
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT7=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ] && [ $HARD_OUTPUT5 -eq 0 ] && [ $HARD_OUTPUT6 -eq 0 ] && [ $HARD_OUTPUT7 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#############################################################################
# 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected#
#############################################################################
header "55-Ensure unsuccessful unauthorized file access attempts are collected"
OUTPUT_MSG "55-Ensure unsuccessful unauthorized file access attempts are collected"
msg "grep access /etc/audit/rules.d/*.rules"
audit_response=0
grep -s access /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" &> /dev/null
audit_response_check $?
grep -s access /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" &> /dev/null
audit_response_check $?
grep -s access /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" &> /dev/null
audit_response_check $?
grep -s access /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 4 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg "auditctl -l | grep access"
auditctl -l | grep access | grep -e \
audit_response=$(auditctl -l | grep "access" | wc -l 2>&1)
if [ $audit_response -ge 4 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" > /etc/audit/rules.d/access.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/access.rules 2> /dev/null
	HARD_OUTPUT2=$?
	echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/access.rules 2> /dev/null
	HARD_OUTPUT3=$?
	echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/access.rules 2> /dev/null
	HARD_OUTPUT4=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT5=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ] && [ $HARD_OUTPUT5 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

############################################################
# 4.1.12 Ensure successful file system mounts are collected#
############################################################
header "56-Ensure successful file system mounts are collected"
OUTPUT_MSG "56-Ensure successful file system mounts are collected"
msg "grep mounts /etc/audit/rules.d/*.rules"
audit_response=0
grep -s mounts /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" &> /dev/null
audit_response_check $?
grep -s mounts /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg "auditctl -l | grep mounts"
audit_response=$(auditctl -l | grep "access" | wc -l 2>&1)
if [ $audit_response -ge 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" > /etc/audit/rules.d/mounts.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/mounts.rules 2> /dev/null
	HARD_OUTPUT2=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT3=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

############################################################
# 4.1.14 Ensure file deletion events by users are collected#
############################################################
header "57-Ensure file deletion events by users are collected"
OUTPUT_MSG "57-Ensure file deletion events by users are collected"
msg "grep delete /etc/audit/rules.d/*.rules"
audit_response=0
grep -s delete /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" &> /dev/null
audit_response_check $?
grep -s delete /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg "auditctl -l | grep delete" 
audit_response=$(auditctl -l | grep "delete" | wc -l 2>&1)
if [ $audit_response -ge 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" > /etc/audit/rules.d/delete.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/delete.rules 2> /dev/null
	HARD_OUTPUT2=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT3=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#############################################################################
# 4.1.3 Ensure changes to system administration scope (sudoers) is collected#
#############################################################################
header "58-Ensure changes to system administration scope (sudoers) is collected"
OUTPUT_MSG "58-Ensure changes to system administration scope (sudoers) is collected"
msg "grep scope /etc/audit/rules.d/*.rules"
audit_response=0
grep -s scope /etc/audit/rules.d/*.rules | grep -e "-w /etc/sudoers -p wa -k scope" &> /dev/null 
audit_response_check $?
grep -s scope /etc/audit/rules.d/*.rules | grep -e "-w /etc/sudoers.d/ -p wa -k scope" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi 
msg "auditctl -l | grep scope"
audit_response=$(auditctl -l | grep "scope" | wc -l 2>&1)
if [ $audit_response -ge 2 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-w /etc/sudoers -p wa -k scope" > /etc/audit/rules.d/scope.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/scope.rules 2> /dev/null
	HARD_OUTPUT2=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT3=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#####################################################################
# 4.1.16 Ensure system administrator actions (sudolog) are collected#
#####################################################################
header "59-Ensure system administrator actions (sudolog) are collected"
OUTPUT_MSG "59-Ensure system administrator actions (sudolog) are collected"
msg "auditctl -l | grep actions     /var/log/sudo.log"
auditctl -l | grep -E '\-w\s.?\/var\/log\/sudo\.log.?\s\-p\swa\s\-k\sactions' &> /dev/null
check_output=$?
if [ $check_output -eq 0 ];then
  echo -w $(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//') -p wa -k actions | \
  grep -s -E '\-w\s.?\/var\/log\/sudo\.log.?\s\-p\swa\s\-k\sactions' &> /dev/null
  check_retval_eq_0 $?
else
  failed_result
fi

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-w /var/log/sudo.log -p wa -k actions" > /etc/audit/rules.d/auditsudo.rules 2> /dev/null
	HARD_OUTPUT1=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT2=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] ;then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#################################################################
# 4.1.15 Ensure kernel module loading and unloading is collected#
#################################################################
header "60-Ensure kernel module loading and unloading is collected"
OUTPUT_MSG "60-Ensure kernel module loading and unloading is collected"
msg "grep modules /etc/audit/rules.d/*.rules"
audit_response=0
grep -s modules /etc/audit/rules.d/*.rules | grep -e "-w /sbin/insmod -p x -k modules" &> /dev/null
audit_response_check $?
grep -s modules /etc/audit/rules.d/*.rules | grep -e "-w /sbin/rmmod -p x -k modules" &> /dev/null
audit_response_check $?
grep -s modules /etc/audit/rules.d/*.rules | grep -e "-w /sbin/modprobe -p x -k modules" &> /dev/null
audit_response_check $?
grep -s modules /etc/audit/rules.d/*.rules | grep -e "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" &> /dev/null
audit_response_check $?
if [ $audit_response -eq 4 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result
fi
msg "auditctl -l | grep modules" 
audit_response=$(auditctl -l | grep "modules" | wc -l 2>&1)
if [ $audit_response -ge 4 ];then
  success_result
  OUTPUTRESULT=$((OUTPUTRESULT+1))
else
  failed_result	
fi

#hardening
SUCCESS_VALUE=2
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    echo "-w /sbin/insmod -p x -k modules" > /etc/audit/rules.d/modules.rules 2> /dev/null
	HARD_OUTPUT1=$?
	echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/modules.rules 2> /dev/null
	HARD_OUTPUT2=$?
	echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/modules.rules 2> /dev/null
	HARD_OUTPUT3=$?
	echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/modules.rules 2> /dev/null
	HARD_OUTPUT4=$?
	# level 2
	systemctl restart auditd &> /dev/null
	HARD_OUTPUT5=$?
	#level 3
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ] && [ $HARD_OUTPUT3 -eq 0 ] && [ $HARD_OUTPUT4 -eq 0 ] && [ $HARD_OUTPUT5 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

######################################
# 4.2.1.1 Ensure rsyslog is installed#
######################################
header "61-Ensure rsyslog is installed"
OUTPUT_MSG "61-Ensure rsyslog is installed"
msg "rpm -q rsyslog"
rpm -q rsyslog &> /dev/null
check_retval_eq_0 $?

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    yum install rsyslog -y &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#############################################
# 4.2.1.2 Ensure rsyslog Service is enabled #
#############################################
header "62-Ensure rsyslog Service is enabled"
OUTPUT_MSG "62-Ensure rsyslog Service is enabled"
msg "systemctl is-enabled rsyslog"
systemctl is-enabled rsyslog &> /dev/null
check_retval_eq_0 $?

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    systemctl --now enable rsyslog &> /dev/null
	if [ $? -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

#############################################################
# 4.2.1.3 Ensure rsyslog default file permissions configured#
#############################################################
header "63-Ensure rsyslog default file permissions configured"
OUTPUT_MSG "63-Ensure rsyslog default file permissions configured"
msg "grep -i ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
grep -i "^\$filecreatemode" /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep -Ei "$filecreatemode\s0640" &> /dev/null
check_retval_eq_0 $?

#hardening
SUCCESS_VALUE=1
if [ $OUTPUTRESULT -eq $SUCCESS_VALUE ];then
   OUTPUT_preset_result
else
    # level 1
    FILE=/etc/rsyslog.conf
    if [ -f "$FILE" ]; then
	    sed -i '/filecreatemode/Id' /etc/rsyslog.conf 2> /dev/null
	    HARD_OUTPUT1=$?
	    echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
	    HARD_OUTPUT2=$?
    else
		HARD_OUTPUT1=1
		HARD_OUTPUT2=1
	fi
	if [ $HARD_OUTPUT1 -eq 0 ] && [ $HARD_OUTPUT2 -eq 0 ];then
		OUTPUT_success_result
	else
		OUTPUT_failed_result
	fi
fi
OUTPUTRESULT="0"

for (( x=0; x < $(($WIDTH+1)); x++));do
    printf %s '=' >> RHEL7-8_Auditing_Report.txt
done
printf "\n" >> RHEL7-8_Auditing_Report.txt
printf "$RED%$(($WIDTH - 2))s$NC" "FAILED CHECKS: " >> RHEL7-8_Auditing_Report.txt
printf "$RED%4s\n" "$FAILED_CHECKS$NC" >> RHEL7-8_Auditing_Report.txt
printf "$GREEN%$(($WIDTH - 2))s$NC" "PASSED CHECKS: " >> RHEL7-8_Auditing_Report.txt
printf "$GREEN%4s\n" "$PASSED_CHECKS$NC" >> RHEL7-8_Auditing_Report.txt
printf "%$(($WIDTH - 2))s" "TOTAL CHECKS: " >> RHEL7-8_Auditing_Report.txt
printf "$BOLD%4s\n" "$(($PASSED_CHECKS + $FAILED_CHECKS))$NC" >> RHEL7-8_Auditing_Report.txt



for (( x=0; x < $(($WIDTH+6)); x++));do
    printf %s '=' 
done
printf "\n" 
printf "$RED%$(($WIDTH + 4))s$NC" "FAILED : " 
printf "$RED%4s\n" "$OUTPUT_FAILED_CHECKS$NC" 
printf "$YELLOW%$(($WIDTH + 4))s$NC" "SETMANUALLY : " 
printf "$YELLOW%4s\n" "$OUTPUT_SETMANUALLY_CHECKS$NC" 
printf "$GREEN%$(($WIDTH + 4))s$NC" "PASSED : " 
printf "$GREEN%4s\n" "$OUTPUT_PASSED_CHECKS$NC"
printf "$CYAN%$(($WIDTH + 4))s$NC" "PRESET : " 
printf "$CYAN%4s\n" "$OUTPUT_PRESET_CHECKS$NC"
printf "Audit Report Created:$BOLD RHEL7-8_Auditing_Report.txt$NC                                          total : "
printf "$BOLD%4s\n" "$(($OUTPUT_PASSED_CHECKS + $OUTPUT_FAILED_CHECKS + $OUTPUT_SETMANUALLY_CHECKS + $OUTPUT_PRESET_CHECKS))$NC"
printf "\n"
