#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
#########################

BURIQ () {
    curl -sS https://raw.githubusercontent.com/IMMANVPN/access/main/ip > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
    exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
    d1=(`date -d "$exp" +%s`)
    d2=(`date -d "$biji" +%s`)
    exp2=$(( (d1 - d2) / 86400 ))
    if [[ "$exp2" -le "0" ]]; then
    echo $user > /etc/.$user.ini
    else
    rm -f /etc/.$user.ini > /dev/null 2>&1
    fi
    done
    rm -f /root/tmp
}

MYIP=$(curl -sS ipv4.icanhazip.com)
Name=$(curl -sS https://raw.githubusercontent.com/IMMANVPN/access/main/ip | grep $MYIP | awk '{print $2}')
echo $Name > /usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman () {
if [ -f "/etc/.$Name.ini" ]; then
CekTwo=$(cat /etc/.$Name.ini)
    if [ "$CekOne" = "$CekTwo" ]; then
        res="Expired"
    fi
else
res="Permission Accepted..."
fi
}

PERMISSION () {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    IZIN=$(curl -sS https://raw.githubusercontent.com/IMMANVPN/access/main/ip | awk '{print $4}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
    Bloman
    else
    res="Permission Denied!"
    fi
    BURIQ
}
clear
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
PERMISSION
if [ -f /home/needupdate ]; then
red "Your script need to update first !"
exit 0
elif [ "$res" = "Permission Accepted..." ]; then
echo -ne
else
red "Permission Denied!"
exit 0
fi

[[ ! -f "/etc/IP" ]] && wget -qO- ipv4.icanhazip.com > /etc/IP
cekray=`cat /root/log-install.txt | grep -ow "XRAY" | sort | uniq`
if [ "$cekray" = "XRAY" ]; then
domen=`cat /etc/xray/domain`
raycheck='xray'
else
domen=`cat /etc/v2ray/domain`
raycheck='v2ray'
fi

PID=`ps -ef |grep -v grep | grep sshws |awk '{print $2}'`
if [[ ! -z ${PID} ]]; then
IPs="$domen"
else
IPs=$(cat /etc/IP)
fi
[[ ! -d /var/lib/scrz-prem ]] && exit 0
[[ ! -f /etc/.maAsiss/res_token ]] && touch /etc/.maAsiss/res_token
[[ ! -f /etc/.maAsiss/user_flood ]] && touch /etc/.maAsiss/user_flood
[[ ! -f /etc/.maAsiss/log_res ]] && touch /etc/.maAsiss/log_res
[[ ! -f /etc/.maAsiss/User_Generate_Token ]] && touch /etc/.maAsiss/User_Generate_Token
[[ ! -d /etc/.maAsiss/.cache ]] && mkdir /etc/.maAsiss/.cache
[[ ! -f /etc/.maAsiss/.cache/StatusDisable ]] && {
touch /etc/.maAsiss/.cache/StatusDisable
cat <<-EOF >/etc/.maAsiss/.cache/StatusDisable
SSH : [ON]
VLESS : [ON]
EOF
}

source /root/ResBotAuth
source /etc/.maAsiss/.Shellbtsss
User_Active=/etc/.maAsiss/list_user
User_Token=/etc/.maAsiss/User_Generate_Token
Res_Token=/etc/.maAsiss/res_token
User_Flood=/etc/.maAsiss/user_flood

ShellBot.init --token $Toket --monitor --return map --flush
ShellBot.username
echo "Admin ID = $Admin_ID"
admin_bot_panel=$(grep -w "admin_panel" /etc/.maAsiss/bot.conf | awk '{print $NF}')
_limTotal=$(grep -w "limite_trial" /etc/.maAsiss/bot.conf | awk '{print $NF}')
nameStore=$(grep -w "store_name" /etc/.maAsiss/bot.conf | awk '{print $NF}')
rm -f /tmp/authToken 
rm -f /tmp/authAdmin

AUTOBLOCK() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" != '1' ]] && {
   Max=9
   [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
   return 0
   } || [[ "$(grep -w "${message_from_id}" $User_Active | grep -wc 'reseller')" != '1' ]] && {
   echo $message_date + $Max | bc >> /etc/.maAsiss/.cache/$message_chat_id
   [[ "$(grep -wc "$message_date" "/etc/.maAsiss/.cache/$message_chat_id")" = '1' ]] && {
         echo "$message_chat_id" >> /etc/.maAsiss/user_flood
         rm -f /etc/.maAsiss/.cache/$message_chat_id
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "Youre flooding im sorry to block you\nThis ur ID: <code>${message_chat_id[$id]}</code>\n\nContact $admin_bot_panel to unblock" \
             --parse_mode html
         ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
         return 0
      }
    }
  }
}

Disable_Order() {
   [[ "${message_from_id[$id]}" == "$Admin_ID" ]] && {
     ShellBot.deleteMessage	--chat_id ${message_chat_id[$id]} \
              --message_id ${message_message_id[$id]}
              
     [[ "$(grep -wc "ssh" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderSSH
         sed -i "/SSH/c\SSH : [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled SSH" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ "$(grep -wc "vless" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderVLESS
         sed -i "/VLESS/c\VLESS : [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled VLess" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ -f /tmp/msgid ]] && {
     while read msg_id; do
         ShellBot.deleteMessage	--chat_id ${message_chat_id[$id]} \
              --message_id $msg_id
     done <<<"$(cat /tmp/msgid)"
     rm -f /tmp/msgid
     }
     [[ "$(grep -wc "off" "/tmp/order")" = '1' ]] && {         
         rm -f /etc/.maAsiss/.cache/DisableOrderSSH
         rm -f /etc/.maAsiss/.cache/DisableOrderVLESS        
         sed -i "s/\[OFF\]/\[ON\]/g" /etc/.maAsiss/.cache/StatusDisable
         bdx=$(echo ${message_message_id[$id]} + 1 | bc)
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "☑️ Successfully Enabled Order ☑️" \
             --parse_mode html
         sleep 1
         ShellBot.deleteMessage	--chat_id ${message_chat_id[$id]} \
              --message_id $bdx
     } 
  }
}

about_server() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" = '1' ]] && return 0 || AUTOBLOCK
ISP=`curl -sS ip-api.com | grep -w "isp" | awk '{print $3,$4,$5,$6,$7,$8,$9}' | cut -d'"' -f2 | cut -d',' -f1 | tee -a /etc/afak.conf`
CITY=`curl -sS ip-api.com | grep -w "city" | awk '{print $3}' | cut -d'"' -f2 | tee -a /etc/afak.conf`
WKT=`curl -sS ip-api.com | grep -w "timezone" | awk '{print $3}' | cut -d'"' -f2 | tee -a /etc/afak.conf`
IPVPS=`curl -sS ip-api.com | grep -w "query" | awk '{print $3}' | cut -d'"' -f2 | tee -a /etc/afak.conf`

    local msg
    msg="<b>Server Information</b>\n\n"
    msg+="<code>ISP  : $ISP\n"
    msg+="CITY : $CITY\n"
    msg+="TIME : $WKT\n"
    msg+="IP.  : $IPVPS</code>\n"
    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
        --text "$msg" \
        --parse_mode html
    return 0
}

msg_welcome() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" = '1' ]] && return 0 || AUTOBLOCK
[[ "$(grep -wc ${message_chat_id[$id]} $User_Token)" = '0' ]] && {
r1=$(tr -dc A-Za-z </dev/urandom | head -c 4)
r2=$(tr -dc A-Za-z </dev/urandom | head -c 2)
r3=$(tr -dc A-Za-z </dev/urandom | head -c 3)
r4=$(tr -dc A-Za-z </dev/urandom | head -c 1)
r5=$(tr -dc A-Za-z </dev/urandom | head -c 5)
r6=$(tr -dc A-Za-z </dev/urandom | head -c 2)
r7=$(tr -dc A-Za-z </dev/urandom | head -c 4)
r8=$(tr -dc A-Za-z </dev/urandom | head -c 2)
r9=$(tr -dc A-Za-z </dev/urandom | head -c 4)
fcm=$(echo ${message_from_id[$id]} | sed 's/\([0-9]\{2,\}\)\([0-9]\)\([0-9]\)\([0-9]\)\([0-9]\)\([0-9]\)\([0-9]\)\([0-9]\)/\1'$r1'\2'$r2'\3'$r3'\4'$r4'\5'$r5'\6'$r6'\7'$r7'\8'$r8'/ig' | rev)
echo "ID_User : ${message_chat_id[$id]} Token : $fcm" >> /etc/.maAsiss/User_Generate_Token
} || {
fcm=$(grep -w ${message_chat_id[$id]} $User_Token | awk '{print $NF}')
}

local msg
msg="===========================\n"
msg+="Welcome <b>${message_from_first_name[$id]}</b>\n\n"
msg+="To access the menu [ /menu ]\n"
msg+="To see server information [ /info ]\n"
msg+="for any questions, contact admin @ownerimmanvpn\n\n"
msg+="===========================\n"
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
msg+="<b>Acces Token:</b>\n"
msg+="<code>$fcm</code>\n"
msg+="===========================\n"
} 
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
     --text "$(echo -e $msg)" \
     --parse_mode html
return 0
}

menu_func() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" = '1' ]] && return 0 || AUTOBLOCK
hargassh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
hargavless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')

     env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💲Price List :💲\n"
        env_msg+="<code>SSH            : $hargassh\n"
        env_msg+="VLess          : $hargavless\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🤵 Admin Panel : $admin_bot_panel 🤵\n"
        env_msg+="💡 Limit Trial : $_limTotal users 💡\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💰 Current Balance : RM $_SaldoTotal 💰\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} --text "$env_msg" \
            --reply_markup "$menu_re_main_updater1" \
            --parse_mode html
        return 0
    else
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "===========================\n⛔ ACCESS DENIED ⛔\n===========================\n\nfor register to be a reseller contact : $admin_bot_panel\n\n===========================\nBot Panel By : @IMMANVPN\n===========================\n"
        return 0
    fi
}

menu_func_cb() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] && {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu')"
        return 0
    }
    if [[ "$(grep -w "${message_from_id}" $User_Active | grep -wc 'reseller')" != '0' ]]; then
        _SaldoTotal=$(grep -w 'Saldo_Reseller' /etc/.maAsiss/db_reseller/${callback_query_from_id}/${callback_query_from_id} | awk '{print $NF}')       

[[ ! -f "/etc/.maAsiss/update-info" ]] && {
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
} || {
   inf=$(cat /etc/.maAsiss/update-info)
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="🏷 Information for reseller :\n\n"
   env_msg+="$inf\n\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
}
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re_main')"
        return 0
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

info_port() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        portssh=$(grep -w "OpenSSH" /root/log-install.txt | awk '{print $NF}')
        portsshws=$(grep -w "SSH Websocket" /root/log-install.txt | awk '{print $5,$6}')
        portovpn=$(grep -w " OpenVPN" /root/log-install.txt | awk '{print $4,$5,$6,$7,$8,$9,$10}')
        portssl=$(grep -w "Stunnel4" /root/log-install.txt | awk '{print $4,$5,$6,$7}')
        portdb=$(grep -w "Dropbear" /root/log-install.txt | awk '{print $4,$5,$6,$7}')
        portsqd=$(grep -w "Squid Proxy" /root/log-install.txt | awk '{print $5,$6}')
        portudpgw=$(grep -w "Badvpn" /root/log-install.txt | awk '{print $4}')
        portnginx=$(grep -w "Nginx" /root/log-install.txt | awk '{print $NF}')
        slowdns=$(grep -w "SlowDNS" /root/log-install.txt | awk '{print $NF}')
        portvlesstls=$(grep -w "Vless TLS" /root/log-install.txt | awk '{print $NF}')
        portvless=$(grep -w "Vless None TLS" /root/log-install.txt | awk '{print $NF}')
        OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
        OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
        OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
        wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`
                        
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="OpenSSH : $portssh\n"
        env_msg+="SSH-WS : $portsshws\n"
        env_msg+="SSH-WS-SSL : $wsssl\n"
        env_msg+="OHP SSH : $OhpSSH\n"
        env_msg+="OHP Dropbear : $OhpDB\n"
        env_msg+="OHP OpenVPN : $OhpOVPN\n"
        env_msg+="OpenVPN : $portovpn\n"
        env_msg+="Stunnel : $portssl\n"
        env_msg+="Dropbear : $portdb\n"
        env_msg+="Squid Proxy : $portsqd\n"
        env_msg+="Badvpn : $portudpgw\n"
        env_msg+="Nginx : $portnginx\n"
        env_msg+="SlowDNS : $slowdns\n"
        env_msg+="Vless TLS : $portvlesstls\n"
        env_msg+="Vless HTTP : $portvless\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu')"
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

admin_price_see() {
hargassh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
hargavless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')

[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💲Price List :💲\n"
        env_msg+="<code>SSH            : $hargassh\n"
        env_msg+="VLess          : $hargavless\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu_admin')"
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

admin_service_see() {
[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_adm_ser')"
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

menu_reserv() {
        stsSSH=$(grep -w "SSH" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsVLESS=$(grep -w "VLESS" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🟢 Status Order : \n\n"
        env_msg+="<code>SSH            : $stsSSH\n"
        env_msg+="VLess          : $stsVLESS\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re_ser')"
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

status_order() {
        stsSSH=$(grep -w "SSH" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsVLESS=$(grep -w "VLESS" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🟢 Status Order : \n\n"
        env_msg+="<code>SSH            : $stsSSH\n"
        env_msg+="VLess          : $stsVLESS\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'status_disable')" \
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

how_to_order() {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💡 How to use : [code] \n\n"
        env_msg+="<code>SSH            : ssh\n"
        env_msg+="VLess          : vless\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="usage: /disable[space][code]\n"
        env_msg+="example: <code>/disable ssh</code>\n\n"
        env_msg+="note: you can use multiple args\n"
        env_msg+="example: <code>/disable ssh ssr trojan trgo</code>\n\n"
        env_msg+="usage: /disable[space][off] to turn off\n"
        env_msg+="example: <code>/disable off</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'status_how_to')" \
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

see_log() {
    beha=$(cat /etc/.maAsiss/log_res)
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$beha</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
    [[ "$(cat /etc/.maAsiss/log_res | wc -l)" = '0' ]] && {
    ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ No Information Available ⛔"
         return 0
    } || {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu_admin')" \
        return 0
    }
  } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

res_opener() {
[[ ! -f "/etc/.maAsiss/update-info" ]] && {
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
} || {
   inf=$(cat /etc/.maAsiss/update-info)
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="🏷 Information for reseller :\n\n"
   env_msg+="$inf\n\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
}

    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re_main')"
        return 0
    } || {
    ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

res_closer() {
hargassh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
hargavless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')

    if [[ "$(grep -w "${message_from_id}" $User_Active | grep -wc 'reseller')" != '0' ]]; then
        _SaldoTotal=$(grep -w 'Saldo_Reseller' /etc/.maAsiss/db_reseller/${callback_query_from_id}/${callback_query_from_id} | awk '{print $NF}')       
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💲Price List :💲\n"
        env_msg+="<code>SSH            : $hargassh\n"
        env_msg+="VLess          : $hargavless\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🤵 Admin Panel : $admin_bot_panel 🤵\n"
        env_msg+="💡 Limit Trial : $_limTotal users💡\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💰 Current Balance : $_SaldoTotal 💰\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re_main_updater')"
        return 0
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

user_already_exist() {
    userna=$1
   if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        datata=$(find /etc/.maAsiss/ -name $userna | sort | uniq | wc -l)
        for accc in "${datata[@]}"
        do
             _resl=$accc
        done  
        _results=$(echo $_resl)
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        datata=$(find /etc/.maAsiss/ -name $userna | sort | uniq | wc -l)
        for accc in "${datata[@]}"
        do
             _resl=$accc
        done  
        _results=$(echo $_resl)
      fi
      [[ "$_results" != "0" ]] && {
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ User $userna already exist , try other username " \
                --parse_mode html
         ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "Func Error Do Nothing" \
                --reply_markup "$(ShellBot.ForceReply)"
         return 0
      }   
}

adduser_ssh() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

cret_user() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSSH ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order SSH" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
    file_user=$1
    userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
    passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
    data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
    exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)

    if /usr/sbin/useradd -M -N -s /bin/false $userna -e $exp; then
        (echo "${passw}";echo "${passw}") | passwd "${userna}"
    else
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ ERROR CREATING USER" \
                --parse_mode html
        return 0
    fi
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
        saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
        if [ "$saldores" -lt "$pricessh" ]; then
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Your Balance Not Enough" \
                --parse_mode html
            return 0
        else
            echo "$userna:$passw:$info_data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
            echo "$userna:$passw:$info_data" >/etc/.maAsiss/info-users/$userna
            _CurrSal=$(echo $saldores - $pricessh | bc)
            sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
            sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active
            echo "$userna:$passw 30Days SSH | ${message_from_username}" >> /etc/.maAsiss/log_res
        fi
    }
}

12month_user() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSSH ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order SSH" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
    file_user=$1
    userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
    passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
    data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
    exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
   
     if /usr/sbin/useradd -M -N -s /bin/false $userna -e $exp; then
        (echo "${passw}";echo "${passw}") | passwd "${userna}"
    else
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ ERROR CREATING USER")" \
                --parse_mode html
        return 0
    fi

    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
        saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
        urday=$(echo $pricessh * 2 | bc)
        if [ "$saldores" -lt "$urday" ]; then
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Your Balance Not Enough " \
                --parse_mode html
            return 0
        else
            echo "$userna:$passw:$info_data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
            echo "$userna:$passw:$info_data" >/etc/.maAsiss/info-users/$userna
            _CurrSal=$(echo $saldores - $urday | bc)
            sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
            sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active
            echo "$userna:$passw 365Days SSH | ${message_from_username}" >> /etc/.maAsiss/log_res
        fi
    }
}

del_ssh() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_ssh() {
    userna=$1
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        userdel --force "$userna" 2>/dev/null
        kill-by-user $userna
rm /root/login-db.txt > /dev/null 2>&1
rm /root/login-db-pid.txt > /dev/null 2>&1
    } || {
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'
            return 0
        }
        userdel --force "$userna" 2>/dev/null
        rm /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
        rm /etc/.maAsiss/info-users/$userna
        kill-by-user $userna
        
rm /root/login-db.txt > /dev/null 2>&1
rm /root/login-db-pid.txt > /dev/null 2>&1
    }
}

info_users_ssh() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        arq_info=/tmp/$(echo $RANDOM)
        fun_infu() {
            local info
            for user in $(cat /etc/passwd | awk -F : '$3 >= 1000 {print $1}' | grep -v nobody); do
                info='━━━━━━━━━━━━━━━━━━━━━\n'
                datauser=$(chage -l $user | grep -i co | awk -F : '{print $2}')
                [[ $datauser = ' never' ]] && {
                    data="Never"
                } || {
                    databr="$(date -d "$datauser" +"%Y%m%d")"
                    hoje="$(date -d today +"%Y%m%d")"
                    [[ $hoje -ge $databr ]] && {
                        data="Expired"
                    } || {
                        dat="$(date -d"$datauser" '+%Y-%m-%d')"
                        data=$(echo -e "$((($(date -ud $dat +%s) - $(date -ud $(date +%Y-%m-%d) +%s)) / 86400)) Days")
                    }
                }
                info+="$user • $data"
                echo -e "$info"
            done
        }
        fun_infu >$arq_info
        while :; do
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id $Admin_ID \
                --text "$(while read line; do echo $line; done < <(sed '1,30!d' $arq_info))" \
                --parse_mode html
            sed -i 1,30d $arq_info
            [[ $(cat $arq_info | wc -l) = '0' ]] && rm $arq_info && break
        done
    elif [[ "$(grep -wc "${callback_query_from_id}" $User_Active)" != '0' ]]; then
        [[ $(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_by_res | wc -l) == '0' ]] && {
            ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "YOU HAVE NOT CREATED A USER YET!"
            return 0
        }
        arq_info=/tmp/$(echo $RANDOM)
        fun_infu() {
            local info
            for user in $(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_by_res); do
                info='━━━━━━━━━━━━━━━━━━━━━\n'
                datauser=$(chage -l $user | grep -i co | awk -F : '{print $2}')
                [[ $datauser = ' never' ]] && {
                    data="Never"
                } || {
                    databr="$(date -d "$datauser" +"%Y%m%d")"
                    hoje="$(date -d today +"%Y%m%d")"
                    [[ $hoje -ge $databr ]] && {
                        data="Expired"
                    } || {
                        dat="$(date -d"$datauser" '+%Y-%m-%d')"
                        data=$(echo -e "$((($(date -ud $dat +%s) - $(date -ud $(date +%Y-%m-%d) +%s)) / 86400)) Days")
                    }
                }
                info+="$user • $data"
                echo -e "$info"
            done
        }
        fun_infu >$arq_info
        while :; do
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "$(while read line; do echo $line; done < <(sed '1,30!d' $arq_info))" \
                --parse_mode html
            sed -i 1,30d $arq_info
            [[ $(cat $arq_info | wc -l) = '0' ]] && rm $arq_info && break
        done
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

renew_ssh() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "⏳ Renew SSH ⏳\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_renew_ssh() {
    userna=$1
    inputdate=$2
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        [[ "$(echo -e "$inputdate" | sed -e 's/[^/]//ig')" != '//' ]] && {
            udata=$(date "+%d/%m/%Y" -d "+$inputdate days")
            sysdate="$(echo "$udata" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
        } || {
            udata=$(echo -e "$inputdate")
            sysdate="$(echo -e "$inputdate" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
            today="$(date -d today +"%Y%m%d")"
            timemachine="$(date -d "$sysdate" +"%Y%m%d")"
            [ $today -ge $timemachine ] && {
                verify='1'
                ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Date Invalid" \
                    --parse_mode html
                _erro='1'
                return 0
            }
        }
        chage -E $sysdate $userna
        [[ -e /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna ]] && {
            data2=$(cat /etc/.maAsiss/info-users/$userna | awk -F : {'print $3'})
            sed -i "s;$data2;$udata;" /etc/.maAsiss/info-users/$userna
            echo $userna $udata ${message_from_id}
            sed -i "s;$data2;$udata;" /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
        }
    elif [[ "$(grep -wc "${callback_query_from_id}" $User_Active)" != '0' ]]; then
        [[ "$(echo -e "$inputdate" | sed -e 's/[^/]//ig')" != '//' ]] && {
            udata=$(date "+%d/%m/%Y" -d "+$inputdate days")
            sysdate="$(echo "$udata" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
         } || {
            udata=$(echo -e "$inputdate")
            sysdate="$(echo -e "$inputdate" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
            today="$(date -d today +"%Y%m%d")"
            timemachine="$(date -d "$sysdate" +"%Y%m%d")"
            [ $today -ge $timemachine ] && {
                verify='1'
                ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Date Invalid" \
                    --parse_mode html
                _erro='1'
                return 0
            }
         }
         chage -E $sysdate $userna
         [[ -e /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna ]] && {
            pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
            saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
            if [ "$saldores" -lt "$pricessh" ]; then
                ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Your Balance Not Enough ⛔" \
                    --parse_mode html
                return 0
            else
                data2=$(cat /etc/bot/info-users/$userna | awk -F : {'print $3'})
                sed -i "s;$data2;$udata;" /etc/.maAsiss/info-users/$userna
                echo $userna $udata ${message_from_id}
                sed -i "s;$data2;$udata;" /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
                _CurrSal=$(echo $saldores - $pricessh | bc)
                sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
                sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active
            fi
         }
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

add_ssh_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL SSH 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL SSH 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_ssh_trial() {
    mkdir -p /etc/.maAsiss/info-users
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSSH ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order SSH" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    password='1'
    t_time=$1
    ex_date=$(date '+%d/%m/%C%y' -d " +2 days")
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }
    /usr/sbin/useradd -M -N -s /bin/false $userna -e $tuserdate >/dev/null 2>&1
    (
        echo "$password"
        echo "$password"
    ) | passwd $userna >/dev/null 2>&1
    echo "$password" >/etc/.maAsiss/$userna
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        echo "$userna:$password:$ex_date" >/etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
        echo "$userna:$password:$ex_date" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
    }
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL SSH by ${message_from_id} $dates
kill-by-user $userna
userdel --force $userna
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2

rm /root/login-db.txt > /dev/null 2>&1
rm /root/login-db-pid.txt > /dev/null 2>&1
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF
    chmod +x /etc/.maAsiss/$userna.sh
    echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
    [[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"
        ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
        opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
        db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
        ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
        sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
        ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
        ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
        portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
        wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`
        OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
        OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
        OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`

        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 TRIAL SSH ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="Host : $IPs \n"
        env_msg+="Username: <code>$userna</code>\n"
        env_msg+="Password: 1\n"
        env_msg+="Expired On: $t_time $hrs ⏳\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="OpenSSH : $opensh\n"
        env_msg+="Dropbear : $db\n"
        env_msg+="SSH-WS : $portsshws\n"
        env_msg+="SSH-WS-SSL : $wsssl\n"
        env_msg+="SSL/TLS : $ssl\n"
        env_msg+="Port Squid : $sqd\n"
        env_msg+="OHP SSH : $OhpSSH\n"
        env_msg+="OHP Dropbear : $OhpDB\n"
        env_msg+="OHP OpenVPN : $OhpOVPN\n"
        env_msg+="UDPGW : 7100-7300 \n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="OpenVPN Config : http://$IPs:81/\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="Payload WS : \n\n"
        env_msg+="<code>GET / HTTP/1.1[crlf]Host: $IPs [crlf]Upgrade: websocket[crlf][crlf]</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$env_msg" \
            --parse_mode html
        return 0
}

fun_drop() {
    port_dropbear=$(ps aux | grep dropbear | awk NR==1 | awk '{print $17;}')
    log=/var/log/auth.log
    loginsukses='Password auth succeeded'
    pids=$(ps ax | grep dropbear | grep " $port_dropbear" | awk -F" " '{print $1}')
    for pid in $pids; do
        pidlogs=$(grep $pid $log | grep "$loginsukses" | awk -F" " '{print $3}')
        i=0
        for pidend in $pidlogs; do
            let i=i+1
        done
        if [ $pidend ]; then
            login=$(grep $pid $log | grep "$pidend" | grep "$loginsukses")
            PID=$pid
            user=$(echo $login | awk -F" " '{print $10}' | sed -r "s/'/ /g")
            waktu=$(echo $login | awk -F" " '{print $2"-"$1,$3}')
            while [ ${#waktu} -lt 13 ]; do
                waktu=$waktu" "
            done
            while [ ${#user} -lt 16 ]; do
                user=$user" "
            done
            while [ ${#PID} -lt 8 ]; do
                PID=$PID" "
            done
            echo "$user $PID $waktu"
        fi
    done
}

user_online_ssh() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        cad_onli=/tmp/$(echo $RANDOM)
        fun_online() {
            local info2
            for user in $(cat /etc/passwd | awk -F : '$3 >= 1000 {print $1}' | grep -v nobody); do
                [[ $(netstat -nltp | grep 'dropbear' | wc -l) != '0' ]] && drop="$(fun_drop | grep "$user" | wc -l)" || drop=0
                [[ -e /etc/openvpn/openvpn-status.log ]] && ovp="$(cat /etc/openvpn/openvpn-status.log | grep -E ,"$user", | wc -l)" || ovp=0
                sqd="$(ps -u $user | grep sshd | wc -l)"
                _cont=$(($drop + $ovp))
                conex=$(($_cont + $sqd))
                [[ $conex -gt '0' ]] && {
                    timerr="$(ps -o etime $(ps -u $user | grep sshd | awk 'NR==1 {print $1}') | awk 'NR==2 {print $1}')"
                    info2+="━━━━━━━━━━━━━━━━━━━━━\n"
                    info2+="<code>🟢 $user      ⃣ $conex      ⏳ $timerr</code>\n"
                }
            done
            echo -e "$info2"
        }
        fun_online >$cad_onli
        [[ $(cat $cad_onli | wc -w) != '0' ]] && {
            while :; do
                ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
                     --message_id ${callback_query_message_message_id[$id]}
                ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                    --text "$(while read line; do echo $line; done < <(sed '1,30!d' $cad_onli))" \
                    --parse_mode html
                sed -i 1,30d $cad_onli
                [[ "$(cat $cad_onli | wc -l)" = '0' ]] && {
                    rm $cad_onli
                    break
                }
            done
        } || {
            ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "No users online" \
                --parse_mode html
            return 0
        }
    elif [[ "$(grep -wc "${callback_query_from_id}" $User_Active)" != '0' ]]; then
        [[ $(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_by_res | wc -l) == '0' ]] && {
            ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "YOU HAVE NOT CREATED A USER YET!"
            return 0
        }
        cad_onli=/tmp/$(echo $RANDOM)
        fun_online() {
            local info2
            for user in $(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_by_res); do
                [[ $(netstat -nltp | grep 'dropbear' | wc -l) != '0' ]] && drop="$(fun_drop | grep "$user" | wc -l)" || drop=0
                [[ -e /etc/openvpn/openvpn-status.log ]] && ovp="$(cat /etc/openvpn/openvpn-status.log | grep -E ,"$user", | wc -l)" || ovp=0
                sqd="$(ps -u $user | grep sshd | wc -l)"
                conex=$(($sqd + $ovp + $drop))
                [[ $conex -gt '0' ]] && {
                    timerr="$(ps -o etime $(ps -u $user | grep sshd | awk 'NR==1 {print $1}') | awk 'NR==2 {print $1}')"
                    info2+="━━━━━━━━━━━━━━━━━━━━━\n"
                    info2+="<code>👤 $user      ⃣ $conex      ⏳ $timerr</code>\n"
                }
            done
            echo -e "$info2"
        }
        fun_online >$cad_onli
        [[ $(cat $cad_onli | wc -w) != '0' ]] && {
            while :; do
                ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
                    --message_id ${callback_query_message_message_id[$id]}
                ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                    --text "<code>$(while read line; do echo $line; done < <(sed '1,30!d' $cad_onli))</code>" \
                    --parse_mode html
                sed -i 1,30d $cad_onli
                [[ "$(cat $cad_onli | wc -l)" = '0' ]] && {
                    rm $cad_onli
                    break
                }
            done
        } || {
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "No users online" \
                --parse_mode html
            return 0
        }
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

Saldo_CheckerSSH() {
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
        saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
        if [ "$saldores" -lt "$pricessh" ]; then
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Your Balance Not Enough ⛔" \
                --parse_mode html
            _erro="1"
            return 0
        else
            echo
        fi
    }
}

Saldo_CheckerSSH12Month() {
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
        saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
        urday=$(echo $pricessh * 2 | bc)
        if [ "$saldores" -lt "$urday" ]; then
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Your Balance Not Enough ⛔" \
                --parse_mode html
            _erro="1"
            return 0
        else
            echo
        fi
    }
}

verifica_acesso() {
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        [[ "$(grep -wc ${message_from_id} $User_Active)" == '0' ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "WTF !! Whooo Are You ???")" \
                            --parse_mode html
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
    }
}

ssh_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu1')"
        return 0
    }
}

add_res(){
        gg=$(cat $Res_Token | awk '{print $2}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> List name reseller</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$gg</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$env_msg" \
                --parse_mode html 
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👥 ADD Reseller 👥\n\nEnter the name:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

cret_res() {
    file_res=$1
    [[ -z "$file_res" ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e Error)"
        _erro='1'
        break
    }
    name_res=$(sed -n '1 p' $file_res | cut -d' ' -f2)
    uname_res=$(sed -n '2 p' $file_res | cut -d' ' -f2)
    saldo_res=$(sed -n '3 p' $file_res | cut -d' ' -f2)
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        t_res='reseller'
    }
    Token=$(cat /tmp/scvpsss)
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_by_res
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/trial-fold
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_vless
    touch /etc/.maAsiss/db_reseller/"$uname_res"/$uname_res
    echo -e "USER: $uname_res SALDO: $saldo_res TYPE: $t_res" >>$User_Active
    echo -e "Name: $name_res TOKEN: $Token" >> $Res_Token
    echo -e "=========================\nSaldo_Reseller: $saldo_res\n=========================\n" >/etc/.maAsiss/db_reseller/"$uname_res"/$uname_res
    sed -i '$d' $file_res
    
    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
           --text "✅ Successfully Added Reseller. ✅\n\n<b>Name </b>: $name_res\n<b>Token </b>: $Token\n<b>Saldo </b>: $saldo_res\n\n<b>BOT </b>: @${message_reply_to_message_from_username}" \
           --parse_mode html
    return 0
}

del_res() {
    gg=$(cat $Res_Token | awk '{print $2}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> List name reseller</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$gg</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$env_msg" \
                --parse_mode html 
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE Reseller 🗑\n\nInput Name of Reseller:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_res() {
    _cli_rev=$1
    [[ -z "$_cli_rev" ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "Error")"
        return 0
    }
    cek_res_token=$(grep -w "$_cli_rev" "$Res_Token" | awk '{print $NF}' | sed -e 's/[^0-9]//ig'| rev)
    [[ "${message_from_id[$id]}" == "$Admin_ID" ]] && {
        [[ "$(grep -wc "$cek_res_token" $User_Active)" != '0' ]] && {
            [[ -e "/etc/.maAsiss/db_reseller/$cek_res_token/$cek_res_token" ]] && _dirsts='db_reseller' || _dirsts='suspensos'
            [[ "$(ls /etc/.maAsiss/$_dirsts/$cek_res_token/user_by_res | wc -l)" != '0' ]] && {
                for _user in $(ls /etc/.maAsiss/$_dirsts/$cek_res_token/user_by_res); do
                    userdel --force "$_user" 2>/dev/null
                    kill-by-user $_user
                done
            }
            
            rm /root/login-db.txt > /dev/null 2>&1
            rm /root/login-db-pid.txt > /dev/null 2>&1
            sed -i "/\b$_cli_rev\b/d" $Res_Token
            [[ -d /etc/.maAsiss/$_dirsts/$cek_res_token ]] && rm -rf /etc/.maAsiss/$_dirsts/$cek_res_token >/dev/null 2>&1
            sed -i "/\b$cek_res_token\b/d" $User_Active
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "✅ SUCCESSFULLY REMOVED ✅")" \
                --parse_mode html
            return 0
        } || {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e ⛔ Reseller DOES NOT EXIST ⛔)"
            return 0
        }
    }
}

reset_saldo_res() {
    gg=$(cat $Res_Token | awk '{print $2}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> List </b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$gg</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$env_msg" \
                --parse_mode html 
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🌀 Reset Saldo Reseller 🌀\n\nInput Name of Reseller:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_reset_saldo_res() {
    _cli_rev=$(cat /tmp/resSaldo | awk '{print $NF}' | sed -e 's/[^0-9]//ig'| rev)
    [[ -z "$_cli_rev" ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "Error")"
        return 0
    }
    cek_res_token=$(grep -ow "$_cli_rev" "$User_Active")
    [[ "${message_from_id[$id]}" == "$Admin_ID" ]] && {
       [[ "$(grep -wc "$cek_res_token" $User_Active)" != '0' ]] && {
            sed -i "/Saldo_Reseller/c\Saldo_Reseller: 0" /etc/.maAsiss/db_reseller/"$cek_res_token"/$cek_res_token
            sed -i "/$cek_res_token/c\USER: $cek_res_token SALDO: 0 TYPE: reseller" $User_Active
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "✅ Succesfully Reset Saldo 0 ✅")" \
                --parse_mode html
            rm -f /tmp/resSaldo
            return 0
    
    } || {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e ⛔ Reseller DOES NOT EXIST ⛔)"
        return 0
    }
  }
}

# {name0}](tg://user?id={uid})
func_list_res() {
    if [[ "${callback_query_from_id[$id]}" = "$Admin_ID" ]]; then
        local msg1
        msg1="━━━━━━━━━━━━━━━━━━━━━\n📃 List Reseller !\n━━━━━━━━━━━━━━━━━━━━━\n"
        cek_res_token=$(cat $Res_Token | awk '{print $NF}' | sed -e 's/[^0-9]//ig'| rev)
        gg=$(cat $Res_Token | awk '{print $NF}')
        [[ "$(cat /etc/.maAsiss/res_token | wc -l)" != '0' ]] && {
            while read _atvs; do
                _uativ="$(echo $_atvs | awk '{print $2}')"
                _cursald="$(echo $_atvs | awk '{print $4}')"
                msg1+="• [Reseller](tg://user?id=$_uativ) | • $_cursald \n"
            done <<<"$(grep -w "$cek_res_token" "$User_Active")"
            ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$(echo -e "$msg1")" \
                --parse_mode markdown \
                --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'list_bck_adm')" \
            return 0
        } || {
            ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "YOU DO NOT HAVE RESELLERS"
            return 0
        }
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

topup_res() {
        gg=$(cat $Res_Token | awk '{print $2}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> List name reseller</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$gg</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$env_msg" \
                --parse_mode html 
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "💸 Topup Saldo 💸\n\nName reseller:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_topup_res() {
    userna=$1
    saldo=$2
    _SaldoTotal=$(grep -w 'Saldo_Reseller' /etc/.maAsiss/db_reseller/$userna/$userna | awk '{print $NF}')
    _TopUpSal=$(echo $_SaldoTotal + $saldo | bc)
    sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_TopUpSal" /etc/.maAsiss/db_reseller/$userna/$userna
    sed -i "/$userna/c\USER: $userna SALDO: $_TopUpSal TYPE: reseller" $User_Active
}

func_verif_limite_res() {
    userna=$1
    [[ "$(grep -w "$userna" $User_Active | awk '{print $NF}')" == 'reseller' ]] && {
        echo $_userrev
        _result=$(ls /etc/.maAsiss/db_reseller/$userna/trial-fold | wc -l)       
    }
}

func_limit_publik() {
   getMes=$1
   getLimits=$(grep -w "MAX_USERS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
   _result=$(ls /etc/.maAsiss/public_mode/$getMes | wc -l)
   [[ ! -d /etc/.maAsiss/public_mode ]] && {
       ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
                    --text "⛔ Public mode is off" \
                    --parse_mode html
                ShellBot.sendMessage --chat_id
                return 0
   }
   _result2=$(ls /etc/.maAsiss/public_mode --ignore='settings' | wc -l)
   [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
       [[ "$_result2" -ge "$getLimits" ]] && {
            ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
                    --text "⛔ Max $getLimits Users" \
                    --parse_mode html
                ShellBot.sendMessage --chat_id
                return 0
       }
       [[ "$_result" -ge "1" ]] && {
            ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
                    --text "⛔ Max Limit Create only 1 Users" \
                    --parse_mode html
                ShellBot.sendMessage --chat_id
                return 0
       }
   }
}

res_ssh_menu() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re')"
        return 0
    }
}

unset menu_re
menu_re=''
ShellBot.InlineKeyboardButton --button 'menu_re' --line 1 --text '➕ Add SSH ➕' --callback_data '_add_res_ssh'
ShellBot.InlineKeyboardButton --button 'menu_re' --line 2 --text '🟢 List Member SSH 🟢' --callback_data '_member_res_ssh'
ShellBot.InlineKeyboardButton --button 'menu_re' --line 3 --text '⏳ Create Trial SSH ⏳' --callback_data '_trial_res_ssh'
ShellBot.InlineKeyboardButton --button 'menu_re' --line 4 --text '🔙 Back 🔙' --callback_data '_goback'
ShellBot.regHandleFunction --function adduser_ssh --callback_data _add_res_ssh
ShellBot.regHandleFunction --function info_users_ssh --callback_data _member_res_ssh
ShellBot.regHandleFunction --function add_ssh_trial --callback_data _trial_res_ssh
ShellBot.regHandleFunction --function menu_reserv --callback_data _goback
unset menu_re1
menu_re1="$(ShellBot.InlineKeyboardMarkup -b 'menu_re')"

unset menu1
menu1=''
ShellBot.InlineKeyboardButton --button 'menu1' --line 1 --text 'Add SSH' --callback_data '_add_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 1 --text 'Del SSH' --callback_data '_del_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 2 --text 'Renew SSH' --callback_data '_renew_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 3 --text 'Member SSH' --callback_data '_member_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 3 --text 'User Online' --callback_data '_online_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 4 --text 'Create Trial SSH' --callback_data '_trial_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 5 --text '🔙 Back 🔙' --callback_data '_goback1'
ShellBot.regHandleFunction --function adduser_ssh --callback_data _add_ssh
ShellBot.regHandleFunction --function del_ssh --callback_data _del_ssh
ShellBot.regHandleFunction --function renew_ssh --callback_data _renew_ssh
ShellBot.regHandleFunction --function info_users_ssh --callback_data _member_ssh
ShellBot.regHandleFunction --function user_online_ssh --callback_data _online_ssh
ShellBot.regHandleFunction --function add_ssh_trial --callback_data _trial_ssh
ShellBot.regHandleFunction --function admin_service_see --callback_data _goback1
unset keyboard2
keyboard2="$(ShellBot.InlineKeyboardMarkup -b 'menu1')"


#====== ALL ABOUT V2RAY =======#

res_v2ray_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_vray')"
        return 0
    }
}
v2ray_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_vray')"
        return 0
    }
}

#======= VLESS MENU =========
res_vless_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_vless')"
        return 0
    }
}

vless_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_vless')"
        return 0
    }
}

add_vless() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER VLess 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_vless() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderVLESS ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order VLESS" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
tls="$(cat /root/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-vless
echo "$userna:$data" >/etc/.maAsiss/info-user-vless/$userna

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

case $selected_option in
    "Digi BS") vlesslink="vless://${uuid}@162.159.134.61:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Digi XL") vlesslink="vless://${uuid}@app.optimizely.com:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Umo Funz") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=m.pubgmobile.com#${userna}" ;;
    "Maxis UL") vlesslink="vless://${uuid}@speedtest.net:$none?path=/vlessws&security=$tls%26encryption=none%26type=ws&host=fast.${domain}&sni=speedtest.net#${userna}" ;;
    "Unifi XL") vlesslink="vless://${uuid}@104.17.10.12:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Yes XL") vlesslink="vless://${uuid}@104.17.113.188:$none?path=/vlessws%26encryption=none%26type=ws&host=tap-database.who.int.${domain}#${userna}" ;;
    "Sim BS 1") vlesslink="vless://${uuid}@104.17.148.22:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Sim BS 2") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=www.speedtest.net#${userna}" ;;
    *) vlesslink="Invalid option selected." ;;
esac

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b> 🔸 YOUR ACCOUNT HAS BEEN CREATED 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Name : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="$selected_option : \n"
env_msg+="<code>$vlesslink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html 
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

pricevless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricevless" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-vless
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_vless
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-vless/$userna
_CurrSal=$(echo $saldores - $pricevless | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

case $selected_option in
    "Digi BS") vlesslink="vless://${uuid}@162.159.134.61:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Digi XL") vlesslink="vless://${uuid}@app.optimizely.com:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Umo Funz") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=m.pubgmobile.com#${userna}" ;;
    "Maxis UL") vlesslink="vless://${uuid}@speedtest.net:$none?path=/vlessws&security=$tls%26encryption=none%26type=ws&host=fast.${domain}&sni=speedtest.net#${userna}" ;;
    "Unifi XL") vlesslink="vless://${uuid}@104.17.10.12:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Yes XL") vlesslink="vless://${uuid}@104.17.113.188:$none?path=/vlessws%26encryption=none%26type=ws&host=tap-database.who.int.${domain}#${userna}" ;;
    "Sim BS 1") vlesslink="vless://${uuid}@104.17.148.22:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Sim BS 2") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=www.speedtest.net#${userna}" ;;
    *) vlesslink="Invalid option selected." ;;
esac

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b> 🔸 YOUR ACCOUNT HAS BEEN CREATED 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Name : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="$selected_option : \n"
env_msg+="<code>$vlesslink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days VLESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
fi
}

func_add_vless2() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderVLESS ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order VLESS" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
tls="$(cat /root/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-vless
echo "$userna:$data" >/etc/.maAsiss/info-user-vless/$userna

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

case $selected_option in
    "Digi BS") vlesslink="vless://${uuid}@162.159.134.61:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Digi XL") vlesslink="vless://${uuid}@app.optimizely.com:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Umo Funz") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=m.pubgmobile.com#${userna}" ;;
    "Maxis UL") vlesslink="vless://${uuid}@speedtest.net:$none?path=/vlessws&security=$tls%26encryption=none%26type=ws&host=fast.${domain}&sni=speedtest.net#${userna}" ;;
    "Unifi XL") vlesslink="vless://${uuid}@104.17.10.12:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Yes XL") vlesslink="vless://${uuid}@104.17.113.188:$none?path=/vlessws%26encryption=none%26type=ws&host=tap-database.who.int.${domain}#${userna}" ;;
    "Sim BS 1") vlesslink="vless://${uuid}@104.17.148.22:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Sim BS 2") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=www.speedtest.net#${userna}" ;;
    *) vlesslink="Invalid option selected." ;;
esac

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b> 🔸 YOUR ACCOUNT HAS BEEN CREATED 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Name : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="$selected_option : \n"
env_msg+="<code>$vlesslink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html 
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

pricevless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricevless * 2 | bc)
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-vless
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_vless
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-vless/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

case $selected_option in
    "Digi BS") vlesslink="vless://${uuid}@162.159.134.61:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Digi XL") vlesslink="vless://${uuid}@app.optimizely.com:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Umo Funz") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=m.pubgmobile.com#${userna}" ;;
    "Maxis UL") vlesslink="vless://${uuid}@speedtest.net:$none?path=/vlessws&security=$tls%26encryption=none%26type=ws&host=fast.${domain}&sni=speedtest.net#${userna}" ;;
    "Unifi XL") vlesslink="vless://${uuid}@104.17.10.12:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Yes XL") vlesslink="vless://${uuid}@104.17.113.188:$none?path=/vlessws%26encryption=none%26type=ws&host=tap-database.who.int.${domain}#${userna}" ;;
    "Sim BS 1") vlesslink="vless://${uuid}@104.17.148.22:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Sim BS 2") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=www.speedtest.net#${userna}" ;;
    *) vlesslink="Invalid option selected." ;;
esac

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b> 🔸 YOUR ACCOUNT HAS BEEN CREATED 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Name : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="$selected_option : \n"
env_msg+="<code>$vlesslink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 365Days VLESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
fi
}

add_vless_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL VLess 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL VLess 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_vless_trial() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderVLESS ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order VLESS" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}
mkdir -p /etc/.maAsiss/info-user-vless
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    domain=$(cat /etc/$raycheck/domain)
    tls="$(cat /root/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
    none="$(cat /root/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"

    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }
    
echo "$userna:$exp" >/etc/.maAsiss/info-user-vless/$userna
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
  
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL VLESS by ${message_from_id} $dates
exp=\$(grep -wE "^#& $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^#& $userna $exp/,/^},{/d" /etc/$raycheck/config.json
systemctl restart $raycheck > /dev/null 2>&1
rm /etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
rm /etc/.maAsiss/info-user-vless/$userna
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF
chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

case $selected_option in
    "Digi BS") vlesslink="vless://${uuid}@162.159.134.61:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Digi XL") vlesslink="vless://${uuid}@app.optimizely.com:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Umo Funz") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=m.pubgmobile.com#${userna}" ;;
    "Maxis UL") vlesslink="vless://${uuid}@speedtest.net:$none?path=/vlessws&security=$tls%26encryption=none%26type=ws&host=fast.${domain}&sni=speedtest.net#${userna}" ;;
    "Unifi XL") vlesslink="vless://${uuid}@104.17.10.12:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Yes XL") vlesslink="vless://${uuid}@104.17.113.188:$none?path=/vlessws%26encryption=none%26type=ws&host=tap-database.who.int.${domain}#${userna}" ;;
    "Sim BS 1") vlesslink="vless://${uuid}@104.17.148.22:$none?path=/vlessws%26encryption=none%26type=ws&host=${domain}#${userna}" ;;
    "Sim BS 2") vlesslink="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws&host=www.speedtest.net#${userna}" ;;
    *) vlesslink="Invalid option selected." ;;
esac

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b> 🔸 YOUR ACCOUNT HAS BEEN CREATED 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Name : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="$selected_option : \n"
env_msg+="<code>$vlesslink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0

}

renew_vless() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "⏳ Renew VLESS ⏳\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_renew_vless() {
    userna=$1
    inputdate=$2
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        [[ "$(echo -e "$inputdate" | sed -e 's/[^/]//ig')" != '//' ]] && {
            udata=$(date "+%d/%m/%Y" -d "+$inputdate days")
            sysdate="$(echo "$udata" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
        } || {
            udata=$(echo -e "$inputdate")
            sysdate="$(echo -e "$inputdate" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
            today="$(date -d today +"%Y%m%d")"
            timemachine="$(date -d "$sysdate" +"%Y%m%d")"
            [ $today -ge $timemachine ] && {
                verify='1'
                ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Date Invalid" \
                    --parse_mode html
                _erro='1'
                return 0
            }
        }
        chage -E $sysdate $userna
        [[ -e /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna ]] && {
            data2=$(cat /etc/.maAsiss/info-users/$userna | awk -F : {'print $3'})
            sed -i "s;$data2;$udata;" /etc/.maAsiss/info-users/$userna
            echo $userna $udata ${message_from_id}
            sed -i "s;$data2;$udata;" /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
        }
    elif [[ "$(grep -wc "${callback_query_from_id}" $User_Active)" != '0' ]]; then
        [[ "$(echo -e "$inputdate" | sed -e 's/[^/]//ig')" != '//' ]] && {
            udata=$(date "+%d/%m/%Y" -d "+$inputdate days")
            sysdate="$(echo "$udata" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
         } || {
            udata=$(echo -e "$inputdate")
            sysdate="$(echo -e "$inputdate" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
            today="$(date -d today +"%Y%m%d")"
            timemachine="$(date -d "$sysdate" +"%Y%m%d")"
            [ $today -ge $timemachine ] && {
                verify='1'
                ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Date Invalid" \
                    --parse_mode html
                _erro='1'
                return 0
            }
         }
         chage -E $sysdate $userna
         [[ -e /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna ]] && {
            pricevless=$(grep -w "Price VLESS" /etc/.maAsiss/price | awk '{print $NF}')
            saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
            if [ "$saldores" -lt "$pricevless" ]; then
                ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Your Balance Not Enough ⛔" \
                    --parse_mode html
                return 0
            else
                data2=$(cat /etc/bot/info-users/$userna | awk -F : {'print $3'})
                sed -i "s;$data2;$udata;" /etc/.maAsiss/info-users/$userna
                echo $userna $udata ${message_from_id}
                sed -i "s;$data2;$udata;" /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
                _CurrSal=$(echo $saldores - $pricevless | bc)
                sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
                sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active
            fi
         }
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

list_member_vless() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -E "^#& " "/etc/$raycheck/config.json" | cut -d ' ' -f 2 | column -t | sort | uniq | wc -l)
      _results=$(grep -E "^#& " "/etc/$raycheck/config.json" | cut -d ' ' -f 2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_vless | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_vless )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🟢 VLESS MEMBER LIST 🟢 \n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

del_vless() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER VLess 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_vless() {
    userna=$1
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        exp=$(grep -wE "^#& $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^#& $userna $exp/,/^},{/d" /etc/$raycheck/config.json
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        systemctl restart $raycheck > /dev/null 2>&1
    } || {
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -wE "^#& $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^#& $userna $exp/,/^},{/d" /etc/$raycheck/config.json
        rm /etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
        rm /etc/.maAsiss/info-user-vless/$userna
        systemctl restart $raycheck > /dev/null 2>&1
    }
}

check_login_vless(){
if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
echo -n > /tmp/other.txt
data=( `cat /etc/$raycheck/config.json | grep '^#&' | cut -d ' ' -f 2 | sort | uniq`);

echo -e "━━━━━━━━━━━━━━━━━━━━━" > /tmp/vmess-login
echo -e "         🟢 VLess User Login 🟢  " >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login

for akun in "${data[@]}"
do
if [[ -z "$akun" ]]; then
akun="tidakada"
fi

echo -n > /tmp/ipvmess.txt
data2=( `netstat -anp | grep ESTABLISHED | grep tcp6 | grep $raycheck | awk '{print $5}' | cut -d: -f1 | sort | uniq`);
for ip in "${data2[@]}"
do

jum=$(cat /var/log/$raycheck/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
if [[ "$jum" = "$ip" ]]; then
echo "$jum" >> /tmp/ipvmess.txt
else
echo "$ip" >> /tmp/other.txt
fi
jum2=$(cat /tmp/ipvmess.txt)
sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
done

jum=$(cat /tmp/ipvmess.txt)
if [[ -z "$jum" ]]; then
echo > /dev/null
else
jum2=$(cat /tmp/ipvmess.txt | nl)
echo "user : $akun" >> /tmp/vmess-login
echo "$jum2" >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login
fi
rm -rf /tmp/ipvmess.txt
done

oth=$(cat /tmp/other.txt | sort | uniq | nl)
echo "other" >> /tmp/vmess-login
echo "$oth" >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login
rm -rf /tmp/other.txt
msg=$(cat /tmp/vmess-login)
cekk=$(cat /tmp/vmess-login | wc -l)
if [ "$cekk" = "0" ] || [ "$cekk" = "6" ]; then
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ NO USERS ONLINE ⛔" \
                --parse_mode html
rm /tmp/vmess-login
return 0
else
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "$msg" \
         --parse_mode html
rm /tmp/vmess-login
return 0
fi
else
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
return 0
fi
}

res_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menuzzz')" \
        return 0
    }
}

unset menu_vless
menu_vless=''
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 1 --text 'Add VLess' --callback_data '_add_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 2 --text 'Delete VLess' --callback_data '_delete_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 3 --text 'Create Trial VLess' --callback_data '_trial_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 4 --text 'Renew VLess' --callback_data '_renew_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 5 --text 'List Member VLess' --callback_data '_member_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 6 --text 'Check User Login VLess' --callback_data '_login_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 7 --text '🔙 Back 🔙' --callback_data '_gobackvless'
ShellBot.regHandleFunction --function add_vless --callback_data _add_vless
ShellBot.regHandleFunction --function del_vless --callback_data _delete_vless
ShellBot.regHandleFunction --function add_vless_trial --callback_data _trial_vless
ShellBot.regHandleFunction --function renew_vless --callback_data _renew_vless
ShellBot.regHandleFunction --function list_member_vless --callback_data _member_vless
ShellBot.regHandleFunction --function check_login_vless --callback_data _login_vless
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobackvless
unset keyboardvless
keyboardvless="$(ShellBot.InlineKeyboardMarkup -b 'menu_vless')"

unset res_menu_vless
res_menu_vless=''
ShellBot.InlineKeyboardButton --button 'res_menu_vless' --line 1 --text '➕ Add VLess ➕' --callback_data '_res_add_vless'
ShellBot.InlineKeyboardButton --button 'res_menu_vless' --line 3 --text '⏳ Create Trial VLess ⏳' --callback_data '_res_trial_vless'
ShellBot.InlineKeyboardButton --button 'res_menu_vless' --line 4 --text '🟢 List Member VLess 🟢' --callback_data '_res_member_vless'
ShellBot.InlineKeyboardButton --button 'res_menu_vless' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobackvless'
ShellBot.regHandleFunction --function add_vless --callback_data _res_add_vless
ShellBot.regHandleFunction --function add_vless_trial --callback_data _res_trial_vless
ShellBot.regHandleFunction --function list_member_vless --callback_data _res_member_vless
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobackvless
unset keyboardvlessres
keyboardvlessres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_vless')"

#====== SETTINGS DATABASE =======#

Ganti_Harga() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "💰 Change Price 💰\n\nPrice SSH:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

public_mod() {
[[ -f /etc/.maAsiss/public_mode/settings ]] && {
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
     --text "✅ Public mode is already on ✅"
return 0
}
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        [[ ! -d /etc/.maAsiss/public_mode ]] && mkdir /etc/.maAsiss/public_mode
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🌐 Enable Public Mode 🌐\n\nExpired Days [ex:3]:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

public_mod_off() {
[[ ! -f /etc/.maAsiss/public_mode/settings ]] && {
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
     --text "⛔ Public mode is currently off ⛔"
return 0
} || {
rm -rf /etc/.maAsiss/public_mode
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
   --text "✅ Success disable public mode ✅"
return 0
}   
}

Add_Info_Reseller() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "📢 Info for reseller 📢\n\ntype your information:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

unblock_usr() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "😤 Unblock user 😤\n\nInput user ID to unblock:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

Del_Info_Reseller() {
[[ ! -f /etc/.maAsiss/update-info ]] && {
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
     --text "⛔ No Information Available ⛔"
return 0
} || {
rm -f /etc/.maAsiss/update-info
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
     --text "✅ Success Delete Information ✅"
return 0
}   
}

admin_server() {
[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "Select Option Below:" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu_admin')"
        return 0
    }
}


#======= MAIN MENU =========
see_sys() {
        systemctl is-active --quiet stunnel4 && stsstn="Running 🟢" || stsstn="Not Running 🔴"
        systemctl is-active --quiet dropbear && stsdb="Running 🟢" || stsdb="Not Running 🔴"
        systemctl is-active --quiet $raycheck && stsray="Running 🟢" || stsray="Not Running 🔴"

        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🟢 Status Service : \n\n"
        env_msg+="<code>Dropbear     : $stsdb\n"
        env_msg+="Stunnel      : $stsstn\n"
        env_msg+="VLess        : $stsray\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu_admin')"
        return 0
    }
}

sets_menu() {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'sett_menus')"
        return 0
    }
}


unset menuzzz
menuzzz=''
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 1 --text '👨‍🦱 Add Reseller 👨‍🦱' --callback_data '_add_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 2 --text '💰 Top Up Balance 💰' --callback_data '_top_up_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 3 --text '📃 List %26 Info Reseller 📃' --callback_data '_list_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 4 --text '🗑 Remove Reseller 🗑' --callback_data '_del_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 5 --text '🌀 Reset Saldo Reseller 🌀' --callback_data '_reset_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 10 --text '🔙 Back 🔙' --callback_data '_gobakcuy'
ShellBot.regHandleFunction --function add_res --callback_data _add_res
ShellBot.regHandleFunction --function topup_res --callback_data _top_up_res
ShellBot.regHandleFunction --function func_list_res --callback_data _list_res
ShellBot.regHandleFunction --function del_res --callback_data _del_res
ShellBot.regHandleFunction --function reset_saldo_res --callback_data _reset_res
ShellBot.regHandleFunction --function menu_func_cb --callback_data _gobakcuy
unset keyboardzz
keyboardzz="$(ShellBot.InlineKeyboardMarkup -b 'menuzzz')"


unset menu_adm_ser
menu_adm_ser=''
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 1 --text '• Menu SSH •' --callback_data '_menussh'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 2 --text '• Menu VLess •' --callback_data '_menuvless'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 7 --text '🔙 Back 🔙' --callback_data '_mebck'
ShellBot.regHandleFunction --function ssh_menus --callback_data _menussh
ShellBot.regHandleFunction --function vless_menus --callback_data _menuvless
ShellBot.regHandleFunction --function menu_func_cb --callback_data _mebck
unset menu_adm_ser1
menu_adm_ser1="$(ShellBot.InlineKeyboardMarkup -b 'menu_adm_ser')"


unset list_bck_adm
list_bck_adm=''
ShellBot.InlineKeyboardButton --button 'list_bck_adm' --line 1 --text '🔙 Back 🔙' --callback_data 'list_bck_'
ShellBot.regHandleFunction --function res_menus --callback_data list_bck_
unset list_bck_adm1
list_bck_adm1="$(ShellBot.InlineKeyboardMarkup -b 'list_bck_adm')"


unset status_disable
status_disable=''
ShellBot.InlineKeyboardButton --button 'status_disable' --line 1 --text '💡 How To Use 💡' --callback_data '_how_to'
ShellBot.InlineKeyboardButton --button 'status_disable' --line 2 --text '🔙 Back 🔙' --callback_data '_stsbck'
ShellBot.regHandleFunction --function how_to_order --callback_data _how_to
ShellBot.regHandleFunction --function menu_func_cb --callback_data _stsbck
unset status_disable1
status_disable1="$(ShellBot.InlineKeyboardMarkup -b 'status_disable')"

unset status_how_to
status_how_to=''
ShellBot.InlineKeyboardButton --button 'status_how_to' --line 1 --text '🔙 Back 🔙' --callback_data '_howbck'
ShellBot.regHandleFunction --function status_order --callback_data _howbck
unset status_how_to1
status_how_to1="$(ShellBot.InlineKeyboardMarkup -b 'status_how_to')"

unset sett_menus
sett_menus=''
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 1 --text '🔒 Status Order 🔒' --callback_data '_orderfo'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 1 --text '💰 Change Price 💰' --callback_data '_price'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 2 --text '🤵 Reseller 🤵' --callback_data '_ressssseller'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 2 --text '✍️ See Log Reseller ✍️' --callback_data '_seelog'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 3 --text '🌐 OpenPublic 🌐' --callback_data '_publicmode'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 3 --text '📛 DisablePublic 📛' --callback_data '_publicmodeoff'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 4 --text '🔔 Add Info 🔔' --callback_data '_addinfo'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 4 --text '🔕 Del Info 🔕' --callback_data '_delinfo'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 10 --text '🔙 Back 🔙' --callback_data '_setssbck'
ShellBot.regHandleFunction --function status_order --callback_data _orderfo
ShellBot.regHandleFunction --function Add_Info_Reseller --callback_data _addinfo
ShellBot.regHandleFunction --function Del_Info_Reseller --callback_data _delinfo
ShellBot.regHandleFunction --function Ganti_Harga --callback_data _price
ShellBot.regHandleFunction --function res_menus --callback_data _ressssseller
ShellBot.regHandleFunction --function see_log --callback_data _seelog
ShellBot.regHandleFunction --function public_mod --callback_data _publicmode
ShellBot.regHandleFunction --function public_mod_off --callback_data _publicmodeoff
ShellBot.regHandleFunction --function menu_func_cb --callback_data _setssbck
unset sett_menus1
sett_menus1="$(ShellBot.InlineKeyboardMarkup -b 'sett_menus')"

unset menu
menu=''
ShellBot.InlineKeyboardButton --button 'menu' --line 1 --text '❇️ Open Service ❇️️' --callback_data '_openserv'
ShellBot.InlineKeyboardButton --button 'menu' --line 1 --text '🟢 Status Service 🟢️️' --callback_data '_stsserv'
ShellBot.InlineKeyboardButton --button 'menu' --line 2 --text '📋 Current Price 📋' --callback_data '_priceinfo'
ShellBot.InlineKeyboardButton --button 'menu' --line 2 --text '⚙️ Settings Menu ⚙️' --callback_data '_menusettss'
ShellBot.InlineKeyboardButton --button 'menu' --line 10 --text '⚠️ Unblock User ⚠️' --callback_data '_unblck'
ShellBot.regHandleFunction --function admin_service_see --callback_data _openserv
ShellBot.regHandleFunction --function see_sys --callback_data _stsserv
ShellBot.regHandleFunction --function admin_price_see --callback_data _priceinfo
ShellBot.regHandleFunction --function sets_menu --callback_data _menusettss
ShellBot.regHandleFunction --function unblock_usr --callback_data _unblck
unset keyboard1
keyboard1="$(ShellBot.InlineKeyboardMarkup -b 'menu')"

unset menu_re_ser
menu_re_ser=''
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 1 --text '• SSH •' --callback_data '_res_ssh_menu'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 2 --text '• VLess •' --callback_data '_res_vless_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 10 --text '🔙 Back 🔙' --callback_data 'clses_ser_res'
ShellBot.regHandleFunction --function res_ssh_menu --callback_data _res_ssh_menu
ShellBot.regHandleFunction --function res_vless_menus --callback_data _res_vless_menus
ShellBot.regHandleFunction --function res_opener --callback_data clses_ser_res
unset menu_re_ser1
menu_re_ser1="$(ShellBot.InlineKeyboardMarkup -b 'menu_re_ser')"


unset menu_re_main
menu_re_main=''
ShellBot.InlineKeyboardButton --button 'menu_re_main' --line 1 --text '⚖️ Open Service ⚖️️' --callback_data '_pps_serv'
ShellBot.InlineKeyboardButton --button 'menu_re_main' --line 2 --text '🟢 Status Service 🟢️' --callback_data '_sts_serv'
ShellBot.InlineKeyboardButton --button 'menu_re_main' --line 3 --text '📚 Info Port 📚' --callback_data '_pports'
ShellBot.InlineKeyboardButton --button 'menu_re_main' --line 4 --text '📁 Close Menu 📁' --callback_data 'closesss'
ShellBot.regHandleFunction --function menu_reserv --callback_data _pps_serv
ShellBot.regHandleFunction --function see_sys --callback_data _sts_serv
ShellBot.regHandleFunction --function info_port --callback_data _pports
ShellBot.regHandleFunction --function res_closer --callback_data closesss
unset menu_re_main1
menu_re_main1="$(ShellBot.InlineKeyboardMarkup -b 'menu_re_main')"

unset back_menu
back_menu=''
ShellBot.InlineKeyboardButton --button 'back_menu' --line 1 --text '🔙 Back 🔙' --callback_data '_res_back_opn'
ShellBot.regHandleFunction --function res_opener --callback_data _res_back_opn
unset back_menu1
back_menu1="$(ShellBot.InlineKeyboardMarkup -b 'back_menu')"

unset back_menu_admin
back_menu_admin=''
ShellBot.InlineKeyboardButton --button 'back_menu_admin' --line 1 --text '🔙 Back 🔙' --callback_data '_res_backadm_opn'
ShellBot.regHandleFunction --function menu_func_cb --callback_data _res_backadm_opn
unset back_menu_admin1
back_menu_admin1="$(ShellBot.InlineKeyboardMarkup -b 'back_menu_admin')"

unset menu_re_main_updater
menu_re_main_updater=''
ShellBot.InlineKeyboardButton --button 'menu_re_main_updater' --line 1 --text '📂 Open Menu 📂' --callback_data '_res_main_opn'
ShellBot.regHandleFunction --function res_opener --callback_data _res_main_opn
unset menu_re_main_updater1
menu_re_main_updater1="$(ShellBot.InlineKeyboardMarkup -b 'menu_re_main_updater')"

hantuu() {
    ShellBot.deleteMessage --chat_id ${message_chat_id[$id]} \
             --message_id ${message_message_id[$id]}
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        while read _atvs; do
              msg1+="• [ 👻Anonymous](tg://user?id=$_atvs) \n"
        done <<<"$(cat /etc/.maAsiss/User_Generate_Token |  awk '{print $3}' )"
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
              --text "$msg1" \
              --parse_mode markdown
        return 0
    }
}
#================================| PUBLIC MODE |=====================================
_if_public() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" = '1' ]] && return 0 || AUTOBLOCK
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
   [[ ! -f /etc/.maAsiss/public_mode/settings ]] && {
       ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "<b>Public Mode Has Been Closed by Admin</b>" \
            --parse_mode html
       return 0
   }
}
ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
portovpn=$(grep -w " OpenVPN" /root/log-install.txt | awk '{print $5,$7,$9}')
portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`

getLimits=$(grep -w "MAX_USERS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
dx=$(ls /etc/.maAsiss/public_mode --ignore='settings' | wc -l)
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="<b>  WELCOME TO $nameStore</b>\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="•> <b>1 ID Tele = 1 Server VPN</b>\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="•OpenSSH : $opensh\n"
   env_msg+="•Dropbear : $db\n"
   env_msg+="•SSH WS : $portsshws\n"
   env_msg+="•SSH-WS-SSL : $wsssl\n"
   env_msg+="•SSL/TLS : $ssl\n"
   env_msg+="•OHP SSH : $OhpSSH\n"
   env_msg+="•OHP Dropbear : $OhpDB\n"
   env_msg+="•OHP OpenVPN : $OhpOVPN\n"
   env_msg+="•Squid : $sqd\n"
   env_msg+="•OpenVPN : $portovpn\n"
   env_msg+="•UDPGW : 7100-7300\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="•> Status = 👤 $dx / $getLimits Max \n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"

# ShellBot.deleteMessage --chat_id ${message_chat_id[$id]} \
     # --message_id ${message_message_id[$id]}
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
     --text "$env_msg" \
     --reply_markup "$pub_menu1" \
     --parse_mode html
}

ssh_publik(){
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} --message_id ${callback_query_message_message_id[$id]}
func_limit_publik ${callback_query_from_id}
r0=$(tr -dc a-zA-Z </dev/urandom | head -c5)
r1=$(tr -dc 0-9 </dev/urandom | head -c3)
userna=$(echo $r0$r1)
passw=$r1
getDays=$(grep -w "MAX_DAYS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
data=$(date '+%d/%m/%C%y' -d " +$getDays days")
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)

if /usr/sbin/useradd -M -N -s /bin/false $userna -e $exp; then
    (echo "${passw}";echo "${passw}") | passwd "${userna}"
else
    ShellBot.sendMessage --chat_id ${callback_query_chat_id[$id]} \
            --text "⛔ ERROR CREATING USER" \
            --parse_mode html
    return 0
fi

[[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
        mkdir -p /etc/.maAsiss/public_mode/${callback_query_from_id}
        echo "$userna:$passw:$data" >/etc/.maAsiss/public_mode/${callback_query_from_id}/$userna
        echo "$userna:$passw $getDays Days SSH | ${callback_query_from_first_name}" >> /root/log-public
}

ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 SSH ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Host : $IPs \n"
env_msg+="Username: <code>$userna</code>\n"
env_msg+="Password: <code>$passw</code>\n"
env_msg+="Expired On: $data 📅\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="OpenSSH : $opensh\n"
env_msg+="Dropbear : $db\n"
env_msg+="SSH-WS : $portsshws\n"
env_msg+="SSH-WS-SSL : $wsssl\n"
env_msg+="SSL/TLS : $ssl\n"
env_msg+="OHP SSH : $OhpSSH\n"
env_msg+="OHP Dropbear : $OhpDB\n"
env_msg+="OHP OpenVPN : $OhpOVPN\n"
env_msg+="Port Squid : $sqd\n"
env_msg+="UDPGW : 7100-7900 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="OpenVPN Config : http://$IPs:81/\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Payload WS : \n\n"
env_msg+="<code>GET / HTTP/1.1[crlf]Host: $IPs [crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
}

vless_publik() {
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} --message_id ${callback_query_message_message_id[$id]}
func_limit_publik ${callback_query_from_id}
r0=$(tr -dc a-zA-Z </dev/urandom | head -c5)
r1=$(tr -dc 0-9 </dev/urandom | head -c3)
userna=$(echo $r0$r1)
passw=$r1
getDays=$(grep -w "MAX_DAYS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
data=$(date '+%d/%m/%C%y' -d " +$getDays days")
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)

domain=$(cat /etc/$raycheck/domain)
tls="$(cat /root/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

vlesslink1="vless://${uuid}@${domain}:$tls?path=/vlessws%26security=tls%26encryption=none%26type=ws#${userna}"
vlesslink2="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>     🔸 VLESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /vlessws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n"
env_msg+="<code>$vlesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n"
env_msg+="<code>$vlesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

[[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
        mkdir -p /etc/.maAsiss/public_mode/${callback_query_from_id}
        echo "$userna:$uuid:$data" >/etc/.maAsiss/public_mode/${callback_query_from_id}/$userna
        echo "$userna:$uuid $getDays Days VLESS | ${callback_query_from_first_name}" >> /root/log-public
}

ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
    --text "$env_msg" \
    --parse_mode html 
systemctl restart $raycheck > /dev/null 2>&1
return 0

}


unset pub_menu
pub_menu=''
ShellBot.InlineKeyboardButton --button 'pub_menu' --line 1 --text '• VLess •' --callback_data 'vless'
ShellBot.InlineKeyboardButton --button 'pub_menu' --line 3 --text '• SSH •' --callback_data 'ssh'
ShellBot.regHandleFunction --function ssh_publik --callback_data ssh
ShellBot.regHandleFunction --function vless_publik --callback_data vless

unset pub_menu1
pub_menu1="$(ShellBot.InlineKeyboardMarkup -b 'pub_menu')"
while :; do
    ShellBot.getUpdates --limit 100 --offset $(ShellBot.OffsetNext) --timeout 35
    for id in $(ShellBot.ListUpdates); do
        (
            ShellBot.watchHandle --callback_data ${callback_query_data[$id]}
            [[ ${message_chat_type[$id]} != 'private' ]] && {
                   ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ only run this command on private chat / pm on bot")" \
                        --parse_mode html
                   >$CAD_ARQ
                   break
                   ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
            }
            CAD_ARQ=/tmp/cad.${message_from_id[$id]}
            echotoprice=/tmp/price
            if [[ ${message_entities_type[$id]} == bot_command ]]; then
                case ${message_text[$id]} in
                *)
                    :
                    comando=(${message_text[$id]})
                    [[ "${comando[0]}" = "/start" ]] && msg_welcome
                    [[ "${comando[0]}" = "/menu" ]] && menu_func
                    [[ "${comando[0]}" = "/info" ]] && about_server
                    [[ "${comando[0]}" = "/anonym" ]] && hantuu
                    [[ "${comando[0]}" = "/free" ]] && _if_public
                    [[ "${comando[0]}" = "/disable" ]] && echo "${message_text[$id]}" > /tmp/order && Disable_Order
                    ;;
                esac
            fi
            if [[ ${message_reply_to_message_message_id[$id]} ]]; then
                case ${message_reply_to_message_text[$id]} in
                '👤 CREATE USER 👤\n\nUsername:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    [[ "$(awk -F : '$3 >= 1000 { print $1 }' /etc/passwd | grep -w ${message_text[$id]} | wc -l)" != '0' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⚠️ User Already Exist..")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: IMMANVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Password:' \
                        --reply_markup "$(ShellBot.ForceReply)" # Força a resposta.
                    }
                    ;;
                'Password:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    echo "Password: ${message_text[$id]}" >>$CAD_ARQ
                    # Próximo campo.
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    }
                    ;;
                'Validity in days:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 365)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    cret_user $CAD_ARQ
                    [[ "(grep -w ${message_text[$id]} /etc/passwd)" = '0' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e ⛔ Error creating user !)" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }

                        ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
                        opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
                        db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
                        ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
                        sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
                        ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
                        ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
                        portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
                        OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
                        OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
                        OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
                        wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`

                        env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>       🔸 SSH ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="Host : $IPs \n"
                        env_msg+="Username: <code>$(awk -F " " '/Name/ {print $2}' $CAD_ARQ)</code>\n"
                        env_msg+="Password: <code>$(awk -F " " '/Password/ {print $2}' $CAD_ARQ)</code>\n"
                        env_msg+="Expired On: $(awk -F " " '/Validity/ {print $2}' $CAD_ARQ) 🗓\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="OpenSSH : $opensh\n"
                        env_msg+="Dropbear : $db\n"
                        env_msg+="SSH-WS : $portsshws\n"
                        env_msg+="SSH-WS-SSL : $wsssl\n"
                        env_msg+="SSL/TLS : $ssl\n"
                        env_msg+="OHP SSH : $OhpSSH\n"
                        env_msg+="OHP Dropbear : $OhpDB\n"
                        env_msg+="OHP OpenVPN : $OhpOVPN\n"
                        env_msg+="Port Squid : $sqd\n"
                        env_msg+="UDPGW : 7100-7300 \n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="OpenVPN Config : http://$IPs:81/\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="Payload WS : \n\n"
                        env_msg+="<code>GET / HTTP/1.1[crlf]Host: $IPs [crlf]Upgrade: websocket[crlf][crlf]</code>\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                            --text "$env_msg" \
                            --parse_mode html
                        break
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 365)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    Saldo_CheckerSSH12Month
                    [[ "$_erro" != '1' ]] && {
                    12month_user $CAD_ARQ
                    [[ "(grep -w ${message_text[$id]} /etc/passwd)" = '0' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e ⛔ Error creating user !)" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }

                        ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
                        opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
                        db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
                        ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
                        sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
                        ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
                        ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
                        portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
                        OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
                        OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
                        OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
                        wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`

                        local env_msg
                        env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>       🔸 SSH ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="Host : $IPs \n"
                        env_msg+="Username: <code>$(awk -F " " '/Name/ {print $2}' $CAD_ARQ)</code>\n"
                        env_msg+="Password: <code>$(awk -F " " '/Password/ {print $2}' $CAD_ARQ)</code>\n"
                        env_msg+="Expired On: $(awk -F " " '/Validity/ {print $2}' $CAD_ARQ) 🗓\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="OpenSSH : $opensh\n"
                        env_msg+="Dropbear : $db\n"
                        env_msg+="SSH-WS : $portsshws\n"
                        env_msg+="SSH-WS-SSL : $wsssl\n"
                        env_msg+="SSL/TLS : $ssl\n"
                        env_msg+="OHP SSH : $OhpSSH\n"
                        env_msg+="OHP Dropbear : $OhpDB\n"
                        env_msg+="OHP OpenVPN : $OhpOVPN\n"
                        env_msg+="Port Squid : $sqd\n"
                        env_msg+="UDPGW : 7100-7900 \n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="OpenVPN Config : http://$IPs:81/\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="Payload WS : \n\n"
                        env_msg+="<code>GET / HTTP/1.1[crlf]Host: $IPs [crlf]Upgrade: websocket[crlf][crlf]</code>\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                            --text "$env_msg" \
                            --parse_mode html
                        break
                        }
                else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Can't be more than 365 Days")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                fi
                    }
                    ;;
                '⏳ Renew SSH ⏳\n\nUsername:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    echo "${message_text[$id]}" >/tmp/name-d
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Input the days or date:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    }
                    ;;
                'Input the days or date:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    [[ ${message_text[$id]} != ?(+|-)+([0-9/]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "⛔ Error! Follow the example \nData format [EX: 30]" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 365)); then
                    func_renew_ssh $(cat /tmp/name-d) ${message_text[$id]}
                    [[ "$_erro" == '1' ]] && break
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "$(echo -e "━━━━━━━━━━━━━━━━━━━━━\n<b>✅ DATE CHANGED !</b> !\n━━━━━━━━━━━━━━━━━━━━━\n\n<b>Username:</b> $(cat /tmp/name-d)\n<b>New date:</b> $udata")" \
                        --parse_mode html
                    rm /tmp/name-d >/dev/null 2>&1
                else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Can't be more than 365 Days")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                fi
                    }
                    ;;
                '🗑 REMOVE USER 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_ssh ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👥 ADD Reseller 👥\n\nEnter the name:')
                    verifica_acesso
                    echo "Name: ${message_text[$id]}" > $CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'User token by generate:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'User token by generate:')
                    verifica_acesso
                    _VAR1=$(echo ${message_text[$id]} | sed -e 's/[^0-9]//ig'| rev)
                    [[ ! -z $(grep -w "$_VAR1" "$User_Active" ) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Already Registered")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "${message_text[$id]}" >/tmp/scvpsss
                    echo "User: $_VAR1" >> $CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Saldo:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Saldo:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⚠️ Use only numbers [EX: 100000]")" \
                            --parse_mode html
                        break
                    }
                    echo "Saldo: ${message_text[$id]}" >> $CAD_ARQ
                    sleep 1
                    cret_res $CAD_ARQ
                    ;;
                '🗑 REMOVE Reseller 🗑\n\nInput Name of Reseller:')
                    echo -e "${message_text[$id]}" >$CAD_ARQ
                    _VAR12=$(grep -w "${message_text[$id]}" "$Res_Token")
                    [[ -z $_VAR12 ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Token invalid")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    func_del_res $_VAR12
                    sed -i "/\b${message_text[$id]}\b/d" $Res_Token
                    break
                    ;;
                '💸 Topup Saldo 💸\n\nName reseller:')
                    verifica_acesso
                    cek_res_token=$(grep -w "${message_text[$id]}" "$Res_Token" | awk '{print $NF}' | sed -e 's/[^0-9]//ig'| rev)
                    echo $cek_res_token > /tmp/ruii
                    echo ${message_text[$id]} > /tmp/ruiix
                    [[ -z $cek_res_token ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ No user found")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                 #   _VARSaldo=$(echo ${message_text[$id]} | sed -e 's/[^0-9]//ig'| rev)
                 #   echo -e "${message_text[$id]}" > /tmp/name-l
                 #   sed -i 's/^@//' /tmp/name-l
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Topup Saldo:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Topup Saldo:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⚠️ Use only numbers [EX: 100000]")" \
                            --parse_mode html
                        break
                    }
                    func_topup_res $(cat /tmp/ruii) ${message_text[$id]}
                    [[ "$_erro" == '1' ]] && break
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "$(echo -e "━━━━━━━━━━━━━━━━━\n  ✅ <b>Succesfully Topup !</b> ✅ !\n━━━━━━━━━━━━━━━━━\n<b>Name:</b> $(cat /tmp/ruiix) \n<b>Topup Saldo:</b> ${message_text[$id]}\n<b>Total Saldo Now:</b> $_TopUpSal \n━━━━━━━━━━━━━━━━━")" \
                        --parse_mode html
                    rm /tmp/ruii >/dev/null 2>&1 && rm /tmp/ruiix >/dev/null 2>&1
                    ;;
                '👤 CREATE TRIAL SSH 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_ssh_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER VLess 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: IMMANVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'VLess Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'VLess Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_vless $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 365)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_vless2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 365 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER VLess 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_vless ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL VLess 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_vless_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '💰 Change Price 💰\n\nPrice SSH:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        >$echotoprice
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price SSH : ${message_text[$id]}" >$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price VLess:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price VLess:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price VLess : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                    ;;
                '📢 Info for reseller 📢\n\ntype your information:')
                    verifica_acesso
                    echo "${message_text[$id]}" > /etc/.maAsiss/update-info
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully Added Information* ✅" \
                        --parse_mode markdown
                    ;;
                '🌀 Reset Saldo Reseller 🌀\n\nInput Name of Reseller:')
                    verifica_acesso
                    _VAR14=$(grep -w "${message_text[$id]}" "$Res_Token")
                    [[ -z $_VAR14 ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "No username found 🔴")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo $_VAR14 > /tmp/resSaldo
                    func_reset_saldo_res
                    ;;
                '🌐 Enable Public Mode 🌐\n\nExpired Days [ex:3]:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        >$echotoprice
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "MAX_DAYS : ${message_text[$id]}" > /etc/.maAsiss/public_mode/settings
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Max User [ex:10]:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Max User [ex:10]:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "MAX_USERS : ${message_text[$id]}" >> /etc/.maAsiss/public_mode/settings
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                          --text "Succesfully enable public mode√\n\nShare your bot and tell everyones to type /free" \
                          --parse_mode html
                    ;;
                '😤 Unblock user 😤\n\nInput user ID to unblock:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 100938380]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    _VA4=$(grep -w "${message_text[$id]}" "/etc/.maAsiss/user_flood")
                    [[ -z $_VA4 ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "ID not found 🔴")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sed -i "/^${message_text[$id]}/d" "/etc/.maAsiss/user_flood"
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                          --text "Succesfully unblock user id <b>${message_text[$id]}</b>" \
                          --parse_mode html
                    ;;
                esac
            fi
        ) &
    done
done
