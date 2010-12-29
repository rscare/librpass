[ $(pgrep -u $UID xclip) ] && kill $(pgrep -u $UID xclip) 2>&1 > /dev/null
rpass -bu "$(rpass|dmenu -i -p 'Account name: ')"|xclip -i
[ $(pgrep -u $UID xclip) ] && kill $(pgrep -u $UID xclip) 2>&1 > /dev/null
