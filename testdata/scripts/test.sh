
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

sh ${SCRIPT_DIR}/add_user.sh
sh ${SCRIPT_DIR}/get_all_users.sh
sh ${SCRIPT_DIR}/challenge.sh
sh ${SCRIPT_DIR}/authorize.sh