#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

PROJECT_DIR="${PROJECT_DIR:-$HOME/automation}"
VENV_DIR="${VENV_DIR:-$PROJECT_DIR/.venv}"

sudo apt update
sudo apt install -y sshpass

GALAXY="$VENV_DIR/bin/ansible-galaxy"
[ -x "$GALAXY" ] || GALAXY="ansible-galaxy"   # venv 없으면 시스템 ansible-galaxy 폴백
"$GALAXY" collection install -p "$PROJECT_DIR/collections" --force ansible.posix

cat <<EOF

====================================================================
 5단계 사전 준비 완료.
 다음으로 SSH 공개키를 배포된 VM(계정: ubuntu)에 등록하세요:

   cd $PROJECT_DIR
   ansible-playbook -i 5.inventory.ini 5.push_ssh_key.yaml          # 비밀번호 입력 프롬프트
   # 또는:  SSH_PASSWORD='VMware123!' ansible-playbook -i 5.inventory.ini 5.push_ssh_key.yaml
====================================================================
EOF
