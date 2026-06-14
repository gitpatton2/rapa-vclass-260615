#!/usr/bin/env bash
###############################################################################
# WSL Ubuntu 26.04 / Python 3.14 - Ansible 제어 노드 구축 스크립트
#
#   - Ansible 및 모든 Python 의존성을 단일 venv 에 통합 설치
#     (시스템 ansible 과 venv SDK 가 분리되어 모듈을 못 찾는 문제 방지)
#   - Windows 관리 : psrp (HTTPS / 5986) + vclass-Root-CA 신뢰 기반 암호화 통신
#   - vSphere 관리 : pyVmomi + vSphere Automation SDK + community.vmware
#
# 멱등(idempotent): 여러 번 실행해도 안전합니다.
###############################################################################
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive   # krb5-user 등 설치 시 대화형 프롬프트 방지

# ====== 사용자 조정 변수 (환경변수로 덮어쓸 수 있음) =========================
PROJECT_DIR="${PROJECT_DIR:-$HOME/automation}"          # Ansible 프로젝트 루트
VENV_DIR="${VENV_DIR:-$PROJECT_DIR/.venv}"              # 가상환경 (모든 의존성 포함)
PYBIN="${PYBIN:-python3.14}"                            # 사용할 Python 인터프리터
ROOT_CA_SRC="${ROOT_CA_SRC:-$PROJECT_DIR/certs/rootca.cer}"  # 프로젝트 내 Root CA 위치 (자동 생성됨)
WIN_ADMIN_DESKTOP="${WIN_ADMIN_DESKTOP:-/mnt/c/Users/Administrator/Desktop}"  # DC 스크립트가 rootca 를 내보내는 위치(WSL on DC)
ROOT_CA_NAME="vclass-root-ca"
WINRM_PORT="${WINRM_PORT:-5986}"
DOMAIN_FQDN="${DOMAIN_FQDN:-vclass.local}"              # AD 도메인 (Kerberos realm 산출용)
DC_FQDN="${DC_FQDN:-dc.vclass.local}"                   # 도메인 컨트롤러 FQDN
WIN_USER="${WIN_USER:-administrator}"                   # Windows 접속 계정 (도메인 계정이면 'VCLASS\\user' 형태)
KRB5_REALM="${KRB5_REALM:-$(printf '%s' "$DOMAIN_FQDN" | tr '[:lower:]' '[:upper:]')}"  # Kerberos realm (기본: 도메인 대문자 = VCLASS.LOCAL)
VCENTER_FQDN="${VCENTER_FQDN:-vcsa.vclass.rapa}"        # vCenter FQDN
VCENTER_IP="${VCENTER_IP:-192.168.6.4}"                 # vCenter IP (DNS 미해석 시 /etc/hosts 보정용)
VCENTER_USER="${VCENTER_USER:-administrator@vsphere.rapa}"  # vCenter SSO 계정

# ====== 로그 헬퍼 ============================================================
log()  { printf '\n\033[1;36m[*] %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m  [OK] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  [WARN] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  [ERR] %s\033[0m\n' "$*" >&2; exit 1; }

# ====== 1. 시스템 패키지 =====================================================
log "1. 시스템 패키지 설치"
sudo apt update
# krb5-user 설치 중 'Default Kerberos realm' 대화형 프롬프트를 막기 위해 값을 미리 지정
# (사용자 오입력 방지 -> 항상 $KRB5_REALM 로 자동 설정)
echo "krb5-config krb5-config/default_realm string $KRB5_REALM" | sudo debconf-set-selections
echo "krb5-config krb5-config/add_servers_realm string $KRB5_REALM" | sudo debconf-set-selections
# 빌드/암호화/Kerberos 의존성 포함 (Python 3.14 휠 빌드 대비 rustc/cargo 포함)
sudo apt install -y \
    software-properties-common ca-certificates curl git openssl unzip \
    build-essential pkg-config libffi-dev libssl-dev \
    python3-venv python3-dev python3-pip \
    krb5-user libkrb5-dev gss-ntlmssp \
    rustc cargo
# 버전 지정 패키지는 배포본에 따라 없을 수 있으므로 실패를 무시하고 시도
sudo apt install -y "${PYBIN}" "${PYBIN}-venv" "${PYBIN}-dev" 2>/dev/null || true
command -v "$PYBIN" >/dev/null 2>&1 || PYBIN="python3"   # 폴백
ok "패키지 설치 완료 (python=$("$PYBIN" --version 2>&1))"

# ====== 2. 가상환경 생성 =====================================================
log "2. Python 가상환경 생성 ($VENV_DIR)"
mkdir -p "$PROJECT_DIR"
[ -d "$VENV_DIR" ] || "$PYBIN" -m venv "$VENV_DIR"
PIP="$VENV_DIR/bin/pip"            # 절대경로 바이너리 직접 호출 -> source 불필요
"$PIP" install --upgrade pip wheel setuptools
ok "가상환경 준비 완료"

# ====== 3. Ansible + 연결 라이브러리 (venv 내부) =============================
log "3. Ansible 및 연결 라이브러리 설치"
# Windows(psrp): pypsrp(+credssp/kerberos), pyspnego(NTLM), requests-credssp
# vSphere      : pyVmomi, aiohttp(vmware.vmware_rest), jmespath(json_query)
"$PIP" install \
    ansible \
    "pypsrp[credssp,kerberos]" requests-credssp \
    pyvmomi aiohttp jmespath
ok "핵심 라이브러리 설치 완료"

# ====== 4. vSphere Automation SDK ===========================================
log "4. vSphere Automation SDK 설치"
SDK_DIR="$PROJECT_DIR/vsphere-automation-sdk-python"
[ -d "$SDK_DIR/.git" ] || git clone https://github.com/vmware/vsphere-automation-sdk-python.git "$SDK_DIR"
# 로컬 'file://localhost/' 경로 표기를 'file://' 로 보정 (pip 호환)
sed -i 's#file://localhost/#file://#g' "$SDK_DIR/setup.py" 2>/dev/null || true
"$PIP" install "$SDK_DIR/"
ok "vSphere SDK 설치 완료"

# ====== 5. Ansible 컬렉션 ====================================================
log "5. Ansible 컬렉션 설치"
GALAXY="$VENV_DIR/bin/ansible-galaxy"
"$GALAXY" collection install -p "$PROJECT_DIR/collections" --force \
    ansible.windows community.windows community.vmware vmware.vmware vmware.vmware_rest
ok "컬렉션 설치 완료"

# ====== 6. Root CA 신뢰 구성 (vclass-Root-CA) ===============================
log "6. Root CA 신뢰 구성"
CERT_DIR="$PROJECT_DIR/certs"
mkdir -p "$CERT_DIR"
CA_PEM="$CERT_DIR/${ROOT_CA_NAME}.pem"

# Setup-ADCS-WinRM-HTTPS.ps1 이 Administrator 데스크톱에 내보낸 rootca 를 자동으로 가져온다.
if [ ! -f "$ROOT_CA_SRC" ]; then
    for cand in "$WIN_ADMIN_DESKTOP/rootca.cer" "$WIN_ADMIN_DESKTOP/rootca.pem"; do
        if [ -f "$cand" ]; then
            cp "$cand" "$ROOT_CA_SRC"
            ok "Windows 데스크톱에서 Root CA 가져옴: $cand"
            break
        fi
    done
fi

if [ -f "$ROOT_CA_SRC" ]; then
    # 이미 PEM 이면 복사, DER(.cer) 이면 PEM 으로 변환
    if openssl x509 -in "$ROOT_CA_SRC" -inform PEM -noout >/dev/null 2>&1; then
        cp "$ROOT_CA_SRC" "$CA_PEM"
    else
        openssl x509 -inform DER -in "$ROOT_CA_SRC" -out "$CA_PEM"
    fi
    # 시스템 신뢰 저장소에도 등록 (openssl/curl 등 공용 도구가 신뢰)
    sudo cp "$CA_PEM" "/usr/local/share/ca-certificates/${ROOT_CA_NAME}.crt"
    sudo update-ca-certificates >/dev/null
    ok "Root CA 등록 완료 -> $CA_PEM"
    openssl x509 -in "$CA_PEM" -noout -subject -issuer -enddate | sed 's/^/      /'
    CA_PRESENT=1
else
    CA_PRESENT=0
    warn "Root CA 를 찾지 못했습니다 (인증서 검증은 ignore 로 진행)."
    cat <<EOF
      DC 에서 Setup-ADCS-WinRM-HTTPS.ps1 을 실행하면 rootca 가 자동 생성됩니다:
        $WIN_ADMIN_DESKTOP/rootca.cer
      생성 후 이 스크립트를 다시 실행하면 위 경로에서 자동으로 가져옵니다.
      (다른 PC 의 WSL 이면 ROOT_CA_SRC 변수로 직접 경로 지정 가능)
EOF
fi

# 검증 정책/CA 경로 결정
if [ "$CA_PRESENT" -eq 1 ]; then
    CERT_VALIDATION="validate"
    # ansible 버전에 따라 CA 번들 변수명이 cert_trust_path / ca_trust_path 로 다름 -> 둘 다 지정
    CA_LINE="ansible_psrp_cert_trust_path: $CA_PEM
ansible_psrp_ca_trust_path: $CA_PEM"
else
    CERT_VALIDATION="ignore"
    CA_LINE="# ansible_psrp_cert_trust_path: $CA_PEM   # Root CA 배치 후 validate 와 함께 사용"
fi

# ====== 6b. vCenter VMCA 루트 신뢰 구성 =====================================
# vCenter 인증서는 자체 VMCA 가 발급하므로 vclass-Root-CA 와 별개입니다.
# vCenter 가 제공하는 신뢰 루트 번들(/certs/download.zip)을 받아 신뢰시킵니다.
log "6b. vCenter VMCA 루트 인증서 신뢰 구성"
VMCA_PEM="$CERT_DIR/vmca-root.pem"
VMCA_PRESENT=0

# DNS 로 vCenter FQDN 이 풀리지 않으면 /etc/hosts 에 IP 매핑 추가
if ! getent hosts "$VCENTER_FQDN" >/dev/null 2>&1; then
    if ! grep -qE "[[:space:]]$VCENTER_FQDN([[:space:]]|\$)" /etc/hosts 2>/dev/null; then
        echo "$VCENTER_IP    $VCENTER_FQDN" | sudo tee -a /etc/hosts >/dev/null
        ok "/etc/hosts 에 추가: $VCENTER_IP -> $VCENTER_FQDN"
    fi
fi

# 부트스트랩 단계이므로 -k 로 번들만 안전하게 내려받은 뒤, 받은 루트로 신뢰를 구성
TMPZIP="$(mktemp)"; TMPVC="$(mktemp -d)"
if curl -fsSk --connect-timeout 10 -o "$TMPZIP" "https://$VCENTER_FQDN/certs/download.zip"; then
    unzip -o "$TMPZIP" -d "$TMPVC" >/dev/null 2>&1 || true
    # Linux 용 루트 인증서는 certs/lin/*.0 (PEM) 형태로 들어 있음
    mapfile -t VMCA_FILES < <(find "$TMPVC" -path '*/lin/*.0' 2>/dev/null)
    if [ "${#VMCA_FILES[@]}" -eq 0 ]; then
        mapfile -t VMCA_FILES < <(find "$TMPVC" -path '*/lin/*' -name '*.crt' 2>/dev/null)
    fi
    if [ "${#VMCA_FILES[@]}" -gt 0 ]; then
        : > "$VMCA_PEM"
        idx=0
        for f in "${VMCA_FILES[@]}"; do
            cat "$f" >> "$VMCA_PEM"
            echo "" >> "$VMCA_PEM"
            sudo cp "$f" "/usr/local/share/ca-certificates/vmca-root-${idx}.crt"
            idx=$((idx+1))
        done
        sudo update-ca-certificates >/dev/null
        VMCA_PRESENT=1
        ok "VMCA 루트 ${#VMCA_FILES[@]}개 등록 완료 -> $VMCA_PEM (+ 시스템 신뢰 저장소)"
        openssl x509 -in "${VMCA_FILES[0]}" -noout -subject -enddate 2>/dev/null | sed 's/^/      /'
    else
        warn "다운로드한 번들에서 Linux 루트 인증서를 찾지 못했습니다."
    fi
else
    warn "vCenter($VCENTER_FQDN) 에서 인증서 번들을 받지 못했습니다(네트워크/도달성 확인)."
    cat <<EOF
      vCenter 가 켜진 뒤 다시 실행하거나, 수동으로 받아 신뢰시키세요:
        curl -sk -o vmca.zip https://$VCENTER_FQDN/certs/download.zip
        unzip vmca.zip && sudo cp certs/lin/*.0 /usr/local/share/ca-certificates/vmca-root.crt
        sudo update-ca-certificates
EOF
fi
rm -rf "$TMPZIP" "$TMPVC"

# vCenter 인증서 검증 정책 결정
if [ "$VMCA_PRESENT" -eq 1 ]; then VC_VALIDATE="true"; else VC_VALIDATE="false"; fi

# ====== 7. Ansible 프로젝트 스캐폴딩 ========================================
log "7. Ansible 설정 / 인벤토리 / 플레이북 생성"
mkdir -p "$PROJECT_DIR/group_vars"

# --- ansible.cfg ---
cat > "$PROJECT_DIR/ansible.cfg" <<EOF
[defaults]
inventory          = ./inventory.ini
collections_path   = ./collections
host_key_checking  = False
interpreter_python = $VENV_DIR/bin/python
# ansible-core 2.21 / community.general 12 에서 'yaml' stdout 콜백은 제거됨.
# 기본(default) 콜백 + result_format=yaml 조합으로 YAML 출력 유지.
stdout_callback    = default
result_format      = yaml
retry_files_enabled = False

[inventory]
enable_plugins = ini, yaml
EOF

# --- inventory.ini ---
cat > "$PROJECT_DIR/inventory.ini" <<EOF
[windows]
dc       ansible_host=$DC_FQDN

[windows:vars]
ansible_connection = psrp
ansible_port       = $WINRM_PORT

[vsphere]
vcenter01 ansible_host=$VCENTER_FQDN
EOF

# --- group_vars/windows.yml (psrp / HTTPS / Root CA) ---
cat > "$PROJECT_DIR/group_vars/windows.yml" <<EOF
---
# 접속 계정. 기본 administrator. 도메인 계정은 'VCLASS\\user' 형태(작은따옴표라 백슬래시는 그대로).
ansible_user: '$WIN_USER'
# 비밀번호는 파일에 저장하지 않음: 실행 시 입력(vars_prompt) 또는 환경변수, 추후 ansible-vault
#   - 플레이북:  ansible-playbook ping-test.yml   (실행 시 비밀번호 입력 프롬프트)
#   - 애드혹:    WIN_PASSWORD='***' ansible windows -m ansible.windows.win_ping
ansible_password: "{{ win_password | default(lookup('env','WIN_PASSWORD')) }}"

# WinRM-PSRP over HTTPS (DC/멤버에 5986 리스너가 구성된 상태)
ansible_connection: psrp
ansible_port: $WINRM_PORT
ansible_psrp_protocol: https

# 인증: 도메인 계정이면 negotiate(NTLM/Kerberos)가 가장 간단.
#       클라이언트 인증서 매핑 없이도 동작합니다. 필요시 credssp 로 변경.
ansible_psrp_auth: negotiate

# 서버 인증서 검증: vclass-Root-CA 를 신뢰 경로로 사용
ansible_psrp_cert_validation: $CERT_VALIDATION
$CA_LINE
EOF

# --- group_vars/vsphere.yml ---
# vCenter 인증서는 VMCA(자체 CA)가 발급하므로 위 vclass-Root-CA 와는 별개입니다.
# 비밀번호는 보안을 위해 파일에 저장하지 않습니다. 실행 시 입력받거나(-> 아래 vcenter-test.yml 의 vars_prompt),
# 임시로 환경변수 VCENTER_PASSWORD 로 주입합니다. (추후 ansible-vault 로 이관 권장)
cat > "$PROJECT_DIR/group_vars/vsphere.yml" <<EOF
---
ansible_connection: local
vcenter_hostname: $VCENTER_FQDN
vcenter_username: "$VCENTER_USER"
# 비밀번호 미저장: 런타임 입력(vars_prompt) 또는 환경변수에서 가져옴
vcenter_password: "{{ vcenter_password | default(lookup('env','VCENTER_PASSWORD')) }}"
# VMCA 루트 신뢰 시 true (시스템 신뢰 저장소에 등록됨)
vcenter_validate_certs: $VC_VALIDATE
EOF

# --- Windows 연결 테스트 플레이북 (비밀번호는 실행 시 입력받음) ---
# vars_prompt 는 그룹변수 로드 전에 평가되므로 prompt 문자열엔 그룹변수를 쓰지 않음(정적).
cat > "$PROJECT_DIR/ping-test.yml" <<EOF
---
- name: Windows 연결 테스트 (psrp / HTTPS)
  hosts: windows
  gather_facts: false
  vars_prompt:
    - name: win_password
      prompt: "Windows 비밀번호를 입력하세요 ($WIN_USER)"
      private: true
      unsafe: true
  tasks:
    - name: win_ping
      ansible.windows.win_ping:
EOF

# --- vCenter 연결 테스트 플레이북 (비밀번호는 실행 시 입력받음) ---
# vars_prompt 로 입력받은 값은 파일에 저장되지 않으며 화면에도 표시되지 않습니다(private).
# 비대화형(자동화)에서는 환경변수로도 가능:  VCENTER_PASSWORD=... ansible-playbook vcenter-test.yml
cat > "$PROJECT_DIR/vcenter-test.yml" <<'EOF'
---
- name: vCenter 연결 테스트
  hosts: vsphere
  gather_facts: false
  vars_prompt:
    - name: vcenter_password
      prompt: "vCenter 비밀번호를 입력하세요 (administrator@vsphere.rapa)"
      private: true
      unsafe: true
  tasks:
    - name: vCenter about-info
      community.vmware.vmware_about_info:
        hostname: "{{ vcenter_hostname }}"
        username: "{{ vcenter_username }}"
        password: "{{ vcenter_password }}"
        validate_certs: "{{ vcenter_validate_certs }}"
      delegate_to: localhost
      no_log: true
      register: vc_info

    - name: 결과 출력
      ansible.builtin.debug:
        msg: "연결 성공 - vCenter {{ vc_info.about_info.version | default('?') }} (build {{ vc_info.about_info.build | default('?') }})"
EOF
ok "프로젝트 생성 완료 -> $PROJECT_DIR"

# ====== 8. Kerberos realm (선택) ============================================
# negotiate 는 Kerberos 실패 시 NTLM 으로 자동 폴백하므로 필수는 아니지만,
# Kerberos 를 쓰려면 /etc/krb5.conf 가 필요합니다. 없을 때만 생성합니다.
log "8. Kerberos realm 설정 (선택)"
if [ ! -f /etc/krb5.conf ]; then
    sudo tee /etc/krb5.conf >/dev/null <<EOF
[libdefaults]
    default_realm = $KRB5_REALM
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    $KRB5_REALM = {
        kdc = $DC_FQDN
        admin_server = $DC_FQDN
    }

[domain_realm]
    .$DOMAIN_FQDN = $KRB5_REALM
    $DOMAIN_FQDN = $KRB5_REALM
EOF
    ok "/etc/krb5.conf 생성 (realm=$KRB5_REALM)"
else
    warn "/etc/krb5.conf 가 이미 존재하여 건너뜀"
fi

# ====== 9. 셸 편의 설정 ======================================================
log "9. 셸 편의 설정"
add_line() { grep -qF -- "$1" "$2" 2>/dev/null || echo "$1" >> "$2"; }
touch "$HOME/.bashrc" "$HOME/.vimrc" "$HOME/.bash_aliases"
add_line 'export PATH=$PATH:$HOME/.local/bin' "$HOME/.bashrc"
# alias 는 ~/.bash_aliases 에 둔다 (Ubuntu 기본 .bashrc 가 자동 source).
add_line "alias act='source $VENV_DIR/bin/activate'" "$HOME/.bash_aliases"
# 혹시 .bashrc 가 .bash_aliases 를 안 읽는 환경이면 source 구문을 보강
add_line '[ -f ~/.bash_aliases ] && . ~/.bash_aliases' "$HOME/.bashrc"
add_line "autocmd FileType yaml setlocal ai ts=2 sw=2 et nu" "$HOME/.vimrc"
ok "완료 (.bash_aliases / .bashrc / .vimrc)"

# ====== 완료 안내 ============================================================
ANSIBLE="$VENV_DIR/bin/ansible"
cat <<EOF

====================================================================
 설치 완료!  프로젝트 위치: $PROJECT_DIR
--------------------------------------------------------------------
 1) 가상환경 활성화 (또는 alias 'act' 사용):
        source $VENV_DIR/bin/activate
        cd $PROJECT_DIR
    * alias 'act' 를 지금 바로 쓰려면 현재 셸에 재적용:
        source ~/.bashrc      # (또는 새 터미널을 열면 자동 적용)
 2) Windows(psrp) 연결 테스트 (접속 계정: $WIN_USER):
        ansible-playbook ping-test.yml          # 실행 시 비밀번호 입력 프롬프트
        # 애드혹(프롬프트 미지원)은 환경변수로:  WIN_PASSWORD='***' ansible windows -m ansible.windows.win_ping
        # 계정 변경:  WIN_USER='VCLASS\someuser' ./setup-ansible-control-node.sh 로 재생성
 3) vCenter 연결 테스트 (실행 시 비밀번호를 안전하게 입력받음):
        ansible-playbook vcenter-test.yml
        # 비대화형으로 줄 때:  VCENTER_PASSWORD='***' ansible-playbook vcenter-test.yml
--------------------------------------------------------------------
 Windows Root CA(psrp) 검증: $([ "$CA_PRESENT" -eq 1 ] && echo "validate (vclass-Root-CA 신뢰됨)" || echo "ignore (DC 에서 Setup-ADCS-WinRM-HTTPS.ps1 실행 후 재실행하면 자동 적용)")
 vCenter VMCA 검증        : $([ "$VMCA_PRESENT" -eq 1 ] && echo "true (VMCA 루트 신뢰됨)" || echo "false (VMCA 미수신 - vCenter 도달 후 재실행)")
 TLS 수동 확인:
        openssl s_client -connect $DC_FQDN:$WINRM_PORT -CAfile $CA_PEM </dev/null
        openssl s_client -connect $VCENTER_FQDN:443 -CAfile $VMCA_PEM </dev/null
====================================================================
EOF

# 스크립트를 'source' 로 실행했다면 현재 셸에 alias 즉시 반영
if (return 0 2>/dev/null); then
    # shellcheck disable=SC1090
    . "$HOME/.bashrc" || true
    ok "현재 셸에 .bashrc 재적용 완료 (alias 'act' 사용 가능)"
fi
