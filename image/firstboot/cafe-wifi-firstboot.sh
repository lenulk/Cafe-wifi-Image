#!/usr/bin/env bash
# ============================================================================
#  cafe-wifi-firstboot -- รันครั้งเดียวตอนบูตแรกของ image (M2, docs/image-build-plan.md §4)
#
#  สร้างทุกอย่างที่ "ห้ามติดไปกับ image" (§2) ให้เป็นของเครื่องนี้เครื่องเดียว แล้วเข้าโหมดตั้งค่า
#    1. machine-id + SSH host keys (ถ้ายังไม่มี)
#    2. อ่าน cafewifi.conf จาก bootfs (ชื่อร้าน, SSH key ของช่าง, setup code)
#    3. setup code -> /etc/cafe-wifi/setup-code (ไม่มีใน conf = สุ่มเอง แล้วเขียน SETUP-CODE.txt ลง bootfs)
#    4. install.sh --stage firstboot  (secrets, MariaDB, SSH พอร์ตสำรอง, TLS)
#    5. ลบ cafewifi.conf ออกจาก bootfs แล้วปักธง .firstboot-done
#
#  รันซ้ำได้ทุกขั้น (ไฟดับกลางทางแล้วบูตใหม่ = ทำต่อจากเดิม ไม่สร้างกุญแจทับ):
#  install.sh ใช้ secrets.env เดิมถ้ามี และเขียนแบบ atomic · ธงปักเป็นขั้นสุดท้ายหลัง sync เท่านั้น
#
#  ตัวแปร CAFEWIFI_* ไว้ทดสอบนอก Pi เท่านั้น (ดู image/firstboot/test_firstboot.sh)
# ============================================================================
set -euo pipefail
umask 027

ETC_DIR="${CAFEWIFI_ETC_DIR:-/etc/cafe-wifi}"
INSTALL_SH="${CAFEWIFI_INSTALL_SH:-/opt/cafe-wifi/install.sh}"
LED_DIR="${CAFEWIFI_LED_DIR:-/sys/class/leds/ACT}"
APP_USER="${CAFEWIFI_APP_USER:-cafewifi}"
SKIP_OS_IDENTITY="${CAFEWIFI_SKIP_OS_IDENTITY:-0}"   # ทดสอบนอก Pi: ไม่แตะ machine-id / host keys / ผู้ใช้ OS
DONE_FLAG="${ETC_DIR}/.firstboot-done"
CODE_FILE="${ETC_DIR}/setup-code"
CONF_NAME="cafewifi.conf"
# ตัวอักษรของ setup code: ตัด 0/O/1/I/L ที่อ่านสับสนบนสติกเกอร์ทิ้ง
CODE_ALPHABET="ABCDEFGHJKMNPQRSTUVWXYZ23456789"
DEFAULT_TECH_USER="cafeadmin"

log()  { printf '[firstboot] %s\n' "$*"; }
fail() { printf '[firstboot] ผิดพลาด: %s\n' "$*" >&2; exit 1; }

# ---------- LED (ACT สีเขียว) -- ตารางความหมายอยู่ใน docs/install-from-image.md ขั้น 3 ----------
led() {  # led busy|ready|error
  [[ -w "${LED_DIR}/trigger" ]] || return 0
  case "$1" in
    busy)  echo timer > "${LED_DIR}/trigger" 2>/dev/null || return 0
           echo 80  > "${LED_DIR}/delay_on"  2>/dev/null || true
           echo 80  > "${LED_DIR}/delay_off" 2>/dev/null || true ;;
    ready) echo heartbeat > "${LED_DIR}/trigger" 2>/dev/null || true ;;
    error) # กะพริบ 3 ครั้งแล้วหยุด ซ้ำไปเรื่อย ๆ (ต้องมี ledtrig-pattern) -- ไม่มีก็ติดค้างแทน
           if echo pattern > "${LED_DIR}/trigger" 2>/dev/null; then
             echo "1 150 0 150 1 150 0 150 1 150 0 1500" > "${LED_DIR}/pattern" 2>/dev/null || true
           else
             echo none > "${LED_DIR}/trigger" 2>/dev/null || true
             echo 1 > "${LED_DIR}/brightness" 2>/dev/null || true
           fi ;;
  esac
}
trap 'rc=$?; (( rc != 0 )) && led error; exit $rc' EXIT
# systemd ตัดด้วย SIGTERM ตอน timeout -- ไม่ดักไว้ bash ตายเลยโดยไม่รัน EXIT trap ไฟค้าง "กะพริบถี่"
# ช่างจะรอไปเรื่อย ๆ (เจอจริงบนการ์ด B 2026-10-04)
trap 'exit 143' TERM INT

# ---------- หา bootfs (Bookworm = /boot/firmware, รุ่นเก่า = /boot) ----------
find_bootfs() {
  if [[ -n "${CAFEWIFI_BOOT_DIR:-}" ]]; then [[ -d "$CAFEWIFI_BOOT_DIR" ]] && echo "$CAFEWIFI_BOOT_DIR"; return 0; fi
  local d
  for d in /boot/firmware /boot; do
    if [[ -f "${d}/config.txt" ]]; then echo "$d"; return; fi
  done
  echo ""
}

# ---------- อ่าน cafewifi.conf โดยไม่ source (ไฟล์มาจากใครก็ได้ที่ถือการ์ด) ----------
# รับเฉพาะคีย์ที่รู้จัก · ตัด CR ของ Notepad และ BOM ของ UTF-8 ออก · ค่าที่มีอักขระอันตรายถูกปฏิเสธโดย install.sh
CONF_GATEWAY_NAME=""; CONF_SSH_PUBKEY=""; CONF_SETUP_CODE=""; CONF_TECH_USER=""
read_conf() {
  local f="$1" line key val
  [[ -f "$f" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    line="${line#$'\xef\xbb\xbf'}"
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"; val="${line#*=}"
    key="${key//[[:space:]]/}"
    # ตัดช่องว่างหัวท้าย + เครื่องหมายคำพูดครอบ (คนแก้ด้วย Notepad มักใส่)
    val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
    if [[ "$val" == \"*\" || "$val" == \'*\' ]] && (( ${#val} >= 2 )); then val="${val:1:${#val}-2}"; fi
    case "$key" in
      GATEWAY_NAME) CONF_GATEWAY_NAME="$val" ;;
      SSH_PUBKEY)   CONF_SSH_PUBKEY="$val" ;;
      SETUP_CODE)   CONF_SETUP_CODE="$val" ;;
      TECH_USER)    CONF_TECH_USER="$val" ;;
      *) log "ไม่รู้จักคีย์ '${key}' ใน ${CONF_NAME} -- ข้าม" ;;
    esac
  done < "$f"
}

# ---------- setup code ----------
normalize_code() {  # ตัวพิมพ์ใหญ่ ตัด - และช่องว่าง: "k7qm-29xd" == "K7QM29XD"
  local c="${1^^}"
  c="${c//-/}"; c="${c//[[:space:]]/}"
  printf '%s' "$c"
}
random_code() {  # 8 ตัวจาก CODE_ALPHABET (31 ตัว ~ 39.6 บิต) -- ทายผ่าน wizard ไม่ได้เพราะล็อกหลังผิด 5 ครั้ง
  local out="" n i
  for i in 1 2 3 4 5 6 7 8; do
    # rejection sampling: 248 = 31*8 กันการเอียงจาก modulo
    while :; do
      n=$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')
      (( n < 248 )) && break
    done
    out+="${CODE_ALPHABET:n % ${#CODE_ALPHABET}:1}"
  done
  printf '%s' "$out"
}
pretty_code() { printf '%s-%s' "${1:0:4}" "${1:4}"; }

write_atomic() {  # write_atomic <path> <mode> <owner:group>  (เนื้อหาจาก stdin)
  local path="$1" mode="$2" own="$3" tmp="${1}.new"
  cat > "$tmp"
  chmod "$mode" "$tmp"
  chown "$own" "$tmp" 2>/dev/null || true
  sync "$tmp" 2>/dev/null || sync
  mv -f "$tmp" "$path"
}

ensure_setup_code() {
  local boot="$1" code=""
  if [[ -n "$CONF_SETUP_CODE" ]]; then
    code="$(normalize_code "$CONF_SETUP_CODE")"
    [[ "$code" =~ ^[A-Z0-9]{8,32}$ ]] || fail "SETUP_CODE ใน ${CONF_NAME} ต้องเป็นตัวอักษร/ตัวเลข 8-32 ตัว"
    log "ใช้ setup code จาก ${CONF_NAME}"
  elif [[ -s "$CODE_FILE" ]]; then
    log "มี setup code จากรอบก่อนแล้ว -- ใช้ของเดิม"
    code="$(head -n1 "$CODE_FILE")"
  else
    code="$(random_code)"
    log "ไม่มี setup code ใน ${CONF_NAME} -- สุ่มให้ และเขียนลง bootfs/SETUP-CODE.txt"
  fi
  printf '%s\n' "$code" | write_atomic "$CODE_FILE" 0640 "root:${APP_USER}"
  # ช่างอ่านจาก bootfs ได้เสมอ (ถอดการ์ดไปเสียบคอม) -- wizard ลบไฟล์นี้ทิ้งเมื่อสร้างแอดมินเสร็จ (M4)
  # เขียนทุกรอบ (ไม่ใช่เฉพาะตอนสุ่ม): ไฟดับหลังเก็บ code ในเครื่องแต่ก่อนเขียนไฟล์นี้ = ช่างไม่มีทางรู้ code
  if [[ -n "$boot" && -z "$CONF_SETUP_CODE" ]]; then
    printf 'Cafe-WiFi setup code: %s\r\n' "$(pretty_code "$code")" | write_atomic "${boot}/SETUP-CODE.txt" 0644 "root:root"
  fi
}

# ---------- เอกลักษณ์ของเครื่อง (§2 ข้อ 9-10) ----------
ensure_os_identity() {
  (( SKIP_OS_IDENTITY )) && return 0
  if [[ ! -s /etc/machine-id ]] || grep -qx uninitialized /etc/machine-id; then
    log "สร้าง machine-id ใหม่"
    rm -f /etc/machine-id
    systemd-machine-id-setup >/dev/null
  fi
  if ! compgen -G '/etc/ssh/ssh_host_*_key' >/dev/null; then
    log "สร้าง SSH host keys ใหม่"
  fi
  ssh-keygen -A >/dev/null   # สร้างเฉพาะชนิดที่ยังไม่มี -- รันซ้ำไม่ทับของเดิม
  # host key ที่ขาดครึ่งจากไฟดับ (ไฟล์ว่าง) ทำให้ sshd ไม่ขึ้น -> ลบแล้วสร้างใหม่
  local k
  for k in /etc/ssh/ssh_host_*_key; do
    if ! ssh-keygen -y -f "$k" >/dev/null 2>&1; then
      log "host key ${k} เสีย -- สร้างใหม่"
      rm -f "$k" "${k}.pub"
    fi
  done
  ssh-keygen -A >/dev/null
}

# ---------- บัญชีช่าง: SSH key เท่านั้น ไม่มีรหัสผ่าน (§2 ข้อ 12: ห้ามมี ras/1234 ใน image) ----------
ensure_tech_user() {
  (( SKIP_OS_IDENTITY )) && return 0
  [[ -n "$CONF_SSH_PUBKEY" ]] || { log "ไม่มี SSH_PUBKEY ใน ${CONF_NAME} -- ไม่สร้างบัญชีช่าง (ดูแลผ่านหน้าแอดมินเท่านั้น)"; return 0; }
  local user="${CONF_TECH_USER:-$DEFAULT_TECH_USER}" tmp
  [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail "TECH_USER '${user}' ไม่ใช่ชื่อผู้ใช้ที่ถูกต้อง"
  [[ "$user" != root && "$user" != "$APP_USER" ]] || fail "TECH_USER ห้ามเป็น ${user}"
  tmp="$(mktemp)"
  printf '%s\n' "$CONF_SSH_PUBKEY" > "$tmp"
  ssh-keygen -l -f "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; fail "SSH_PUBKEY ใน ${CONF_NAME} ไม่ใช่ public key ที่ถูกต้อง"; }
  rm -f "$tmp"
  if ! id -u "$user" >/dev/null 2>&1; then
    log "สร้างบัญชีช่าง ${user} (SSH key เท่านั้น)"
    useradd -m -s /bin/bash "$user"
  fi
  passwd -l "$user" >/dev/null
  local home; home="$(getent passwd "$user" | cut -d: -f6)"
  install -d -m 0700 -o "$user" -g "$user" "${home}/.ssh"
  touch "${home}/.ssh/authorized_keys"
  grep -qxF "$CONF_SSH_PUBKEY" "${home}/.ssh/authorized_keys" || printf '%s\n' "$CONF_SSH_PUBKEY" >> "${home}/.ssh/authorized_keys"
  chown "$user:$user" "${home}/.ssh/authorized_keys"; chmod 0600 "${home}/.ssh/authorized_keys"
  # ไม่มีรหัสผ่าน = sudo ต้องไม่ถามรหัส (เข้ามาได้ด้วย key อย่างเดียวอยู่แล้ว)
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$user" > "/etc/sudoers.d/010-${user}.new"
  chmod 0440 "/etc/sudoers.d/010-${user}.new"
  visudo -cf "/etc/sudoers.d/010-${user}.new" >/dev/null || { rm -f "/etc/sudoers.d/010-${user}.new"; fail "sudoers ของ ${user} ไม่ผ่านการตรวจ"; }
  mv -f "/etc/sudoers.d/010-${user}.new" "/etc/sudoers.d/010-${user}"
}

main() {
  [[ $EUID -eq 0 || -n "${CAFEWIFI_ETC_DIR:-}" ]] || fail "ต้องรันด้วย root"
  if [[ -e "$DONE_FLAG" ]]; then log "ทำไปแล้ว (${DONE_FLAG}) -- ไม่ทำซ้ำ"; exit 0; fi
  led busy

  local boot conf=""
  boot="$(find_bootfs)"
  if [[ -n "$boot" ]]; then conf="${boot}/${CONF_NAME}"; else log "หา bootfs ไม่เจอ -- ใช้ค่าปริยายทั้งหมด"; fi
  [[ -n "$conf" ]] && read_conf "$conf"

  install -d -m 0750 -o root -g "$APP_USER" "$ETC_DIR" 2>/dev/null || install -d -m 0750 "$ETC_DIR"

  ensure_os_identity
  ensure_setup_code "$boot"
  ensure_tech_user

  local args=(--stage firstboot)
  [[ -n "$CONF_GATEWAY_NAME" ]] && args+=(--ssid "$CONF_GATEWAY_NAME")
  log "รัน ${INSTALL_SH} ${args[*]}"
  bash "$INSTALL_SH" "${args[@]}" || fail "install.sh --stage firstboot ล้มเหลว (ดู /var/log/cafe-wifi/install.log) -- บูตใหม่จะลองต่อจากเดิม"

  # conf มี setup code + key ช่าง ซึ่งใครถือการ์ดก็อ่านได้ -- ใช้เสร็จแล้วลบ (ค่าเก็บในเครื่องแล้ว)
  if [[ -n "$conf" && -f "$conf" ]]; then rm -f "$conf"; log "ลบ ${CONF_NAME} ออกจาก bootfs แล้ว"; fi

  sync
  : > "${DONE_FLAG}.new"; sync; mv -f "${DONE_FLAG}.new" "$DONE_FLAG"; sync
  log "บูตครั้งแรกเสร็จ -- เข้าโหมดตั้งค่า"
  led ready
  # โหมดตั้งค่า (M4): cafe-wifi-setup.service + cafe-wifi-apply.path ถูก enable ไว้ใน image และรอ
  # After= service นี้อยู่แล้ว จึงขึ้นเองต่อจากนี้ -- ไม่ต้องสั่ง start
}

main "$@"
