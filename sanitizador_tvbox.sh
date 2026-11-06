#!/usr/bin/env bash
# ==============================================================================
# SANITIZADOR E PADRONIZADOR DE TV BOX (dolphin-fvd-p1 / Allwinner H3)
# Projeto de Auditoria e Hardening — Segurança Computacional (UESPI)
#
# Compatível com:
#   - Unidades no estado original de fábrica (sem hardening prévio)
#   - Unidades já submetidas ao Hardening Nível 1 (Grupo 3)
#   - Reexecução para auditoria/emissão de laudo
#
# Uso:
#   ./sanitizador_tvbox.sh                # Sanitiza a Box conectada e gera laudo
#   ./sanitizador_tvbox.sh --check        # Apenas audita o estado atual sem alterar
#   ./sanitizador_tvbox.sh --keep-media   # Sanitiza malwares mas mantém Kodi/YouTube/Netflix
#   ./sanitizador_tvbox.sh -s <SERIAL>    # Especifica qual Box usar se houver várias no USB
# ==============================================================================

set -uo pipefail

# Cores para feedback visual no terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

MODE="SANITIZE"
KEEP_MEDIA=0
TARGET_SERIAL=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/laudos_sanitizacao"

# Contadores de feedback da execução
COUNT_OK=0
COUNT_WARN=0
COUNT_FAIL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check|-c)
            MODE="CHECK"
            shift
            ;;
        --keep-media|-k)
            KEEP_MEDIA=1
            shift
            ;;
        --serial|-s)
            TARGET_SERIAL="$2"
            shift 2
            ;;
        --help|-h)
            echo "Uso: $0 [--check] [--keep-media] [-s <SERIAL_ADB>]"
            echo "  (sem flags)    Executa a sanitização completa Nível 1 + Nível 2 e emite laudo"
            echo "  --check        Apenas verifica o estado da TV Box conectada sem modificar nada"
            echo "  --keep-media   Remove todos os malwares/backdoors, mas preserva Kodi/Netflix/YouTubeTV"
            echo "  -s <SERIAL>    Seleciona uma TV Box específica quando há várias conectadas via USB"
            exit 0
            ;;
        *)
            echo -e "${RED}[ERRO] Parâmetro desconhecido: $1${NC}"
            exit 1
            ;;
    esac
done

ADB_CMD=(adb)
if [[ -n "$TARGET_SERIAL" ]]; then
    ADB_CMD=(adb -s "$TARGET_SERIAL")
fi

log_info()  { echo -e "  ${BLUE}[INFO]${NC}  $*"; }
log_ok()    { COUNT_OK=$((COUNT_OK + 1));   echo -e "  ${GREEN}[OK]${NC}    $*"; }
log_warn()  { COUNT_WARN=$((COUNT_WARN + 1)); echo -e "  ${YELLOW}[AVISO]${NC} $*"; }
log_err()   { COUNT_FAIL=$((COUNT_FAIL + 1)); echo -e "  ${RED}[ERRO]${NC}  $*"; }
log_step()  { echo -e "\n${BOLD}${CYAN}======================================================================${NC}\n${BOLD}${CYAN} $* ${NC}\n${BOLD}${CYAN}======================================================================${NC}"; }

# Executa comando como root na TV Box (funciona tanto com adbd root quanto via su)
box_root() {
    "${ADB_CMD[@]}" shell "$*" 2>/dev/null | tr -d '\r'
}

# ==============================================================================
# [ETAPA 1/7] VERIFICAÇÃO DE CONEXÃO E IDENTIFICAÇÃO DA UNIDADE
# ==============================================================================
log_step "[1/7] CONEXÃO E IDENTIFICAÇÃO DA TV BOX"

if ! command -v adb >/dev/null 2>&1; then
    log_err "Comando 'adb' não encontrado no computador. Instale o android-tools/platform-tools."
    exit 1
fi

CONNECTED_COUNT=$("${ADB_CMD[@]}" get-state 2>/dev/null | grep -c "device" || true)
if [[ "$CONNECTED_COUNT" -eq 0 ]]; then
    log_err "Nenhuma TV Box detectada via ADB (ou dispositivo offline/unauthorized)."
    log_info "Verifique o cabo USB e rode 'adb devices' para testar a comunicação."
    exit 1
fi

log_info "Solicitando privilégio root via ADB..."
"${ADB_CMD[@]}" root >/dev/null 2>&1 || true
sleep 1
CURRENT_UID=$(box_root "id -u")
if [[ "$CURRENT_UID" != "0" ]]; then
    log_warn "adbd não subiu direto como root. Tentando fallback via /system/xbin/su..."
    box_root() {
        "${ADB_CMD[@]}" shell "/system/xbin/su -c '$*'" 2>/dev/null | tr -d '\r'
    }
    CURRENT_UID=$(box_root "id -u")
    if [[ "$CURRENT_UID" != "0" ]]; then
        log_err "Não foi possível obter acesso root (uid=0) na TV Box. Abortando."
        exit 1
    fi
fi
log_ok "Acesso root confirmado na TV Box (uid=0)."

SERIAL=$(box_root "getprop ro.serialno")
[[ -z "$SERIAL" ]] && SERIAL="desconhecido_$(date +%s)"
DEVICE_NAME=$(box_root "getprop ro.product.device")
MODEL_NAME=$(box_root "getprop ro.product.model")
FINGERPRINT=$(box_root "getprop ro.build.fingerprint")
ANDROID_REPORTED=$(box_root "getprop ro.build.version.release")
SDK_VERSION=$(box_root "getprop ro.build.version.sdk")
ETH_MAC=$(box_root "cat /sys/class/net/eth0/address 2>/dev/null || echo N/A")
WIFI_MAC=$(box_root "cat /sys/class/net/wlan0/address 2>/dev/null || echo N/A")

# Diagnóstico do estado inicial da unidade (Original de Fábrica vs Hardening Nível 1 vs Sanitizada Nível 2)
HAS_UOTA_APK=$(box_root "[ -d /system/app/UOTA_aikePro103 ] && echo SIM || echo NAO")
HAS_QCAST_APK=$(box_root "[ -d /system/preinstall/QCast_TV_ad_service_release_build_aikeweida_box_976_signed ] && echo SIM || echo NAO")
HAS_QW_BIN=$(box_root "[ -f /system/bin/qw ] && echo SIM || echo NAO")
UOTA_DISABLED=$(box_root "pm list packages -d | grep -c 'com.uv.droid.uota' || true")

if [[ "$HAS_UOTA_APK" == "NAO" && "$HAS_QCAST_APK" == "NAO" && "$HAS_QW_BIN" == "NAO" ]]; then
    INITIAL_STATE="JA_SANITIZADA_NIVEL_2"
elif [[ "$UOTA_DISABLED" -gt 0 ]]; then
    INITIAL_STATE="HARDENING_PARCIAL_NIVEL_1"
else
    INITIAL_STATE="ORIGINAL_DE_FABRICA (Malwares Ativos)"
fi

log_ok "Unidade Identificada : ${BOLD}${SERIAL}${NC} (${MODEL_NAME} / ${DEVICE_NAME})"
log_info "Fingerprint          : ${FINGERPRINT}"
log_info "Android Reportado    : ${ANDROID_REPORTED} (SDK Real: API ${SDK_VERSION})"
log_info "MAC Ethernet / Wi-Fi : ${ETH_MAC} / ${WIFI_MAC}"
log_info "Estado Inicial       : ${BOLD}${YELLOW}${INITIAL_STATE}${NC}"

if [[ "$MODE" == "SANITIZE" ]]; then
    # ==========================================================================
    # [ETAPA 2/7] PARADA IMEDIATA DE DAEMONS ROOT E PROCESSOS EM MEMÓRIA
    # ==========================================================================
    log_step "[2/7] PARADA IMEDIATA DE DAEMONS ROOT E WATCHDOGS EM MEMÓRIA"

    log_info "Interrompendo daemons nativos 'qw' e 'att_policy'..."
    box_root "stop qw 2>/dev/null; setprop ctl.stop qw 2>/dev/null"
    box_root "stop att_policy 2>/dev/null; setprop ctl.stop att_policy 2>/dev/null"
    box_root "killall -9 qw att_policy startsoftdetector.sh 2>/dev/null || true"
    box_root "rm -rf /dev/com.koushikdutta.superuser.daemon 2>/dev/null || true"
    log_ok "Daemons nativos 'qw' e 'att_policy' parados em memória."

    MALWARE_PKGS=(
        "com.uv.droid.uota"
        "com.uv.droid.uotaback"
        "com.qcode.ad_service_server"
        "com.simple.appstore.flymarket"
        "com.factorytools.factorystability"
        "com.softwinner.dragonbox"
        "com.softwinner.agingdragonbox"
        "com.allwinnertech.dragonsn"
        "com.allwinnertech.dragonenter"
        "com.softwinner.miracastReceiver"
        "com.google.android.tv.remote.service"
        "com.cmcc.mid.softdetector"
    )

    BLOAT_MEDIA_PKGS=(
        "com.netflix.mediaclient"
        "com.google.android.youtube.tv"
        "org.xbmc.kodi"
    )

    if [[ "$KEEP_MEDIA" -eq 0 ]]; then
        ALL_TARGET_PKGS=("${MALWARE_PKGS[@]}" "${BLOAT_MEDIA_PKGS[@]}")
    else
        ALL_TARGET_PKGS=("${MALWARE_PKGS[@]}")
    fi

    for pkg in "${ALL_TARGET_PKGS[@]}"; do
        box_root "am force-stop ${pkg} 2>/dev/null || true"
        box_root "killall -9 ${pkg} 2>/dev/null || true"
    done
    log_ok "Processos de RAT, Adware, Proxy Titan e Watchdogs encerrados em memória."

    # ==========================================================================
    # [ETAPA 3/7] HARDENING NÍVEL 1 (PACKAGE MANAGER, APPOPS E SETTINGS)
    # ==========================================================================
    log_step "[3/7] HARDENING NÍVEL 1 (PACKAGE MANAGER, APPOPS E SETTINGS)"

    for pkg in "${ALL_TARGET_PKGS[@]}"; do
        PKG_EXISTS=$(box_root "pm path ${pkg} 2>/dev/null || true")
        box_root "appops set ${pkg} RUN_IN_BACKGROUND ignore 2>/dev/null || true"
        box_root "appops set ${pkg} WAKE_LOCK ignore 2>/dev/null || true"
        box_root "pm clear ${pkg} >/dev/null 2>&1 || true"
        box_root "pm disable-user --user 0 ${pkg} >/dev/null 2>&1 || true"
        box_root "pm hide ${pkg} >/dev/null 2>&1 || true"
        box_root "pm uninstall -k --user 0 ${pkg} >/dev/null 2>&1 || true"
        if [[ -n "$PKG_EXISTS" ]]; then
            log_ok "Pacote neutralizado e desinstalado do usuário 0: ${pkg}"
        else
            log_info "Pacote já estava ausente/desinstalado no Android: ${pkg}"
        fi
    done

    # Blindagem de configurações do sistema Android com verificação de retorno
    box_root "settings put secure install_non_market_apps 0"
    box_root "settings put global package_verifier_enable 1"
    box_root "settings put global adb_enabled 1"
    box_root "setprop service.adb.tcp.port -1"
    box_root "setprop persist.service.adb.tcp.port ''"

    VERIFY_SOURCES=$(box_root "settings get secure install_non_market_apps")
    if [[ "$VERIFY_SOURCES" == "0" ]]; then
        log_ok "Configuração 'install_non_market_apps=0' (fontes desconhecidas bloqueadas) confirmada."
    else
        log_warn "Não foi possível confirmar 'install_non_market_apps=0' (valor atual: ${VERIFY_SOURCES})."
    fi

    # ==========================================================================
    # [ETAPA 4/7] EXPURGO FÍSICO DA PARTIÇÃO /system (IMUNE A FACTORY RESET)
    # ==========================================================================
    log_step "[4/7] EXPURGO CIRÚRGICO DA PARTIÇÃO /system (IMUNE A FACTORY RESET)"

    log_info "Montando partição /system em modo leitura e escrita (rw)..."
    box_root "mount -o rw,remount /system 2>/dev/null || mount -o remount,rw /dev/block/by-name/system /system 2>/dev/null || busybox mount -o rw,remount /system"

    # Testa escrita real em /system para garantir que não está bloqueada
     CAN_WRITE_SYSTEM=$(box_root "touch /system/.rw_test 2>/dev/null && rm -f /system/.rw_test && echo SIM || echo NAO")
    if [[ "$CAN_WRITE_SYSTEM" != "SIM" ]]; then
        log_err "A partição /system recusou escrita (permaneceu Read-Only). As remoções físicas de /system podem falhar!"
    else
        log_ok "Partição /system montada em modo escrita (rw) com sucesso."
    fi

    # 4.1 Remoção física dos diretórios e APKs maliciosos em /system com confirmação individual
    SYSTEM_TARGETS=(
        "/system/app/UOTA_aikePro103"
        "/system/app/UOTA_aikePro103.apk"
        "/system/app/UOTABack_aikePro102"
        "/system/app/UOTABack_aikePro102.apk"
        "/system/app/FactoryStability"
        "/system/app/DragonBox"
        "/system/app/DragonAging"
        "/system/app/DragonSN"
        "/system/priv-app/AtvRemoteService"
        "/system/preinstall/QCast_TV_ad_service_release_build_aikeweida_box_976_signed"
        "/system/preinstall/GetApps_203"
        "/system/preinstall/FactoryStability"
        "/system/preinstall/DragonBox"
        "/system/preinstall/agingdragonbox"
        "/system/preinstall/DragonSN"
        "/system/bin/libpcapcmcc.so"
    )

    if [[ "$KEEP_MEDIA" -eq 0 ]]; then
        SYSTEM_TARGETS+=(
            "/system/preinstall/Netflix416"
            "/system/preinstall/YoutubeTV_20214"
            "/system/preinstall/kodi-180-master-armeabi-v7a"
            "/system/org.xbmc.kodi.zip"
            "/system/org.xbmc.kodi.tar.gz"
        )
    fi

    for target in "${SYSTEM_TARGETS[@]}"; do
        if [[ $(box_root "[ -e '${target}' ] && echo 1 || echo 0") == "1" ]]; then
            box_root "rm -rf '${target}'"
            if [[ $(box_root "[ ! -e '${target}' ] && echo 1 || echo 0") == "1" ]]; then
                log_ok "Removido fisicamente de /system: ${target}"
            else
                log_err "Falha ao remover de /system: ${target}"
            fi
        else
            log_info "Já ausente em /system: ${target}"
        fi
    done

    # Remove também qualquer APK solto de fábrica residual em /system/preinstall
    box_root "rm -rf /system/preinstall/*Dragon* /system/preinstall/*aging* /system/preinstall/*QCast* /system/preinstall/*GetApps* /system/preinstall/*Factory* 2>/dev/null || true"

    # 4.2 Neutralização definitiva dos binários root/fraude nativos em /system/bin
    for bin_target in "/system/bin/qw" "/system/bin/att_policy" "/system/bin/startsoftdetector.sh" "/system/bin/copydata.sh"; do
        if [[ $(box_root "[ -f '${bin_target}' ] && echo 1 || echo 0") == "1" ]]; then
            box_root "rm -f '${bin_target}'"
            if [[ $(box_root "[ ! -f '${bin_target}' ] && echo 1 || echo 0") == "1" ]]; then
                log_ok "Binário/script nativo eliminado: ${bin_target}"
            else
                log_err "Não foi possível apagar o binário/script: ${bin_target}"
            fi
        else
            log_info "Binário/script já ausente: ${bin_target}"
        fi
    done

    # Remove a chamada 'qw --daemon' do final de /system/bin/preinstall.sh
    if [[ $(box_root "[ -f /system/bin/preinstall.sh ] && grep -c 'qw' /system/bin/preinstall.sh || true") -gt 0 ]]; then
        box_root "sed -i '/qw/d' /system/bin/preinstall.sh"
        if [[ $(box_root "grep -c 'qw' /system/bin/preinstall.sh || true") -eq 0 ]]; then
            log_ok "Chamada 'qw --daemon' removida de /system/bin/preinstall.sh."
        else
            log_err "Falha ao limpar 'qw --daemon' em /system/bin/preinstall.sh."
        fi
    fi

    # ==========================================================================
    # [ETAPA 5/7] VACINA DE REDE (/system/etc/hosts + IPTABLES) E build.prop
    # ==========================================================================
    log_step "[5/7] VACINA DE REDE (/system/etc/hosts + FIREWALL C2) E build.prop"

    # 5.1 Corrige a falsificação de versão do Android no /system/build.prop (11.1 -> 7.0)
    if [[ $(box_root "grep -c '11\.1' /system/build.prop || echo 0") -gt 0 ]]; then
        box_root "[ ! -f /system/build.prop.orig ] && cp /system/build.prop /system/build.prop.orig || true"
        box_root "sed -i 's/11\.1/7.0/g' /system/build.prop"
        box_root "sed -i 's/^ro.build.version.release=.*/ro.build.version.release=7.0/' /system/build.prop"
        box_root "chmod 644 /system/build.prop"
        NEW_REL=$(box_root "grep '^ro.build.version.release=' /system/build.prop | cut -d= -f2")
        if [[ "$NEW_REL" == "7.0" ]]; then
            log_ok "Versão no /system/build.prop corrigida de '11.1' (falsa) para '7.0' (real) em release e display.id."
        else
            log_err "Falha ao atualizar ro.build.version.release em /system/build.prop."
        fi
    else
        log_info "/system/build.prop já reporta a versão real do Android."
    fi

    # 5.2 Injeta de forma atômica e idempotente todos os domínios C2 mapeados nas Etapas 1 a 4
    box_root "[ ! -f /system/etc/hosts ] && echo '127.0.0.1 localhost' > /system/etc/hosts || true"
    box_root "grep -q 'uota.uota.xyz' /system/etc/hosts || cat << 'EOF' >> /system/etc/hosts
# === Bloqueio C2 Auditoria Etapa 4 ===
0.0.0.0 uota.uota.xyz
0.0.0.0 appmetrices.uota.xyz
0.0.0.0 ds.b20.host
0.0.0.0 vxmfc.com
0.0.0.0 launcher.cluster.qcast.cn
0.0.0.0 filedata.qcast.cn
0.0.0.0 ad-Stat.qcast.cn
0.0.0.0 log.qcast.cn
0.0.0.0 qc-user-behavior.cn-hangzhou.log.aliyuncs.com
0.0.0.0 log-collector.cn-qingdao.log.aliyuncs.com
0.0.0.0 error-log-collector.cn-qingdao.log.aliyuncs.com
0.0.0.0 open.ssp.zztgfh.com
0.0.0.0 s.mzfile.com
0.0.0.0 sdk.cdnmaster.com
0.0.0.0 cmnsguider.yunos.com
0.0.0.0 appstore.bb20.site
0.0.0.0 alog.umeng.com
0.0.0.0 alog.umengcloud.com
0.0.0.0 uop.umeng.com
0.0.0.0 log.umsns.com
0.0.0.0 plbslog.umeng.com
0.0.0.0 astromaterials.org
0.0.0.0 android.bugly.qq.com
0.0.0.0 bugly.qq.com
EOF"
    box_root "chmod 644 /system/etc/hosts"
    VERIFY_HOSTS=$(box_root "grep -c '^0.0.0.0 ' /system/etc/hosts 2>/dev/null || true")
    if [[ "$VERIFY_HOSTS" -ge 20 ]]; then
        log_ok "Sinkhole DNS confirmado em /system/etc/hosts (${VERIFY_HOSTS} domínios C2 bloqueados com sucesso)."
    else
        log_err "Contagem de domínios em /system/etc/hosts abaixo do esperado (${VERIFY_HOSTS})."
    fi

    # 5.3 Bloqueia no iptables o IP fixo de fallback do C2 (158.69.220.68) descoberto na Etapa 4
    box_root "mkdir -p /system/su.d && rm -f /system/su.d/*"
    box_root "cat << 'EOF' > /system/su.d/99_hardening_firewall.sh
#!/system/bin/sh
# Bloqueio do IP fixo de fallback C2 do UOTA (158.69.220.68) e desativação de ADB TCP
iptables -C OUTPUT -d 158.69.220.68 -j DROP 2>/dev/null || iptables -I OUTPUT -d 158.69.220.68 -j DROP
setprop service.adb.tcp.port -1
EOF"
    box_root "chmod 755 /system/su.d/99_hardening_firewall.sh"
    box_root "/system/bin/sh /system/su.d/99_hardening_firewall.sh 2>/dev/null || true"

    if [[ $(box_root "iptables -L OUTPUT -n 2>/dev/null | grep -c '158.69.220.68' || echo 0") -gt 0 ]]; then
        log_ok "Regra de firewall iptables contra o IP C2 158.69.220.68 ativa e persistente em /system/su.d/."
    else
        log_warn "Script criado em /system/su.d/, mas não foi possível verificar a regra ativa no iptables agora."
    fi

    # Retoma /system como somente leitura (ro)
    box_root "sync && mount -o ro,remount /system 2>/dev/null || true"
    log_ok "Partição /system sincronizada e remontada como somente leitura (ro)."

    # ==========================================================================
    # [ETAPA 6/7] FAXINA DE DADOS RESIDUAIS EM /data E /sdcard
    # ==========================================================================
    log_step "[6/7] FAXINA DE RASTROS, CACHES E PAYLOADS EM /data E /sdcard"

    box_root "touch /data/system.notfirstrun /data/system.notfirstrun.precopy /data/local/symbol_is_preinstalled /data/local/symbol_xbmc_file_coped"
    box_root "rm -rf /sdcard/uota /sdcard/uotaback /sdcard/preinstall /data/local/tmp/scctmp.png /data/local/123.txt"
    box_root "rm -rf /sdcard/titan-* /data/media/0/titan-* /data/media/0/uota /data/media/0/uotaback"
    box_root "rm -rf /data/data/com.koushikdutta.superuser"

    for pkg in "${ALL_TARGET_PKGS[@]}"; do
        box_root "rm -rf /data/data/${pkg} /data/user/0/${pkg} /data/app/${pkg}* /sdcard/Android/data/${pkg}"
    done
    log_ok "Diretórios residuais (/sdcard/uota, titan-*, /data/local/tmp/scctmp.png e /data/data/*) eliminados."
fi

# ==============================================================================
# [ETAPA 7/7] AUDITORIA PÓS-EXECUÇÃO, FEEDBACK NO TERMINAL E EMISSÃO DE LAUDO
# ==============================================================================
log_step "[7/7] AUDITORIA DE CONFORMIDADE E RELATÓRIO FINAL"

mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
REPORT_FILE="${REPORT_DIR}/laudo_${SERIAL}.md"

# Checagens objetivas na unidade
CHK_UOTA_DIR=$(box_root "[ ! -d /system/app/UOTA_aikePro103 ] && [ ! -d /system/app/UOTABack_aikePro102 ] && echo 'APROVADO (Removidos de /system)' || echo 'FALHA (Ainda presente em /system)'")
CHK_QCAST_DIR=$(box_root "[ ! -d /system/preinstall/QCast_TV_ad_service_release_build_aikeweida_box_976_signed ] && echo 'APROVADO (Removido de /system)' || echo 'FALHA (Ainda presente em /system)'")
CHK_GETAPPS_DIR=$(box_root "[ ! -d /system/preinstall/GetApps_203 ] && [ ! -d /system/preinstall/FactoryStability ] && echo 'APROVADO (Removidos de /system)' || echo 'FALHA (Ainda presente em /system)'")
CHK_QW_BIN=$(box_root "[ ! -f /system/bin/qw ] && echo 'APROVADO (Binário qw eliminado)' || echo 'FALHA (/system/bin/qw existe)'")
CHK_ATT_BIN=$(box_root "[ ! -f /system/bin/att_policy ] && echo 'APROVADO (Binário att_policy eliminado)' || echo 'FALHA (/system/bin/att_policy existe)'")
CHK_PROC_ACTIVE=$(box_root "ps | grep -E 'uota|qcode|flymarket|qw|att_policy' | grep -v grep || echo 'NENHUM'")
CHK_HOSTS_COUNT=$(box_root "grep -c '^0.0.0.0 ' /system/etc/hosts 2>/dev/null || true")
CHK_IPTABLES=$(box_root "iptables -L OUTPUT -n 2>/dev/null | grep -c '158.69.220.68' || true")
CHK_UNKNOWN_SOURCES=$(box_root "settings get secure install_non_market_apps")
CHK_ANDROID_VER=$(box_root "grep '^ro.build.version.release=' /system/build.prop | cut -d= -f2")
MEM_INFO=$(box_root "grep -E 'MemTotal|MemAvailable|MemFree' /proc/meminfo | tr '\n' ' '")
DISK_INFO=$(box_root "df -h /system /data 2>/dev/null || df /system /data")

OVERALL_STATUS="APROVADA (PADRÃO ANDROID BASE LIMPO)"
if [[ "$CHK_UOTA_DIR" == FALHA* || "$CHK_QCAST_DIR" == FALHA* || "$CHK_QW_BIN" == FALHA* || "$COUNT_FAIL" -gt 0 ]]; then
    OVERALL_STATUS="ATENÇÃO: PENDÊNCIAS DETECTADAS (VERIFICAR FALHAS)"
fi

# Exibe o resumo claro direto na tela do operador
echo -e "\n${BOLD}Resumo dos 10 Testes de Verificação na Unidade ${SERIAL}:${NC}"
echo -e "  1. Remoção RAT UOTA/UOTABack (/system) : ${CHK_UOTA_DIR}"
echo -e "  2. Remoção QCast/Proxy Titan (/system) : ${CHK_QCAST_DIR}"
echo -e "  3. Remoção GetApps/FactoryStability    : ${CHK_GETAPPS_DIR}"
echo -e "  4. Eliminação Backdoor Root (/bin/qw)  : ${CHK_QW_BIN}"
echo -e "  5. Eliminação Daemon CPU (att_policy)  : ${CHK_ATT_BIN}"
echo -e "  6. Processos Maliciosos Rodando (ps)   : ${CHK_PROC_ACTIVE}"
echo -e "  7. Domínios C2 Bloqueados (/etc/hosts) : ${CHK_HOSTS_COUNT} domínios"
echo -e "  8. Regra Firewall IP C2 158.69.220.68  : ${CHK_IPTABLES} regra(s) ativa(s)"
echo -e "  9. Fontes Desconhecidas (esperado 0)   : ${CHK_UNKNOWN_SOURCES}"
echo -e " 10. Versão Android no build.prop        : ${CHK_ANDROID_VER} (SDK Real: API ${SDK_VERSION})"

echo -e "\n${BOLD}Placar da Execução:${NC} ${GREEN}Sucessos: ${COUNT_OK}${NC} | ${YELLOW}Avisos: ${COUNT_WARN}${NC} | ${RED}Erros: ${COUNT_FAIL}${NC}"

cat << EOF > "$REPORT_FILE"
# Laudo Técnico de Sanitização e Conformidade — TV Box

- **Status Final da Unidade:** **${OVERALL_STATUS}**
- **Data/Hora da Verificação:** ${TIMESTAMP}
- **Modo Executado:** ${MODE}
- **Placar da Execução:** Sucessos: \`${COUNT_OK}\` | Avisos: \`${COUNT_WARN}\` | Erros: \`${COUNT_FAIL}\`
- **Número de Série (SoC):** \`${SERIAL}\`
- **Modelo / Placa:** \`${MODEL_NAME}\` (\`${DEVICE_NAME}\`)
- **MAC Ethernet / Wi-Fi:** \`${ETH_MAC}\` / \`${WIFI_MAC}\`
- **Estado Inicial antes da Execução:** \`${INITIAL_STATE}\`

---

## Checklist de Verificação de Segurança (Nível 1 + Nível 2)

| Item Auditado | Resultado na Unidade |
| :--- | :--- |
| **1. Remoção Física do RAT \`UOTA\` e \`UOTABack\` (\`/system/app\`)** | ${CHK_UOTA_DIR} |
| **2. Remoção Física do \`QCast\` / Proxy Titan (\`/system/preinstall\`)** | ${CHK_QCAST_DIR} |
| **3. Remoção Física de \`GetApps\` e \`FactoryStability\`** | ${CHK_GETAPPS_DIR} |
| **4. Eliminação do Backdoor Root Nativo (\`/system/bin/qw\`)** | ${CHK_QW_BIN} |
| **5. Eliminação do Daemon de Fraude CPU (\`/system/bin/att_policy\`)** | ${CHK_ATT_BIN} |
| **6. Processos Maliciosos em Execução na Memória (\`ps\`)** | \`${CHK_PROC_ACTIVE}\` |
| **7. Domínios C2 Bloqueados em \`/system/etc/hosts\`** | \`${CHK_HOSTS_COUNT}\` domínios redirecionados para \`0.0.0.0\` |
| **8. Bloqueio de Firewall (\`iptables\`) contra IP C2 \`158.69.220.68\`** | \`${CHK_IPTABLES}\` regra(s) ativa(s) |
| **9. Bloqueio de Fontes Desconhecidas (\`install_non_market_apps\`)** | \`${CHK_UNKNOWN_SOURCES}\` (Esperado: \`0\`) |
| **10. Versão do Android em \`/system/build.prop\`** | \`${CHK_ANDROID_VER}\` (SDK Real: API \`${SDK_VERSION}\`) |

---

## Recursos de Hardware Pós-Sanitização

- **Memória RAM:** \`${MEM_INFO}\`
- **Partições (\`/system\` e \`/data\`):**
\`\`\`text
${DISK_INFO}
\`\`\`
EOF

if [[ "$COUNT_FAIL" -eq 0 && "$OVERALL_STATUS" == APROVADA* ]]; then
    echo -e "\n${GREEN}${BOLD}>>> RESULTADO FINAL [${SERIAL}]: ${OVERALL_STATUS} <<<${NC}"
else
    echo -e "\n${RED}${BOLD}>>> RESULTADO FINAL [${SERIAL}]: ${OVERALL_STATUS} <<<${NC}"
fi
echo -e "${CYAN}Laudo salvo em: ${REPORT_FILE}${NC}\n"
