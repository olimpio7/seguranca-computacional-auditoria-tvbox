# Auditoria Forense, Engenharia Reversa e Sanitização de TV Box Android (`dolphin-fvd-p1` / Allwinner H3)

> **Universidade Estadual do Piauí (UESPI) — Campus Piripiri**  
> **Curso:** Bacharelado em Ciência da Computação  
> **Disciplina:** Segurança Computacional (2026)  
> **Docente:** Prof. Dr. José Vigno

Este repositório reúne a investigação completa — da análise estática e interceptação dinâmica de rede até a engenharia reversa de payloads ocultos, sanitização em nível de sistema (`root` / `/system`) e prova de resistência a *Factory Reset* — realizada sobre unidades TV Box genéricas comercializadas como *"Android 11.1 / 8 GB RAM / 128 GB ROM / 5G"* (baseadas na placa `dolphin-fvd-p1`, SoC Allwinner H3 `sun8iw7`, Android 7.0 Nougat API 24).

📄 **[Clique aqui para ler o Relatório Mestre Unificado Completo (`RELATORIO_UNIFICADO_SEGURANCA_COMPUTACIONAL.md`)](./RELATORIO_UNIFICADO_SEGURANCA_COMPUTACIONAL.md)** (também disponível em PDF: **[`RELATORIO_UNIFICADO_SEGURANCA_COMPUTACIONAL.pdf`](./RELATORIO_UNIFICADO_SEGURANCA_COMPUTACIONAL.pdf)**)

---

## 👥 Autores e Participantes por Etapa

O projeto foi desenvolvido de forma integrada e cumulativa ao longo de quatro etapas técnicas pelos discentes da disciplina de **Segurança Computacional**:

| Etapa | Escopo Técnico | Autores | Documento Original da Etapa |
| :--- | :--- | :--- | :--- |
| **Etapa 1 (Grupo 1)** | **Análise Estática e Caracterização do Firmware:** Inventário SHA-256 de 507 artefatos e 94 APKs, verificação de falsificação de hardware (`1 GB RAM` e `Android 7.0` reais), scripts `init` (`.rc`) e identificação inicial de `UOTA`, `QCast` e `GetApps`. | • **Maria Rita**<br>• **Pedro Gabryel** | [`RELATORIO_GRUPO1.pdf`](./grupos-auditorias/Pedro%20e%20Maria%20Rita/RELATORIO_GRUPO1.pdf) |
| **Etapa 2 (Grupo 2)** | **Análise Dinâmica e Interceptação em Rede Isolada:** Construção do laboratório `lab-tvbox` (`hostapd`, `dnsmasq`, `nftables`, `tcpdump`), servidor *sinkhole* na porta TCP `2082`, captura de *beacons* C2 e correlação de sockets (`E1` a `E6`). | • **João Marcello**<br>• **Vinícius Dias** | [`relatorio_grupo2.pdf`](./grupos-auditorias/Vinicius%20e%20Jo%C3%A3o%20Marcello/relatorio_grupo2.pdf) |
| **Etapa 3 (Grupo 3)** | **Preservação Forense e Hardening Nível 1:** Extração `dd` + MD5 das 8 partições NAND, classificação *Whitelist/Greylist/Blacklist*, contenção via `pm disable-user`, `pm hide` e `appops`, e bloqueio de fontes desconhecidas. | • **Francisco Tiago**<br>• **Olimpio**<br>• **Wellyson** | [`Grupo3_Documentacao_de_Entrega_completo.pdf`](./grupos-auditorias/Olimpio,%20Tiago%20e%20Wellyson/Grupo3_Documentacao_de_Entrega_completo.pdf) |
| **Etapa 4 (Fase Final)** | **Engenharia Reversa Profunda, Sanitização Nível 2 e Prova de Imunidade ao Factory Reset:** Dissecação de `qw` e `att_policy`, descoberta do RAT WebSocket (`ds.b20.host`), chaves AES-128 de `command.do`, descompilação dos 3 `.dex` ocultos do `QCast` (`TITAN_PLUGIN_DAEMON` + scanner LAN/ADB), fraude hardcoded em `Settings.apk`, script [`sanitizador_tvbox.sh`](./sanitizador_tvbox.sh) e experimento em 3 estados pós-`MASTER_CLEAR`. | • **Olimpio** | Consolidada no [`RELATORIO_UNIFICADO_SEGURANCA_COMPUTACIONAL.pdf`](./RELATORIO_UNIFICADO_SEGURANCA_COMPUTACIONAL.pdf) e em [`evidencias_resistencia/`](./evidencias_resistencia/) |

---

## 🔍 Principais Descobertas da Auditoria

1. **Falsificação em Dupla Camada (Propriedades + Bytecode Smali):**
   - O equipamento declara **Android 11.1 com 8 GB de RAM e 128 GB de armazenamento**, mas possui apenas **1 GB de RAM DDR3**, **~8 GB NAND** e **Android 7.0 (API 24)** sobre kernel Linux `3.4.39` com patch de segurança de `2016-10-05` e SELinux em modo `Permissive`.
   - Mesmo corrigindo `/system/build.prop`, a tela "Sobre o dispositivo" exibia `11.1` porque o método `DeviceInfoSettings.onCreate` dentro de `Settings.apk` foi adulterado no código Smali com a instrução estática `const-string v6, "11.1"`.
2. **Backdoors Root Nativos na Inicialização (`init`):**
   - Além do SuperSU (`2.82:SUPERSU`) em `/system/xbin/su`, o script `init.debug.rc` inicia como `class core` o binário [`/system/bin/qw`](./evidencias_binarios_elf.txt), um daemon Koush Superuser modificado que concede shell `root` (`uid=0`) sem prompt via socket local a qualquer processo que case com uma *whitelist* interna (`dragonbox`, `process_utils`, `/data/local/tmp`).
   - O serviço [`/system/bin/att_policy`](./evidencias_binarios_elf.txt) (`antutu.rc`) monitora em loop a instalação do AnTuTu Benchmark para forçar os núcleos da CPU para o governador `performance` ignorando limites térmicos.
3. **Trojan de Acesso Remoto (RAT) em `UOTA` e `UOTABack`:**
   - Operando com `android.uid.system` e *watchdog* mútuo (`ps -ef | grep`), a dupla se comunica com `uota.uota.xyz:2082` (e o IP fixo de fallback **`158.69.220.68:2082`**) para baixar `/sdcard/uota/script.zip`, decifrar `command.do` via **AES-128-CBC** (Chave: `XSiPLGG_JaTxyZ9yGR-eBw==`, IV: `E7vgilUjL7UbrV0zu7mNIA==`) e executá-lo como `root` (`su`).
   - A classe `ConnectionManager` ([`focused_apks_decompiled.txt`](./focused_apks_decompiled.txt)) abre um túnel WebSocket (`Socket.IO`) para **`ds.b20.host`** mantendo dois shells interativos (`sh`) abertos para execução de comandos em tempo real (`cmd` e `cmdb`), exfiltração de arquivos (`dld`) e captura ao vivo da tela da TV (`scc` via `screencap -p /data/local/tmp/scctmp.png`).
4. **Proxy Residencial P2P (`Titan Network`) e Scanner LAN/ADB Ocultos no `QCast`:**
   - O arquivo `assets/qcast_advertisement.zip` esconde 3 módulos `.dex` carregados dinamicamente ([`qcast_dynamic_dex_decompiled.txt`](./qcast_dynamic_dex_decompiled.txt)) que instalam o plugin nativo **`TITAN_PLUGIN_DAEMON` (`io.titannetwork.service`)** — transformando a TV Box em um nó de proxy residencial comercial — além de varrer a sub-rede local via ARP/ICMP (`DefaultDiscovery`) e tentar conexões ADB laterais na porta `5555` (`AdbConnect`).
5. **Sanitização Definitiva Nível 2 e Imunidade Comprovada ao Factory Reset:**
   - O script [`sanitizador_tvbox.sh`](./sanitizador_tvbox.sh) expurga fisicamente os malwares da partição `/system`, neutraliza `qw` e `att_policy`, vacina `/system/etc/hosts` com 25 domínios bloqueados e adiciona bloqueio `iptables` para o IP C2 `158.69.220.68`.
   - O experimento documentado em [`evidencias_resistencia/`](./evidencias_resistencia/) comprovou que, mesmo após um **Reset de Fábrica (`MASTER_CLEAR`)**, nenhum malware retorna e o sistema estabiliza com **~520 MB de RAM livre**.

---

## 📂 Estrutura do Repositório

```text
├── RELATORIO_UNIFICADO_SEGURANCA_COMPUTACIONAL.pdf  # Relatório Mestre Unificado (PDF formatado)
├── RELATORIO_UNIFICADO_SEGURANCA_COMPUTACIONAL.md   # Relatório Mestre Unificado (Markdown)
├── sanitizador_tvbox.sh                             # Script Automatizado de Sanitização Cirúrgica Nível 2
├── laudos_sanitizacao/                              # Certificado individual de conformidade pós-sanitização
├── evidencias_resistencia/                          # Capturas brutas dos 3 estados do teste de Factory Reset
│   ├── estado1_original_fabrica/
│   ├── pos_sanitizacao_pre_reset/
│   └── pos_reset_de_fabrica/
├── grupos-auditorias/                               # Relatórios PDF originais das Etapas 1, 2 e 3
│   ├── Pedro e Maria Rita/RELATORIO_GRUPO1.pdf
│   ├── Vinicius e João Marcello/relatorio_grupo2.pdf
│   └── Olimpio, Tiago e Wellyson/Grupo3_Documentacao_de_Entrega_completo.pdf
├── evidencias_binarios_elf.txt                      # Evidências forenses dos binários ELF (qw, att_policy, su)
├── focused_apks_decompiled.txt                      # Descompilação Dalvik verificada (FactoryStability, UOTA, UOTABack)
└── qcast_dynamic_dex_decompiled.txt                 # Descompilação Dalvik verificada (APK QCast + 3 .dex ocultos)
```
