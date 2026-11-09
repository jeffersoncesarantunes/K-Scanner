# K-Scanner

Linux memory auditing tool for RWX (W^X) detection and automated forensic triage.

[![CI](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Scanner/ci.yml?style=flat-square&logo=githubactions&label=CI)](https://github.com/jeffersoncesarantunes/K-Scanner/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/K-Scanner/codeql.yml?style=flat-square&logo=codeql&label=CodeQL)](https://github.com/jeffersoncesarantunes/K-Scanner/actions/workflows/codeql.yml)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Tested-On](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square)](https://archlinux.org/)

## Por que existe

Construí o K-Scanner porque ferramentas de forense existentes são pesadas, dependem de ptrace ou injetam código no processo alvo. Queria algo que lesse apenas `/proc`, sem modificar o sistema alvo, rápido o suficiente para rodar em um servidor em produção sem derrubá-lo, e que me entregasse evidência concreta (dump, hash, strings, desmontagem) quando encontrasse uma região RWX suspeita. É uma ferramenta de triagem local, não um substituto para um EDR ou SIEM.

## O que faz

Lê `/proc/[PID]/maps`, mapeia regiões de memória por processo, detecta violações do princípio W^X (Write XOR Execute), classifica por nível de confiança e, quando solicitado, extrai artefatos forenses (`.bin`, `.sha256`, `.strings.txt`, `.hex.txt`, `.shellcode.txt`) direto para `build/dumps/`. Tudo read-only: não usa ptrace, não injeta nada, não altera o processo alvo.

Opcionalmente tem TUI ncurses, eBPF para telemetria em tempo real, busca regex ao vivo na memória (`--live`), varredura YARA nos dumps (`--yara`), modo headless (`--watch`) e supressão de falsos positivos de JIT (`--silent-jit`).

## O que não faz

- Não é scanner de rede nem agente SIEM.
- Não identifica malware por si só — apenas sinaliza regiões RWX; navegadores, Node, Python e Electron usam RWX para JIT e são legítimos.
- Não vê dentro de containers a não ser que tenha acesso ao namespace do host.
- Requer root para inspecionar a memória de outros processos.

## Casos de uso reais

Auditar um servidor web após suspeita de injeção de shellcode: ver quais processos têm regiões RWX e dumpá-las para análise offline.

Investigar carga anômala em um host: listar processos com RWX ativo e conferir se há payload reflexivo ou carregamento de código injetado.

Validar hardening de um binário próprio: confirmar que seu processo não mantém memória simultaneamente gravável e executável fora de seções JIT conhecidas.

Monitoramento contínuo leve: `--watch` em loop de 2s para alertar apenas quando algo muda, sem rodar um agente pesado.

## Saída de exemplo

Modo interativo (TUI):

```
PID   PROCESS           STATUS      CONFIDENCE  INFO          CTN
1234  firefox           RWX ALERT   LOW         01dx JIT      n/a
5678  mystery-bin       RWX ALERT   CRITICAL    03dx anon       abc123def456
9101  sshd              SAFE        SAFE        STABLE        n/a
```

Pressione `ENTER` sobre um alerta para gerar o relatório forense em `build/dumps/`:

```
pid_5678_0x7f1234000000.bin
pid_5678_0x7f1234000000.sha256
pid_5678_0x7f1234000000.strings.txt
pid_5678_0x7f1234000000.hex.txt
pid_5678_0x7f1234000000.shellcode.txt
```

Exportação JSON/CSV:

```bash
sudo ./kscanner --json
# [
#   {"pid":5678,"process":"mystery-bin","status":"RWX ALERT","confidence":"CRITICAL",...},
#   ...
# ]
```

## Como construir e usar

```bash
git clone https://github.com/jeffersoncesarantunes/K-Scanner.git
cd K-Scanner
make bpf && make
sudo ./kscanner              # TUI interativo
sudo ./kscanner --watch      # monitoramento headless (2s)
sudo ./kscanner --json       # exporta JSON
sudo ./kscanner --csv        # exporta CSV
sudo ./kscanner --live 1132 'pattern'   # busca regex na memória de um PID
sudo ./kscanner --bpf        # telemetria eBPF em tempo real
```

`make bpf` compila o objeto BPF; `make` constrói o binário. `libbpf` é detectado automaticamente para suporte a eBPF.

## Espelhamento

Este projeto é mantido espelhado no Codeberg, para não depender de uma única plataforma:
https://codeberg.org/jeffersoncesarantunes/K-Scanner

## Contribuições

Veja [CONTRIBUTING.md](./CONTRIBUTING.md).

## Segurança

Veja [SECURITY.md](./SECURITY.md). Não abra issues públicas para vulnerabilidades.

## Licença

Veja [LICENSE](./LICENSE)
