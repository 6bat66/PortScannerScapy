from scapy.all import *
import random
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

def varrer_porta(alvo, porta, spoof_ips=None, verbose=False):
    spoof_ip = random.choice(spoof_ips) if spoof_ips else None
    try:
        camada_ip = IP(dst=alvo, src=spoof_ip) if spoof_ip else IP(dst=alvo)
        camada_tcp = TCP(dport=porta, flags='S')
        pacote = camada_ip/camada_tcp
        resp = sr1(pacote, timeout=1, verbose=False)
        if resp and (TCP in resp) and (resp[TCP].flags & 0x12):
            msg = f"{alvo}:{porta}"
            print(f"[+] {msg} está aberta")
            return msg
        elif verbose:
            print(f"[-] {alvo}:{porta} está fechada ou não respondeu")
    except Exception as e:
        if verbose:
            print(f"[!] Erro ao varrer {alvo}:{porta}: {e}")

def processar_chunk_portas(alvo, chunk_portas, arquivo_saida, spoof_ips=None, verbose=False, max_workers=200):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_result = {executor.submit(varrer_porta, alvo, porta, spoof_ips, verbose): porta for porta in chunk_portas}
        for future in as_completed(future_to_result):
            resultado = future.result()
            if resultado and arquivo_saida:
                with open(arquivo_saida, "a") as arquivo:
                    arquivo.write(resultado + "\n")

def principal(alvos, quantidade_portas=100, arquivo_saida=None, spoof_ips=None, verbose=False):
    max_workers_por_chunk = 300 if len(alvos) * quantidade_portas > 1000 else 10
    for alvo in alvos:
        print(f"[*] Iniciando varredura no alvo {alvo}...")
        todas_portas = random.sample(range(1, 65536), min(quantidade_portas, 65535))
        chunks_portas = [todas_portas[i:i + 1000] for i in range(0, len(todas_portas), 1000)]
        with ThreadPoolExecutor(max_workers=6) as executor_chunk:
            futures = [executor_chunk.submit(processar_chunk_portas, alvo, chunk, arquivo_saida, spoof_ips, verbose, max_workers_por_chunk) for chunk in chunks_portas]
            for future in as_completed(futures):
                future.result()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de Varredura de Portas")
    parser.add_argument("alvos", nargs='+', help="Lista de endereços IP, domínios ou redes a serem varridos")
    parser.add_argument("-p", "--quantidade_portas", type=int, default=100, help="Quantidade de portas para varrer. Máximo: 65535.")
    parser.add_argument("-o", "--saida", type=str, help="Salva a lista de portas abertas no arquivo especificado. Formato: 'IP:PORTA'.")
    parser.add_argument("-s", "--spoof_ips", nargs='+', help="Lista de IPs para spoofing. Um IP será escolhido aleatoriamente para cada varredura.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Ativa detalhes verbosos da varredura.")
    
    args = parser.parse_args()
    principal(args.alvos, args.quantidade_portas, args.saida, args.spoof_ips, args.verbose)
