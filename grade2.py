import os
import socket
import time
import threading
import hashlib
import logging
from tqdm import tqdm

# TFTP 기본 설정
TFTP_PORT = 69
BUFFER_SIZE = 512
TIMEOUT = 5  # 초
MAX_RETRY = 3  # 최대 재시도 횟수

# 로깅 설정
logging.basicConfig(filename='tftp_client.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# 파일 덮어쓰기 확인 함수
def ask_overwrite(filename):
    """파일 덮어쓰기 여부 확인"""
    if os.path.exists(filename):
        response = input(f"{filename} already exists. Do you want to overwrite? (y/n): ")
        return response.lower() == 'y'
    return True


# TFTP 서버와 연결하는 함수
def connect_to_server(server_ip):
    """TFTP 서버와 연결"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.connect((server_ip, TFTP_PORT))
        return sock
    except socket.timeout:
        logging.error("Connection timed out")
        return None


# 파일 다운로드 기능
def download_file(server_ip, filename, retry=0):
    """파일 다운로드"""
    if retry >= MAX_RETRY:
        logging.error(f"Failed to download {filename} after {MAX_RETRY} attempts")
        return

    sock = connect_to_server(server_ip)
    if not sock:
        logging.error(f"Could not connect to server for {filename}")
        return

    # RRQ (Read Request) 패킷 생성
    rrq_packet = create_rrq_packet(filename)
    sock.send(rrq_packet)

    # 파일 수신 준비
    file_data = b""
    progress_bar = tqdm(unit='B', unit_scale=True, total=os.path.getsize(filename) if os.path.exists(filename) else 0)

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            progress_bar.update(len(data))
            file_data += data
            if len(data) < BUFFER_SIZE:  # 마지막 블록
                break
        except socket.timeout:
            logging.warning(f"Timeout occurred during download of {filename}, retrying...")
            return download_file(server_ip, filename, retry + 1)

    with open(filename, "wb") as f:
        f.write(file_data)

    logging.info(f"File {filename} downloaded successfully.")
    progress_bar.close()


# 체크섬 계산 (MD5)
def calculate_checksum(file_path):
    """파일의 MD5 체크섬 계산"""
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
    return md5.hexdigest()


# 파일 업로드 기능
def upload_file(server_ip, filename):
    """파일 업로드"""
    sock = connect_to_server(server_ip)
    if not sock:
        logging.error(f"Could not connect to server for uploading {filename}")
        return

    # WRQ (Write Request) 패킷 생성
    wrq_packet = create_wrq_packet(filename)
    sock.send(wrq_packet)

    with open(filename, "rb") as f:
        block_number = 1
        while chunk := f.read(BUFFER_SIZE):
            data_packet = create_data_packet(block_number, chunk)
            sock.send(data_packet)
            block_number += 1

            try:
                ack, addr = sock.recvfrom(BUFFER_SIZE)
                if ack != block_number.to_bytes(2, 'big'):
                    logging.error(f"Error in ACK for block {block_number}")
                    break
            except socket.timeout:
                logging.warning(f"Timeout occurred during upload of {filename}, retrying...")
                return upload_file(server_ip, filename)

    logging.info(f"File {filename} uploaded successfully.")


# RRQ 패킷 생성 (Read Request)
def create_rrq_packet(filename):
    """RRQ (Read Request) 패킷 생성"""
    return b'\x00\x01' + filename.encode('ascii') + b'\x00octet\x00'


# WRQ 패킷 생성 (Write Request)
def create_wrq_packet(filename):
    """WRQ (Write Request) 패킷 생성"""
    return b'\x00\x02' + filename.encode('ascii') + b'\x00octet\x00'


# DATA 패킷 생성
def create_data_packet(block_number, data):
    """DATA 패킷 생성"""
    return b'\x00\x03' + block_number.to_bytes(2, 'big') + data


# ACK 패킷 생성
def create_ack_packet(block_number):
    """ACK 패킷 생성"""
    return b'\x00\x04' + block_number.to_bytes(2, 'big')


# 서버 응답 시간 측정
def measure_response_time(server_ip):
    """서버 응답 시간 측정"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    start_time = time.time()
    sock.sendto(b"ping", (server_ip, TFTP_PORT))
    try:
        sock.recvfrom(512)
        end_time = time.time()
        return end_time - start_time
    except socket.timeout:
        logging.error("Ping request timed out")
        return None


# 멀티스레딩 처리
def handle_multiple_files(server_ip, files_to_download, files_to_upload):
    """멀티스레딩을 통해 여러 파일을 동시에 다운로드 및 업로드"""
    threads = []

    for file in files_to_download:
        t = threading.Thread(target=download_file, args=(server_ip, file))
        threads.append(t)
        t.start()

    for file in files_to_upload:
        t = threading.Thread(target=upload_file, args=(server_ip, file))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()


# 메인 함수
def main():
    server_ip = "192.168.1.1"  # TFTP 서버 IP 주소 예시
    files_to_download = ["file1.txt", "file2.txt"]
    files_to_upload = ["file3.txt", "file4.txt"]

    # 서버 응답 시간 측정
    response_time = measure_response_time(server_ip)
    if response_time:
        print(f"Server response time: {response_time} seconds")

    # 멀티스레딩으로 파일 다운로드 및 업로드 실행
    handle_multiple_files(server_ip, files_to_download, files_to_upload)


if __name__ == "__main__":
    main()
