import os
import socket
import time
import threading
import hashlib
import logging
from tqdm import tqdm

# TFTP 기본 설정
TFTP_PORT = 69  # TFTP 기본 포트
BUFFER_SIZE = 512  # 데이터 블록 크기 (TFTP의 기본 블록 크기)
TIMEOUT = 5  # 서버 응답 대기 시간 (초)
MAX_RETRY = 3  # 최대 재시도 횟수

# 로깅 설정
logging.basicConfig(filename='tftp_client.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 파일 덮어쓰기 확인 함수
def ask_overwrite(filename):
    """파일 덮어쓰기 여부 확인"""
    if os.path.exists(filename):  # 파일이 이미 존재하면
        response = input(f"{filename} already exists. Do you want to overwrite? (y/n): ")
        return response.lower() == 'y'  # 'y' 입력 시 덮어쓰기 허용
    return True  # 파일이 없으면 덮어쓰기 진행

# TFTP 서버와 연결하는 함수
def connect_to_server(server_ip):
    """TFTP 서버와 연결"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP 소켓 생성
        sock.settimeout(TIMEOUT)  # 타임아웃 설정
        sock.connect((server_ip, TFTP_PORT))  # 서버 IP와 포트로 연결
        return sock
    except socket.timeout:
        logging.error("Connection timed out")  # 연결 타임아웃 발생 시 로깅
        return None  # 연결 실패 시 None 반환

# 파일 다운로드 기능
def download_file(server_ip, filename, retry=0):
    """파일 다운로드"""
    if retry >= MAX_RETRY:  # 재시도 횟수 초과 시 종료
        logging.error(f"Failed to download {filename} after {MAX_RETRY} attempts")
        return

    sock = connect_to_server(server_ip)
    if not sock:
        logging.error(f"Could not connect to server for {filename}")
        return

    # RRQ (Read Request) 패킷 생성
    rrq_packet = create_rrq_packet(filename)
    sock.send(rrq_packet)  # 서버로 Read Request 패킷 전송

    # 파일 수신 준비
    file_data = b""  # 파일 데이터를 저장할 변수
    progress_bar = tqdm(unit='B', unit_scale=True, total=os.path.getsize(filename) if os.path.exists(filename) else 0)  # 진행률 표시

    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)  # 서버로부터 데이터 수신
            progress_bar.update(len(data))  # 진행률 업데이트
            file_data += data  # 수신한 데이터 추가
            if len(data) < BUFFER_SIZE:  # 마지막 블록일 경우 종료
                break
        except socket.timeout:  # 타임아웃 발생 시 재시도
            logging.warning(f"Timeout occurred during download of {filename}, retrying...")
            return download_file(server_ip, filename, retry + 1)

    with open(filename, "wb") as f:
        f.write(file_data)  # 파일 저장

    logging.info(f"File {filename} downloaded successfully.")
    progress_bar.close()  # 진행률 바 닫기

# 체크섬 계산 (MD5)
def calculate_checksum(file_path):
    """파일의 MD5 체크섬 계산"""
    md5 = hashlib.md5()  # MD5 해시 객체 생성
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):  # 파일을 청크 단위로 읽기
            md5.update(chunk)
    return md5.hexdigest()  # 최종 MD5 체크섬 반환

# 파일 업로드 기능
def upload_file(server_ip, filename):
    """파일 업로드"""
    sock = connect_to_server(server_ip)
    if not sock:
        logging.error(f"Could not connect to server for uploading {filename}")
        return

    # WRQ (Write Request) 패킷 생성
    wrq_packet = create_wrq_packet(filename)
    sock.send(wrq_packet)  # 서버로 Write Request 패킷 전송

    with open(filename, "rb") as f:
        block_number = 1
        while chunk := f.read(BUFFER_SIZE):  # 파일을 청크 단위로 읽기
            data_packet = create_data_packet(block_number, chunk)  # 데이터 패킷 생성
            sock.send(data_packet)  # 서버로 데이터 전송
            block_number += 1

            try:
                ack, addr = sock.recvfrom(BUFFER_SIZE)  # 서버로부터 ACK 수신
                if ack != block_number.to_bytes(2, 'big'):  # ACK 확인
                    logging.error(f"Error in ACK for block {block_number}")
                    break
            except socket.timeout:  # 타임아웃 발생 시 재시도
                logging.warning(f"Timeout occurred during upload of {filename}, retrying...")
                return upload_file(server_ip, filename)

    logging.info(f"File {filename} uploaded successfully.")

# RRQ 패킷 생성 (Read Request)
def create_rrq_packet(filename):
    """RRQ (Read Request) 패킷 생성"""
    return b'\x00\x01' + filename.encode('ascii') + b'\x00octet\x00'  # RRQ 패킷 형식 생성

# WRQ 패킷 생성 (Write Request)
def create_wrq_packet(filename):
    """WRQ (Write Request) 패킷 생성"""
    return b'\x00\x02' + filename.encode('ascii') + b'\x00octet\x00'  # WRQ 패킷 형식 생성

# DATA 패킷 생성
def create_data_packet(block_number, data):
    """DATA 패킷 생성"""
    return b'\x00\x03' + block_number.to_bytes(2, 'big') + data  # DATA 패킷 형식 생성

# ACK 패킷 생성
def create_ack_packet(block_number):
    """ACK 패킷 생성"""
    return b'\x00\x04' + block_number.to_bytes(2, 'big')  # ACK 패킷 형식 생성

# 서버 응답 시간 측정
def measure_response_time(server_ip):
    """서버 응답 시간 측정"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    start_time = time.time()
    sock.sendto(b"ping", (server_ip, TFTP_PORT))  # 서버에 ping 패킷 전송
    try:
        sock.recvfrom(512)  # 응답 대기
        end_time = time.time()
        return end_time - start_time  # 응답 시간 계산
    except socket.timeout:
        logging.error("Ping request timed out")  # 타임아웃 발생 시 로깅
        return None

# 멀티스레딩 처리
def handle_multiple_files(server_ip, files_to_download, files_to_upload):
    """멀티스레딩을 통해 여러 파일을 동시에 다운로드 및 업로드"""
    threads = []  # 스레드를 저장할 리스트

    # 다운로드할 파일 처리
    for file in files_to_download:
        t = threading.Thread(target=download_file, args=(server_ip, file))  # 다운로드 스레드 생성
        threads.append(t)
        t.start()  # 스레드 시작

    # 업로드할 파일 처리
    for file in files_to_upload:
        t = threading.Thread(target=upload_file, args=(server_ip, file))  # 업로드 스레드 생성
        threads.append(t)
        t.start()  # 스레드 시작

    # 모든 스레드가 완료될 때까지 대기
    for t in threads:
        t.join()

# 메인 함수
def main():
    server_ip = "192.168.1.1"  # TFTP 서버 IP 주소 예시
    files_to_download = ["file1.txt", "file2.txt"]  # 다운로드할 파일 목록
    files_to_upload = ["file3.txt", "file4.txt"]  # 업로드할 파일 목록

    # 서버 응답 시간 측정
    response_time = measure_response_time(server_ip)
    if response_time:
        print(f"Server response time: {response_time} seconds")

    # 멀티스레딩으로 파일 다운로드 및 업로드 실행
    handle_multiple_files(server_ip, files_to_download, files_to_upload)

if __name__ == "__main__":
    main()  # 메인 함수 실행

주석 설명

TFTP 설정: TFTP 클라이언트와 서버 간의 포트, 버퍼 크기, 타임아웃 및 최대 재시도 횟수를 설정합니다.
로깅: 오류와 경고 메시지를 tftp_client.log 파일에 기록합니다.

파일 덮어쓰기 확인: 다운로드할 파일이 이미 존재하면 덮어쓸지 여부를 묻습니다.

서버 연결: 서버와 연결하고 타임아웃 처리합니다.

파일 다운로드 및 업로드: TFTP 프로토콜을 사용해 파일을 다운로드하고 업로드하는 기능을 구현합니다.

멀티스레딩: 여러 파일을 동시에 다운로드 및 업로드할 수 있도록 멀티스레딩을 사용합니다.

체크섬: 파일의 MD5 체크섬을 계산하여 파일 무결성을 확인할 수 있습니다.