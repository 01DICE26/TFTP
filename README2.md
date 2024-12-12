#!/usr/bin/python3
'''
$ tftp ip_address [-p port_number] <get|put> filename
'''
import os
import sys
import socket
import argparse
import time
from struct import pack

DEFAULT_PORT = 69  # TFTP 기본 포트
BLOCK_SIZE = 512  # TFTP 데이터 블록 크기
DEFAULT_TRANSFER_MODE = 'octet'  # 기본 전송 모드 (바이너리 모드)

# TFTP 패킷의 OPCODE (Operation Codes)
OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}
# TFTP에서 사용할 모드 정의
MODE = {'netascii': 1, 'octet': 2, 'mail': 3}

# TFTP 오류 코드
ERROR_CODE = {
    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user."
}

# 기본 타임아웃 설정
TIMEOUT = 5  # 초
MAX_RETRY = 3  # 최대 재시도 횟수

# 서버와 연결 함수
def connect_to_server(server_ip, port=DEFAULT_PORT):
    """서버와 연결을 시도하는 함수"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP 소켓 생성
    sock.settimeout(TIMEOUT)  # 타임아웃 설정
    server_address = (server_ip, port)  # 서버 주소 설정
    return sock, server_address

# RRQ 패킷 생성 (Read Request)
def send_rrq(filename, mode, sock, server_address):
    """파일을 읽어오기 위한 RRQ (Read Request) 패킷을 서버로 전송"""
    format = f'>h{len(filename)}sB{len(mode)}sB'  # 패킷 형식 정의
    rrq_message = pack(format, OPCODE['RRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)
    sock.sendto(rrq_message, server_address)  # 서버로 RRQ 패킷 전송
    print(f"Sent RRQ for {filename}")

# WRQ 패킷 생성 (Write Request)
def send_wrq(filename, mode, sock, server_address):
    """파일을 업로드하기 위한 WRQ (Write Request) 패킷을 서버로 전송"""
    format = f'>h{len(filename)}sB{len(mode)}sB'  # 패킷 형식 정의
    wrq_message = pack(format, OPCODE['WRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)
    sock.sendto(wrq_message, server_address)  # 서버로 WRQ 패킷 전송
    print(f"Sent WRQ for {filename}")

# ACK 패킷 생성
def send_ack(seq_num, server_address, sock):
    """데이터 패킷에 대한 ACK 패킷을 서버로 전송"""
    ack_message = pack('>hh', OPCODE['ACK'], seq_num)  # ACK 패킷 생성
    sock.sendto(ack_message, server_address)  # ACK 패킷 전송

# 파일 다운로드 처리 함수
def download_file(sock, server_address, filename):
    """파일을 다운로드하는 함수"""
    print(f"Starting download of {filename}")
    file_data = b""  # 파일 데이터를 저장할 변수
    expected_block_number = 1  # 기대되는 블록 번호
    file = open(filename, 'wb')  # 다운로드한 파일을 저장할 파일 객체 생성
    
    while True:
        try:
            # 서버로부터 데이터를 수신
            data, server_new_socket = sock.recvfrom(516)  # 데이터와 서버 새 소켓 받기
            opcode = int.from_bytes(data[:2], 'big')  # OPCODE 확인

            # DATA 패킷 처리
            if opcode == OPCODE['DATA']:
                block_number = int.from_bytes(data[2:4], 'big')  # 블록 번호 추출
                if block_number == expected_block_number:
                    send_ack(block_number, server_new_socket, sock)  # ACK 전송
                    file_block = data[4:]  # 데이터 블록 추출
                    file.write(file_block)  # 파일에 데이터 저장
                    expected_block_number += 1  # 기대되는 블록 번호 증가
                else:
                    send_ack(block_number, server_new_socket, sock)  # ACK 전송

            # ERROR 패킷 처리
            elif opcode == OPCODE['ERROR']:
                error_code = int.from_bytes(data[2:4], byteorder='big')  # 오류 코드 추출
                print(ERROR_CODE[error_code])  # 오류 메시지 출력
                file.close()  # 파일 닫기
                os.remove(filename)  # 다운로드한 파일 삭제
                break

            else:
                break

            # 마지막 블록이면 종료
            if len(file_block) < BLOCK_SIZE:
                file.close()
                print("File transfer completed")
                break

        except socket.timeout:
            # 타임아웃 발생 시 재시도
            print("Timeout occurred, retrying...")
            return download_file(sock, server_address, filename)

# 파일 업로드 처리 함수
def upload_file(sock, server_address, filename):
    """파일을 업로드하는 함수"""
    print(f"Starting upload of {filename}")
    block_number = 1  # 첫 번째 블록부터 시작
    with open(filename, 'rb') as file:
        while True:
            file_block = file.read(BLOCK_SIZE)  # 파일을 블록 단위로 읽기
            if not file_block:
                break  # 더 이상 읽을 블록이 없으면 종료
            data_packet = pack('>hh', OPCODE['DATA'], block_number) + file_block  # DATA 패킷 생성
            sock.sendto(data_packet, server_address)  # DATA 패킷 전송

            try:
                ack, server_new_socket = sock.recvfrom(516)  # ACK 수신
                ack_block = int.from_bytes(ack[2:4], 'big')  # ACK에서 블록 번호 추출
                if ack_block != block_number:
                    print(f"Error in ACK for block {block_number}, retrying...")
                    return upload_file(sock, server_address, filename)  # ACK 오류 발생 시 재시도
                block_number += 1  # 다음 블록 번호로 증가
            except socket.timeout:
                print(f"Timeout occurred during upload of {filename}, retrying...")
                return upload_file(sock, server_address, filename)  # 타임아웃 발생 시 재시도

    print("File upload completed successfully.")

# 파일 전송 처리 (다운로드 및 업로드)
def transfer_file(sock, server_address, operation, filename):
    """파일 전송 작업을 처리하는 함수 (다운로드 및 업로드)"""
    if operation == "get":
        download_file(sock, server_address, filename)  # 다운로드 처리
    elif operation == "put":
        upload_file(sock, server_address, filename)  # 업로드 처리
    else:
        print("Invalid operation. Use 'get' or 'put'.")

# 메인 함수
def main():
    """메인 함수: TFTP 클라이언트 실행"""
    # 명령줄 인자 파싱
    parser = argparse.ArgumentParser(description='TFTP client program')
    parser.add_argument('host', help="Server IP address", type=str)
    parser.add_argument('operation', help="get or put a file", type=str)
    parser.add_argument('filename', help="name of file to transfer", type=str)
    parser.add_argument('-p', '--port', dest='port', type=int, default=DEFAULT_PORT)  # 기본 포트는 69
    args = parser.parse_args()

    # 서버와 연결
    sock, server_address = connect_to_server(args.host, args.port)

    # 파일 전송 (다운로드 또는 업로드)
    send_rrq(args.filename, DEFAULT_TRANSFER_MODE, sock, server_address) if args.operation == "get" else send_wrq(args.filename, DEFAULT_TRANSFER_MODE, sock, server_address)
    transfer_file(sock, server_address, args.operation, args.filename)  # 다운로드 또는 업로드 실행

if __name__ == "__main__":
    main()  # 메인 함수 실행

주석 설명

기본 설정:

TFTP 프로토콜에서 사용하는 기본 포트, 블록 크기, 전송 모드 등이 정의됩니다.
연결 설정 (connect_to_server):

TFTP 서버와 UDP 소켓을 통해 연결하고, 서버 IP와 포트를 지정합니다.
패킷 생성 (send_rrq, send_wrq):

RRQ (Read Request) 및 WRQ (Write Request) 패킷을 생성하여 서버에 전송합니다.
파일 다운로드 (download_file):

TFTP 프로토콜을 통해 서버로부터 파일을 다운로드하고, 각 데이터 블록을 저장합니다.
파일 업로드 (upload_file):

로컬 파일을 TFTP 서버로 업로드하는 과정입니다. 파일을 블록 단위로 읽어 서버에 전송하고, ACK를 기다립니다.
타임아웃 및 재시도:

연결이 끊어지거나 서버가 응답하지 않으면 socket.timeout 예외를 처리하여 재시도합니다.
파일 전송 처리 (transfer_file):

get (다운로드) 또는 put (업로드) 명령에 따라 다운로드 또는 업로드 작업을 분기 처리합니다.