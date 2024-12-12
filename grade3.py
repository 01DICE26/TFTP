#!/usr/bin/python3
'''
$ tftp ip_address [-p port_mumber] <get|put> filename
'''
import os
import sys
import socket
import argparse
import time
from struct import pack

DEFAULT_PORT = 69
BLOCK_SIZE = 512
DEFAULT_TRANSFER_MODE = 'octet'

OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}
MODE = {'netascii': 1, 'octet': 2, 'mail': 3}

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


# 서버와 연결
def connect_to_server(server_ip, port=DEFAULT_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    server_address = (server_ip, port)
    return sock, server_address


# RRQ 패킷 생성 (Read Request)
def send_rrq(filename, mode, sock, server_address):
    format = f'>h{len(filename)}sB{len(mode)}sB'
    rrq_message = pack(format, OPCODE['RRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)
    sock.sendto(rrq_message, server_address)
    print(f"Sent RRQ for {filename}")


# WRQ 패킷 생성 (Write Request)
def send_wrq(filename, mode, sock, server_address):
    format = f'>h{len(filename)}sB{len(mode)}sB'
    wrq_message = pack(format, OPCODE['WRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)
    sock.sendto(wrq_message, server_address)
    print(f"Sent WRQ for {filename}")


# ACK 패킷 생성
def send_ack(seq_num, server_address, sock):
    ack_message = pack('>hh', OPCODE['ACK'], seq_num)
    sock.sendto(ack_message, server_address)


# 파일 다운로드 처리
def download_file(sock, server_address, filename):
    print(f"Starting download of {filename}")
    file_data = b""
    expected_block_number = 1
    file = open(filename, 'wb')

    while True:
        try:
            data, server_new_socket = sock.recvfrom(516)  # 데이터 받기
            opcode = int.from_bytes(data[:2], 'big')

            # DATA 패킷 처리
            if opcode == OPCODE['DATA']:
                block_number = int.from_bytes(data[2:4], 'big')
                if block_number == expected_block_number:
                    send_ack(block_number, server_new_socket, sock)
                    file_block = data[4:]
                    file.write(file_block)
                    expected_block_number += 1
                else:
                    send_ack(block_number, server_new_socket, sock)

            # 오류 처리
            elif opcode == OPCODE['ERROR']:
                error_code = int.from_bytes(data[2:4], byteorder='big')
                print(ERROR_CODE[error_code])
                file.close()
                os.remove(filename)
                break

            else:
                break

            if len(file_block) < BLOCK_SIZE:
                file.close()
                print("File transfer completed")
                break

        except socket.timeout:
            print("Timeout occurred, retrying...")
            return download_file(sock, server_address, filename)


# 파일 업로드 처리
def upload_file(sock, server_address, filename):
    print(f"Starting upload of {filename}")
    block_number = 1
    with open(filename, 'rb') as file:
        while True:
            file_block = file.read(BLOCK_SIZE)
            if not file_block:
                break
            data_packet = pack('>hh', OPCODE['DATA'], block_number) + file_block
            sock.sendto(data_packet, server_address)

            try:
                ack, server_new_socket = sock.recvfrom(516)  # ACK 받기
                ack_block = int.from_bytes(ack[2:4], 'big')
                if ack_block != block_number:
                    print(f"Error in ACK for block {block_number}, retrying...")
                    return upload_file(sock, server_address, filename)
                block_number += 1
            except socket.timeout:
                print(f"Timeout occurred during upload of {filename}, retrying...")
                return upload_file(sock, server_address, filename)

    print("File upload completed successfully.")


# 파일 전송 처리 (다운로드 및 업로드)
def transfer_file(sock, server_address, operation, filename):
    if operation == "get":
        download_file(sock, server_address, filename)
    elif operation == "put":
        upload_file(sock, server_address, filename)
    else:
        print("Invalid operation. Use 'get' or 'put'.")


# 메인 함수
def main():
    parser = argparse.ArgumentParser(description='TFTP client program')
    parser.add_argument('host', help="Server IP address", type=str)
    parser.add_argument('operation', help="get or put a file", type=str)
    parser.add_argument('filename', help="name of file to transfer", type=str)
    parser.add_argument('-p', '--port', dest='port', type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    # 서버와 연결
    sock, server_address = connect_to_server(args.host, args.port)

    # 파일 전송 (다운로드 또는 업로드)
    send_rrq(args.filename, DEFAULT_TRANSFER_MODE, sock, server_address) if args.operation == "get" else send_wrq(
        args.filename, DEFAULT_TRANSFER_MODE, sock, server_address)
    transfer_file(sock, server_address, args.operation, args.filename)


if __name__ == "__main__":
    main()
