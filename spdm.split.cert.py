
# Python code to check sys logs

import sys
import binascii
import re


SPDM_HEADER_LEN = 2 + 2 + 48  # Length(2) + Reserved(2) + SHA384 RootHash(48)

def read_hex_chain(filename: str) -> bytes:
    """从 cert.chain.txt 读取并转换为二进制字节串。"""
    with open(filename, "r", encoding="utf-8") as f:
        text = f.read()

    # 只保留 0-9a-fA-F
    hex_str = "".join(re.findall(r"[0-9a-fA-F]", text))
    if len(hex_str) % 2 != 0:
        raise ValueError("Hex string length is not even; input may be corrupted")

    return bytes.fromhex(hex_str)

def parse_der_certs(der_buf: bytes):
    """
    从纯 DER 拼接区解析多个 X.509 证书。
    每个证书是一个顶层 SEQUENCE（tag 0x30）。
    返回: [(offset, length), ...] ，offset 相对 der_buf 起始。
    """
    certs = []
    off = 0
    n = len(der_buf)

    while off < n:
        if der_buf[off] != 0x30:
            raise ValueError(f"Expected SEQUENCE (0x30) at offset {off}, got 0x{der_buf[off]:02x}")

        if off + 2 > n:
            raise ValueError("Buffer too short to contain DER length")

        # 解析 DER 长度
        len1 = der_buf[off + 1]
        if len1 < 0x80:
            # short form
            content_len = len1
            len_of_len = 1
            total_len = 1 + len_of_len + content_len
        else:
            # long form
            num_len_bytes = len1 & 0x7F
            if num_len_bytes == 0:
                raise ValueError(f"Indefinite length form not expected at offset {off}")
            if off + 2 + num_len_bytes > n:
                raise ValueError("Buffer too short for long-form length bytes")

            content_len = 0
            for i in range(num_len_bytes):
                content_len = (content_len << 8) | der_buf[off + 2 + i]

            len_of_len = 1 + num_len_bytes
            total_len = 1 + len_of_len + content_len

        if off + total_len > n:
            raise ValueError(
                f"DER object at offset {off} (len={total_len}) "
                f"extends beyond buffer end {n}"
            )

        certs.append((off, total_len))
        off += total_len

    return certs

def main(filename: str):
    # 1. 读取并还原二进制
    buf = read_hex_chain(filename)
    print(f"Total bytes in SPDM cert_chain: {len(buf)}, +orginal header={52+len(buf)}")

    # 3. 解析 DER 证书
    certs = parse_der_certs(buf)

    print(f"\nFound {len(certs)} certificate(s):")
    for idx, (off, length) in enumerate(certs):
        print(f"  Cert {idx}: offset={off}, length={length}")
        certfilename = f"{filename}.cert{idx}.der"
        with open(certfilename , "wb") as f:
            f.write(buf[certs[0][0]: certs[0][0] + certs[0][1]])

    
if __name__=='__main__':
    argc = len(sys.argv)
    if argc < 1 :
        print("no input file")
	else:
		main(sys.argv[1])


