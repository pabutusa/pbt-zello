import websocket
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
import base64
import time
import json
import configparser
from struct import *
import wave
import opuslib


seq = 1

def main():
    global seq
    print("Hello, world!")
    config = configparser.ConfigParser()
    config.read('pbt-zello.ini')
    
    connection = create_zello_connection(config)
    print(connection)
    stream = start_stream(connection)
    
    enc = opuslib.api.encoder.create_state(16000,1,opuslib.APPLICATION_AUDIO)
    
    f = wave.open("pdcent_20200708-142547.wav",'rb')
    numFrames = f.getnframes()
    rate = f.getframerate()
    chunk = int(rate*0.06)
    print("frames: {0} channels: {1}".format(numFrames, f.getnchannels()))
    print("width: {0} rate: {1} chuck size:{2}".format(f.getsampwidth(), rate, chunk))
    
    w=f.readframes(chunk)
    while len(w) >= chunk:
        out = opuslib.api.encoder.encode(enc, w, chunk, len(w)*2)
        send_data = bytearray(pack('!BII',1,stream,0)) + out
        connection.send_binary(send_data)
        w=f.readframes(chunk)


    stop_stream(connection, stream)
    
    
def create_zello_jwt(key, issuer):
    #Create a Zello-specific JWT.  Can't use PyJWT because Zello doesn't support url safe base64 encoding in the JWT.
    header = {"typ": "JWT", "alg": "RS256"}
    payload = {"iss": issuer,"exp": round(time.time()+60)}
    signer = pkcs1_15.new(key)
    json_header = json.dumps(header, separators=(",", ":"), cls=None).encode("utf-8")
    json_payload = json.dumps(payload, separators=(",",":"), cls=None).encode("utf-8")
    h = SHA256.new(base64.standard_b64encode(json_header) + b"." + base64.standard_b64encode(json_payload))
    signature = signer.sign(h)
    jwt = (base64.standard_b64encode(json_header) + b"." + base64.standard_b64encode(json_payload) + b"." + base64.standard_b64encode(signature))
    return jwt

def create_zello_connection(config):
    global seq
    with open(config['DEFAULT']['keyfile'],'r') as keyfile:
        priv_key = RSA.import_key(keyfile.read())

    encoded_jwt = create_zello_jwt(priv_key, config['DEFAULT']['issuer'])
    print(encoded_jwt)

    ws = websocket.create_connection(config['DEFAULT']['zello_url'])
    ws.settimeout(1)
    send = {'command':'logon',}
    send['seq'] = seq
    send['auth_token'] = encoded_jwt.decode('utf-8')
    send['username'] = config['DEFAULT']['username']
    send['password'] = config['DEFAULT']['password']
    send['channel'] = config['DEFAULT']['channel']
    ws.send(json.dumps(send))
    result = ws.recv()
    data = json.loads(result)
    print(data)
    seq = seq + 1
    return ws

def make_codec_hdr(rate, frames, size):
    #base64 encoded 4 byte string: first 2 bytes for sample rate, 3rd for number of frames per packet (1 or 2), 4th for the frame size
    #gd4BPA==  => 0x80 0x3e 0x01 0x3c  => 16000 Hz, 1 frame per packet, 60 ms frame size
    return base64.standard_b64encode(pack('HBB',rate,frames,size)).decode("utf-8")
    
def start_stream(ws):
    global seq
    send = {'command':'start_stream', 'type':'audio', 'codec':'opus'}
    send['seq'] = seq
    seq = seq + 1
    send['codec_header'] = make_codec_hdr(16000, 1, 60)
    send['packet_duration'] = 60
    ws.send(json.dumps(send))
    result = ws.recv()
    data = json.loads(result)
    print(data)
    
    while 'stream_id' not in data.keys():
        if 'error' in data.keys():
            if data['error'] == 'channel is not ready':
                send['seq'] = seq
                seq = seq + 1
                ws.send(json.dumps(send))
                
        result = ws.recv()
        data = json.loads(result)
        print(data)

    stream_id = int(data['stream_id'])
    return stream_id

def stop_stream(ws,stream_id):
    send = {'command':'stop_stream',}
    send['stream_id'] = stream_id
    ws.send(json.dumps(send))

if __name__ == '__main__':
    main()
    
