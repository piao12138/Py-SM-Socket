import os
import SM2
import SM9
import time
import socket
import tkinter
import secrets
import datetime
import threading
from SM3 import sm3_hash
from SM2_Key_Exchange import E_SM2
from tkinter import messagebox, filedialog
from pysmx.SM2 import generate_keypair
from SM4 import sm4_decode, sm4_encode
from Enc_File import decrypt_file, encrypt_file
from util import string2int, int2string

status = 0


def main_fun():
    global status
    global TCP_Client_Socket
    # 1.创建TCP套接字
    TCP_Client_Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 2.连接TCP服务器
    try:
        server_ip = server_ip_entry.get()
        sever_port = int(server_port_entry.get())
        sever_addr = (server_ip, sever_port)
        TCP_Client_Socket.connect(sever_addr)

        status_label.config(text='连接服务器成功', bg='lightgreen')
        status = 1

        # B 初始化

        option = True

        sm2_B = E_SM2(ID='Bob')

        PB, IDB = sm2_B.pk, sm2_B.ID

        msg = TCP_Client_Socket.recv(99999999)

        # B 接收 A 信息

        message = msg.decode('utf-8')
        print("\nget-negotiation-message: ", message, "\n\n")

        PA = (int(message.split("——")[1]), int(message.split("——")[2]))
        print("PA", PA, "\n\n")

        IDA = message.split("——")[3]

        RA = (int(message.split("——")[4]), int(message.split("——")[5]))
        print("RA", RA, "\n\n")

        # B 响应协商
        res, content = sm2_B.agreement_response(RA, PA, IDA, option)
        if not res:
            print('B报告协商错误：', content)

        if option:
            RB, KB, SB, S2 = content
        else:
            RB, KB = content
            SB = None

        print("PB", PB, "\n\n")
        print("RB", RB, "\n\n")

        # B 发信息给 A

        send_data = "Key——" + str(PB[0]) + "——" + str(PB[1]) + "——" + IDB + "——" + str(RB[0]) + "——" + str(
            RB[1]) + "——" + SB.decode("latin-1")

        TCP_Client_Socket.send(send_data.encode())
        print("send-A-Verify-message: ", send_data, "\n\n")

        # B 协商确认

        time.sleep(1)
        msg = TCP_Client_Socket.recv(99999999)

        message = msg.decode('utf-8')
        print("get-B-Verify-message: ", message, "\n\n")

        SA = (message.split("——")[1]).encode("latin-1")

        if option:
            res, content = sm2_B.agreement_confirm2(S2, SA)
            if not res:
                print('B报告协商错误：', content)
            global sm4_Key
            sm4_Key = KB
            print("Share-Key: ", KB, "\n\n")

        # 4.数据处理
        try:
            while status == 1:
                if status == 0:
                    break
                msg = TCP_Client_Socket.recv(99999999)
                if not msg:
                    break
                val = msg.decode('utf-8')

                if val == "File":

                    server_response = TCP_Client_Socket.recv(99999999)
                    filename = server_response.decode("utf-8")

                    print("\nFileName: ", filename)

                    server_response = TCP_Client_Socket.recv(99999999)
                    file_size = int(server_response.decode("utf-8"))

                    print("\n接收到的大小：", file_size)

                    # 2.接收文件内容
                    f = open(filename, "wb")
                    received_size = 0

                    while received_size < file_size:
                        size = 0  # 准确接收数据大小，解决粘包
                        if file_size - received_size > 99999999:  # 多次接收
                            size = 99999999
                        else:  # 最后一次接收完毕
                            size = file_size - received_size

                        data = TCP_Client_Socket.recv(size)  # 多次接收内容，接收大数据
                        data_len = len(data)
                        received_size += data_len

                        f.write(data)

                    f.close()

                    print("\n实际接收的大小:", received_size)  # 解码

                    data = TCP_Client_Socket.recv(99999999).decode("utf-8")
                    print("\n", data)

                    Key = sm4_decode(str(sm4_Key), data.split("——")[1])
                    print("\nSM4-encode: ", data.split("——")[1], "\n\n")
                    print("SM2-SK: ", Key.encode("latin-1"), "\n\n")

                    h = data.split("——")[2]

                    S = data.split("——")[3]

                    C = data.split("——")[4]

                    m = sm3_hash(C)
                    print("SM3-hash: ", m, "\n\n")

                    sm9 = SM9.CryptSM9_Signature(Key)
                    sm9.generate_key()  # 这句很重要，虽然没有用到参数，但是如果没这句 SM9 算法初始化永远失败

                    print("SM3-Hash: ", m, "\n\n")
                    print("Sign-H: ", h, "\n\n")
                    print("Sign-S: ", S, "\n\n")

                    print("SM9-Verify: ", sm9.verify(m, h, S), "\n\n")

                    if int(sm9.verify(m, h, S)) != 0:
                        key = int(SM2.Decrypto(C.encode("latin-1"), Key.encode('latin-1')))

                        print("\nkey: ", key)

                        decrypt_file(filename, int2string(key))

                        os.remove(filename)

                        val1 = str(datetime.datetime.now()) + '   tcp received\nFile received successfully' + '\n\n\n'

                        received_text.config(state="normal")
                        received_text.insert('end', val1)
                        received_text.configure(state='disabled')
                    else:
                        received_text.config(state="normal")
                        received_text.insert('end', "Signature verification failed")
                        received_text.configure(state='disabled')

                else:

                    Key = sm4_decode(str(sm4_Key), val.split("——")[1])
                    print("\nSM4-encode: ", val.split("——")[1], "\n\n")
                    print("SM2-SK: ", Key.encode("latin-1"), "\n\n")

                    h = val.split("——")[2]

                    S = val.split("——")[3]

                    C = val.split("——")[4]

                    m = sm3_hash(C)
                    print("SM3-hash: ", m, "\n\n")

                    sm9 = SM9.CryptSM9_Signature(Key)
                    sm9.generate_key()  # 这句很重要，虽然没有用到参数，但是如果没这句 SM9 算法初始化永远失败

                    print("Sign-H: ", h, "\n\n")
                    print("Sign-S: ", S, "\n\n")

                    print("SM9-Verify: ", sm9.verify(m, h, S), "\n\n")

                    if int(sm9.verify(m, h, S)) != 0:
                        m_prime = int2string(int(SM2.Decrypto(C.encode("latin-1"), Key.encode('latin-1')))).decode(
                            "utf-8")
                        print("Messages sent by the Server: ", m_prime, "\n")

                        val1 = str(datetime.datetime.now()) + '   tcp received\n' + m_prime + '\n\n'

                        received_text.config(state="normal")
                        received_text.insert('end', val1)
                        received_text.configure(state='disabled')
                    else:
                        received_text.config(state="normal")
                        received_text.insert('end', "Signature verification failed")
                        received_text.configure(state='disabled')

        except:
            status = 0
            messagebox.showwarning(title='warning', message='连接已断开')
        # # 关闭套接字
        # TCP_Client_Socket.close()
        # # print('套接字关闭')
        # status_label.config(text='服务器已断开连接', bg='yellow')
        # status = 0
    except TimeoutError:
        # print('连接服务器失败')
        status_label.config(text='连接服务器失败', bg='pink')
        status = 0
    except Exception as ex:
        # print(str(ex))
        status = 0
        messagebox.showerror(title='error', message=str(ex))


def thread_main_fun():
    thread_add1 = threading.Thread(target=main_fun)
    thread_add1.start()


def send_message():
    if status == 1:

        send_data = send_text.get(0.0, 'end')

        m = string2int(send_data)

        PUBLIC_KEY, PRIVATE_KEY = generate_keypair(64)

        C = (SM2.Encrypto(str(m), PUBLIC_KEY)).decode("latin-1")

        Key = sm4_encode(str(sm4_Key), PRIVATE_KEY.decode("latin-1"))
        print("\nSM4-encode: ", Key, "\n\n")
        print("SM2-SK: ", PRIVATE_KEY, "\n\n")

        m = sm3_hash(C)
        print("SM3-hash: ", m, "\n\n")
        print("\n\nkey: ", sm4_Key, "\n\n")

        sm9 = SM9.CryptSM9_Signature(PRIVATE_KEY.decode("latin-1"))
        PK, SK = sm9.generate_key()
        h, S = sm9.sign(m, SK)

        print("Sign-H: ", h, "\n\n")
        print("Sign-S: ", S, "\n\n")
        print("C: ", C, "\n\n")

        send_data = "massge——" + Key + "——" + h + "——" + S + "——" + C

        # 发送数据给服务器
        TCP_Client_Socket.send(send_data.encode())
    else:
        messagebox.showwarning(title='warning', message='请先连接服务器')


def disconnect():
    try:
        global status
        status = 0
        # 关闭套接字
        TCP_Client_Socket.close()
        # print('套接字关闭')
        status_label.config(text='套接字已关闭', bg='yellow')
    except Exception as ex:
        messagebox.showerror(title='error', message=str(ex))


def File_Send():
    try:
        if status == 1:

            file_name = File_send_text.get(0.0, 'end')

            print("\nfile: ", file_name.split("/")[-1][:-1])

            TCP_Client_Socket.send("File".encode("utf-8"))  # 发送文件传输标识符

            key = secrets.randbits(200)

            rkey = int2string(key)

            print("file_name[:-1]: ", file_name[:-1])

            encrypt_file(file_name[:-1], rkey)

            filename = (file_name[:-1]) + '.enc'

            print("filename: ", filename)

            time.sleep(1)

            TCP_Client_Socket.send((filename.split("/")[-1]).encode("utf-8"))  # 发送文件名字

            # 1.先发送文件大小，让客户端准备接收
            time.sleep(1)
            size = os.stat(filename).st_size  # 获取文件大小
            TCP_Client_Socket.send(str(size).encode("utf-8"))  # 发送数据长度
            print("\n发送的大小：", size)

            # 2.发送文件内容
            f = open(filename, "rb")
            for line in f:
                TCP_Client_Socket.send(line)  # 发送数据
            f.close()

            os.remove(filename)

            PUBLIC_KEY, PRIVATE_KEY = generate_keypair(64)

            C = (SM2.Encrypto(str(key), PUBLIC_KEY)).decode("latin-1")

            Key = sm4_encode(str(sm4_Key), PRIVATE_KEY.decode("latin-1"))
            print("\nSM4-encode: ", Key, "\n\n")
            print("SM2-SK: ", PRIVATE_KEY, "\n\n")

            m = sm3_hash(C)
            print("SM3-hash: ", m, "\n\n")
            print("\n\nkey: ", sm4_Key, "\n\n")

            sm9 = SM9.CryptSM9_Signature(PRIVATE_KEY.decode("latin-1"))
            PK, SK = sm9.generate_key()
            h, S = sm9.sign(m, SK)

            print("Sign-H: ", h, "\n\n")
            print("Sign-S: ", S, "\n\n")
            print("rkey: ", rkey)

            send_data = "massge——" + Key + "——" + h + "——" + S + "——" + C

            TCP_Client_Socket.send(send_data.encode("utf-8"))  # 发送数据长度

        else:
            messagebox.showwarning(title='warning', message='请先建立连接')

    except Exception as ex:
        messagebox.showerror(title='error', message=str(ex))


def select_file():
    Filepath = filedialog.askopenfilename()  # 获得选择好的文件
    File_send_text.delete('1.0', 'end')
    File_send_text.insert("end", Filepath)


win = tkinter.Tk()
win.title('TCP-Client')
win.geometry('780x400')
win.option_add('*Font', '宋体 10')

server_ip_label = tkinter.Label(win, text='ServerIP:')
server_ip_label.place(x=20, y=20)
server_ip_entry = tkinter.Entry(win, width=20)
server_ip_entry.place(x=90, y=20)
server_port_label = tkinter.Label(win, text='ServerPort:')
server_port_label.place(x=250, y=20)
server_port_entry = tkinter.Entry(win, width=10)
server_port_entry.place(x=335, y=20)
server_ip_entry.insert('end', '127.0.0.1')
server_port_entry.insert('end', '12345')
connect_button = tkinter.Button(win, text='Connect', command=thread_main_fun)
connect_button.place(x=410, y=17)
disconnect_button = tkinter.Button(win, text='Disconnect', command=disconnect)
disconnect_button.place(x=490, y=17)
status_label = tkinter.Label(win, text='等待连接服务器', bg='yellow', width=25)
status_label.place(x=580, y=20)

frame1 = tkinter.Frame(win, width=360, height=330, bg='ivory')
frame1.place(x=20, y=50)
frame2 = tkinter.Frame(win, width=360, height=330, bg='ivory')
frame2.place(x=400, y=50)

send_label = tkinter.Label(frame1, text='Send massage to the Server', bg='ivory')
send_label.place(x=5, y=5)
send_button = tkinter.Button(frame1, text='Send Message', command=send_message)
send_button.place(x=260, y=2)
send_text = tkinter.Text(frame1, width=49, height=14)
send_text.place(x=5, y=25)

File_send_label = tkinter.Label(frame1, text='Send file to the Server', bg='ivory')
File_send_label.place(x=5, y=230)
File_select_button = tkinter.Button(frame1, text='Select Path', command=select_file)
File_select_button.place(x=265, y=250)
File_Send_button = tkinter.Button(frame1, text='Send File', command=File_Send)
File_Send_button.place(x=272, y=280)
File_send_text = tkinter.Text(frame1, width=30, height=3)
File_send_text.place(x=5, y=260)

received_label = tkinter.Label(frame2, text='Received massage from the Server', bg='ivory')
received_label.place(x=5, y=5)
received_text = tkinter.Text(frame2, width=49, height=23)
received_text.place(x=5, y=25)
received_text.configure(state='disabled')


def quit1():
    os._exit(0)


win.resizable(False, False)
win.protocol("WM_DELETE_WINDOW", quit1)
win.mainloop()
