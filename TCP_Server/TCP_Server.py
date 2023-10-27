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
from Enc_File import encrypt_file, decrypt_file
from util import string2int, int2string

status = 0


def main_fun():
    try:
        global status
        global tcp_client
        global tcp_server
        # 创建tcp服务端套接字
        # 参数同客户端配置一致，这里不再重复
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 设置端口号复用，让程序退出端口号立即释放，否则的话在30秒-2分钟之内这个端口是不会被释放的，这是TCP的为了保证传输可靠性的机制。
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        # 给客户端绑定端口号，客户端需要知道服务器的端口号才能进行建立连接。IP地址不用设置，默认就为本机的IP地址。
        server_ip = server_ip_entry.get()
        sever_port = int(server_port_entry.get())
        sever_addr = (server_ip, sever_port)
        tcp_server.bind(sever_addr)
        status_label.config(text='服务已开启,等待连接', bg='yellow')
        # 设置监听
        # 128:最大等待建立连接的个数， 提示： 目前是单任务的服务端，同一时刻只能服务与一个客户端，后续使用多任务能够让服务端同时服务与多个客户端
        # 不需要让客户端进行等待建立连接
        # listen后的这个套接字只负责接收客户端连接请求，不能收发消息，收发消息使用返回的这个新套接字tcp_client来完成
        tcp_server.listen(128)
        # 等待客户端建立连接的请求, 只有客户端和服务端建立连接成功代码才会解阻塞，代码才能继续往下执行
        # 1. 专门和客户端通信的套接字： tcp_client
        # 2. 客户端的ip地址和端口号： tcp_client_address
        tcp_client, tcp_client_address = tcp_server.accept()
        status = 1
        status_label.config(text='连接成功', bg='lightgreen')

        # A 初始化
        option = True

        sm2_A = E_SM2(ID='Alice')

        PA, IDA = sm2_A.pk, sm2_A.ID

        rA, RA = sm2_A.agreement_initiate()

        print("\nPA", PA, "\n\n")
        print("RA", RA, "\n\n")

        # A将RA发送给B
        send_data = "Key——" + str(PA[0]) + "——" + str(PA[1]) + "——" + IDA + "——" + str(RA[0]) + "——" + str(RA[1])

        print("send-negotiation-message: ", send_data, "\n\n")

        tcp_client.send(send_data.encode())

        time.sleep(1)
        msg = tcp_client.recv(99999999)

        message = msg.decode('utf-8')
        print("get-negotiation-message: ", message, "\n\n")

        PB = (int(message.split("——")[1]), int(message.split("——")[2]))

        IDB = message.split("——")[3]

        RB = (int(message.split("——")[4]), int(message.split("——")[5]))

        SB = (message.split("——")[6]).encode("latin-1")

        print("PB", PB, "\n\n")
        print("RB", RB, "\n\n")

        # A 协商确认
        res, content = sm2_A.agreement_confirm(rA, RA, RB, PB, IDB, SB, option)
        if not res:
            print('A报告协商错误：', content)

        if option:
            global SA
            KA, SA = content
        else:
            KA = content

        # A将SA发送给B
        send_data = "Key——" + SA.decode("latin-1")

        print("send-B-Verify-message: ", send_data, "\n\n")

        tcp_client.send(send_data.encode())

        global sm4_Key
        sm4_Key = KA
        print("Share-Key: ", KA, "\n\n")

        # 代码执行到此说明连接建立成功

        try:
            while status == 1:
                if status == 0:
                    break
                recv_data = tcp_client.recv(99999999).decode("utf-8")
                if not recv_data:
                    break

                if recv_data == "File":

                    server_response = tcp_client.recv(99999999)
                    filename = server_response.decode("utf-8")

                    print("\nFileName: ", filename)

                    server_response = tcp_client.recv(99999999)
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

                        data = tcp_client.recv(size)  # 多次接收内容，接收大数据
                        data_len = len(data)
                        received_size += data_len

                        f.write(data)

                    f.close()

                    print("\n实际接收的大小:", received_size)  # 解码

                    data = tcp_client.recv(99999999).decode("utf-8")
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

                    Key = sm4_decode(str(sm4_Key), recv_data.split("——")[1])
                    print("\nSM4-encode: ", recv_data.split("——")[1], "\n\n")
                    print("SM2-SK: ", Key.encode("latin-1"), "\n\n")

                    h = recv_data.split("——")[2]

                    S = recv_data.split("——")[3]

                    C = recv_data.split("——")[4]

                    m = sm3_hash(C)
                    print("SM3-hash: ", m, "\n\n")

                    sm9 = SM9.CryptSM9_Signature(Key)
                    sm9.generate_key()  # 这句很重要，虽然没有用到参数，但是如果没这句 SM9 算法初始化永远失败

                    print("SM3-Hash: ", m, "\n\n")
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
            status_label.config(text='连接已断开', bg='yellow')
    except Exception as ex:
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

        send_data = "massge——" + Key + "——" + h + "——" + S + "——" + C

        # 发送数据给客户端
        tcp_client.send(send_data.encode())
    else:
        messagebox.showwarning(title='warning', message='请先建立连接')


def disconnect():
    try:
        global status
        # 关闭服务端的套接字, 终止和客户端提供建立连接请求的服务 但是正常来说服务器的套接字是不需要关闭的，因为服务器需要一直运行。
        tcp_server.close()
        if status == 1:
            # 关闭服务与客户端的套接字， 终止和客户端通信的服务
            # print('套接字关闭')
            tcp_client.close()
            status_label.config(text='服务已关闭', bg='pink')
        status = 0
    except Exception as ex:
        messagebox.showerror(title='error', message=str(ex))


def File_Send():
    try:
        if status == 1:

            file_name = File_send_text.get(0.0, 'end')

            print("\nfile: ", file_name.split("/")[-1][:-1])

            tcp_client.send("File".encode("utf-8"))  # 发送文件传输标识符

            key = secrets.randbits(200)

            rkey = int2string(key)

            print("file_name[:-1]: ", file_name[:-1])

            encrypt_file(file_name[:-1], rkey)

            filename = (file_name[:-1]) + '.enc'

            print("filename: ", filename)

            time.sleep(1)

            tcp_client.send((filename.split("/")[-1]).encode("utf-8"))  # 发送文件名字

            # 1.先发送文件大小，让客户端准备接收
            time.sleep(1)
            size = os.stat(filename).st_size  # 获取文件大小
            tcp_client.send(str(size).encode("utf-8"))  # 发送数据长度
            print("\n发送的大小：", size)

            # 2.发送文件内容
            f = open(filename, "rb")
            for line in f:
                tcp_client.send(line)  # 发送数据
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
            tcp_client.send(send_data.encode("utf-8"))

        else:
            messagebox.showwarning(title='warning', message='请先建立连接')

    except Exception as ex:
        messagebox.showerror(title='error', message=str(ex))


def select_file():
    Filepath = filedialog.askopenfilename()  # 获得选择好的文件
    File_send_text.delete('1.0', 'end')
    File_send_text.insert("end", Filepath)


win = tkinter.Tk()
win.title('TCP-Server')
win.geometry('780x400')
win.option_add('*Font', '宋体 10')

server_ip_label = tkinter.Label(win, text='ServerIP:')
server_ip_label.place(x=20, y=20)
server_ip_entry = tkinter.Entry(win, width=20)
server_ip_entry.place(x=90, y=20)
server_port_label = tkinter.Label(win, text='ServerPort:')
server_port_label.place(x=250, y=20)
server_port_entry = tkinter.Entry(win, width=8)
server_port_entry.place(x=335, y=20)
connect_button = tkinter.Button(win, text='Open', command=thread_main_fun)
connect_button.place(x=410, y=17)
disconnect_button = tkinter.Button(win, text='OFF', command=disconnect)
disconnect_button.place(x=490, y=17)
status_label = tkinter.Label(win, text='服务未开启', bg='yellow', width=25)
status_label.place(x=580, y=20)

server_ip_entry.insert('end', '127.0.0.1')
server_port_entry.insert('end', '12345')

frame1 = tkinter.Frame(win, width=360, height=330, bg='ivory')
frame1.place(x=20, y=50)
frame2 = tkinter.Frame(win, width=360, height=330, bg='ivory')
frame2.place(x=400, y=50)

send_label = tkinter.Label(frame1, text='Send massage to the Client', bg='ivory')
send_label.place(x=5, y=5)
send_button = tkinter.Button(frame1, text='Send Message', command=send_message)
send_button.place(x=260, y=2)
send_text = tkinter.Text(frame1, width=49, height=14)
send_text.place(x=5, y=25)

File_send_label = tkinter.Label(frame1, text='Send file to the Client', bg='ivory')
File_send_label.place(x=5, y=230)
File_select_button = tkinter.Button(frame1, text='Select Path', command=select_file)
File_select_button.place(x=265, y=250)
File_Send_button = tkinter.Button(frame1, text='Send File', command=File_Send)
File_Send_button.place(x=272, y=280)
File_send_text = tkinter.Text(frame1, width=30, height=3)
File_send_text.place(x=5, y=260)

received_label = tkinter.Label(frame2, text='Received massage from the Client', bg='ivory')
received_label.place(x=5, y=5)
received_text = tkinter.Text(frame2, width=49, height=23)
received_text.place(x=5, y=25)
received_text.configure(state='disabled')


def quit1():
    os._exit(0)


win.resizable(False, False)
win.protocol("WM_DELETE_WINDOW", quit1)
win.mainloop()
