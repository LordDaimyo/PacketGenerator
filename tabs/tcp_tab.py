from tkinter import *
from tkinter import scrolledtext
from scapy.layers.inet import TCP


class TcpTab(Frame):
    def __init__(self):
        super().__init__()

        self.first_line = 2
        self.width = 16
        self.pad_x_val = 5

        self.create_tcp_fields()
        self.create_tcp_data_field()

    def create_tcp_fields(self):
        # First line - labels

        self.lbl_tcp_source_port = Label(self, text='Source Port (16 bits)')
        self.lbl_tcp_source_port.grid(column=0, row=self.first_line, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.lbl_tcp_dest_port = Label(self, text='Destination Port (16 bits)')
        self.lbl_tcp_dest_port.grid(column=16, row=self.first_line, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Second line - entry

        self.ent_tcp_source_port = Entry(self, width=self.width*4)
        self.ent_tcp_source_port.grid(column=0, row=self.first_line+1, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.ent_tcp_dest_port = Entry(self, width=self.width*4)
        self.ent_tcp_dest_port.grid(column=16, row=self.first_line+1, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Third line - labels

        self.lbl_tcp_sequence_num = Label(self, text='Sequence Number (32 bits)')
        self.lbl_tcp_sequence_num.grid(column=0, row=self.first_line+2, columnspan=32, sticky='we', padx=self.pad_x_val)

        # Fourth line - entry

        self.ent_tcp_sequence_num = Entry(self, width=self.width*8)
        self.ent_tcp_sequence_num.grid(column=0, row=self.first_line+3, columnspan=32, sticky='we', padx=self.pad_x_val)

        # Fifth line - label

        self.lbl_tcp_ack_num = Label(self, text='Acknowledgment Number (32 bits)')
        self.lbl_tcp_ack_num.grid(column=0, row=self.first_line+4, columnspan=32, sticky='we', padx=self.pad_x_val)

        # Sixth line - entry
        self.ent_tcp_ack_num = Entry(self, width=self.width*8)
        self.ent_tcp_ack_num.grid(column=0, row=self.first_line+5, columnspan=32, sticky='we', padx=self.pad_x_val)

        # Seventh line - label
        self.lbl_tcp_offset = Label(self, text='Offset (4 bits)')
        self.lbl_tcp_offset.grid(column=0, row=self.first_line+6, columnspan=4, sticky='we', padx=self.pad_x_val)

        self.lbl_tcp_reserved = Label(self, text='Reserved (4 bits)')
        self.lbl_tcp_reserved.grid(column=4, row=self.first_line+6, columnspan=4, sticky='we', padx=self.pad_x_val)

        # TCP Flags
        ########################################################################################################
        self.lbl_tcp_flag_C = Label(self, text='C')
        self.lbl_tcp_flag_C.grid(column=8, row=self.first_line+6, columnspan=1, sticky='we')

        self.lbl_tcp_flag_E = Label(self, text='E')
        self.lbl_tcp_flag_E.grid(column=9, row=self.first_line+6, columnspan=1, sticky='we')

        self.lbl_tcp_flag_U = Label(self, text='U')
        self.lbl_tcp_flag_U.grid(column=10, row=self.first_line+6, columnspan=1, sticky='we')

        self.lbl_tcp_flag_A = Label(self, text='A')
        self.lbl_tcp_flag_A.grid(column=11, row=self.first_line+6, columnspan=1, sticky='we')

        self.lbl_tcp_flag_P = Label(self, text='P')
        self.lbl_tcp_flag_P.grid(column=12, row=self.first_line+6, columnspan=1, sticky='we')

        self.lbl_tcp_flag_R = Label(self, text='R')
        self.lbl_tcp_flag_R.grid(column=13, row=self.first_line+6, columnspan=1, sticky='we')

        self.lbl_tcp_flag_S = Label(self, text='S')
        self.lbl_tcp_flag_S.grid(column=14, row=self.first_line+6, columnspan=1, sticky='we')

        self.lbl_tcp_flag_F = Label(self, text='F')
        self.lbl_tcp_flag_F.grid(column=15, row=self.first_line+6, columnspan=1, sticky='we')
        ########################################################################################################

        self.lbl_tcp_window = Label(self, text='Window (16 bits)')
        self.lbl_tcp_window.grid(column=16, row=self.first_line+6, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Eigth line - entry
        self.ent_tcp_offset = Entry(self, width=self.width)
        self.ent_tcp_offset.grid(column=0, row=self.first_line+7, columnspan=4, sticky='we', padx=self.pad_x_val)

        self.ent_tcp_reserved = Entry(self, width=self.width)
        self.ent_tcp_reserved.grid(column=4, row=self.first_line+7, columnspan=4, sticky='we', padx=self.pad_x_val)

        # TCP Flags
        ########################################################################################################
        self.chk_tcp_flag_C_var = IntVar()
        self.chk_tcp_flag_C_var.set(0)
        self.chk_tcp_flag_C = Checkbutton(self, var=self.chk_tcp_flag_C_var)
        self.chk_tcp_flag_C.grid(column=8, row=self.first_line+7, sticky='we')

        self.chk_tcp_flag_E_var = IntVar()
        self.chk_tcp_flag_E_var.set(0)
        self.chk_tcp_flag_E = Checkbutton(self, var=self.chk_tcp_flag_E_var)
        self.chk_tcp_flag_E.grid(column=9, row=self.first_line+7, sticky='we')

        self.chk_tcp_flag_U_var = IntVar()
        self.chk_tcp_flag_U_var.set(0)
        self.chk_tcp_flag_U = Checkbutton(self, var=self.chk_tcp_flag_U_var)
        self.chk_tcp_flag_U.grid(column=10, row=self.first_line+7, sticky='we')

        self.chk_tcp_flag_A_var = IntVar()
        self.chk_tcp_flag_A_var.set(0)
        self.chk_tcp_flag_A = Checkbutton(self, var=self.chk_tcp_flag_A_var)
        self.chk_tcp_flag_A.grid(column=11, row=self.first_line+7, sticky='we')

        self.chk_tcp_flag_P_var = IntVar()
        self.chk_tcp_flag_P_var.set(0)
        self.chk_tcp_flag_P = Checkbutton(self, var=self.chk_tcp_flag_P_var)
        self.chk_tcp_flag_P.grid(column=12, row=self.first_line+7, sticky='we')

        self.chk_tcp_flag_R_var = IntVar()
        self.chk_tcp_flag_R_var.set(0)
        self.chk_tcp_flag_R = Checkbutton(self, var=self.chk_tcp_flag_R_var)
        self.chk_tcp_flag_R.grid(column=13, row=self.first_line+7, sticky='we')

        self.chk_tcp_flag_S_var = IntVar()
        self.chk_tcp_flag_S_var.set(0)
        self.chk_tcp_flag_S = Checkbutton(self, var=self.chk_tcp_flag_S_var)
        self.chk_tcp_flag_S.grid(column=14, row=self.first_line+7, sticky='we')

        self.chk_tcp_flag_F_var = IntVar()
        self.chk_tcp_flag_F_var.set(0)
        self.chk_tcp_flag_F = Checkbutton(self, var=self.chk_tcp_flag_F_var)
        self.chk_tcp_flag_F.grid(column=15, row=self.first_line+7, sticky='we')
        ########################################################################################################

        self.ent_tcp_window = Entry(self, width=self.width*2)
        self.ent_tcp_window.grid(column=16, row=self.first_line+7, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Tenth line - labels
        self.lbl_tcp_checksum = Label(self, text='Checksum (16 bits)')
        self.lbl_tcp_checksum.grid(column=0, row=self.first_line+8, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.lbl_tcp_urgent_pointer = Label(self, text='Urgent Pointer (16 bits)')
        self.lbl_tcp_urgent_pointer.grid(column=16, row=self.first_line+8, columnspan=16, sticky='we',
                                         padx=self.pad_x_val)

        # Eleventh line - entry
        self.ent_tcp_checksum = Entry(self, width=self.width*2)
        self.ent_tcp_checksum.grid(column=0, row=self.first_line+9, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.ent_tcp_urgent_pointer = Entry(self, width=self.width*2)
        self.ent_tcp_urgent_pointer.grid(column=16, row=self.first_line+9, columnspan=16, sticky='we',
                                         padx=self.pad_x_val)

    def create_tcp_data_field(self):
        self.lbl_tcp_data = Label(self, text='Data')
        self.lbl_tcp_data.grid(column=0, row=self.first_line+10, columnspan=32, sticky='we')

        self.scr_tcp_data = scrolledtext.ScrolledText(self, width=self.width*4, height='8')
        self.scr_tcp_data.grid(column=0, row=self.first_line+11, columnspan=32, sticky='we', padx=self.pad_x_val)

    def get_packet(self):
        data = self.scr_tcp_data.get("1.0", END)[:-1]

        tcp_header = TCP(
            sport=self.get_tcp_sport(),
            dport=self.get_tcp_dport(),
            seq=self.get_tcp_seq(),
            ack=self.get_tcp_ack(),
            dataofs=self.get_tcp_dataofs(),
            reserved=self.get_tcp_reserved(),
            flags=self.get_tcp_flags(),
            window=self.get_tcp_window(),
            chksum=self.get_tcp_chksum(),
            urgptr=self.get_tcp_urgptr()
        )/data

        return tcp_header

    def get_tcp_sport(self):
        sport = self.ent_tcp_source_port.get()

        if sport == '':
            sport = 20
        else:
            sport = int(sport)

        return sport

    def get_tcp_dport(self):
        dport = self.ent_tcp_dest_port.get()

        if dport == '':
            dport = 80
        else:
            dport = int(dport)

        return dport

    def get_tcp_seq(self):
        seq = self.ent_tcp_sequence_num.get()

        if seq == '':
            seq = 0
        else:
            seq = int(seq)

        return seq

    def get_tcp_ack(self):
        ack = self.ent_tcp_ack_num.get()

        if ack == '':
            ack = 0
        else:
            ack = int(ack)

        return ack

    def get_tcp_dataofs(self):
        dataofs = self.ent_tcp_offset.get()

        if dataofs == '':
            dataofs = None
        else:
            dataofs = int(dataofs)

        return dataofs

    def get_tcp_reserved(self):
        reserved = self.ent_tcp_reserved.get()

        if reserved == '':
            reserved = 0
        else:
            reserved = int(reserved)

        return reserved

    def get_tcp_flags(self):
        C = self.chk_tcp_flag_C_var.get()
        E = self.chk_tcp_flag_E_var.get()
        U = self.chk_tcp_flag_U_var.get()
        A = self.chk_tcp_flag_A_var.get()
        P = self.chk_tcp_flag_P_var.get()
        R = self.chk_tcp_flag_R_var.get()
        S = self.chk_tcp_flag_S_var.get()
        F = self.chk_tcp_flag_F_var.get()

        result_byte = (C << 7) | (E << 6) | (U << 5) | (A << 4) | (P << 3) | (R << 2) | (S << 1) | F

        return result_byte

    def get_tcp_window(self):
        window = self.ent_tcp_window.get()

        if window == '':
            window = 8192
        else:
            window = int(window)

        return window

    def get_tcp_chksum(self):
        chksum = self.ent_tcp_checksum.get()

        if chksum == '':
            chksum = None
        else:
            chksum = int(chksum)

        return chksum

    def get_tcp_urgptr(self):
        urgptr = self.ent_tcp_urgent_pointer.get()

        if urgptr == '':
            urgptr = 0
        else:
            urgptr = int(urgptr)

        return urgptr

    def clear_fields(self):
        self.ent_tcp_source_port.delete(0, END)
        self.ent_tcp_dest_port.delete(0, END)
        self.ent_tcp_sequence_num.delete(0, END)
        self.ent_tcp_ack_num.delete(0, END)
        self.ent_tcp_offset.delete(0, END)
        self.ent_tcp_reserved.delete(0, END)
        self.chk_tcp_flag_C_var.set(0)
        self.chk_tcp_flag_E_var.set(0)
        self.chk_tcp_flag_U_var.set(0)
        self.chk_tcp_flag_A_var.set(0)
        self.chk_tcp_flag_P_var.set(0)
        self.chk_tcp_flag_R_var.set(0)
        self.chk_tcp_flag_S_var.set(0)
        self.chk_tcp_flag_F_var.set(0)
        self.ent_tcp_window.delete(0, END)
        self.ent_tcp_checksum.delete(0, END)
        self.ent_tcp_urgent_pointer.delete(0, END)

        self.scr_tcp_data.delete("1.0", END)

    def set_field(self, packet, data):
        self.clear_fields()

        self.ent_tcp_source_port.insert(0, packet.getfieldval('sport'))
        self.ent_tcp_dest_port.insert(0, packet.getfieldval('dport'))
        self.ent_tcp_sequence_num.insert(0, packet.getfieldval('seq'))
        self.ent_tcp_ack_num.insert(0, packet.getfieldval('ack'))
        self.ent_tcp_offset.insert(0, packet.getfieldval('dataofs'))
        self.ent_tcp_reserved.insert(0, packet.getfieldval('reserved'))
        self.chk_tcp_flag_C_var.set((packet.getfieldval('flags').value >> 7) & 1)
        self.chk_tcp_flag_E_var.set((packet.getfieldval('flags').value >> 6) & 1)
        self.chk_tcp_flag_U_var.set((packet.getfieldval('flags').value >> 5) & 1)
        self.chk_tcp_flag_A_var.set((packet.getfieldval('flags').value >> 4) & 1)
        self.chk_tcp_flag_P_var.set((packet.getfieldval('flags').value >> 3) & 1)
        self.chk_tcp_flag_R_var.set((packet.getfieldval('flags').value >> 2) & 1)
        self.chk_tcp_flag_S_var.set((packet.getfieldval('flags').value >> 1) & 1)
        self.chk_tcp_flag_F_var.set(packet.getfieldval('flags').value & 1)
        self.ent_tcp_window.insert(0, packet.getfieldval('window'))
        self.ent_tcp_checksum.insert(0, packet.getfieldval('chksum'))
        self.ent_tcp_urgent_pointer.insert(0, packet.getfieldval('urgptr'))

        self.scr_tcp_data.insert("1.0", data.load)
