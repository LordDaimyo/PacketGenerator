from tkinter import *
from tkinter import scrolledtext
from scapy.layers.inet import UDP


class UdpTab(Frame):
    def __init__(self):
        super().__init__()

        self.first_line = 2
        self.width = 16
        self.pad_x_val = 5

        self.create_udp_fields()
        self.create_udp_data_field()

    def create_udp_fields(self):
        # First line - labels

        self.lbl_udp_source_port = Label(self, text='Source Port (16 bits)')
        self.lbl_udp_source_port.grid(column=0, row=self.first_line, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.lbl_udp_dest_port = Label(self, text='Destination Port (16 bits)')
        self.lbl_udp_dest_port.grid(column=16, row=self.first_line, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Second line - entry

        self.ent_udp_source_port = Entry(self, width=self.width*4)
        self.ent_udp_source_port.grid(column=0, row=self.first_line+1, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.ent_udp_dest_port = Entry(self, width=self.width*4)
        self.ent_udp_dest_port.grid(column=16, row=self.first_line+1, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Third line - labels

        self.lbl_udp_len = Label(self, text='Length (16 bits)')
        self.lbl_udp_len.grid(column=0, row=self.first_line+2, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.lbl_udp_checksum = Label(self, text='Checksum (16 bits)')
        self.lbl_udp_checksum.grid(column=16, row=self.first_line+2, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Fourth line - entry

        self.ent_udp_len = Entry(self, width=self.width*4)
        self.ent_udp_len.grid(column=0, row=self.first_line+3, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.ent_udp_checksum = Entry(self, width=self.width*4)
        self.ent_udp_checksum.grid(column=16, row=self.first_line+3, columnspan=16, sticky='we', padx=self.pad_x_val)

    def create_udp_data_field(self):
        self.lbl_udp_data = Label(self, text='Data')
        self.lbl_udp_data.grid(column=0, row=self.first_line+4, columnspan=32, sticky='we')

        self.scr_udp_data = scrolledtext.ScrolledText(self, width=self.width*4, height='8')
        self.scr_udp_data.grid(column=0, row=self.first_line+5, columnspan=32, sticky='we', padx=self.pad_x_val)

    def get_packet(self):
        data = self.scr_udp_data.get("1.0", END)[:-1]

        udp_header = UDP(
            sport=self.get_udp_sport(),
            dport=self.get_udp_dport(),
            len=self.get_udp_len(),
            chksum=self.get_udp_chksum()
        )/data

        return udp_header

    def get_udp_sport(self):
        sport = self.ent_udp_source_port.get()

        if sport == '':
            sport = 53
        else:
            sport = int(sport)

        return int(sport)

    def get_udp_dport(self):
        dport = self.ent_udp_dest_port.get()

        if dport == '':
            dport = 53
        else:
            dport = int(dport)

        return int(dport)

    def get_udp_len(self):
        length = self.ent_udp_len.get()

        if length == '':
            length = None
        else:
            length = int(length)

        return length

    def get_udp_chksum(self):
        chksum = self.ent_udp_checksum.get()

        if chksum == '':
            chksum = None
        else:
            chksum = int(chksum)

        return chksum

    def clear_fields(self):
        self.ent_udp_source_port.delete(0, END)
        self.ent_udp_dest_port.delete(0, END)
        self.ent_udp_len.delete(0, END)
        self.ent_udp_checksum.delete(0, END)

        self.scr_udp_data.delete("1.0", END)

    def set_field(self, packet, data):
        self.clear_fields()

        self.ent_udp_source_port.insert(0, packet.getfieldval('sport'))
        self.ent_udp_dest_port.insert(0, packet.getfieldval('dport'))
        self.ent_udp_len.insert(0, packet.getfieldval('len'))
        self.ent_udp_checksum.insert(0, packet.getfieldval('chksum'))

        self.scr_udp_data.insert("1.0", data.load)
