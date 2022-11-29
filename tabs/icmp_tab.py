from tkinter import *
from tkinter.ttk import Combobox
from tkinter import scrolledtext
from scapy.layers.inet import ICMP


class IcmpTab(Frame):
    def __init__(self):
        super().__init__()

        self.first_line = 2
        self.width = 16
        self.pad_x_val = 5

        self.create_icmp_fields()
        self.create_icmp_data_field()

    def create_icmp_fields(self):
        # First line - labels
        self.lbl_icmp_type = Label(self, text='Type (8 bits)')
        self.lbl_icmp_type.grid(column=0, row=self.first_line, columnspan=8, sticky='we', padx=self.pad_x_val)

        self.lbl_icmp_code = Label(self, text='Code (8 bits)')
        self.lbl_icmp_code.grid(column=8, row=self.first_line, columnspan=8, sticky='we', padx=self.pad_x_val)

        self.lbl_icmp_checksum = Label(self, text='Checksum (16 bits)')
        self.lbl_icmp_checksum.grid(column=16, row=self.first_line, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Second line - entry
        self.cmb_icmp_type = Combobox(self, width=self.width*2, state='readonly')
        self.cmb_icmp_type['values'] = ("Echo reply", "Echo request")
        self.cmb_icmp_type.current(0)
        self.cmb_icmp_type.grid(column=0, row=self.first_line+1, columnspan=8, sticky='we', padx=self.pad_x_val)

        self.ent_icmp_code = Entry(self, width=self.width*2)
        self.ent_icmp_code.grid(column=8, row=self.first_line+1, columnspan=8, sticky='we', padx=self.pad_x_val)

        self.ent_icmp_checksum = Entry(self, width=self.width*4)
        self.ent_icmp_checksum.grid(column=16, row=self.first_line+1, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Third line - labels
        self.lbl_icmp_identifier = Label(self, text='Identifier (16 bits)')
        self.lbl_icmp_identifier.grid(column=0, row=self.first_line+2, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.lbl_icmp_sequence_num = Label(self, text='Sequence Number (16 bits)')
        self.lbl_icmp_sequence_num.grid(column=16, row=self.first_line+2, columnspan=16, sticky='we',
                                        padx=self.pad_x_val)

        # Fourth line - entry

        self.ent_icmp_identifier = Entry(self, width=self.width*4)
        self.ent_icmp_identifier.grid(column=0, row=self.first_line+3, columnspan=16, sticky='we', padx=self.pad_x_val)

        self.ent_icmp_sequence_num = Entry(self, width=self.width*4)
        self.ent_icmp_sequence_num.grid(column=16, row=self.first_line+3, columnspan=16, sticky='we',
                                        padx=self.pad_x_val)

    def create_icmp_data_field(self):
        self.lbl_icmp_data = Label(self, text='Data')
        self.lbl_icmp_data.grid(column=0, row=self.first_line + 5, columnspan=32, sticky='we')

        self.scr_icmp_data = scrolledtext.ScrolledText(self, width=self.width * 4, height='8')
        self.scr_icmp_data.grid(column=0, row=self.first_line + 6, columnspan=32, sticky='we', padx=self.pad_x_val)

    def get_packet(self):
        data = self.scr_icmp_data.get("1.0", END)[:-1]

        icmp_header = ICMP(
            type=self.get_icmp_type(),
            code=self.get_icmp_code(),
            chksum=self.get_icmp_chksum(),
            id=self.get_icmp_id(),
            seq=self.get_icmp_seq()
        )/data

        return icmp_header

    def get_icmp_type(self):
        type = self.cmb_icmp_type.get()

        if type.lower() == 'echo request':
            type = 8
        elif type.lower() == 'echo reply':
            type = 0
        return type

    def get_icmp_code(self):
        code = self.ent_icmp_code.get()

        if code == '':
            code = 0
        else:
            code = int(code)

        return code

    def get_icmp_chksum(self):
        chksum = self.ent_icmp_checksum.get()

        if chksum == '':
            chksum = None
        else:
            chksum = int(chksum)

        return chksum

    def get_icmp_id(self):
        id = self.ent_icmp_identifier.get()

        if id == '':
            id = 0
        else:
            id = int(id)

        return id

    def get_icmp_seq(self):
        seq = self.ent_icmp_sequence_num.get()

        if seq == '':
            seq = 0
        else:
            seq = int(seq)

        return seq

    def clear_fields(self):
        self.cmb_icmp_type.current(0)
        self.ent_icmp_code.delete(0, END)
        self.ent_icmp_checksum.delete(0, END)
        self.ent_icmp_identifier.delete(0, END)
        self.ent_icmp_sequence_num.delete(0, END)

        self.scr_icmp_data.delete("1.0", END)

    def set_field(self, packet, data):
        self.clear_fields()

        type = packet.getfieldval('type')
        if type.lower() == 'echo reply':
            self.cmb_icmp_type.current(0)
        elif type.lower() == 'echo request':
            self.cmb_icmp_type.current(1)

        self.ent_icmp_code.insert(0, packet.getfieldval('code'))
        self.ent_icmp_checksum.insert(0, packet.getfieldval('chksum'))
        self.ent_icmp_identifier.insert(0, packet.getfieldval('id'))
        self.ent_icmp_sequence_num.insert(0, packet.getfieldval('seq'))

        self.scr_icmp_data.insert("1.0", data.load)
