import tkinter.ttk as ttk
from scapy.layers.inet import *
from scapy.all import *
import psutil

from tabs.ip_tab import *
from tabs.tcp_tab import *
from tabs.udp_tab import *
from tabs.icmp_tab import *


class MainWindow(Tk):
    def __init__(self):
        super().__init__()

        self.title("Packet generator")
        self.geometry("1200x600")
        self.resizable(True, True)
        #self.iconbitmap("icon.ico")

        self.first_line = 2
        self.pad_x_val = 5
        self.width = 16

        self.create_ip_fields()
        self.create_transport_tabs()
        self.create_packet_manager()
        self.create_netcards()

    # ***************************************** GRAPHICS ***************************************** #
    def create_ip_fields(self):
        # First line labels

        self.lbl_ip_header = Label(self, text='IP Header')
        self.lbl_ip_header.grid(column=0, row=self.first_line-1, columnspan=32, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_version = Label(self, text='IP Version (4 bits)')
        self.lbl_ip_version.grid(column=0, row=self.first_line, columnspan=4, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_IHL = Label(self, text='IHL (4 bits)')
        self.lbl_ip_IHL.grid(column=4, row=self.first_line, columnspan=4, sticky='we', padx=self.pad_x_val)

        # TOS block: priority (3 bit) + TOS flags (3 bit) + ECN(Explicit Congestion Notification) (2 bit)
        #################################################################################################
        self.lbl_ip_TOS_priority = Label(self, text='Priority (3 bits)')
        self.lbl_ip_TOS_priority.grid(column=8, row=self.first_line, columnspan=3, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_TOS_D = Label(self, text='D')
        self.lbl_ip_TOS_D.grid(column=11, row=self.first_line, columnspan=1, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_TOS_T = Label(self, text='T')
        self.lbl_ip_TOS_T.grid(column=12, row=self.first_line, columnspan=1, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_TOS_R = Label(self, text='R')
        self.lbl_ip_TOS_R.grid(column=13, row=self.first_line, columnspan=1, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_TOS_ECN = Label(self, text='ECN (2 bits)')
        self.lbl_ip_TOS_ECN.grid(column=14, row=self.first_line, columnspan=2, sticky='we', padx=self.pad_x_val)
        #################################################################################################

        self.lbl_ip_total_len = Label(self, text='Total Length (16 bits)')
        self.lbl_ip_total_len.grid(column=16, row=self.first_line, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Second line - enter fields

        self.ent_ip_version = Entry(self, width=self.width-2)
        self.ent_ip_version.grid(column=0, row=self.first_line+1, columnspan=4, sticky='we', padx=self.pad_x_val)

        self.ent_ip_IHL = Entry(self, width=self.width-2)
        self.ent_ip_IHL.grid(column=4, row=self.first_line+1, columnspan=4, sticky='we', padx=self.pad_x_val)

        # TOS block: priority + TOS flags(checkboxes) + ECN
        #################################################################################################
        self.ent_ip_TOS_priority = Entry(self, width=self.width-4)
        self.ent_ip_TOS_priority.grid(column=8, row=self.first_line+1, columnspan=3, sticky='we', padx=self.pad_x_val)

        self.chk_ip_TOS_D_var = IntVar()
        self.chk_ip_TOS_D_var.set(0)
        self.chk_ip_TOS_D = Checkbutton(self, var=self.chk_ip_TOS_D_var)
        self.chk_ip_TOS_D.grid(column=11, row=self.first_line+1, sticky='we')

        self.chk_ip_TOS_T_var = IntVar()
        self.chk_ip_TOS_T_var.set(0)
        self.chk_ip_TOS_T = Checkbutton(self, var=self.chk_ip_TOS_T_var)
        self.chk_ip_TOS_T.grid(column=12, row=self.first_line+1, sticky='we')

        self.chk_ip_TOS_R_var = IntVar()
        self.chk_ip_TOS_R_var.set(0)
        self.chk_ip_TOS_R = Checkbutton(self, var=self.chk_ip_TOS_R_var)
        self.chk_ip_TOS_R.grid(column=13, row=self.first_line+1, sticky='we')

        self.ent_ip_TOS_ECN = Entry(self, width=self.width-6)
        self.ent_ip_TOS_ECN.grid(column=14, row=self.first_line+1, columnspan=2, sticky='we', padx=self.pad_x_val)
        #################################################################################################

        self.ent_ip_total_len = Entry(self, width=self.width*4)
        self.ent_ip_total_len.grid(column=16, row=self.first_line+1, columnspan=16, sticky='we', padx=self.pad_x_val)

        # Third line - labels

        self.lbl_ip_identification = Label(self, text='Identification (16 bits)')
        self.lbl_ip_identification.grid(column=0, row=self.first_line+2, columnspan=16, sticky='we',
                                        padx=self.pad_x_val)

        # IP flags

        self.lbl_ip_flags_X = Label(self, text='RB')
        self.lbl_ip_flags_X.grid(column=16, row=self.first_line+2, columnspan=1, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_flags_D = Label(self, text='DF')
        self.lbl_ip_flags_D.grid(column=17, row=self.first_line+2, columnspan=1, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_flags_M = Label(self, text='MF')
        self.lbl_ip_flags_M.grid(column=18, row=self.first_line+2, columnspan=1, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_fragment_offset = Label(self, text='Fragment offset (13 bits)')
        self.lbl_ip_fragment_offset.grid(column=19, row=self.first_line+2, columnspan=13, sticky='we',
                                         padx=self.pad_x_val)

        # Fourth line - enter fields

        self.ent_ip_identification = Entry(self, width=self.width*4)
        self.ent_ip_identification.grid(column=0, row=self.first_line+3, columnspan=16, sticky='we',
                                        padx=self.pad_x_val)

        # IP flags

        self.chk_ip_flags_X_var = IntVar()
        self.chk_ip_flags_X_var.set(0)
        self.chk_ip_flags_X = Checkbutton(self, var=self.chk_ip_flags_X_var)
        self.chk_ip_flags_X.grid(column=16, row=self.first_line+3, sticky='we')

        self.chk_ip_flags_D_var = IntVar()
        self.chk_ip_flags_D_var.set(0)
        self.chk_ip_flags_D = Checkbutton(self, var=self.chk_ip_flags_D_var)
        self.chk_ip_flags_D.grid(column=17, row=self.first_line+3, sticky='we')

        self.chk_ip_flags_M_var = IntVar()
        self.chk_ip_flags_M_var.set(0)
        self.chk_ip_flags_M = Checkbutton(self, var=self.chk_ip_flags_M_var)
        self.chk_ip_flags_M.grid(column=18, row=self.first_line+3, sticky='we')

        self.ent_ip_fragment_offset = Entry(self, width=32)
        self.ent_ip_fragment_offset.grid(column=19, row=self.first_line+3, columnspan=13, sticky='we',
                                         padx=self.pad_x_val)

        # Fifth line - labels

        self.lbl_ip_TTL = Label(self, text='Time to live (8 bits)')
        self.lbl_ip_TTL.grid(column=0, row=self.first_line+4, columnspan=8, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_protocol = Label(self, text='Protocol (8 bits)')
        self.lbl_ip_protocol.grid(column=8, row=self.first_line+4, columnspan=8, sticky='we', padx=self.pad_x_val)

        self.lbl_ip_header_checksum = Label(self, text='Header checksum (16 bits)')
        self.lbl_ip_header_checksum.grid(column=16, row=self.first_line+4, columnspan=16, sticky='we',
                                         padx=self.pad_x_val)

        # Sixth line - entry fields

        self.ent_ip_TTL = Entry(self, width=16)
        self.ent_ip_TTL.grid(column=0, row=self.first_line+5, columnspan=8, sticky='we', padx=self.pad_x_val)

        #self.ent_ip_protocol = Entry(self, width=16)
        #self.ent_ip_protocol.grid(column=8, row=self.first_line+5, columnspan=8, sticky='we', padx=self.pad_x_val)

        self.cmb_ip_protocol = Combobox(self, width=16, state='readonly')
        self.cmb_ip_protocol['values'] = ('TCP', 'UDP', 'ICMP')
        self.cmb_ip_protocol.current(0)
        self.cmb_ip_protocol.grid(column=8, row=self.first_line+5, columnspan=8, sticky='we', padx=self.pad_x_val)

        self.ent_ip_header_checksum = Entry(self, width=32)
        self.ent_ip_header_checksum.grid(column=16, row=self.first_line+5, columnspan=16, sticky='we',
                                         padx=self.pad_x_val)

        # Seventh line - label

        self.lbl_ip_source = Label(self, text='Source Address (32 bits)')
        self.lbl_ip_source.grid(column=0, row=self.first_line+6, columnspan=32, sticky='we', padx=self.pad_x_val)

        # Eighth line - source address entry

        self.ent_ip_source = Entry(self, width=64)
        self.ent_ip_source.grid(column=0, row=self.first_line+7, columnspan=32, sticky='we', padx=self.pad_x_val)

        # Ninth line - label

        self.lbl_ip_dest = Label(self, text='Destination Address (32 bits)')
        self.lbl_ip_dest.grid(column=0, row=self.first_line+8, columnspan=32, sticky='we', padx=self.pad_x_val)

        # Tenth line - destination address entry

        self.ent_ip_dest = Entry(self, width=64)
        self.ent_ip_dest.grid(column=0, row=self.first_line+9, columnspan=32, sticky='we', padx=self.pad_x_val)

        # Eleventh line - label

        self.lbl_ip_option = Label(self, text='Transport protocols')
        self.lbl_ip_option.grid(column=0, row=self.first_line+10, columnspan=32, sticky='we', padx=self.pad_x_val)

    def create_transport_tabs(self):
        self.frm_transport_window = Frame(self)
        self.frm_transport_window.grid(column=0, row=self.first_line+11, columnspan=32, rowspan=10)

        self.transport_tabs = []
        self.main_transport_window = ttk.Notebook(self.frm_transport_window)

        self.transport_tabs.append(IpTab())
        self.transport_tabs.append(TcpTab())
        self.transport_tabs.append(UdpTab())
        self.transport_tabs.append(IcmpTab())

        self.main_transport_window.add(self.transport_tabs[0], text='IP')
        self.main_transport_window.add(self.transport_tabs[1], text='TCP')
        self.main_transport_window.add(self.transport_tabs[2], text='UDP')
        self.main_transport_window.add(self.transport_tabs[3], text='ICMP')

        self.main_transport_window.bind('<<NotebookTabChanged>>', self.tab_changed)

        self.main_transport_window.grid(column=0, row=0)

    def create_packet_manager(self):
        self.stored_packets = []

        self.lbl_list_of_packet_mngt = Label(self, text="Packets")
        self.lbl_list_of_packet_mngt.grid(column=33, row=self.first_line-1, columnspan=32, padx=5, sticky='ew')

        self.list_of_packets = Listbox(self, selectmode=EXTENDED, width=self.width*5, height=13)
        self.list_of_packets.grid(column=33, row=self.first_line, columnspan=32, rowspan=15, sticky='news')

        self.scroller_horizontal = Scrollbar(self, orient=HORIZONTAL)
        self.scroller_horizontal.grid(column=33, row=self.first_line+15, columnspan=32, sticky='ew')

        self.scroller_vertical = Scrollbar(self, orient=VERTICAL)
        self.scroller_vertical.grid(column=58, row=self.first_line, rowspan=15, sticky='ns')

        self.list_of_packets.config(yscrollcommand=self.scroller_vertical.set,
                                    xscrollcommand=self.scroller_horizontal.set)
        self.scroller_vertical.config(command=self.list_of_packets.yview)
        self.scroller_horizontal.config(command=self.list_of_packets.xview)

        self.btn_save = Button(self, text='Save', command=self.save_packet, width=self.width)
        self.btn_save.grid(column=33, row=self.first_line+16, columnspan=4, sticky='we')

        self.btn_delete = Button(self, text='Delete', command=self.delete_packet, width=self.width)
        self.btn_delete.grid(column=37, row=self.first_line+16, columnspan=4, sticky='we')

        self.btn_delete_all = Button(self, text='Delete All', command=self.delete_all_packets, width=self.width)
        self.btn_delete_all.grid(column=33, row=self.first_line+17, columnspan=4, sticky='we')

        self.btn_clear_fields = Button(self, text='Clear Fields', command=self.clear_fields, width=self.width)
        self.btn_clear_fields.grid(column=37, row=self.first_line+17, columnspan=4, sticky='we')

        #self.btn_set_fields = Button(self, text='Set Fields', command=self.set_fields, width=self.width)
        #self.btn_set_fields.grid(column=41, row=self.first_line+17, columnspan=4, sticky='we')

        self.btn_send = Button(self, text='Send', command=self.send_packets, width=self.width)
        self.btn_send.grid(column=33, row=self.first_line+18, columnspan=4, sticky='we')

        #self.btn_save_on_disk = Button(self, command=self.save_on_disk, width=self.width)
        #self.btn_save_on_disk.grid(column=45, row=self.first_line+16, columnspan=4, sticky='we')

    def create_netcards(self):
        self.adapters = psutil.net_if_addrs()
        self.adapters_names = list(self.adapters.keys())

        self.cmb_adapters = Combobox(self, state='readonly')
        self.cmb_adapters['values'] = self.adapters_names
        self.cmb_adapters.current(0)
        self.cmb_adapters.grid(column=37, row=self.first_line+18, columnspan=16, sticky='we')

    # ***************************************** BUTTON COMMANDS ***************************************** #

    def save_packet(self):
        ip_data = self.get_ip_data()

        if self.main_transport_window.index('current') != 0:
            transport_proto = self.get_transport_packet()
            protocol = ip_data/transport_proto
        else:
            protocol = ip_data

        self.stored_packets.append(protocol)
        packet_view = protocol.show(dump=True)
        packet_view = packet_view.replace('\n', ' ')

        test_string_parts = packet_view.split(' ')
        packet_view = ''
        for part in test_string_parts:
            if part != '':
             packet_view += (part + ' ')

        self.list_of_packets.insert(END, packet_view)

    def delete_packet(self):
        select = list(self.list_of_packets.curselection())
        select.reverse()
        for i in select:
            self.list_of_packets.delete(i)
            self.stored_packets.remove(self.stored_packets[i])

    def delete_all_packets(self):
        self.list_of_packets.delete(0, END)
        self.stored_packets.clear()

    def clear_fields(self):
        self.clear_ip_fields()
        self.clear_transport()
        return

    def set_fields(self):
        select = list(self.list_of_packets.curselection())

        if len(select) > 1 or len(select) < 1:
            return

        packet = self.stored_packets[select[0]]

        self.set_ip_field(packet)
        self.set_transport_field(packet)

    def send_packets(self):
        select = list(self.list_of_packets.curselection())
        for ind in select:
            interface_num = self.cmb_adapters.get()
            packet = self.stored_packets[ind]
            sr1(packet, iface=interface_num, timeout=0)
        return

    def save_on_disk(self):
        return
    #    packets = list(self.list_of_packets.curselection())
#
    #    file = open('packets.stored', 'wb')
#
    #    for packet in packets:
    #        pkt = self.stored_packets[packet]
    #        file.write(pkt)
#
    #    file.close()

    def tab_changed(self, event):
        tab = self.main_transport_window.index(self.main_transport_window.select())
        if tab != 0:
            tab -= 1

        self.cmb_ip_protocol.current(tab)


    # ***************************************** GETTING INFO ***************************************** #

    def get_ip_data(self):
        ip_header = IP(
            version=self.get_ip_version(),
            ihl=self.get_ip_IHL(),
            tos=self.get_ip_tos_value(),
            len=self.get_ip_len(),
            id=self.get_ip_id(),
            flags=self.get_ip_flags(),
            frag=self.get_ip_frag(),
            ttl=self.get_ip_ttl(),
            proto=self.get_ip_proto(),
            chksum=self.get_ip_checksum(),
            src=self.get_ip_src(),
            dst=self.get_ip_dst(),
        )

        return ip_header

    def check_none(self, var):
        if var == '':
            return None
        else:
            return int(var)

    def check_zero(self, var):
        if var == '':
            return 0
        else:
            return int(var)

    def get_ip_version(self):
        version = self.ent_ip_version.get()

        if version == '':
            return 4
        else:
            return int(version)

    def get_ip_IHL(self):
        IHL = self.ent_ip_IHL.get()

        return self.check_none(IHL)

    def get_ip_tos_value(self):
        priority = self.ent_ip_TOS_priority.get()
        D = self.chk_ip_TOS_D_var.get()
        T = self.chk_ip_TOS_T_var.get()
        R = self.chk_ip_TOS_R_var.get()
        ECN = self.ent_ip_TOS_ECN.get()

        if (priority == '') or (ECN == ''):
            return 0
        else:
            priority = int(priority)
            ECN = int(ECN)
            result_byte = priority << 5
            result_byte = result_byte | (D << 4)
            result_byte = result_byte | (T << 3)
            result_byte = result_byte | (R << 2)
            result_byte = result_byte | ECN
            return result_byte

    def get_ip_len(self):
        length = self.ent_ip_total_len.get()

        return self.check_none(length)

    def get_ip_id(self):
        id = self.ent_ip_identification.get()

        if id == '':
            return 1
        else:
            return int(id)

    def get_ip_flags(self):
        X = self.chk_ip_flags_X_var.get()
        D = self.chk_ip_flags_D_var.get()
        M = self.chk_ip_flags_M_var.get()

        result = (X << 2) | (D << 1) | M

        return result

    def get_ip_frag(self):
        frag = self.ent_ip_fragment_offset.get()

        return self.check_zero(frag)

    def get_ip_ttl(self):
        ttl = self.ent_ip_TTL.get()

        if ttl == '':
            return 64
        else:
            return int(ttl)

    def get_ip_proto(self):
        proto = self.cmb_ip_protocol.get()
        if proto.lower() == 'tcp':
            return 6
        elif proto.lower() == 'udp':
            return 17
        elif proto.lower() == 'icmp':
            return 1
        else:
            return 6

    def get_ip_checksum(self):
        chksum = self.ent_ip_header_checksum.get()

        return self.check_none(chksum)

    def get_ip_src(self):
        src = self.ent_ip_source.get()

        if src == '':
            return None
        else:
            return src

    def get_ip_dst(self):
        dst = self.ent_ip_dest.get()

        if dst == '':
            return '127.0.0.1'
        else:
            return dst

    def get_transport_packet(self):
        cur_tab = self.main_transport_window.index('current')
        return self.transport_tabs[cur_tab].get_packet()

    # *************************************** CLEAR/SET FIELDS ************************************* #

    def clear_ip_fields(self):
        self.ent_ip_version.delete(0, END)
        self.ent_ip_IHL.delete(0, END)
        self.ent_ip_TOS_priority.delete(0, END)
        self.chk_ip_TOS_D_var.set(0)
        self.chk_ip_TOS_T_var.set(0)
        self.chk_ip_TOS_R_var.set(0)
        self.ent_ip_TOS_ECN.delete(0, END)
        self.ent_ip_total_len.delete(0, END)
        self.ent_ip_identification.delete(0, END)
        self.chk_ip_flags_X_var.set(0)
        self.chk_ip_flags_D_var.set(0)
        self.chk_ip_flags_M_var.set(0)
        self.ent_ip_fragment_offset.delete(0, END)
        self.ent_ip_TTL.delete(0, END)
        self.cmb_ip_protocol.current(0)
        self.ent_ip_header_checksum.delete(0, END)
        self.ent_ip_source.delete(0, END)
        self.ent_ip_dest.delete(0, END)

    def clear_transport(self):
        cur_tab = self.main_transport_window.index('current')
        self.transport_tabs[cur_tab].clear_fields()

    def set_ip_field(self, packet):
        self.clear_ip_fields()

        self.ent_ip_version.insert(0, packet.getfieldval('version'))
        self.ent_ip_IHL.insert(0, packet.getfieldval('ihl'))
        self.ent_ip_TOS_priority.insert(0, packet.getfieldval('tos') >> 5)
        self.chk_ip_TOS_D_var.set((packet.getfieldval('tos') >> 4) & 1)
        self.chk_ip_TOS_T_var.set((packet.getfieldval('tos') >> 3) & 1)
        self.chk_ip_TOS_R_var.set((packet.getfieldval('tos') >> 2) & 1)
        self.ent_ip_TOS_ECN.insert(0, packet.getfieldval('tos') & 3)
        self.ent_ip_total_len.insert(0, packet.getfieldval('len'))
        self.ent_ip_identification.insert(0, packet.getfieldval('id'))
        self.chk_ip_flags_X_var.set((packet.getfieldval('flags').value >> 2) & 1)
        self.chk_ip_flags_D_var.set((packet.getfieldval('flags').value >> 1) & 1)
        self.chk_ip_flags_M_var.set(packet.getfieldval('flags').value & 1)
        self.ent_ip_fragment_offset.insert(0, packet.getfieldval('frag'))
        self.ent_ip_TTL.insert(0, packet.getfieldval('ttl'))
        #self.ent_ip_protocol.insert(0, packet.getfieldval('proto'))
        proto = packet.getfieldval('proto')
        if proto == 6:
            self.cmb_ip_protocol.set('TCP')
        elif proto == 17:
            self.cmb_ip_protocol.set('UDP')
        elif proto == 1:
            self.cmb_ip_protocol.set('ICMP')

        self.ent_ip_header_checksum.insert(0, packet.getfieldval('chksum'))
        self.ent_ip_source.insert(0, packet.getfieldval('src'))
        self.ent_ip_dest.insert(0, packet.getfieldval('dst'))

    def set_transport_field(self, packet):
        data = packet.getlayer('Raw')

        transport = packet.getlayer('ICMP')
        if transport == None:
            transport = packet.getlayer('UDP')
            if transport == None:
                transport = packet.getlayer('TCP')
                if transport == None:
                    transport_num = 0
                else:
                    transport_num = 1
            else:
                transport_num = 2
        else:
            transport_num = 3

        transport_tab = self.transport_tabs[transport_num]
        transport_tab.set_field(transport, data)
