# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
#    List of settings that a user can set for this High Level Analyzer.
#    my_string_setting = StringSetting()
#    my_number_setting = NumberSetting(min_value=0, max_value=100)
    address_length = ChoicesSetting(label='Address level', choices=('Three level', 'Two level'))
    dev_mode = ChoicesSetting(label='Mode', choices=('RX', 'TX'))

    RESET_EVENT = 0
    RESET_CMD = 1
    STATE_CMD = 2
    BUSY_CMD = 3
    QUITBUSY_CMD = 4
    BUSMON_CMD = 5
    ACK_INFO = 16
    ACK_INFO_ADDRESSED = 17

    # Communication type
    UNNUMB_DATA_PACKET = 0b00
    NUMB_DATA_PACKET = 0b01
    UNNUMB_CONTROL_DATA = 0b10
    NUMB_CONTROL_DATA = 0b11

    ACK_CONTI = 139

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
        },
        'cmd_str': {
            'format': '{{data.cmd}}'
        },
        'source_addr_str': {
            'format': 'Source addr: {{data.area}}.{{data.line}}.{{data.dev}}'
        },
        'dist_addr_str': {
            'format': 'Destination addr: {{data.area}}{{data.sep}}{{data.line}}{{data.sep}}{{data.dev}}'
        },
        'dist_2l_addr_str': {
            'format': 'Destination addr: {{data.area}}/{{data.dev}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        Settings can be accessed using the same name used above.
        '''
        self.datalist = []
        self.previousFrameValue = ''
        self.byte_count = 0
        self.data_len = 0
        self.telegram_len = 14 + 2          # Headet + CRC
        self.rx_telegram_len = 7 + 1        # Header + CRC
        self.comm_type = 0

        #print("Settings:", self.address_length)


    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.
        The type and data values in `frame` will depend on the input analyzer.
        '''
        payload_str = ''

        currentFrameValue = int(frame.data['data'].hex(), 16)

        item_arr = [currentFrameValue, frame.start_time, frame.end_time]

        self.datalist.append(item_arr)

        if self.dev_mode == 'TX':

            if self.previousFrameValue == '':
                if currentFrameValue == self.RESET_CMD:
                    payload_str = 'RESET'
                if currentFrameValue == self.STATE_CMD:
                    payload_str = 'STATE'
                if currentFrameValue == self.BUSY_CMD:
                    payload_str = 'BUSY'
                if currentFrameValue == self.QUITBUSY_CMD:
                    payload_str = 'QUIT BUSY'
                if currentFrameValue == self.BUSMON_CMD:
                    payload_str = 'BUS MON'
                if currentFrameValue == self.ACK_INFO:
                    payload_str = 'ACK NO ADDR'
                if currentFrameValue == self.ACK_INFO_ADDRESSED:
                    payload_str = 'ACK ADDR'

            if payload_str != '':
                self.previousFrameValue = ''
                self.byte_count = 0
                self.datalist.clear()
                return AnalyzerFrame('cmd_str', frame.start_time, frame.end_time, {'cmd': payload_str})


            if self.byte_count == 11:
                self.data_len = currentFrameValue & 15
                self.telegram_len += self.data_len * 2               #data * 2
                #print('data_len:\t' + str(self.data_len))
                #print('telegram_len:\t' + str(self.telegram_len))
                #print('byte_count:\t' + str(self.byte_count))

            if self.byte_count == self.telegram_len - 1:
                return self.parse_packet(data = self.datalist, length = self.telegram_len)

        else:

            #print('0x{0:02X}'.format(currentFrameValue))

            if self.previousFrameValue == self.RESET_EVENT:
                if currentFrameValue == self.BUSY_CMD:
                    payload_str = 'BUSY'

            if self.previousFrameValue == '':
                if currentFrameValue == self.ACK_CONTI:
                    payload_str = 'ACK CONTI'

            if payload_str != '':
                self.previousFrameValue = ''
                self.byte_count = 0
                self.datalist.clear()
                return AnalyzerFrame('cmd_str', frame.start_time, frame.end_time, {'cmd': payload_str})
    
            if self.byte_count == 5:
                self.data_len = currentFrameValue & 15
                self.rx_telegram_len += self.data_len
            
            #print('Byte count:\t' + str(self.byte_count))
            #print('Tele len:\t' + str(self.rx_telegram_len))
            
            if self.byte_count == self.rx_telegram_len - 1:
                return self.parse_packet(data = self.datalist, length = self.rx_telegram_len)

        self.previousFrameValue = currentFrameValue
        self.byte_count+=1

    def parse_packet(self, data, length):

        #print('Tele len:\t' + str(length))
        analize_frame = []                      # Output analizer array
        analize_count = 0
        new_data_list = []                      # New data byte list

        if self.dev_mode == 'TX':
            inalize_count = 0

            check_crc_checksum = [data[length - 2], data[length - 1]]

            for i in range(length - 2):
                if i % 2 == 0:
                    temp_array = [data[i + 1][0], data[i + 1][1], data[i + 1][2]]
                    new_data_list.append(temp_array)
                    inalize_count+=1

        else:

            new_data_list = data

        # Response address type (group / Individual) from Routing field
        routing_field = new_data_list[5][0]
        target_addr = routing_field >> 7

        #######################
        # Parse Control Field #
        #######################
        contr_field = new_data_list[0][0]
        len_data = contr_field >> 6
        if len_data == 0:
            payload_str = 'Extended length/'
        elif len_data == 2:
            payload_str = 'Standart length/'
        else:
            payload_str = 'Pool data/'

        repeat = (contr_field >> 5) & 1
        if repeat == 0:
            payload_str += 'Repeat/'
        else:
            payload_str += 'No Repeat/'

        priority = (contr_field >> 2) & 3
        if priority == 0:
            payload_str += 'System priority'
        elif priority == 1:
            payload_str += 'High priority'
        elif priority == 2:
            payload_str += 'Alarm priority'
        else:
            payload_str += 'Normal priority'

        if payload_str != "":
            analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', new_data_list[0][1], new_data_list[0][2], {'cmd': payload_str}))

        ########################
        # Parse Source Address #
        ########################
        area = new_data_list[1][0] >> 4
        line = new_data_list[1][0] & 15
        dev = new_data_list[2][0]

        analize_count+=1
        analize_frame.insert(analize_count, AnalyzerFrame('source_addr_str', new_data_list[1][1], new_data_list[2][2],
            {'area': area, 'line': line, 'dev': dev}))

        #############################
        # Parse Destination Address #
        #############################
        if self.address_length == 'Two level' and target_addr == 1:
            addr = new_data_list[3][0] << 8
            addr += new_data_list[4][0]
            area = addr >> 11
            dev = addr & 2047
            analize_count+=1
            analize_frame.insert(analize_count, AnalyzerFrame('dist_2l_addr_str', new_data_list[3][1], new_data_list[4][2],
                {'area': area, 'dev': dev}))
        else:
            if target_addr == 0:
                area = new_data_list[3][0] >> 4
            else:
                area = new_data_list[3][0] >> 3
            line = new_data_list[3][0] & 7
            dev = new_data_list[4][0]
            analize_count+=1
            sep = '/'
            if target_addr == 0:
                sep = '.'

            brodcast = ''
            if area == 0 and line == 0 and dev == 0:
                brodcast = ' Brodcast'

            analize_frame.insert(analize_count, AnalyzerFrame('dist_addr_str', new_data_list[3][1], new_data_list[4][2],
                {'area': area, 'line': line, 'dev': str(dev) + brodcast, 'sep': sep}))

        #######################
        # Parse Routing field #
        #######################
        if target_addr == 0:
            payload_str = 'Individual/'
        else:
            payload_str = 'Group/'

        data_len = routing_field & 15
        payload_str += 'len: ' + str(self.data_len)
        analize_count+=1
        analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', new_data_list[5][1], new_data_list[5][2],
            {'cmd': payload_str}))

        ###############################
        # Parse Commmand field & Data #
        ###############################
        comm_type = (new_data_list[6][0] & 0xC0) >> 6
        if comm_type == self.UNNUMB_CONTROL_DATA and target_addr == 0:
            #print("Com type\t" + str(self.comm_type))
            comm_status = new_data_list[6][0] & 0x03
            #print("Com status\t" + str(comm_status))

            if comm_status == 0:
                payload_str = 'STATUS: OPEN'
            if comm_status == 1:
                payload_str = 'STATUS: BROKEN'

        elif comm_type == self.NUMB_CONTROL_DATA and target_addr == 0:
            comm_status = new_data_list[6][0] & 0x03

            if comm_status == 2:
                payload_str = 'STATUS: CONFIRM'
            if comm_status == 3:
                payload_str = 'STATUS: FAULT'

        else:

            comm_field = new_data_list[6][0] & 3
            command = comm_field << 2
            comm_field = new_data_list[7][0] >> 6
            command += comm_field
            if command == 0:
                payload_str = 'CMD: VAL READ'
            elif command == 1:
                payload_str = 'VAL RESPONSE'
            elif command == 2:
                payload_str = 'VAL WRITE'
            elif command == 3:
                payload_str = 'IND ADDR WRITE'
            elif command == 4:
                payload_str = 'IND ADDR REQUEST'
            elif command == 5:
                payload_str = 'IND ADDR RESPONSE'
            elif command == 6:
                payload_str = 'ADC READ'
            elif command == 7:
                payload_str = 'ADC RESPONSE'
            elif command == 8:
                payload_str = 'MEM READ'
            elif command == 9:
                payload_str = 'MEM RESPONSE'
            elif command == 10:
                payload_str = 'MEM WRITE'
            elif command == 11:
                payload_str = 'USER MESSSAGE'
            elif command == 12:
                payload_str = 'MASK READ'
            elif command == 13:
                payload_str = 'MASK RESPONSE'
            elif command == 14:
                payload_str = 'RESTART'
            elif command == 15:
                payload_str = 'ESCAPE'
            else:
                payload_str = 'UNKNOWN'

        analize_count+=1

        if data_len == 0:
            analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', new_data_list[6][1], new_data_list[6][2], {'cmd': payload_str}))
        else:
            if data_len == 1:
                payload_str += ' / Data: {0} (0x{0:02X} / bxx{0:06b})'.format(new_data_list[7][0] & 63)
            else:
                payload_str += ' / Data: ' + str(new_data_list[7][0] & 63)

            analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', new_data_list[6][1], new_data_list[7][2], {'cmd': payload_str}))

            if data_len > 1:
                payload_count = 8
                analize_count+=1
                temp_data = []
                for i in range(data_len - 1):
                    if data_len == 2:
                        analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', new_data_list[payload_count][1], new_data_list[payload_count][2], {'cmd': new_data_list[payload_count][0]}))
                    if data_len == 3:
                        temp_data.append(new_data_list[payload_count])
                        if len(temp_data) == 2:
                            result = (temp_data[0][0] << 8) + temp_data[1][0]
                            analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', temp_data[0][1], temp_data[1][2], {'cmd': result}))
                            multi_byte = 0
                    if data_len == 4:
                        temp_data.append(new_data_list[payload_count])
                        if len(temp_data) == 3:
                            result = (temp_data[0][0] << 16) + (temp_data[1][0] << 8) + temp_data[2][0]
                            analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', temp_data[0][1], temp_data[2][2], {'cmd': result}))
                    if data_len == 5:
                        temp_data.append(new_data_list[payload_count])
                        if len(temp_data) == 4:
                            result = (temp_data[0][0] << 24) + (temp_data[1][0] << 16) + (temp_data[2][0] << 8) + temp_data[3][0]
                            analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', temp_data[0][1], temp_data[3][2], {'cmd': result}))
                    if data_len == 15:
                        payload_str = chr(new_data_list[payload_count][0])
                        if new_data_list[payload_count][0] != 0:
                            analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', new_data_list[payload_count][1], new_data_list[payload_count][2], {'cmd': payload_str}))

                    payload_count += 1
                    analize_count += 1


        ##########################
        # Calculate CRC Checksum #
        ##########################
        bcc = 255                           # 0xFF  CRC
        tele_data_end = 64                  # b0100 0000  Data end code

        if self.dev_mode == 'TX':

            for i in range(len(new_data_list)):
                bcc ^= new_data_list[i][0]

            tele_data_end |= len(new_data_list)

            if tele_data_end == check_crc_checksum[0][0] and bcc == check_crc_checksum[1][0]:
                payload_str = 'CRC correct'
            else:
                payload_str = 'CRC not correct'

            analize_count+=1
            analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', check_crc_checksum[0][1], check_crc_checksum[1][2], {'cmd': payload_str}))
            self.telegram_len = 14 + 2   #Headet + CRC

        else:

            for i in range(len(new_data_list) - 1):
                bcc ^= new_data_list[i][0]

            if bcc == data[len(new_data_list) - 1][0]:
                payload_str = 'CRC correct'
            else:
                payload_str = 'CRC not correct'

            analize_count+=1
            analize_frame.insert(analize_count, AnalyzerFrame('cmd_str', data[len(new_data_list) - 1][1], data[len(new_data_list) - 1][2], {'cmd': payload_str}))
            self.rx_telegram_len = 7 + 1        # Header + CRC

        #print('CRC: 0x{0:02X}'.format(bcc))
        self.previousFrameValue = ''
        self.byte_count = 0
        self.datalist.clear()
        self.data_len = 0

        return analize_frame





